#!/usr/bin/env python3
"""
phantom/store.py — unified state storage so Phantom is stateless at the container
level (the prerequisite for Fargate / multiple workers), while staying trivially
runnable on a laptop.

Two axes, each with a local default and a managed override:

  DB (structured state: campaigns, approvals, audit)
    default : sqlite:///phantom/data/phantom.db   (a local file — no server)
    prod    : PHANTOM_DB_URL=postgresql+psycopg://user:pass@host/db
    SQLAlchemy speaks both with the SAME code, so nothing above this layer changes.

  Blob (reports)
    default : phantom/reports/<subdir>/<name>      (local filesystem)
    prod    : PHANTOM_REPORTS_BUCKET=my-bucket      (S3, via boto3)

Local use needs only SQLAlchemy (in requirements). Postgres adds `psycopg`, S3 adds
`boto3` — both optional and only imported when their backend is selected.

Public API:
  session() -> SQLAlchemy Session          # structured state
  db_kind() / blob_kind()                  # which backend is active
  save_blob(subdir, name, text) -> uri     # write a report
  read_blob(subdir, name) -> str | None    # read a report
  write_audit(action, user, roles, data)   # append an audit event
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import (Boolean, Column, DateTime, Integer, String, Text,
                        create_engine)
from sqlalchemy.orm import declarative_base, sessionmaker

ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = Path(__file__).resolve().parent / "data"

Base = declarative_base()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── Models (one shared DB) ───────────────────────────────────────────────────

class Campaign(Base):
    __tablename__ = "campaigns"
    campaign_id = Column(String, primary_key=True)
    created_at = Column(DateTime)
    last_seen = Column(DateTime)
    status = Column(String, default="open", index=True)
    report_count = Column(Integer, default=0)
    subject = Column(String)          # normalized subject
    sender_domain = Column(String)
    tokens = Column(Text)             # JSON list
    iocs = Column(Text)              # JSON dict
    thehive_case = Column(String, nullable=True)
    misp_event = Column(String, nullable=True)
    jira_issue = Column(String, nullable=True)


class CampaignReport(Base):
    __tablename__ = "campaign_reports"
    report_id = Column(String, primary_key=True)
    message_id = Column(String, index=True)
    campaign_id = Column(String, index=True)
    investigated_at = Column(DateTime)
    verdict = Column(String)
    confidence = Column(Integer)
    reported_by = Column(String)
    subject = Column(String)
    sender_domain = Column(String)
    iocs = Column(Text)              # JSON dict


class Approval(Base):
    __tablename__ = "approvals"
    id = Column(String, primary_key=True)
    session_id = Column(String)
    action_type = Column(String)
    resources = Column(Text)         # JSON list
    justification = Column(Text)
    impact = Column(Text)
    impact_level = Column(String)
    requested_by = Column(String)
    requested_at = Column(DateTime)
    expires_at = Column(DateTime)
    status = Column(String, default="pending", index=True)
    decided_by = Column(String, nullable=True)
    decided_at = Column(DateTime, nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, index=True)
    action = Column(String, index=True)
    user = Column(String, nullable=True)
    roles = Column(Text, nullable=True)     # JSON list
    data = Column(Text, nullable=True)      # JSON dict


# ── Engine / session (lazy singleton) ────────────────────────────────────────

_engine = None
_Session = None


def db_url() -> str:
    return os.environ.get("PHANTOM_DB_URL") or f"sqlite:///{_DATA_DIR / 'phantom.db'}"


def db_kind() -> str:
    return "postgres" if db_url().startswith(("postgres", "postgresql")) else "sqlite"


def _init():
    global _engine, _Session
    if _engine is None:
        url = db_url()
        kw = {"future": True, "pool_pre_ping": True}
        if url.startswith("sqlite"):
            _DATA_DIR.mkdir(parents=True, exist_ok=True)
            kw["connect_args"] = {"check_same_thread": False}
        _engine = create_engine(url, **kw)
        Base.metadata.create_all(_engine)
        _Session = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _Session


def session():
    return _init()()


def _reset():  # test hook
    global _engine, _Session
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _Session = None


# ── JSON column helpers ──────────────────────────────────────────────────────

def dumps(v) -> str:
    return json.dumps(v, default=str)


def loads(s, default=None):
    if not s:
        return default
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return default


# ── Audit ────────────────────────────────────────────────────────────────────

def write_audit(action: str, user=None, roles=None, data: dict | None = None) -> None:
    """Persist an audit event to the DB. Best-effort: falls back to a JSONL file
    if the DB is unavailable (audit must never break the calling request)."""
    try:
        s = session()
        try:
            s.add(AuditEvent(ts=_now(), action=action, user=user,
                             roles=dumps(roles) if roles else None,
                             data=dumps(data) if data else None))
            s.commit()
            return
        finally:
            s.close()
    except Exception:
        pass
    # fallback: local JSONL (single-container / DB-down)
    try:
        path = Path(os.environ.get("PHANTOM_AUDIT_LOG",
                                   str(ROOT / "reports" / "audit" / "control-plane.jsonl")))
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(dumps({"ts": _now().isoformat(), "action": action,
                           "user": user, "roles": roles, **(data or {})}) + "\n")
    except OSError:
        pass


# ── Blob store (reports) ─────────────────────────────────────────────────────

def _bucket() -> str:
    return os.environ.get("PHANTOM_REPORTS_BUCKET", "")


def _prefix() -> str:
    return os.environ.get("PHANTOM_REPORTS_PREFIX", "reports/")


def blob_kind() -> str:
    return "s3" if _bucket() else "local"


def save_blob(subdir: str, name: str, text: str) -> str:
    """Write a report. Returns a URI (file path or s3:// url)."""
    bucket = _bucket()
    if bucket:
        import boto3  # optional
        key = f"{_prefix()}{subdir}/{name}"
        boto3.client("s3").put_object(Bucket=bucket, Key=key,
                                      Body=text.encode("utf-8"),
                                      ContentType="text/markdown")
        return f"s3://{bucket}/{key}"
    path = ROOT / "reports" / subdir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path)


def read_blob(subdir: str, name: str) -> str | None:
    bucket = _bucket()
    if bucket:
        import boto3  # optional
        try:
            obj = boto3.client("s3").get_object(Bucket=bucket, Key=f"{_prefix()}{subdir}/{name}")
            return obj["Body"].read().decode("utf-8", "replace")
        except Exception:
            return None
    path = ROOT / "reports" / subdir / name
    return path.read_text(encoding="utf-8") if path.exists() else None
