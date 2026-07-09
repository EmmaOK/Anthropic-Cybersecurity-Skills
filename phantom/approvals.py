#!/usr/bin/env python3
"""Approval store and Google Chat notifications for Phantom IR workflow.

Approvals persist in the shared store (phantom/store.py): a local SQLite file by
default, Postgres when PHANTOM_DB_URL is set — so the API container that files an
approval and the one that serves the decide-link see the same record.
"""
import hashlib
import hmac as _hmac
import os
import uuid
from datetime import datetime, timezone, timedelta

try:
    import httpx
    _HTTPX = True
except ImportError:
    _HTTPX = False

import store
from store import Approval

APPROVAL_EXPIRY_MINUTES = int(os.environ.get("APPROVAL_EXPIRY_MINUTES", "30"))
PHANTOM_BASE_URL = os.environ.get("PHANTOM_BASE_URL", "http://localhost:8080")
GOOGLE_CHAT_WEBHOOK_URL = os.environ.get("GOOGLE_CHAT_WEBHOOK_URL", "")
_SECRET = os.environ.get("APPROVAL_HMAC_SECRET", "phantom-change-in-production").encode()


def _iso(dt):
    return dt.isoformat() if dt else None


def _to_dict(a: Approval) -> dict:
    """Serialize to the same shape the file store returned (ISO date strings)."""
    return {
        "id": a.id, "session_id": a.session_id, "action_type": a.action_type,
        "resources": store.loads(a.resources, []), "justification": a.justification,
        "impact": a.impact, "impact_level": a.impact_level, "requested_by": a.requested_by,
        "requested_at": _iso(a.requested_at), "expires_at": _iso(a.expires_at),
        "status": a.status, "decided_by": a.decided_by, "decided_at": _iso(a.decided_at),
    }


def _token(approval_id: str, decision: str) -> str:
    msg = f"{approval_id}:{decision}".encode()
    return _hmac.new(_SECRET, msg, hashlib.sha256).hexdigest()[:24]


def verify_token(approval_id: str, decision: str, token: str) -> bool:
    return _hmac.compare_digest(_token(approval_id, decision), token)


def create_approval(
    session_id: str,
    action_type: str,
    resources: list,
    justification: str,
    impact: str,
    impact_level: str,
    requested_by: str = "analyst",
) -> dict:
    now = datetime.now(timezone.utc)
    aid = f"apr-{now.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    s = store.session()
    try:
        row = Approval(
            id=aid, session_id=session_id, action_type=action_type,
            resources=store.dumps(resources), justification=justification,
            impact=impact, impact_level=impact_level, requested_by=requested_by,
            requested_at=now, expires_at=now + timedelta(minutes=APPROVAL_EXPIRY_MINUTES),
            status="pending", decided_by=None, decided_at=None)
        s.add(row)
        s.commit()
        return _to_dict(row)
    finally:
        s.close()


def get_approval(approval_id: str) -> dict | None:
    s = store.session()
    try:
        a = s.get(Approval, approval_id)
        return _to_dict(a) if a else None
    finally:
        s.close()


def decide_approval(approval_id: str, decision: str, decided_by: str) -> dict | None:
    s = store.session()
    try:
        a = s.get(Approval, approval_id)
        if not a:
            return None
        if a.status != "pending":
            return _to_dict(a)
        a.status = decision
        a.decided_by = decided_by
        a.decided_at = datetime.now(timezone.utc)
        s.commit()
        return _to_dict(a)
    finally:
        s.close()


def list_approvals(status: str | None = None) -> list:
    s = store.session()
    try:
        q = s.query(Approval)
        if status:
            q = q.filter(Approval.status == status)
        return [_to_dict(a) for a in q.order_by(Approval.requested_at.desc()).all()]
    finally:
        s.close()


def pending_count() -> int:
    s = store.session()
    try:
        return s.query(Approval).filter(Approval.status == "pending").count()
    finally:
        s.close()


def send_google_chat_notification(approval: dict) -> bool:
    if not GOOGLE_CHAT_WEBHOOK_URL or not _HTTPX:
        return False
    aid = approval["id"]
    approve_url = f"{PHANTOM_BASE_URL}/approvals/{aid}/approve?token={_token(aid, 'approved')}"
    deny_url    = f"{PHANTOM_BASE_URL}/approvals/{aid}/deny?token={_token(aid, 'denied')}"
    level = approval["impact_level"]
    emoji = {"LOW": "🟡", "MEDIUM": "🟠", "HIGH": "🔴", "CRITICAL": "🚨"}.get(level, "⚠️")
    resources_str = ", ".join(approval["resources"]) or "—"
    payload = {
        "cards": [{
            "header": {"title": f"{emoji} Phantom IR — Approval Required", "subtitle": f"Impact: {level}"},
            "sections": [{"widgets": [
                {"keyValue": {"topLabel": "Action",          "content": approval["action_type"]}},
                {"keyValue": {"topLabel": "Resources",       "content": resources_str}},
                {"keyValue": {"topLabel": "Justification",   "content": approval["justification"]}},
                {"keyValue": {"topLabel": "Business Impact", "content": approval["impact"]}},
                {"keyValue": {"topLabel": "Requested by",    "content": approval["requested_by"]}},
                {"keyValue": {"topLabel": "Expires in",      "content": f"{APPROVAL_EXPIRY_MINUTES} min"}},
                {"buttons": [
                    {"textButton": {"text": "✅  APPROVE", "onClick": {"openLink": {"url": approve_url}}}},
                    {"textButton": {"text": "❌  DENY",    "onClick": {"openLink": {"url": deny_url}}}},
                ]},
            ]}],
        }]
    }
    try:
        with httpx.Client(timeout=10.0) as c:
            return c.post(GOOGLE_CHAT_WEBHOOK_URL, json=payload).is_success
    except Exception:
        return False
