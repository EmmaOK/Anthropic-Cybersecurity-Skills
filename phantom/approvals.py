#!/usr/bin/env python3
"""Approval store and Google Chat notifications for Phantom IR workflow."""
import hashlib
import hmac as _hmac
import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    import httpx
    _HTTPX = True
except ImportError:
    _HTTPX = False

_DATA_DIR = Path(__file__).parent / "data"
_DATA_DIR.mkdir(exist_ok=True)
_APPROVALS_FILE = _DATA_DIR / "approvals.json"

APPROVAL_EXPIRY_MINUTES = int(os.environ.get("APPROVAL_EXPIRY_MINUTES", "30"))
PHANTOM_BASE_URL = os.environ.get("PHANTOM_BASE_URL", "http://localhost:8080")
GOOGLE_CHAT_WEBHOOK_URL = os.environ.get("GOOGLE_CHAT_WEBHOOK_URL", "")
_SECRET = os.environ.get("APPROVAL_HMAC_SECRET", "phantom-change-in-production").encode()


def _load() -> dict:
    try:
        return json.loads(_APPROVALS_FILE.read_text()) if _APPROVALS_FILE.exists() else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _dump(data: dict) -> None:
    _APPROVALS_FILE.write_text(json.dumps(data, indent=2, default=str))


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
    approval = {
        "id": aid,
        "session_id": session_id,
        "action_type": action_type,
        "resources": resources,
        "justification": justification,
        "impact": impact,
        "impact_level": impact_level,
        "requested_by": requested_by,
        "requested_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=APPROVAL_EXPIRY_MINUTES)).isoformat(),
        "status": "pending",
        "decided_by": None,
        "decided_at": None,
    }
    store = _load()
    store[aid] = approval
    _dump(store)
    return approval


def get_approval(approval_id: str) -> dict | None:
    return _load().get(approval_id)


def decide_approval(approval_id: str, decision: str, decided_by: str) -> dict | None:
    store = _load()
    a = store.get(approval_id)
    if not a or a["status"] != "pending":
        return a
    a["status"] = decision
    a["decided_by"] = decided_by
    a["decided_at"] = datetime.now(timezone.utc).isoformat()
    _dump(store)
    return a


def list_approvals(status: str | None = None) -> list:
    items = list(_load().values())
    if status:
        items = [a for a in items if a["status"] == status]
    return sorted(items, key=lambda a: a["requested_at"], reverse=True)


def pending_count() -> int:
    return sum(1 for a in _load().values() if a["status"] == "pending")


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
