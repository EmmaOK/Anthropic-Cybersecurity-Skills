#!/usr/bin/env python3
"""
phantom/auth.py — authentication + RBAC for the Phantom control plane.

Turns the task-assignment API from "anyone who can reach the port" into an
identity-aware, role-scoped control plane with an audit trail. Self-contained
(stdlib only), so it works whether Phantom runs as a script, in Docker, or
behind an ingress.

Model:
  - Identity   : a caller presents `Authorization: Bearer <token>`. Tokens are
                 never stored in the clear — only their sha256. A token resolves
                 to a Principal(username, roles).
  - RBAC       : each role grants a set of task types (or "*"). A caller may
                 submit a task type only if one of their roles grants it.
                 `can_read_all` lets a role read others' tasks; otherwise a
                 caller sees only tasks they submitted. `admin` implies both.
  - Audit      : every submit / denial / auth failure is appended as JSONL.

Configuration (either is enough to enable enforcement):
  PHANTOM_AUTH_FILE   — JSON: {"users":[{username,token_sha256,roles}],
                                "roles":{name:{task_types:[...],can_read_all,admin}}}
                        Roles omitted from the file fall back to DEFAULT_ROLES.
  PHANTOM_ADMIN_TOKEN — a single bootstrap admin token (plaintext in env; hashed
                        at load). Handy for first run / single-operator setups.

Secure by default: if NEITHER is configured, the gated routes refuse (503) —
unless PHANTOM_AUTH_ALLOW_ANONYMOUS=1, which grants an anonymous caller the
PHANTOM_ANON_ROLE (default "viewer", i.e. read-only).

CLI:
  python auth.py gen-token            # random token + its sha256 (paste hash into the auth file)
  python auth.py hash <token>         # sha256 of an existing token
  python auth.py init-file [path]     # write a starter auth file
  python auth.py whoami <token>       # resolve a token against the current config
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Built-in role policy. `task_types` gates task assignment (from task_agent's
# registry). `permissions` gates non-task actions on the control plane — chat,
# phishing report submission/read, approvals. "*" in either grants all; the
# `admin` flag implies "*" everywhere. Orgs override/extend via the auth file.
#
# Known permission actions: "chat", "phishing:report", "phishing:read",
#   "guardduty:report", "guardduty:read", "approvals:read", "approvals:decide".
DEFAULT_ROLES: dict[str, dict] = {
    "admin":           {"task_types": ["*"], "permissions": ["*"], "can_read_all": True, "admin": True},
    "security-lead":   {"task_types": ["*"], "permissions": ["*"], "can_read_all": True},
    "ir-analyst":      {"task_types": ["detection-engineering", "threat-intelligence",
                                       "dfir-forensics", "insider-threat", "email-security",
                                       "resilience-backup", "securonix-audit", "securonix-triage"],
                        "permissions": ["chat", "phishing:report", "phishing:read",
                                        "guardduty:report", "guardduty:read",
                                        "approvals:read", "approvals:decide"], "can_read_all": True},
    "soc-analyst":     {"task_types": ["threat-intelligence", "detection-engineering",
                                       "dfir-forensics", "securonix-audit", "securonix-hunt",
                                       "securonix-triage", "securonix-soar"],
                        "permissions": ["chat", "phishing:report", "phishing:read",
                                        "guardduty:report", "guardduty:read",
                                        "approvals:read"], "can_read_all": True},
    "appsec-engineer": {"task_types": ["api-security", "supply-chain-devsecops",
                                       "crypto-pki", "mcp-security", "defectdojo-triage",
                                       "defectdojo-sla", "defectdojo-prioritize", "defectdojo-report",
                                       "devsecops-onboard"],
                        "permissions": ["chat"]},
    "cloud-engineer":  {"task_types": ["cloud-posture", "zero-trust-network",
                                       "identity-pam", "resilience-backup"],
                        "permissions": ["chat", "guardduty:report", "guardduty:read"]},
    "red-team":        {"task_types": ["red-team", "purple-team", "deception"], "permissions": ["chat"]},
    "ot-engineer":     {"task_types": ["ot-ics-security", "iot-firmware"], "permissions": ["chat"]},
    "developer":       {"task_types": ["api-security"], "permissions": ["chat"]},
    "service-phishing": {"task_types": [], "permissions": ["phishing:report", "phishing:read"]},
    "service-guardduty": {"task_types": [], "permissions": ["guardduty:report", "guardduty:read"]},
    "viewer":          {"task_types": [], "permissions": ["phishing:read", "guardduty:read",
                                                          "approvals:read"], "can_read_all": True},
}


class AuthError(Exception):
    """Raised on auth/authorization failure; carries an HTTP status + detail."""
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass
class Principal:
    username: str
    roles: list[str] = field(default_factory=list)
    anonymous: bool = False


# ── Configuration ────────────────────────────────────────────────────────────

def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _load_config() -> dict:
    """Merge the auth file (if any) with the bootstrap admin token from env."""
    cfg = {"users": [], "roles": {}}
    path = os.environ.get("PHANTOM_AUTH_FILE", "")
    if path and Path(path).is_file():
        try:
            data = json.loads(Path(path).read_text())
            cfg["users"] = data.get("users", []) or []
            cfg["roles"] = data.get("roles", {}) or {}
        except (json.JSONDecodeError, OSError) as e:
            raise AuthError(500, f"cannot read PHANTOM_AUTH_FILE: {e}")
    admin_token = os.environ.get("PHANTOM_ADMIN_TOKEN", "")
    if admin_token:
        cfg["users"] = list(cfg["users"]) + [
            {"username": "admin", "token_sha256": _hash(admin_token), "roles": ["admin"]}]
    return cfg


def is_configured() -> bool:
    return bool(os.environ.get("PHANTOM_ADMIN_TOKEN") or
                (os.environ.get("PHANTOM_AUTH_FILE") and
                 Path(os.environ["PHANTOM_AUTH_FILE"]).is_file()))


def _allow_anonymous() -> bool:
    return os.environ.get("PHANTOM_AUTH_ALLOW_ANONYMOUS", "").lower() in ("1", "true", "yes")


def _anon_role() -> str:
    return os.environ.get("PHANTOM_ANON_ROLE", "viewer")


def role_policy(role: str, cfg: dict | None = None) -> dict:
    cfg = cfg or _load_config()
    return cfg["roles"].get(role) or DEFAULT_ROLES.get(role) or {"task_types": []}


# ── Authentication ───────────────────────────────────────────────────────────

def _extract_bearer(authorization: str | None) -> str:
    if not authorization:
        return ""
    parts = authorization.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return authorization.strip()  # tolerate a bare token


def authenticate(authorization: str | None) -> Principal:
    """Resolve a caller to a Principal, or raise AuthError."""
    if not is_configured():
        if _allow_anonymous():
            return Principal("anonymous", [_anon_role()], anonymous=True)
        raise AuthError(503, "control-plane auth is not configured — set PHANTOM_AUTH_FILE "
                             "or PHANTOM_ADMIN_TOKEN (or PHANTOM_AUTH_ALLOW_ANONYMOUS=1 for read-only)")
    token = _extract_bearer(authorization)
    if not token:
        raise AuthError(401, "missing bearer token")
    digest = _hash(token)
    for u in _load_config()["users"]:
        if secrets.compare_digest(u.get("token_sha256", ""), digest):
            return Principal(u.get("username", "unknown"), list(u.get("roles", [])))
    raise AuthError(401, "invalid token")


# ── Authorization ────────────────────────────────────────────────────────────

def allowed_task_types(principal: Principal) -> set[str]:
    cfg = _load_config()
    allowed: set[str] = set()
    for r in principal.roles:
        tt = role_policy(r, cfg).get("task_types", [])
        if "*" in tt:
            return {"*"}
        allowed.update(tt)
    return allowed


def can_submit(principal: Principal, task_type: str) -> bool:
    a = allowed_task_types(principal)
    return "*" in a or task_type in a


def can_read_all(principal: Principal) -> bool:
    cfg = _load_config()
    return any(role_policy(r, cfg).get("can_read_all") or role_policy(r, cfg).get("admin")
               for r in principal.roles)


def is_admin(principal: Principal) -> bool:
    cfg = _load_config()
    return any(role_policy(r, cfg).get("admin") for r in principal.roles)


def require_submit(principal: Principal, task_type: str) -> None:
    if not can_submit(principal, task_type):
        raise AuthError(403, f"role(s) {principal.roles} may not submit task type '{task_type}'")


def permissions(principal: Principal) -> set[str]:
    cfg = _load_config()
    perms: set[str] = set()
    for r in principal.roles:
        pol = role_policy(r, cfg)
        if pol.get("admin"):
            return {"*"}
        p = pol.get("permissions", [])
        if "*" in p:
            return {"*"}
        perms.update(p)
    return perms


def can(principal: Principal, action: str) -> bool:
    """True if the principal may perform a non-task action (e.g. 'chat', 'phishing:report')."""
    p = permissions(principal)
    return "*" in p or action in p


def require(principal: Principal, action: str) -> None:
    if not can(principal, action):
        raise AuthError(403, f"role(s) {principal.roles} lack permission '{action}'")


# ── Audit ────────────────────────────────────────────────────────────────────

def audit(action: str, principal: Principal | None = None, **fields) -> None:
    """Record an audit event in the shared store (DB), with a JSONL fallback baked
    into store.write_audit. Never raises (best-effort)."""
    try:
        import store
        store.write_audit(action,
                          user=(principal.username if principal else None),
                          roles=(principal.roles if principal else None),
                          data=fields)
    except Exception:
        pass


# ── CLI ──────────────────────────────────────────────────────────────────────

def _main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 0
    cmd = argv[0]
    if cmd == "gen-token":
        tok = secrets.token_urlsafe(32)
        print(f"token (give to the user):\n  {tok}\n")
        print(f"token_sha256 (put in the auth file):\n  {_hash(tok)}")
        return 0
    if cmd == "hash" and len(argv) > 1:
        print(_hash(argv[1]))
        return 0
    if cmd == "init-file":
        dest = Path(argv[1]) if len(argv) > 1 else ROOT / "phantom" / "auth.example.json"
        tok = secrets.token_urlsafe(32)
        sample = {
            "users": [
                {"username": "alice", "token_sha256": _hash(tok), "roles": ["security-lead"]},
                {"username": "bob", "token_sha256": "<sha256-of-bobs-token>", "roles": ["ir-analyst"]},
            ],
            "roles": {  # optional overrides; omit to use DEFAULT_ROLES
                "ir-analyst": {"task_types": ["detection-engineering", "threat-intelligence",
                                              "dfir-forensics"], "can_read_all": True},
            },
        }
        dest.write_text(json.dumps(sample, indent=2))
        print(f"wrote {dest}\nalice's token (rotate before real use): {tok}")
        return 0
    if cmd == "whoami" and len(argv) > 1:
        try:
            p = authenticate(f"Bearer {argv[1]}")
            print(json.dumps({"username": p.username, "roles": p.roles,
                              "admin": is_admin(p), "can_read_all": can_read_all(p),
                              "allowed_task_types": sorted(allowed_task_types(p)),
                              "permissions": sorted(permissions(p))}, indent=2))
            return 0
        except AuthError as e:
            print(f"AuthError {e.status}: {e.detail}")
            return 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(__import__("sys").argv[1:]))
