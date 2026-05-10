#!/usr/bin/env python3
"""ASI05 - Agent Identity & Privilege Governance: Audit agent tokens and privilege escalation paths."""
import argparse
import base64
import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

OWASP_ID = "ASI05"
TOOL_NAME = "phantom-agent-identity-governance"

# JWT claims that agents should NOT have
OVERPRIVILEGED_SCOPES = [
    "admin", "superuser", "root", "write:all", "read:all",
    "*", "manage:users", "delete:*", "system:*",
]

# Admin-only tool endpoints to probe for privilege escalation
ADMIN_TOOL_PROBES = [
    "/admin/tools", "/tools/admin", "/api/admin",
    "/v1/admin", "/system/tools", "/internal/tools",
]


def decode_jwt_insecure(token: str) -> tuple[dict, dict]:
    """Decode JWT without signature verification (audit only)."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}, {}

    def pad(s):
        return s + "=" * (-len(s) % 4)

    try:
        header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
        return header, payload
    except Exception:
        return {}, {}


def audit_token(token: str) -> list[dict]:
    findings = []
    header, payload = decode_jwt_insecure(token)

    if not payload:
        findings.append({
            "id": f"{OWASP_ID}-001",
            "title": "Invalid or Unparseable Agent Token",
            "severity": "HIGH",
            "description": "Agent token could not be decoded as a valid JWT.",
            "evidence": f"token[:40]={token[:40]}",
            "remediation": "Ensure agent tokens are valid JWTs with proper structure.",
        })
        return findings

    # Check algorithm
    alg = header.get("alg", "")
    if alg.upper() in ("NONE", ""):
        findings.append({
            "id": f"{OWASP_ID}-002",
            "title": "JWT 'none' Algorithm — Signature Bypass",
            "severity": "CRITICAL",
            "description": "Agent token uses 'none' algorithm, meaning no signature verification.",
            "evidence": f"alg={alg}",
            "remediation": "Reject JWTs with alg=none. Enforce RS256 or ES256.",
        })

    # Check expiry
    exp = payload.get("exp")
    if exp is None:
        findings.append({
            "id": f"{OWASP_ID}-003",
            "title": "Agent Token Has No Expiry",
            "severity": "HIGH",
            "description": "Token lacks 'exp' claim — it never expires, enabling persistent access if stolen.",
            "evidence": f"payload_keys={list(payload.keys())}",
            "remediation": "Set short-lived token expiry (≤1 hour) on all agent identity tokens.",
        })
    elif exp < datetime.now(timezone.utc).timestamp():
        findings.append({
            "id": f"{OWASP_ID}-004",
            "title": "Agent Token Is Expired (but may still be accepted)",
            "severity": "MEDIUM",
            "description": "Token expiry has passed. Server may not be validating expiry.",
            "evidence": f"exp={exp}",
            "remediation": "Enforce server-side token expiry validation on every request.",
        })

    # Check agent binding
    if not payload.get("agent_id") and not payload.get("sub"):
        findings.append({
            "id": f"{OWASP_ID}-005",
            "title": "No Agent Identity Binding in Token",
            "severity": "HIGH",
            "description": "Token has no 'agent_id' or 'sub' claim — cannot attribute actions to a specific agent.",
            "evidence": f"payload_keys={list(payload.keys())}",
            "remediation": "Include a unique 'agent_id' claim in all agent tokens for action attribution.",
        })

    # Check overprivileged scopes
    scopes = payload.get("scope", "") or payload.get("scopes", [])
    if isinstance(scopes, str):
        scopes = scopes.split()
    for scope in scopes:
        if scope.lower() in OVERPRIVILEGED_SCOPES:
            findings.append({
                "id": f"{OWASP_ID}-006",
                "title": f"Overprivileged Scope in Token: '{scope}'",
                "severity": "CRITICAL",
                "description": f"Agent token contains overprivileged scope '{scope}' violating least-privilege.",
                "evidence": f"scope={scope}, all_scopes={list(scopes)}",
                "remediation": "Apply least-privilege: grant only the minimum scopes required. Remove wildcard and admin scopes.",
            })

    return findings


def probe_privilege_escalation(server_url: str) -> list[dict]:
    findings = []
    base = server_url.rstrip("/")

    for path in ADMIN_TOOL_PROBES:
        url = base + path
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                if resp.status in (200, 201):
                    findings.append({
                        "id": f"{OWASP_ID}-P{len(findings)+1:03d}",
                        "title": f"Privilege Escalation: Admin Endpoint Accessible",
                        "severity": "CRITICAL",
                        "description": f"Admin endpoint {path} returned HTTP {resp.status} without elevated auth.",
                        "evidence": f"GET {url} → {resp.status}",
                        "remediation": "Restrict admin API paths to privileged roles only. Implement RBAC checks at the route level.",
                    })
        except urllib.error.HTTPError as e:
            if e.code in (200, 201):
                pass  # Edge case
        except Exception:
            pass

    return findings


def main():
    p = argparse.ArgumentParser(description="ASI05 Agent Identity & Privilege Governance")
    p.add_argument("--agent-token", help="JWT agent token to audit")
    p.add_argument("--server-url", help="Agent server URL to probe for privilege escalation")
    p.add_argument("--output", default="asi05_identity_governance_report.json")
    args = p.parse_args()

    if not args.agent_token and not args.server_url:
        print("[ASI05] Provide --agent-token or --server-url", file=sys.stderr)
        sys.exit(2)

    findings = []
    if args.agent_token:
        findings += audit_token(args.agent_token)
    if args.server_url:
        findings += probe_privilege_escalation(args.server_url)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

    report = {
        "tool": TOOL_NAME, "owasp_id": OWASP_ID,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "summary": {"total": len(findings), **counts},
    }
    print(json.dumps(report, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2))
    sys.exit(1 if counts["CRITICAL"] > 0 or counts["HIGH"] > 0 else 0)


if __name__ == "__main__":
    main()
