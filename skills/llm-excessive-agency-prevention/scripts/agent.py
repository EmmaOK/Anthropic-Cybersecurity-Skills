#!/usr/bin/env python3
"""
LLM Excessive Agency Prevention Agent

Audits an LLM agent's tool manifest against an intended function to identify
excess tools and over-scoped permissions. Reads a JSON tool manifest and
produces a prioritized remediation report.

Usage:
    agent.py --manifest tools.json --function "summarize customer emails" --required email_read
    agent.py --manifest tools.json --function "answer questions" --required web_search,file_read
    agent.py --manifest tools.json --function "code review" --output agency_report.json

Tool manifest format (JSON array):
    [
      {"name": "email_read",   "oauth_scopes": ["email:read"]},
      {"name": "email_send",   "oauth_scopes": ["email:write"]},
      {"name": "file_delete",  "oauth_scopes": ["files:delete"]}
    ]

Based on OWASP LLM Top 10 (LLM06:2025 Excessive Agency).
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HIGH_AGENCY_CAPABILITIES = {
    "send_email", "email_send", "delete_files", "file_delete", "execute_code",
    "code_execute", "make_payment", "payment_initiate", "modify_database",
    "db_write", "call_external_api", "create_users", "user_create",
    "modify_permissions", "access_credentials", "infrastructure_provision",
    "shell_exec", "bash", "subprocess",
}

WRITE_SCOPE_MARKERS = (":write", ":delete", ":admin", ":manage", ":execute", ":modify")

AGENCY_LEVEL_MAP = {
    "read": "READ_ONLY",
    "search": "READ_ONLY",
    "list": "READ_ONLY",
    "get": "READ_ONLY",
    "fetch": "READ_ONLY",
    "query": "READ_ONLY",
    "write": "REVERSIBLE_WRITE",
    "update": "REVERSIBLE_WRITE",
    "create": "REVERSIBLE_WRITE",
    "post": "REVERSIBLE_WRITE",
    "send": "IRREVERSIBLE",
    "delete": "IRREVERSIBLE",
    "remove": "IRREVERSIBLE",
    "pay": "IRREVERSIBLE",
    "exec": "AUTONOMOUS",
    "execute": "AUTONOMOUS",
    "shell": "AUTONOMOUS",
    "provision": "AUTONOMOUS",
}


def classify_tool_agency(tool_name: str) -> str:
    name_lower = tool_name.lower()
    for keyword, level in AGENCY_LEVEL_MAP.items():
        if keyword in name_lower:
            return level
    if any(cap in name_lower for cap in HIGH_AGENCY_CAPABILITIES):
        return "AUTONOMOUS"
    return "READ_ONLY"


def audit_manifest(manifest: list[dict], intended_function: str, required_tools: set[str]) -> dict:
    all_tools = {t["name"] for t in manifest}
    excess_tools = all_tools - required_tools
    findings = []

    for tool in manifest:
        name = tool["name"]
        scopes = tool.get("oauth_scopes", [])
        capabilities = tool.get("capabilities", [])
        agency = classify_tool_agency(name)

        if name in excess_tools:
            findings.append({
                "tool": name,
                "finding": "NOT_REQUIRED",
                "agency_level": agency,
                "severity": "HIGH" if agency in ("IRREVERSIBLE", "AUTONOMOUS") else "MEDIUM",
                "detail": f"Tool not needed for '{intended_function}' — remove from manifest",
                "recommendation": f"Remove '{name}' from the tool list entirely",
            })
        else:
            # Required tool — check for over-scoped permissions
            for scope in scopes:
                if any(m in scope for m in WRITE_SCOPE_MARKERS):
                    findings.append({
                        "tool": name,
                        "finding": "EXCESSIVE_SCOPE",
                        "scope": scope,
                        "agency_level": agency,
                        "severity": "MEDIUM",
                        "detail": f"Write/delete/admin scope on required tool — request minimum scope only",
                        "recommendation": f"Replace '{scope}' with its read-only equivalent",
                    })

            # Flag capabilities that are high-agency
            excess_caps = set(capabilities) & HIGH_AGENCY_CAPABILITIES
            if excess_caps:
                findings.append({
                    "tool": name,
                    "finding": "HIGH_AGENCY_CAPABILITY",
                    "capabilities": list(excess_caps),
                    "severity": "HIGH",
                    "detail": f"Tool exposes high-agency capabilities: {excess_caps}",
                    "recommendation": "Require explicit per-invocation user authorization for these capabilities",
                })

    # Summarize by agency level
    level_counts: dict[str, int] = {}
    for t in manifest:
        lvl = classify_tool_agency(t["name"])
        level_counts[lvl] = level_counts.get(lvl, 0) + 1

    return {
        "total_tools": len(all_tools),
        "required_tools": len(required_tools),
        "excess_tools": sorted(excess_tools),
        "excess_tool_count": len(excess_tools),
        "findings": findings,
        "agency_level_breakdown": level_counts,
        "risk": "HIGH" if any(f["severity"] == "HIGH" for f in findings) else (
            "MEDIUM" if findings else "LOW"
        ),
    }


def generate_report(args, audit: dict) -> dict:
    return {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "manifest_file": args.manifest,
        "intended_function": args.function,
        "required_tools": sorted(args.required),
        "tool_audit": audit,
        "recommendation": (
            f"Remove {audit['excess_tool_count']} excess tool(s). "
            f"Review {len([f for f in audit['findings'] if f['finding'] == 'EXCESSIVE_SCOPE'])} over-scoped permission(s)."
            if audit["findings"]
            else "Tool manifest follows least-privilege principle — no excess tools or scopes detected."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="LLM Excessive Agency Prevention Agent")
    parser.add_argument("--manifest", required=True, help="Path to JSON tool manifest file")
    parser.add_argument("--function", required=True, help="Intended function of the LLM agent (quoted string)")
    parser.add_argument(
        "--required",
        required=True,
        help="Comma-separated list of tool names required for the intended function",
    )
    parser.add_argument("--output", default="agency_audit_report.json")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"[error] Manifest file not found: {args.manifest}")
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    if not isinstance(manifest, list):
        print("[error] Manifest must be a JSON array of tool objects")
        sys.exit(1)

    required = {t.strip() for t in args.required.split(",") if t.strip()}
    print(f"[*] Auditing {len(manifest)} tool(s) for function: '{args.function}'")
    print(f"[*] Required tools: {sorted(required)}")

    audit = audit_manifest(manifest, args.function, required)
    report = generate_report(args, audit)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\n[*] Report saved to {args.output}")

    if audit["risk"] == "HIGH":
        sys.exit(1)


if __name__ == "__main__":
    main()
