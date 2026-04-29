#!/usr/bin/env python3
"""
STRIDE Threat Modeling Agent

Three subcommands:
  init    — Scaffold a blank component inventory JSON for a system.
  analyze — Apply STRIDE threat rules to each component and generate a threat list.
  report  — Summarize a completed threat list into a prioritized report.

Usage:
    agent.py init    --system "Payment API" --output components.json
    agent.py analyze --components components.json --output threats.json
    agent.py report  --threats threats.json [--output stride_report.json]

Component inventory format (JSON array):
    [
      {"id": "proc-api", "type": "process",         "name": "Payment API",    "trust_boundary": "dmz"},
      {"id": "store-db", "type": "data_store",       "name": "PostgreSQL",     "trust_boundary": "internal"},
      {"id": "ext-user", "type": "external_entity",  "name": "End User",       "trust_boundary": "internet"},
      {"id": "flow-1",   "type": "data_flow",         "name": "User → API",    "encrypted": true}
    ]
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

COMPONENT_TYPES = ("process", "data_store", "external_entity", "data_flow")

# STRIDE applicability per element type
STRIDE_MAP = {
    "process":         ["S", "T", "R", "I", "D", "E"],
    "data_store":      ["T", "R", "I", "D"],
    "external_entity": ["S", "R"],
    "data_flow":       ["T", "I", "D"],
}

# Threat templates per (component_type, stride_category)
THREAT_TEMPLATES: dict[tuple[str, str], list[dict]] = {
    ("process", "S"): [
        {"description": "Caller identity not verified — service can be impersonated",
         "question": "Is the caller authenticated before any action is taken?",
         "default_severity": "HIGH"},
        {"description": "Service-to-service calls lack mutual authentication",
         "question": "Is mutual TLS or token-based auth used on internal service calls?",
         "default_severity": "MEDIUM"},
    ],
    ("process", "T"): [
        {"description": "Input not validated — injection (SQL, command, SSTI) possible",
         "question": "Are all inputs validated and parameterized before use?",
         "default_severity": "HIGH"},
        {"description": "Business logic accepts values outside intended range (e.g. negative amounts)",
         "question": "Are all numeric/enum inputs range-checked server-side?",
         "default_severity": "HIGH"},
    ],
    ("process", "R"): [
        {"description": "Security events not logged — actions cannot be audited",
         "question": "Are auth, data access, and config-change events logged with user ID, IP, and timestamp?",
         "default_severity": "MEDIUM"},
        {"description": "Log data is stored where the process itself can modify it",
         "question": "Are logs written to an append-only, tamper-resistant store?",
         "default_severity": "MEDIUM"},
    ],
    ("process", "I"): [
        {"description": "Error responses expose stack traces, file paths, or DB schema",
         "question": "Do error messages return only generic information to the caller?",
         "default_severity": "MEDIUM"},
        {"description": "API responses include fields not needed by the caller (over-fetching)",
         "question": "Are API responses filtered to the minimum required fields?",
         "default_severity": "MEDIUM"},
        {"description": "Secrets (API keys, credentials) may appear in logs or URLs",
         "question": "Are credentials absent from query strings, logs, and error messages?",
         "default_severity": "HIGH"},
    ],
    ("process", "D"): [
        {"description": "No rate limiting — process can be overwhelmed by automated requests",
         "question": "Are rate limits applied on all public-facing entry points?",
         "default_severity": "MEDIUM"},
        {"description": "Resource-intensive operations lack quotas or timeouts",
         "question": "Are expensive operations (file uploads, DB queries) protected by size/time limits?",
         "default_severity": "MEDIUM"},
    ],
    ("process", "E"): [
        {"description": "Authorization not enforced per request — only checked at login",
         "question": "Is every request independently authorized server-side?",
         "default_severity": "HIGH"},
        {"description": "Admin functions reachable by standard users via direct URL",
         "question": "Are privilege levels enforced by role checks, not just obscure paths?",
         "default_severity": "HIGH"},
        {"description": "JWT or session token accepted without signature/expiry validation",
         "question": "Are tokens fully validated (signature, expiry, audience, issuer) on every request?",
         "default_severity": "HIGH"},
    ],
    ("data_store", "T"): [
        {"description": "Data at rest not encrypted — physical access exposes sensitive records",
         "question": "Is sensitive data encrypted at rest (column-level or full-disk)?",
         "default_severity": "HIGH"},
        {"description": "No integrity check on read — silent data corruption goes undetected",
         "question": "Are checksums or signatures verified on critical data reads?",
         "default_severity": "LOW"},
    ],
    ("data_store", "R"): [
        {"description": "Read/write access to the data store is not audited",
         "question": "Does the data store log all access with caller identity?",
         "default_severity": "MEDIUM"},
    ],
    ("data_store", "I"): [
        {"description": "Data store accessible from a broader network segment than necessary",
         "question": "Is the data store network-restricted to only the services that need it?",
         "default_severity": "HIGH"},
        {"description": "Backups stored in a less-protected location than primary data",
         "question": "Are backups encrypted and access-controlled to the same standard as primary?",
         "default_severity": "MEDIUM"},
    ],
    ("data_store", "D"): [
        {"description": "No quota or size limit — store can be exhausted by bulk writes",
         "question": "Are write quotas enforced to prevent storage exhaustion?",
         "default_severity": "LOW"},
        {"description": "No backup / point-in-time recovery — data loss is permanent",
         "question": "Are automated backups and tested recovery procedures in place?",
         "default_severity": "MEDIUM"},
    ],
    ("external_entity", "S"): [
        {"description": "External entity identity not verified — caller can be spoofed",
         "question": "Is the external entity authenticated (API key, OAuth, webhook signature)?",
         "default_severity": "HIGH"},
        {"description": "Webhook payloads accepted without HMAC signature verification",
         "question": "Is every incoming webhook payload signature-verified before processing?",
         "default_severity": "HIGH"},
    ],
    ("external_entity", "R"): [
        {"description": "No record of what data the external entity sent or received",
         "question": "Are all interactions with this external entity logged for audit purposes?",
         "default_severity": "MEDIUM"},
    ],
    ("data_flow", "T"): [
        {"description": "Data transmitted without encryption — MITM can modify in transit",
         "question": "Is this data flow encrypted with TLS 1.2+?",
         "default_severity": "HIGH"},
        {"description": "No message integrity check — payload can be silently modified",
         "question": "Is an HMAC or digital signature used to verify payload integrity?",
         "default_severity": "MEDIUM"},
    ],
    ("data_flow", "I"): [
        {"description": "Sensitive data included in query string — visible in access logs and browser history",
         "question": "Is sensitive data transmitted only in the request body or headers?",
         "default_severity": "HIGH"},
        {"description": "TLS certificate not pinned — rogue CA can intercept traffic",
         "question": "Is certificate pinning or HSTS enforced for this flow?",
         "default_severity": "LOW"},
    ],
    ("data_flow", "D"): [
        {"description": "No timeout on this connection — slow-read attack can hold resources open",
         "question": "Are connection and read timeouts configured on both ends of this flow?",
         "default_severity": "LOW"},
    ],
}

STRIDE_LABELS = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}


def cmd_init(args) -> None:
    template = [
        {"id": "ext-user",   "type": "external_entity", "name": "End User",          "trust_boundary": "internet"},
        {"id": "proc-app",   "type": "process",         "name": f"{args.system} API", "trust_boundary": "dmz"},
        {"id": "store-db",   "type": "data_store",      "name": "Primary Database",   "trust_boundary": "internal"},
        {"id": "flow-1",     "type": "data_flow",        "name": "User → App (HTTPS)", "encrypted": True},
        {"id": "flow-2",     "type": "data_flow",        "name": "App → DB",           "encrypted": True},
    ]
    with open(args.output, "w") as f:
        json.dump(template, f, indent=2)
    print(f"[*] Blank component inventory written to {args.output}")
    print(f"[*] Edit the file to describe your actual system, then run: agent.py analyze --components {args.output}")


def cmd_analyze(args) -> None:
    path = Path(args.components)
    if not path.exists():
        print(f"[error] Components file not found: {args.components}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        components = json.load(f)

    threats = []
    tid = 1

    for comp in components:
        ctype = comp.get("type", "").lower()
        if ctype not in COMPONENT_TYPES:
            continue
        applicable = STRIDE_MAP.get(ctype, [])
        for category in applicable:
            for tmpl in THREAT_TEMPLATES.get((ctype, category), []):
                threats.append({
                    "id": f"T-{tid:03d}",
                    "component_id": comp.get("id"),
                    "component_name": comp.get("name"),
                    "component_type": ctype,
                    "stride_category": category,
                    "stride_label": STRIDE_LABELS[category],
                    "description": tmpl["description"],
                    "question": tmpl["question"],
                    "default_severity": tmpl["default_severity"],
                    "severity": tmpl["default_severity"],  # override after review
                    "status": "OPEN",
                    "mitigation": "",
                    "owner": "",
                    "notes": "",
                })
                tid += 1

    with open(args.output, "w") as f:
        json.dump(threats, f, indent=2)

    print(f"[*] Generated {len(threats)} threats across {len(components)} components")
    print(f"[*] Threat list written to {args.output}")
    print(f"[*] Review each threat, set status (OPEN/MITIGATED/NOT_APPLICABLE), add mitigation and owner.")
    print(f"[*] Then run: agent.py report --threats {args.output}")


def cmd_report(args) -> dict:
    path = Path(args.threats)
    if not path.exists():
        print(f"[error] Threats file not found: {args.threats}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        threats: list[dict] = json.load(f)

    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_stride: dict[str, int] = {v: 0 for v in STRIDE_LABELS.values()}
    open_threats = []
    mitigated = 0

    for t in threats:
        sev = t.get("severity", "LOW")
        if sev in by_severity:
            by_severity[sev] += 1
        label = t.get("stride_label", "")
        if label in by_stride:
            by_stride[label] += 1
        if t.get("status", "OPEN") == "MITIGATED":
            mitigated += 1
        else:
            open_threats.append(t)

    open_threats.sort(key=lambda x: sev_order.get(x.get("severity", "LOW"), 0), reverse=True)

    overall_risk = (
        "CRITICAL" if by_severity["CRITICAL"] > 0
        else "HIGH" if by_severity["HIGH"] > 0
        else "MEDIUM" if by_severity["MEDIUM"] > 0
        else "LOW"
    )

    report = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "threats_analyzed": len(threats),
        "mitigated": mitigated,
        "open": len(open_threats),
        "by_severity": by_severity,
        "by_stride_category": by_stride,
        "overall_risk": overall_risk,
        "open_threats": open_threats[:20],  # top 20 open threats
        "recommendation": (
            f"{len(open_threats)} open threat(s) require remediation. "
            f"Prioritize {by_severity['CRITICAL']} CRITICAL and {by_severity['HIGH']} HIGH findings."
            if open_threats
            else "All identified threats are mitigated."
        ),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\n[*] Report saved to {args.output}")

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)

    return report


def main():
    parser = argparse.ArgumentParser(description="STRIDE Threat Modeling Agent")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_init = sub.add_parser("init", help="Create blank component inventory")
    p_init.add_argument("--system", required=True, help="System name")
    p_init.add_argument("--output", default="components.json")

    p_analyze = sub.add_parser("analyze", help="Generate STRIDE threats from component inventory")
    p_analyze.add_argument("--components", required=True)
    p_analyze.add_argument("--output", default="threats.json")

    p_report = sub.add_parser("report", help="Generate prioritized report from threat list")
    p_report.add_argument("--threats", required=True)
    p_report.add_argument("--output", default="stride_report.json")

    args = parser.parse_args()
    if args.subcommand == "init":
        cmd_init(args)
    elif args.subcommand == "analyze":
        cmd_analyze(args)
    elif args.subcommand == "report":
        cmd_report(args)


if __name__ == "__main__":
    main()
