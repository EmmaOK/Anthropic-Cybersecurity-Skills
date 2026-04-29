#!/usr/bin/env python3
"""
RAG Pipeline Security and Data Provenance Agent

Subcommands:
  audit          — Audit a RAG pipeline config JSON for security misconfigurations.
  scan-documents — Scan a directory of documents for prompt injection patterns.

Usage:
    agent.py audit --config rag_config.json [--output rag_audit.json]
    agent.py scan-documents --dir ./docs [--output injection_scan.json]
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

INJECTION_PATTERNS = [
    (r"(?i)ignore\s+(previous|prior|above|all)\s+instructions?", "CRITICAL", "Instruction override attempt"),
    (r"(?i)you\s+are\s+now\s+(a\s+)?(an?\s+)?\w+\s*(assistant|bot|agent|AI)", "CRITICAL", "Role reassignment attempt"),
    (r"(?i)(system\s*prompt|system\s*message)\s*:", "HIGH", "System prompt injection fragment"),
    (r"(?i)disregard\s+(your|all|any)\s+(previous|prior|above|safety|original)", "CRITICAL", "Safety bypass attempt"),
    (r"(?i)act\s+as\s+(if\s+you\s+(are|were)|a\s+)", "HIGH", "Persona hijack attempt"),
    (r"(?i)(do\s+not\s+follow|bypass|override)\s+(safety|content|policy|guideline)", "CRITICAL", "Policy bypass attempt"),
    (r"(?i)print\s+(your\s+)?(system\s+prompt|instructions?|context)", "HIGH", "System prompt extraction attempt"),
    (r"(?i)(forget|ignore|discard)\s+(everything|all)\s+(above|before|previously)", "CRITICAL", "Context clearing attempt"),
    (r"(?i)\[INST\]|\[SYS\]|<\|system\|>|<\|user\|>|<\|assistant\|>", "HIGH", "Raw model instruction token"),
    (r"(?i)translate\s+the\s+following\s+to\s+\w+\s*:\s*(ignore|you are)", "HIGH", "Encoded injection attempt"),
]

RAG_CONTROLS: list[dict] = [
    {
        "id": "RAG-001", "area": "retrieval",
        "field_path": "retrieval.injection_filter",
        "check": lambda v: v is True,
        "severity": "CRITICAL",
        "control": "Retrieval injection filter",
        "finding_template": "injection_filter is disabled — retrieved content not sanitized for prompt injection",
        "remediation": "Enable injection filtering; treat retrieved text as data, not instructions; sanitize before passing to model context",
    },
    {
        "id": "RAG-002", "area": "vector_db",
        "field_path": "vector_db.encryption_at_rest",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Vector DB encryption at rest",
        "finding_template": "encryption_at_rest is false for vector database — embeddings stored in plaintext",
        "remediation": "Enable encryption at rest for all vector database indexes and backing storage",
    },
    {
        "id": "RAG-003", "area": "vector_db",
        "field_path": "vector_db.access_control",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Vector DB access control",
        "finding_template": "access_control is false for vector database — any service can query embeddings",
        "remediation": "Restrict vector DB access to specific service accounts; implement API key or mTLS authentication",
    },
    {
        "id": "RAG-004", "area": "vector_db",
        "field_path": "vector_db.network_isolated",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Vector DB network isolation",
        "finding_template": "network_isolated is false — vector DB reachable from broad network segment",
        "remediation": "Place vector DB in isolated network segment; restrict ingress to agent service IPs only",
    },
    {
        "id": "RAG-005", "area": "retrieval",
        "field_path": "retrieval.sanitize_output",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Retrieval output sanitization",
        "finding_template": "sanitize_output is false — retrieved content passed to model without cleaning",
        "remediation": "Sanitize retrieved content: strip HTML, remove script tags, normalize unicode, filter known injection patterns",
    },
    {
        "id": "RAG-006", "area": "logging",
        "field_path": "logging.pii_redaction",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "PII redaction in logs",
        "finding_template": "pii_redaction is false — retrieved content including PII may appear in logs",
        "remediation": "Enable PII detection and redaction in logging pipeline; use structured logging with field-level masking",
    },
    {
        "id": "RAG-007", "area": "logging",
        "field_path": "logging.tamper_evident",
        "check": lambda v: v is True,
        "severity": "CRITICAL",
        "control": "Tamper-evident logging",
        "finding_template": "tamper_evident is false — RAG pipeline logs can be modified to hide injection incidents",
        "remediation": "Use append-only log store; implement cryptographic chaining or integrity checks on log entries",
    },
    {
        "id": "RAG-008", "area": "embeddings",
        "field_path": "embeddings.integrity_check",
        "check": lambda v: v is True,
        "severity": "MEDIUM",
        "control": "Embedding integrity check",
        "finding_template": "integrity_check is false — embeddings not verified against known-good checksums",
        "remediation": "Compute and store checksums for embedding vectors; alert on deviations that may indicate poisoning",
    },
    {
        "id": "RAG-009", "area": "embeddings",
        "field_path": "embeddings.model_pinned",
        "check": lambda v: v is True,
        "severity": "MEDIUM",
        "control": "Embedding model version pinning",
        "finding_template": "model_pinned is false — embedding model may silently change, breaking similarity consistency",
        "remediation": "Pin embedding model version; re-embed corpus on intentional upgrades only",
    },
    {
        "id": "RAG-010", "area": "data_sources",
        "check_all_sources": True,
        "source_field": "signed",
        "severity": "HIGH",
        "control": "Data source signing",
        "finding_template": "data source '{name}' has signed=false — provenance not cryptographically verified",
        "remediation": "Sign data sources with checksum or digital signature; verify on ingestion",
    },
    {
        "id": "RAG-011", "area": "data_sources",
        "check_all_sources": True,
        "source_field": "access_control",
        "severity": "MEDIUM",
        "control": "Data source access control",
        "finding_template": "data source '{name}' has access_control=false — unrestricted read access",
        "remediation": "Apply least-privilege read controls to all data sources feeding the RAG pipeline",
    },
    {
        "id": "RAG-012", "area": "retrieval",
        "field_path": "retrieval.trust_boundary",
        "check": lambda v: v in ("internal", "trusted"),
        "severity": "HIGH",
        "control": "Retrieval trust boundary",
        "finding_template": "trust_boundary is '{value}' — retrieval includes external or untrusted content without isolation",
        "remediation": "Separate retrieval indexes by trust level; apply stricter sanitization for external/untrusted sources",
    },
]


def get_nested(obj: dict, path: str):
    parts = path.split(".")
    for p in parts:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(p)
    return obj


def set_nested(obj: dict, path: str, value) -> None:
    parts = path.split(".")
    for p in parts[:-1]:
        obj = obj.setdefault(p, {})
    obj[parts[-1]] = value


def audit_config(config: dict) -> list[dict]:
    findings = []
    for ctrl in RAG_CONTROLS:
        if ctrl.get("check_all_sources"):
            for source in config.get("data_sources", []):
                val = source.get(ctrl["source_field"])
                if val is not True:
                    findings.append({
                        "id": ctrl["id"],
                        "severity": ctrl["severity"],
                        "control": ctrl["control"],
                        "finding": ctrl["finding_template"].format(name=source.get("name", "unknown")),
                        "remediation": ctrl["remediation"],
                    })
        elif "field_path" in ctrl:
            val = get_nested(config, ctrl["field_path"])
            if val is None:
                findings.append({
                    "id": ctrl["id"],
                    "severity": ctrl["severity"],
                    "control": ctrl["control"],
                    "finding": f"{ctrl['field_path']} not configured — {ctrl['finding_template']}",
                    "remediation": ctrl["remediation"],
                })
            elif not ctrl["check"](val):
                findings.append({
                    "id": ctrl["id"],
                    "severity": ctrl["severity"],
                    "control": ctrl["control"],
                    "finding": ctrl["finding_template"].replace("{value}", str(val)),
                    "remediation": ctrl["remediation"],
                })
    return findings


def cmd_audit(args) -> dict:
    path = Path(args.config)
    if not path.exists():
        print(f"[error] Config not found: {args.config}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        config = json.load(f)

    findings = audit_config(config)
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        if sev in by_sev:
            by_sev[sev] += 1

    overall = (
        "CRITICAL" if by_sev["CRITICAL"] > 0 else
        "HIGH" if by_sev["HIGH"] > 0 else
        "MEDIUM" if by_sev["MEDIUM"] > 0 else "LOW"
    )

    report = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "pipeline_name": config.get("name", "Unknown"),
        "total_checks": len(RAG_CONTROLS),
        "findings_count": len(findings),
        "by_severity": by_sev,
        "overall_risk": overall,
        "findings": findings,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\n[*] RAG audit saved to {args.output}", file=sys.stderr)

    if overall in ("CRITICAL", "HIGH"):
        sys.exit(1)

    return report


def scan_file_for_injection(filepath: str) -> list[dict]:
    hits = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return hits

    for i, line in enumerate(content.splitlines(), start=1):
        for pattern, severity, label in INJECTION_PATTERNS:
            if re.search(pattern, line):
                hits.append({
                    "file": filepath,
                    "line": i,
                    "severity": severity,
                    "label": label,
                    "excerpt": line.strip()[:200],
                })
                break  # one hit per line
    return hits


def cmd_scan_documents(args) -> dict:
    doc_dir = Path(args.dir)
    if not doc_dir.exists():
        print(f"[error] Directory not found: {args.dir}", file=sys.stderr)
        sys.exit(1)

    extensions = {".txt", ".md", ".json", ".html", ".xml", ".csv"}
    all_hits: list[dict] = []
    files_scanned = 0

    for root, _, files in os.walk(doc_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            if Path(fpath).suffix.lower() in extensions:
                files_scanned += 1
                all_hits.extend(scan_file_for_injection(fpath))

    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for h in all_hits:
        sev = h.get("severity", "LOW")
        if sev in by_sev:
            by_sev[sev] += 1

    overall = (
        "CRITICAL" if by_sev["CRITICAL"] > 0 else
        "HIGH" if by_sev["HIGH"] > 0 else
        "MEDIUM" if by_sev["MEDIUM"] > 0 else
        "CLEAN"
    )

    report = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "directory": str(doc_dir),
        "files_scanned": files_scanned,
        "injection_hits": len(all_hits),
        "by_severity": by_sev,
        "overall_risk": overall,
        "hits": all_hits[:100],
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\n[*] Document scan saved to {args.output}", file=sys.stderr)
    print(f"[*] {files_scanned} files scanned, {len(all_hits)} injection pattern hits", file=sys.stderr)

    if overall in ("CRITICAL", "HIGH"):
        sys.exit(1)

    return report


# ── Remediation helpers ────────────────────────────────────────────────────

def _prompt(finding_id: str, severity: str, control: str, finding_text: str,
            proposed_lines: list[str]) -> str:
    print(f"\n{'─'*64}")
    print(f"[{finding_id}] {severity} — {control}")
    print(f"Finding  : {finding_text}")
    print("\nProposed fix:")
    for line in proposed_lines:
        print(f"  {line}")
    while True:
        try:
            ans = input("\nApply? [y]es / [n]o / [s]kip all / [a]ll remaining > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return "s"
        if ans and ans[0] in ("y", "n", "s", "a"):
            return ans[0]


_RAG_PATCHES: dict[str, dict] = {
    "RAG-001": {"field": "retrieval.injection_filter",  "value": True,
                "desc": ["retrieval.injection_filter = true",
                         "(sanitize all retrieved text before passing to model context)"]},
    "RAG-002": {"field": "vector_db.encryption_at_rest", "value": True,
                "desc": ["vector_db.encryption_at_rest = true",
                         "(enable encryption on vector DB storage backend)"]},
    "RAG-003": {"field": "vector_db.access_control",    "value": True,
                "desc": ["vector_db.access_control = true",
                         "(restrict vector DB to agent service account via API key or mTLS)"]},
    "RAG-004": {"field": "vector_db.network_isolated",  "value": True,
                "desc": ["vector_db.network_isolated = true",
                         "(place vector DB in isolated network segment; restrict ingress to agent IPs)"]},
    "RAG-005": {"field": "retrieval.sanitize_output",   "value": True,
                "desc": ["retrieval.sanitize_output = true",
                         "(strip HTML, remove script tags, normalize unicode, filter injection patterns)"]},
    "RAG-006": {"field": "logging.pii_redaction",       "value": True,
                "desc": ["logging.pii_redaction = true",
                         "(enable PII detection and redaction before log storage)"]},
    "RAG-007": {"field": "logging.tamper_evident",      "value": True,
                "desc": ["logging.tamper_evident = true",
                         "(use append-only log store with cryptographic chaining)"]},
    "RAG-008": {"field": "embeddings.integrity_check",  "value": True,
                "desc": ["embeddings.integrity_check = true",
                         "(compute and verify checksums on embedding vectors at ingestion)"]},
    "RAG-009": {"field": "embeddings.model_pinned",     "value": True,
                "desc": ["embeddings.model_pinned = true",
                         "(pin embedding model version; re-embed corpus on intentional upgrades only)"]},
    "RAG-012": {"field": "retrieval.trust_boundary",    "value": "internal",
                "desc": ["retrieval.trust_boundary = 'internal'",
                         "(separate retrieval indexes by trust level; apply stricter sanitization for external sources)"]},
}

_RAG_MANUAL: dict[str, str] = {
    "RAG-010": (
        "Sign each data source with a checksum or digital signature.\n"
        "  sha256sum <source-file> > <source-file>.sha256\n"
        "  Verify signature on ingestion before indexing."
    ),
    "RAG-011": (
        "Apply least-privilege read controls to each data source.\n"
        "  Review IAM policies / filesystem permissions on every source feeding the pipeline."
    ),
}


def cmd_remediate(args) -> dict:
    audit_path = Path(args.audit)
    if not audit_path.exists():
        print(f"[error] Audit file not found: {args.audit}", file=sys.stderr)
        sys.exit(1)
    with open(audit_path) as f:
        audit = json.load(f)

    findings = audit.get("findings", [])
    if not findings:
        print("[*] No findings in audit — nothing to remediate.")
        return {}

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[error] Config not found: {args.config}", file=sys.stderr)
        sys.exit(1)
    with open(config_path) as f:
        config = json.load(f)

    stem = config_path.stem
    suffix = config_path.suffix or ".json"
    output_path = args.output or str(config_path.parent / f"{stem}.patched{suffix}")

    approved = skipped = manual = 0
    manual_items: list[dict] = []
    auto_approve = False

    for finding in findings:
        fid  = finding.get("id", "")
        fsev = finding.get("severity", "")
        fctl = finding.get("control", "")
        ftxt = finding.get("finding", "")

        manual_note = _RAG_MANUAL.get(fid)
        if manual_note:
            print(f"\n{'─'*64}")
            print(f"[{fid}] {fsev} — {fctl}")
            print(f"Finding  : {ftxt}")
            print(f"\n[MANUAL REQUIRED]\n  {manual_note}")
            manual += 1
            manual_items.append({"id": fid, "severity": fsev, "finding": ftxt, "manual_steps": manual_note})
            continue

        patch = _RAG_PATCHES.get(fid)
        if not patch:
            print(f"\n[{fid}] {fsev} — no auto-patch available; see remediation in audit report")
            skipped += 1
            continue

        if auto_approve:
            print(f"\n[auto-approved] [{fid}] {fctl}")
            decision = "y"
        else:
            decision = _prompt(fid, fsev, fctl, ftxt, patch["desc"])

        if decision == "a":
            auto_approve = True
            decision = "y"
        if decision == "s":
            break
        if decision == "n":
            skipped += 1
            continue

        set_nested(config, patch["field"], patch["value"])
        approved += 1
        print("  [✓] Applied")

    with open(output_path, "w") as f:
        json.dump(config, f, indent=2)

    report = {
        "remediation_timestamp": datetime.now(timezone.utc).isoformat(),
        "source_file": str(config_path),
        "output_file": output_path,
        "findings_count": len(findings),
        "approved_and_applied": approved,
        "skipped": skipped,
        "manual_required": manual,
        "manual_items": manual_items,
    }
    print(f"\n{'═'*64}")
    print(json.dumps(report, indent=2))
    print(f"\n[*] Patched config written to {output_path}", file=sys.stderr)
    print(f"[*] {manual} finding(s) require manual steps — see manual_items above", file=sys.stderr)
    return report


def main():
    parser = argparse.ArgumentParser(description="RAG Pipeline Security and Data Provenance Agent")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_audit = sub.add_parser("audit", help="Audit RAG pipeline config for security misconfigurations")
    p_audit.add_argument("--config", required=True, help="RAG pipeline config JSON")
    p_audit.add_argument("--output", default="rag_audit.json")

    p_scan = sub.add_parser("scan-documents", help="Scan documents for prompt injection patterns")
    p_scan.add_argument("--dir", required=True, help="Directory containing documents to scan")
    p_scan.add_argument("--output", default="injection_scan.json")

    p_rem = sub.add_parser("remediate", help="Interactively apply fixes from an audit report")
    p_rem.add_argument("--audit",  required=True, help="Audit JSON from the audit subcommand")
    p_rem.add_argument("--config", required=True, help="Original RAG pipeline config JSON to patch")
    p_rem.add_argument("--output", default=None,  help="Output file (default: <config>.patched.json)")

    args = parser.parse_args()
    if args.subcommand == "audit":
        cmd_audit(args)
    elif args.subcommand == "scan-documents":
        cmd_scan_documents(args)
    elif args.subcommand == "remediate":
        cmd_remediate(args)


if __name__ == "__main__":
    main()
