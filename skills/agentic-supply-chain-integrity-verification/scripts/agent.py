#!/usr/bin/env python3
"""ASI08 - Agentic Supply Chain Integrity Verification: Audit plugin manifests and signatures."""
import argparse
import hashlib
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OWASP_ID = "ASI08"
TOOL_NAME = "phantom-agentic-supply-chain"

# Permissions that should never be granted to plugins
DANGEROUS_PERMISSIONS = [
    "read_all_files", "write_all_files", "execute_shell", "network_unrestricted",
    "read_secrets", "read_credentials", "read_env", "admin", "root",
    "modify_other_agents", "spawn_agents", "modify_system",
]

# Suspicious patterns in plugin source URLs or package names
SUSPICIOUS_SOURCE_PATTERNS = [
    (r"(typosquat|lookalike|fake)", "Typosquatting indicator in name"),
    (r"github\.com/[^/]+/[^/]+-(?:evil|malicious|hack|pwn)", "Suspicious repository name"),
    (r"http://(?!localhost)", "Non-HTTPS plugin source — MitM risk"),
    (r"(pastebin|hastebin|transfer\.sh|ngrok)", "Untrusted hosting service"),
    (r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", "Raw IP address as plugin source"),
]

# Required fields in a trustworthy plugin manifest
REQUIRED_MANIFEST_FIELDS = [
    ("signature", "CRITICAL", "No cryptographic signature — plugin integrity cannot be verified"),
    ("checksum", "HIGH", "No content checksum — tampering cannot be detected"),
    ("source_url", "HIGH", "No source URL — provenance cannot be verified"),
    ("version", "MEDIUM", "No version pin — supply chain updates cannot be controlled"),
    ("author", "MEDIUM", "No author attribution"),
    ("permissions", "INFO", "No explicit permissions declaration"),
]


def audit_manifest(manifest_data):
    findings = []

    # Handle list of plugins or single plugin
    plugins = manifest_data if isinstance(manifest_data, list) else [manifest_data]

    for plugin in plugins:
        name = plugin.get("name", "unknown")

        # Required fields check
        for field, severity, msg in REQUIRED_MANIFEST_FIELDS:
            if not plugin.get(field):
                findings.append({
                    "id": f"{OWASP_ID}-{len(findings)+1:03d}",
                    "title": f"Plugin '{name}': Missing '{field}'",
                    "severity": severity,
                    "description": f"Plugin '{name}': {msg}",
                    "evidence": f"plugin={name}, field={field}",
                    "remediation": f"Add '{field}' to plugin manifest. Require signature verification before loading.",
                })

        # Dangerous permissions check
        perms = plugin.get("permissions", [])
        if isinstance(perms, str):
            perms = [perms]
        for perm in perms:
            if perm.lower() in DANGEROUS_PERMISSIONS:
                findings.append({
                    "id": f"{OWASP_ID}-{len(findings)+1:03d}",
                    "title": f"Plugin '{name}': Dangerous Permission '{perm}'",
                    "severity": "CRITICAL",
                    "description": f"Plugin '{name}' requests dangerous permission '{perm}'.",
                    "evidence": f"plugin={name}, permissions={perms}",
                    "remediation": "Deny plugins requesting dangerous permissions. Apply least-privilege.",
                })

        # Suspicious source URL
        source = plugin.get("source_url", "") or plugin.get("repository", "")
        for pattern, desc in SUSPICIOUS_SOURCE_PATTERNS:
            if re.search(pattern, source, re.IGNORECASE):
                findings.append({
                    "id": f"{OWASP_ID}-{len(findings)+1:03d}",
                    "title": f"Plugin '{name}': Suspicious Source — {desc}",
                    "severity": "HIGH",
                    "description": f"Plugin '{name}' source URL matches suspicious pattern: {desc}",
                    "evidence": f"source_url={source}",
                    "remediation": "Only allow plugins from approved, allowlisted sources over HTTPS.",
                })

    return findings


def scan_requirements(req_path):
    """Scan requirements.txt for unpinned or suspicious packages."""
    findings = []
    content = Path(req_path).read_text(errors="replace")
    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Unpinned version
        if not re.search(r"[>=<!=]", line):
            findings.append({
                "id": f"{OWASP_ID}-R{len(findings)+1:03d}",
                "title": f"Unpinned Dependency: '{line}'",
                "severity": "MEDIUM",
                "description": f"Dependency '{line}' has no version pin — supply chain updates may introduce malicious code.",
                "evidence": f"line {i}: {line}",
                "remediation": "Pin all dependencies to exact versions. Use a lock file (pip-compile, poetry.lock).",
            })
        # Direct URL install (potential bypass of registry)
        if re.search(r"https?://|git\+|svn\+|hg\+", line, re.IGNORECASE):
            findings.append({
                "id": f"{OWASP_ID}-R{len(findings)+1:03d}",
                "title": f"Direct URL Dependency: '{line[:60]}'",
                "severity": "HIGH",
                "description": "Dependency installed from direct URL bypasses package registry integrity checks.",
                "evidence": f"line {i}: {line}",
                "remediation": "Install dependencies from trusted package registries (PyPI) only. Verify checksums.",
            })
    return findings


def check_against_allowlist(manifest_data, allowlist):
    findings = []
    approved_sources = set(allowlist.get("approved_sources", []))
    approved_authors = set(allowlist.get("approved_authors", []))
    plugins = manifest_data if isinstance(manifest_data, list) else [manifest_data]
    for plugin in plugins:
        name = plugin.get("name", "unknown")
        source = plugin.get("source_url", "") or plugin.get("repository", "")
        author = plugin.get("author", "")
        if approved_sources and not any(src in source for src in approved_sources):
            findings.append({
                "id": f"{OWASP_ID}-A{len(findings)+1:03d}",
                "title": f"Plugin '{name}': Source Not in Allowlist",
                "severity": "HIGH",
                "description": f"Plugin source '{source}' is not in the approved sources allowlist.",
                "evidence": f"source={source}, approved={list(approved_sources)[:5]}",
                "remediation": "Only install plugins from pre-approved sources.",
            })
    return findings


def main():
    p = argparse.ArgumentParser(description="ASI08 Agentic Supply Chain Integrity Verification")
    p.add_argument("--manifest-file", required=True, help="Plugin manifest JSON or requirements.txt")
    p.add_argument("--allowlist", help="JSON file with approved_sources and approved_authors lists")
    p.add_argument("--output", default="asi08_supply_chain_report.json")
    args = p.parse_args()

    findings = []
    manifest_path = Path(args.manifest_file)

    if args.manifest_file.endswith(".txt"):
        findings += scan_requirements(args.manifest_file)
        manifest_data = {}
    else:
        manifest_data = json.loads(manifest_path.read_text())
        findings += audit_manifest(manifest_data)
        if args.allowlist:
            allowlist = json.loads(Path(args.allowlist).read_text())
            findings += check_against_allowlist(manifest_data, allowlist)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

    report = {
        "tool": TOOL_NAME, "owasp_id": OWASP_ID,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "manifest_file": args.manifest_file,
        "findings": findings, "summary": {"total": len(findings), **counts},
    }
    print(json.dumps(report, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2))
    sys.exit(1 if counts["CRITICAL"] > 0 or counts["HIGH"] > 0 else 0)


if __name__ == "__main__":
    main()
