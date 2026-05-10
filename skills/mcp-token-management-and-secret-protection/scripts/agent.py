#!/usr/bin/env python3
"""MCP07 - Token Management & Secret Protection: Scan MCP configs and responses for credential exposure."""
import argparse
import json
import os
import re
import sys
from pathlib import Path

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    import urllib.request
    HAS_HTTPX = False

OWASP_ID = "MCP07"
TOOL_NAME = "phantom-mcp-token-mgmt"

# Regex patterns for detecting hardcoded secrets in files and responses
SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', "API Key"),
    (r'(?i)(secret|secret[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9_\-\/+]{16,})', "Secret Key"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})', "Password"),
    (r'(?i)(token|bearer|auth[_-]?token)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})', "Auth Token"),
    (r'sk-[A-Za-z0-9]{32,}', "OpenAI API Key"),
    (r'sk-ant-[A-Za-z0-9\-]{32,}', "Anthropic API Key"),
    (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS Secret Key"),
    (r'(?i)(private[_-]?key|rsa[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9/+=\n-]{50,})', "Private Key Material"),
    (r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', "JWT Token"),
    (r'(?i)postgres(?:ql)?://[^\s"\']+:[^\s"\'@]+@', "Database Connection String with Credentials"),
    (r'(?i)mongodb://[^\s"\']+:[^\s"\'@]+@', "MongoDB Connection String with Credentials"),
    (r'(?i)redis://:([^\s"\'@]+)@', "Redis Connection String with Password"),
]

# File extensions to scan
SCAN_EXTENSIONS = {".json", ".yaml", ".yml", ".env", ".config", ".conf", ".toml", ".ini", ".py", ".js", ".ts"}


def jsonrpc(url, method, params=None):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    h = {"Content-Type": "application/json"}
    try:
        if HAS_HTTPX:
            r = httpx.post(url, content=payload, headers=h, timeout=10)
            return r.text
        else:
            req = urllib.request.Request(url, data=payload, headers=h)
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.read().decode()
    except Exception as e:
        return str(e)


def scan_text_for_secrets(text, source_label):
    hits = []
    for pattern, secret_type in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            value = match.group(0)
            # Redact actual secret value in evidence
            redacted = value[:8] + "***REDACTED***" + value[-3:] if len(value) > 15 else "***REDACTED***"
            hits.append({
                "secret_type": secret_type,
                "location": source_label,
                "evidence_redacted": redacted,
                "offset": match.start(),
            })
    return hits


def scan_directory(scan_path):
    """Scan files in a directory for hardcoded secrets."""
    results = []
    path = Path(scan_path)
    if not path.exists():
        return results
    for f in path.rglob("*"):
        if f.is_file() and f.suffix.lower() in SCAN_EXTENSIONS:
            # Skip large files and binary-ish files
            if f.stat().st_size > 1_000_000:
                continue
            try:
                text = f.read_text(errors="replace")
                hits = scan_text_for_secrets(text, str(f))
                results.extend(hits)
            except Exception:
                pass
    return results


def probe_response_for_secrets(resp_text, source):
    """Check MCP server responses for accidentally leaked secrets."""
    return scan_text_for_secrets(resp_text, source)


def main():
    p = argparse.ArgumentParser(description="MCP07 Token Management & Secret Protection Audit")
    p.add_argument("--server-url", required=True, help="MCP server base URL")
    p.add_argument("--scan-dir", default=None, help="Local directory to scan for hardcoded secrets (MCP server source)")
    p.add_argument("--output", default="mcp07_report.json")
    args = p.parse_args()

    target = args.server_url.rstrip("/")
    findings = []
    fid = 1

    # 1. Probe server responses for leaked secrets
    for method in ["tools/list", "resources/list", "prompts/list"]:
        resp_text = jsonrpc(target, method)
        hits = probe_response_for_secrets(resp_text, f"Response to {method}")
        for hit in hits:
            findings.append({
                "id": f"{OWASP_ID}-{fid:03d}",
                "title": f"{hit['secret_type']} Leaked in MCP Response",
                "severity": "CRITICAL",
                "description": (
                    f"The MCP server's '{method}' response contains what appears to be a {hit['secret_type']}. "
                    "Credentials must never appear in protocol responses — agents log these responses."
                ),
                "evidence": f"Location: {hit['location']} | Pattern match (redacted): {hit['evidence_redacted']}",
                "remediation": (
                    "Remove all credentials from MCP protocol responses. "
                    "Use vault-injected env vars at runtime; never embed tokens in tool definitions or schemas. "
                    "Implement response logging redaction for all secret patterns."
                ),
            })
            fid += 1

    # 2. Check server URL for credentials embedded in URL
    if "@" in target and ("://" in target):
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "Credentials Embedded in MCP Server URL",
            "severity": "HIGH",
            "description": "The server URL contains embedded credentials (user:pass@host format).",
            "evidence": f"URL contains '@' suggesting embedded credentials: {target[:30]}***",
            "remediation": "Remove credentials from URLs. Use Authorization headers or mTLS instead.",
        })
        fid += 1

    # 3. Scan local directory if provided
    if args.scan_dir:
        file_hits = scan_directory(args.scan_dir)
        # Group by file
        by_file: dict[str, list] = {}
        for hit in file_hits:
            by_file.setdefault(hit["location"], []).append(hit)

        for filepath, hits in by_file.items():
            findings.append({
                "id": f"{OWASP_ID}-{fid:03d}",
                "title": f"Hardcoded Secrets in {Path(filepath).name}",
                "severity": "CRITICAL",
                "description": (
                    f"Found {len(hits)} potential secret(s) hardcoded in {filepath}. "
                    "Hardcoded credentials are exposed in source control, logs, and container images."
                ),
                "evidence": " | ".join(f"{h['secret_type']}: {h['evidence_redacted']}" for h in hits[:5]),
                "remediation": (
                    "Replace hardcoded secrets with environment variable references: os.environ.get('SECRET_NAME'). "
                    "Rotate any exposed credentials immediately. "
                    "Use a secrets manager (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager). "
                    "Add pre-commit hooks (detect-secrets, truffleHog) to prevent future commits."
                ),
            })
            fid += 1

    # 4. Check for long-lived token risk (probe token TTL via server info if available)
    server_info = jsonrpc(target, "initialize", {"protocolVersion": "2024-11-05", "clientInfo": {"name": "audit", "version": "1.0"}})
    if "capabilities" in str(server_info) and "auth" not in str(server_info).lower():
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "MCP Server Capabilities Lack Explicit Auth/Token Lifecycle Declaration",
            "severity": "MEDIUM",
            "description": (
                "Server initialize response does not declare authentication capabilities or token TTL. "
                "This suggests tokens may be long-lived or unmanaged."
            ),
            "evidence": str(server_info)[:300],
            "remediation": (
                "Declare authentication capabilities in the MCP server's initialize response. "
                "Implement short-lived token rotation (≤1 hour TTL). "
                "Use refresh token patterns for long-running agent sessions."
            ),
        })
        fid += 1

    if not findings:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "No Credential Exposure Detected in Probed Responses",
            "severity": "INFO",
            "description": "MCP protocol responses did not contain detectable credential patterns.",
            "evidence": "Scanned: tools/list, resources/list, prompts/list",
            "remediation": "Continue scanning with --scan-dir pointing to MCP server source code.",
        })

    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1

    report = {
        "tool": TOOL_NAME, "target": target, "owasp_id": OWASP_ID,
        "scanned_dir": args.scan_dir,
        "findings": findings,
        "summary": {"total": len(findings), **sev},
    }
    print(json.dumps(report, indent=2))
    if args.output:
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2)

    sys.exit(1 if sev["CRITICAL"] > 0 or sev["HIGH"] > 0 else 0)


if __name__ == "__main__":
    main()
