#!/usr/bin/env python3
"""MCP10 - Supply Chain Security: Audit MCP server dependencies for CVEs and supply chain risks."""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    import urllib.request
    HAS_HTTPX = False

OWASP_ID = "MCP10"
TOOL_NAME = "phantom-mcp-supply-chain"

# Known malicious or typosquatted package patterns
SUSPICIOUS_PACKAGE_PATTERNS = [
    (r"^(requests2|request|requestss)$", "Typosquat of 'requests'"),
    (r"^(flask2|flaask|flas)$", "Typosquat of 'flask'"),
    (r"^(djang0|djanngo|djanjo)$", "Typosquat of 'django'"),
    (r"^(numpy2|nummpy|nuumpy)$", "Typosquat of 'numpy'"),
    (r"^(pil|pillow2|pilows)$", "Typosquat of 'Pillow'"),
    (r"^(setup-tools|setuptools2|setuptoolz)$", "Typosquat of 'setuptools'"),
    (r"^(cryptography2|crytpography)$", "Typosquat of 'cryptography'"),
    (r"^(anthropic-claude|claude-sdk|claude-api)$", "Unofficial Anthropic SDK (use 'anthropic')"),
    (r"^(openai2|open-ai|openai_sdk)$", "Unofficial OpenAI client"),
    (r"^.*logger.*$", "Generic logger package — verify not malicious"),
]

# Packages historically associated with malicious activity
HIGH_RISK_PACKAGES = {
    "colorama2", "colourama", "distibution", "pip-install", "pip-pkg",
    "loglib-modules", "pyg-nightly", "python-dbusx",
}


def jsonrpc(url, method, params=None):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    h = {"Content-Type": "application/json"}
    try:
        if HAS_HTTPX:
            r = httpx.post(url, content=payload, headers=h, timeout=10)
            return r.json()
        else:
            req = urllib.request.Request(url, data=payload, headers=h)
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


def get_installed_packages():
    """Get list of installed Python packages with versions."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except Exception:
        pass
    return []


def run_pip_audit():
    """Run pip-audit if available for CVE scanning."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip_audit", "--format=json", "--output=-"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode in (0, 1) and result.stdout.strip():
            data = json.loads(result.stdout)
            return data.get("dependencies", [])
    except Exception:
        pass
    return None


def check_requirements_file(req_path):
    """Parse requirements.txt/pyproject.toml and check for unpinned deps."""
    findings = []
    fid = 1
    path = Path(req_path)
    if not path.exists():
        return findings

    if path.suffix in (".txt",):
        try:
            lines = path.read_text().splitlines()
            unpinned = []
            git_deps = []
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("git+") or line.startswith("-e git"):
                    git_deps.append(line)
                elif "==" not in line and ">=" not in line and "~=" not in line:
                    unpinned.append(line)

            if unpinned:
                findings.append({
                    "id": f"{OWASP_ID}-{fid:03d}",
                    "title": f"Unpinned Dependencies in {path.name}",
                    "severity": "HIGH",
                    "description": (
                        f"{len(unpinned)} dependencies lack version pins. "
                        "Unpinned dependencies can silently receive malicious updates."
                    ),
                    "evidence": f"Unpinned: {unpinned[:10]}",
                    "remediation": (
                        "Pin all dependencies to exact versions with hashes: pip-compile --generate-hashes. "
                        "Use pip install --require-hashes to enforce integrity at install time."
                    ),
                })
                fid += 1

            if git_deps:
                findings.append({
                    "id": f"{OWASP_ID}-{fid:03d}",
                    "title": f"Git-Sourced Dependencies in {path.name}",
                    "severity": "HIGH",
                    "description": f"Git dependencies are not reproducible and bypass PyPI integrity verification.",
                    "evidence": f"Git deps: {git_deps[:5]}",
                    "remediation": "Replace git deps with versioned PyPI releases. If unavoidable, pin to a specific commit SHA.",
                })
                fid += 1
        except Exception as e:
            findings.append({
                "id": f"{OWASP_ID}-{fid:03d}",
                "title": f"Could not parse {path.name}",
                "severity": "INFO",
                "description": str(e),
                "evidence": req_path,
                "remediation": "Ensure requirements file is valid UTF-8.",
            })
    return findings


def probe_mcp_server_info(target):
    """Check MCP server initialize for version/dependency disclosure."""
    resp = jsonrpc(target, "initialize", params={
        "protocolVersion": "2024-11-05",
        "clientInfo": {"name": "supply-chain-audit", "version": "1.0"},
        "capabilities": {}
    })
    return resp


def main():
    p = argparse.ArgumentParser(description="MCP10 Supply Chain Security Assessment")
    p.add_argument("--server-url", required=True, help="MCP server base URL")
    p.add_argument("--requirements", default=None, help="Path to requirements.txt or pyproject.toml")
    p.add_argument("--scan-env", action="store_true", help="Scan current Python env for CVEs via pip-audit")
    p.add_argument("--output", default="mcp10_report.json")
    args = p.parse_args()

    target = args.server_url.rstrip("/")
    findings = []
    fid = 1

    # 1. Check MCP server self-disclosure
    server_info = probe_mcp_server_info(target)
    server_str = json.dumps(server_info).lower()

    # Check for version disclosure that aids supply chain attacks
    version_patterns = re.findall(r'version["\s:]+([0-9]+\.[0-9]+\.?[0-9]*)', server_str)
    if version_patterns:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "MCP Server Discloses Dependency Versions",
            "severity": "LOW",
            "description": f"Server's initialize response reveals version strings: {version_patterns[:5]}. Aids targeted supply chain attacks.",
            "evidence": server_str[:400],
            "remediation": "Remove library version strings from server info responses to reduce supply chain attack surface.",
        })
        fid += 1

    # 2. Scan requirements file if provided
    if args.requirements:
        req_findings = check_requirements_file(args.requirements)
        for rf in req_findings:
            rf["id"] = f"{OWASP_ID}-{fid:03d}"
            findings.append(rf)
            fid += 1

    # 3. Check installed packages for typosquats
    packages = get_installed_packages()
    for pkg in packages:
        name = pkg.get("name", "").lower()
        if name in HIGH_RISK_PACKAGES:
            findings.append({
                "id": f"{OWASP_ID}-{fid:03d}",
                "title": f"High-Risk Package Installed: '{name}'",
                "severity": "CRITICAL",
                "description": f"Package '{name}' is in the known-malicious/high-risk package list.",
                "evidence": f"Installed version: {pkg.get('version', 'unknown')}",
                "remediation": f"Immediately uninstall '{name}' and audit what it may have exfiltrated. Investigate how it was installed.",
            })
            fid += 1
            continue

        for pattern, label in SUSPICIOUS_PACKAGE_PATTERNS:
            if re.match(pattern, name, re.IGNORECASE):
                findings.append({
                    "id": f"{OWASP_ID}-{fid:03d}",
                    "title": f"Potentially Typosquatted Package: '{name}' — {label}",
                    "severity": "HIGH",
                    "description": f"Package '{name}' matches a typosquatting pattern for a legitimate package: {label}.",
                    "evidence": f"Package: {name} v{pkg.get('version', '?')} | Pattern: {pattern}",
                    "remediation": f"Verify '{name}' is the intended package. If not, remove and install the correct package.",
                })
                fid += 1

    # 4. Run pip-audit for CVE scanning
    if args.scan_env:
        audit_results = run_pip_audit()
        if audit_results is None:
            findings.append({
                "id": f"{OWASP_ID}-{fid:03d}",
                "title": "pip-audit Not Available",
                "severity": "MEDIUM",
                "description": "pip-audit is not installed. CVE scanning of installed packages requires it.",
                "evidence": "pip-audit not found in current Python environment.",
                "remediation": "Install pip-audit: pip install pip-audit. Run as part of your CI pipeline.",
            })
            fid += 1
        else:
            vuln_count = 0
            for dep in audit_results:
                vulns = dep.get("vulns", [])
                if vulns:
                    for vuln in vulns:
                        vuln_count += 1
                        severity = "CRITICAL" if any(
                            c.get("score", 0) >= 9.0 for c in vuln.get("fix_versions", [{}]) if isinstance(c, dict)
                        ) else "HIGH"
                        findings.append({
                            "id": f"{OWASP_ID}-{fid:03d}",
                            "title": f"CVE in Dependency: {dep.get('name')} — {vuln.get('id', 'Unknown')}",
                            "severity": severity,
                            "description": vuln.get("description", "No description available.")[:400],
                            "evidence": (
                                f"Package: {dep.get('name')} v{dep.get('version')} | "
                                f"CVE: {vuln.get('id')} | "
                                f"Fix versions: {vuln.get('fix_versions', [])}"
                            ),
                            "remediation": f"Upgrade {dep.get('name')} to a non-vulnerable version: {vuln.get('fix_versions', ['check PyPI'])}",
                        })
                        fid += 1

            if vuln_count == 0:
                findings.append({
                    "id": f"{OWASP_ID}-{fid:03d}",
                    "title": "No Known CVEs in Installed Dependencies",
                    "severity": "INFO",
                    "description": f"pip-audit scanned {len(audit_results)} packages. No known vulnerabilities found.",
                    "evidence": f"Packages scanned: {len(audit_results)}",
                    "remediation": "Schedule recurring pip-audit scans (weekly) as part of your vulnerability management program.",
                })
                fid += 1

    if not findings:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "No Supply Chain Issues Detected in Automated Probes",
            "severity": "INFO",
            "description": "No typosquats, version disclosure, or CVEs detected in this scan.",
            "evidence": f"Target: {target}",
            "remediation": (
                "Run with --requirements and --scan-env for comprehensive coverage. "
                "Implement SBOM generation (pip-audit --format=cyclonedx) in your CI pipeline."
            ),
        })

    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1

    report = {
        "tool": TOOL_NAME, "target": target, "owasp_id": OWASP_ID,
        "packages_checked": len(packages),
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
