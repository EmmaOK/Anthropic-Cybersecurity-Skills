#!/usr/bin/env python3
"""
Reverse Engineering with Ghidra — agent.py
Authorized use only.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}

GHIDRA_HOME = Path("/opt/homebrew/Cellar/ghidra/12.0.4/ghidra_12.0.4_PUBLIC")
GHIDRA_HEADLESS = GHIDRA_HOME / "support" / "analyzeHeadless"

DANGEROUS_FUNCTIONS = [
    "strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf",
    "fscanf", "sscanf", "strncat", "strncpy",  # still risky
    "system", "popen", "execve", "execl", "execlp", "execle", "execvp",
    "dlopen", "dlsym",
]

CRYPTO_INDICATORS = [
    "CCCrypt", "CCHmac", "CCKeyDerivationPBKDF",
    "EVP_EncryptInit", "EVP_DecryptInit", "SSL_CTX_new",
    "AES_encrypt", "AES_decrypt", "DES_encrypt",
    "RC4_set_key", "MD5_Init", "SHA1_Init",
]

SENSITIVE_PATTERNS = re.compile(
    r"(password|passwd|secret|api[_-]?key|token|credential|private[_-]?key|"
    r"access[_-]?key|auth|jdbc:|mongodb://|postgres://|mysql://|BEGIN.*PRIVATE KEY)",
    re.IGNORECASE
)

def run(cmd: List[str], timeout: int = 60) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def finding(fid: str, title: str, severity: str, description: str,
            evidence: Any = None, recommendation: str = "") -> Dict:
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence or {},
        "recommendation": recommendation,
    }


# ---------------------------------------------------------------------------
# Triage (no Ghidra required)
# ---------------------------------------------------------------------------

def triage(binary_path: str) -> Dict:
    result: Dict[str, Any] = {
        "path": binary_path,
        "size_bytes": 0,
        "file_type": "",
        "sha256": "",
        "md5": "",
        "linked_libs": [],
        "string_count": 0,
        "interesting_strings": [],
        "symbols": [],
    }

    p = Path(binary_path)
    if not p.exists():
        return result

    result["size_bytes"] = p.stat().st_size

    file_out = run(["file", binary_path])
    if file_out:
        result["file_type"] = file_out.strip()

    sha_out = run(["shasum", "-a", "256", binary_path])
    if sha_out:
        result["sha256"] = sha_out.split()[0]

    md5_out = run(["md5", binary_path])
    if md5_out:
        result["md5"] = md5_out.split()[-1]

    otool_out = run(["otool", "-L", binary_path])
    if otool_out:
        libs = [l.strip().split()[0] for l in otool_out.splitlines() if l.startswith("\t")]
        result["linked_libs"] = libs[:30]

    strings_out = run(["strings", "-a", binary_path])
    if strings_out:
        lines = strings_out.splitlines()
        result["string_count"] = len(lines)
        hits = [l for l in lines if SENSITIVE_PATTERNS.search(l) and len(l) > 6]
        result["interesting_strings"] = hits[:30]

    nm_out = run(["nm", "-a", binary_path])
    if nm_out:
        dangerous = [l.strip() for l in nm_out.splitlines()
                     if any(fn in l for fn in DANGEROUS_FUNCTIONS + CRYPTO_INDICATORS)]
        result["symbols"] = dangerous[:30]

    return result


def triage_findings(info: Dict) -> List[Dict]:
    findings = []

    if info.get("interesting_strings"):
        findings.append(finding(
            "BIRE-009",
            "Sensitive Strings Embedded in Binary",
            "HIGH",
            f"Found {len(info['interesting_strings'])} sensitive strings in binary.",
            evidence={"strings": info["interesting_strings"][:15]},
            recommendation="Remove hardcoded secrets. Inject at runtime via environment or keychain."
        ))

    dangerous_syms = [s for s in info.get("symbols", [])
                      if any(fn in s for fn in ["strcpy","gets","sprintf","system","popen","execve"])]
    if dangerous_syms:
        findings.append(finding(
            "BIRE-002",
            "Dangerous Functions Referenced",
            "HIGH",
            f"Binary references {len(dangerous_syms)} dangerous C functions (overflow/injection risk).",
            evidence={"functions": dangerous_syms[:15]},
            recommendation="Replace with safe equivalents: strlcpy, strlcat, snprintf. "
                           "Audit all call sites for attacker-controlled input."
        ))

    crypto_syms = [s for s in info.get("symbols", [])
                   if any(fn in s for fn in ["DES_", "RC4_", "MD5_", "SHA1_"])]
    if crypto_syms:
        findings.append(finding(
            "BIRE-007",
            "Weak Cryptographic Primitives",
            "MEDIUM",
            "Binary links against DES, RC4, MD5, or SHA-1 — all considered cryptographically weak.",
            evidence={"symbols": crypto_syms},
            recommendation="Replace with AES-256-GCM, HMAC-SHA256, or SHA-3."
        ))

    return findings


# ---------------------------------------------------------------------------
# Binary hardening check
# ---------------------------------------------------------------------------

def check_hardening(binary_path: str) -> List[Dict]:
    findings = []

    otool_out = run(["otool", "-Iv", binary_path]) or ""
    if "__stack_chk_fail" not in otool_out:
        findings.append(finding(
            "BIRE-011",
            "Missing Stack Canaries",
            "MEDIUM",
            "No __stack_chk_fail symbol found — stack canaries likely disabled.",
            recommendation="Compile with -fstack-protector-strong."
        ))

    file_out = run(["file", binary_path]) or ""
    if "Mach-O" in file_out and "PIE" not in file_out:
        findings.append(finding(
            "BIRE-010",
            "PIE Not Confirmed",
            "LOW",
            "Could not confirm PIE (position-independent executable) from file output.",
            recommendation="Link with -pie flag."
        ))

    codesign_out = run(["codesign", "-d", "--entitlements", ":-", binary_path]) or ""
    if "allow-unsigned-executable-memory" in codesign_out:
        findings.append(finding(
            "BIRE-012",
            "allow-unsigned-executable-memory Entitlement",
            "HIGH",
            "Binary has allow-unsigned-executable-memory entitlement — enables W^X bypass.",
            evidence={"entitlement": "com.apple.security.cs.allow-unsigned-executable-memory"},
            recommendation="Remove this entitlement unless strictly required (e.g., JIT compiler)."
        ))

    if "disable-library-validation" in codesign_out:
        findings.append(finding(
            "BIRE-012",
            "disable-library-validation Entitlement (DYLD Injection Risk)",
            "HIGH",
            "Library validation disabled — DYLD_INSERT_LIBRARIES injection possible.",
            evidence={"entitlement": "com.apple.security.cs.disable-library-validation"},
            recommendation="Remove unless required. Enable library validation in hardened runtime."
        ))

    return findings


# ---------------------------------------------------------------------------
# Ghidra headless analysis
# ---------------------------------------------------------------------------

def run_ghidra_headless(binary_path: str, project_dir: str,
                        project_name: str = "pentest_re",
                        timeout: int = 300) -> Optional[str]:
    if not GHIDRA_HEADLESS.exists():
        return None

    Path(project_dir).mkdir(parents=True, exist_ok=True)

    cmd = [
        str(GHIDRA_HEADLESS),
        project_dir,
        project_name,
        "-import", binary_path,
        "-analysisTimeoutPerFile", str(timeout),
        "-log", f"/tmp/ghidra_{Path(binary_path).name}.log",
        "-deleteProject",
    ]

    result = run(cmd, timeout=timeout + 60)
    return result


def parse_ghidra_log(log_path: str) -> List[Dict]:
    findings = []
    if not Path(log_path).exists():
        return findings

    content = Path(log_path).read_text(errors="ignore")

    # Extract strings found by Ghidra
    string_hits = [l for l in content.splitlines()
                   if SENSITIVE_PATTERNS.search(l) and "INFO" in l]
    if string_hits:
        findings.append(finding(
            "BIRE-009",
            "Sensitive Strings Identified by Ghidra",
            "HIGH",
            f"Ghidra analysis identified {len(string_hits)} log entries with sensitive patterns.",
            evidence={"log_excerpts": string_hits[:10]},
        ))

    return findings


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_triage(args: argparse.Namespace) -> int:
    info = triage(args.binary)
    findings = triage_findings(info)

    if args.output == "json":
        print(json.dumps({"triage": info, "findings": findings}, indent=2))
    else:
        print(f"\n[Binary Triage: {Path(args.binary).name}]")
        print(f"  Type:    {info['file_type']}")
        print(f"  Size:    {info['size_bytes']:,} bytes")
        print(f"  SHA256:  {info['sha256']}")
        print(f"  Strings: {info['string_count']}")
        if info["interesting_strings"]:
            print(f"  Sensitive strings: {len(info['interesting_strings'])}")
            for s in info["interesting_strings"][:5]:
                print(f"    - {s[:100]}")
        if info["symbols"]:
            print(f"  Dangerous symbols: {len(info['symbols'])}")
            for s in info["symbols"][:5]:
                print(f"    - {s[:80]}")
        _render_findings("Triage Findings", findings)
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    if not GHIDRA_HEADLESS.exists():
        print(f"[!] Ghidra headless not found at {GHIDRA_HEADLESS}")
        print(f"    Verify: ls /opt/homebrew/Cellar/ghidra/")
        return 1

    binary = args.binary
    project_dir = args.project or "/tmp/ghidra_projects"

    print(f"[*] Running Ghidra headless analysis on {binary}")
    print(f"[*] Project dir: {project_dir}")
    print(f"[*] This may take 2-5 minutes...")

    output = run_ghidra_headless(binary, project_dir, timeout=args.timeout)

    if output:
        log_path = f"/tmp/ghidra_{Path(binary).name}.log"
        if args.output == "json":
            print(json.dumps({"log": output[:5000]}, indent=2))
        else:
            print("[+] Ghidra analysis complete.")
            print(f"[*] Log: {log_path}")
            # Show key lines
            for line in output.splitlines():
                if any(k in line for k in ["ERROR", "WARNING", "WARN", "function", "string"]):
                    print(f"  {line[:200]}")
    else:
        print("[!] Ghidra analysis failed or timed out.")
        return 1

    return 0


def cmd_find_vulns(args: argparse.Namespace) -> int:
    binary = args.binary
    if not Path(binary).exists():
        print(f"[!] Binary not found: {binary}")
        return 1

    findings = []

    info = triage(binary)
    findings.extend(triage_findings(info))
    findings.extend(check_hardening(binary))

    if args.output == "json":
        print(json.dumps(findings, indent=2))
    else:
        _render_findings("Vulnerability Analysis", findings)
    return 0


def cmd_strings_cmd(args: argparse.Namespace) -> int:
    binary = args.binary
    if not Path(binary).exists():
        print(f"[!] Binary not found: {binary}")
        return 1

    pattern = re.compile(args.pattern, re.IGNORECASE) if args.pattern else SENSITIVE_PATTERNS
    result = run(["strings", "-a", binary])
    if not result:
        print("[!] strings command failed.")
        return 1

    hits = [(i, l) for i, l in enumerate(result.splitlines())
            if pattern.search(l) and len(l) > 4]

    if args.output == "json":
        print(json.dumps([{"line": i, "value": l} for i, l in hits], indent=2))
    else:
        print(f"[*] Found {len(hits)} matching strings in {Path(binary).name}")
        for i, l in hits[:50]:
            print(f"  line {i:5d}: {l[:150]}")
    return 0


def cmd_hardening(args: argparse.Namespace) -> int:
    binary = args.binary
    if not Path(binary).exists():
        print(f"[!] Binary not found: {binary}")
        return 1

    findings = check_hardening(binary)

    if args.output == "json":
        print(json.dumps(findings, indent=2))
    else:
        _render_findings("Binary Hardening Check", findings)
    return 0


def cmd_assess(args: argparse.Namespace) -> int:
    binary = args.binary
    if not Path(binary).exists():
        print(f"[!] Binary not found: {binary}")
        return 1

    print(f"[*] Full assessment: {binary}")
    all_findings: List[Dict] = []

    print("[*] Triaging binary...")
    info = triage(binary)
    all_findings.extend(triage_findings(info))

    print("[*] Checking hardening...")
    all_findings.extend(check_hardening(binary))

    if GHIDRA_HEADLESS.exists() and not args.skip_ghidra:
        print("[*] Running Ghidra analysis (this takes a few minutes)...")
        project_dir = args.project or "/tmp/ghidra_projects"
        run_ghidra_headless(binary, project_dir)
        log_path = f"/tmp/ghidra_{Path(binary).name}.log"
        all_findings.extend(parse_ghidra_log(log_path))

    report = {
        "tool": "reverse-engineering-binaries-with-ghidra",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "binary": binary,
        "triage": info,
        "finding_count": len(all_findings),
        "severity_summary": _severity_counts(all_findings),
        "findings": all_findings,
    }

    if args.output_file:
        out = _render_markdown(report)
        Path(args.output_file).write_text(out)
        print(f"[+] Report written to {args.output_file}")
    else:
        _render_findings("Full Assessment", all_findings)

    return 0


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _severity_counts(findings: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1
    return counts


def _render_findings(title: str, findings: List[Dict]) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")
    if not findings:
        print("  No findings.")
        return
    for f in sorted(findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x["severity"])):
        icon = SEVERITY_ICON.get(f["severity"], "⚪")
        print(f"\n{icon} [{f['id']}] {f['title']} ({f['severity']})")
        print(f"   {f['description'][:300]}")
        if f.get("recommendation"):
            print(f"   Fix: {f['recommendation'][:200]}")


def _render_markdown(report: Dict) -> str:
    lines = ["# Binary Reverse Engineering Report"]
    lines.append(f"\n**Generated:** {report['generated_at']}  ")
    lines.append(f"**Binary:** {report['binary']}  ")
    lines.append(f"**Type:** {report['triage'].get('file_type', 'unknown')}  ")
    lines.append(f"**SHA256:** {report['triage'].get('sha256', 'N/A')}  ")
    lines.append("\n## Severity Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = report["severity_summary"].get(sev, 0)
        if c:
            lines.append(f"| {SEVERITY_ICON[sev]} {sev} | {c} |")
    lines.append("\n## Findings\n")
    for f in sorted(report["findings"],
                    key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x["severity"])):
        icon = SEVERITY_ICON.get(f["severity"], "⚪")
        lines.append(f"### {icon} [{f['id']}] {f['title']}")
        lines.append(f"\n**Severity:** {f['severity']}  ")
        lines.append(f"**Description:** {f['description']}")
        if f.get("evidence"):
            lines.append(f"\n**Evidence:**\n```json\n{json.dumps(f['evidence'], indent=2)}\n```")
        if f.get("recommendation"):
            lines.append(f"\n**Recommendation:** {f['recommendation']}")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="agent.py",
        description="Binary Reverse Engineering with Ghidra — authorized use only"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("triage", help="Quick pre-Ghidra triage (strings, symbols, hashes)")
    p.add_argument("--binary", required=True)
    p.add_argument("--output", choices=["text", "json"], default="text")

    p = sub.add_parser("analyze", help="Run Ghidra headless analysis")
    p.add_argument("--binary", required=True)
    p.add_argument("--project", help="Ghidra project directory (default: /tmp/ghidra_projects)")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--output", choices=["text", "json"], default="text")

    p = sub.add_parser("find-vulns", help="Identify vulnerability patterns (no Ghidra required)")
    p.add_argument("--binary", required=True)
    p.add_argument("--output", choices=["text", "json"], default="text")

    p = sub.add_parser("strings", help="Extract and filter strings from binary")
    p.add_argument("--binary", required=True)
    p.add_argument("--pattern", help="Regex pattern (default: sensitive keywords)")
    p.add_argument("--output", choices=["text", "json"], default="text")

    p = sub.add_parser("hardening", help="Check binary security hardening (PIE, canaries, entitlements)")
    p.add_argument("--binary", required=True)
    p.add_argument("--output", choices=["text", "json"], default="text")

    p = sub.add_parser("assess", help="Full assessment with Ghidra + triage + hardening")
    p.add_argument("--binary", required=True)
    p.add_argument("--project", help="Ghidra project directory")
    p.add_argument("--output-file", help="Write markdown report to file")
    p.add_argument("--skip-ghidra", action="store_true", help="Skip Ghidra headless analysis")
    p.add_argument("--output", choices=["text", "json"], default="text")

    args = parser.parse_args()
    dispatch = {
        "triage": cmd_triage,
        "analyze": cmd_analyze,
        "find-vulns": cmd_find_vulns,
        "strings": cmd_strings_cmd,
        "hardening": cmd_hardening,
        "assess": cmd_assess,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
