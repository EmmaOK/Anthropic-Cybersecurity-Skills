#!/usr/bin/env python3
"""
Desktop Application Penetration Test — agent.py
Authorized penetration testing use only.
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

DANGEROUS_STRINGS = re.compile(
    r"(password|passwd|secret|api_key|apikey|token|credential|private_key|"
    r"client_secret|auth_token|access_key|jdbc:|mongodb://|postgres://|mysql://)",
    re.IGNORECASE
)

ELECTRON_DANGEROUS = re.compile(
    r"(nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false|"
    r"enableRemoteModule\s*:\s*true|webSecurity\s*:\s*false|"
    r"allowRunningInsecureContent\s*:\s*true)",
    re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd: List[str], timeout: int = 30) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else (r.stdout + r.stderr)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def tool_path(name: str) -> Optional[str]:
    venv_bin = Path("/Users/emmanuelokonkwo/security-tools/bin") / name
    if venv_bin.exists():
        return str(venv_bin)
    result = run(["which", name])
    return result.strip() if result and result.strip() else None


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
# Analysis modules
# ---------------------------------------------------------------------------

def profile_app(app_path: str) -> Dict:
    info: Dict[str, Any] = {"path": app_path, "type": "unknown", "details": {}}
    p = Path(app_path)

    if app_path.endswith(".app"):
        info["type"] = "macOS app bundle"
        binary_candidates = list(p.glob("Contents/MacOS/*"))
        if binary_candidates:
            binary = str(binary_candidates[0])
            info["details"]["binary"] = binary
            file_out = run(["file", binary])
            if file_out:
                info["details"]["file_type"] = file_out.strip()
            otool_out = run(["otool", "-L", binary])
            if otool_out:
                libs = [l.strip().split()[0] for l in otool_out.splitlines() if l.startswith("\t")]
                info["details"]["linked_libs"] = libs[:20]
                if any("Electron" in l or "electron" in l for l in libs):
                    info["type"] = "Electron app"
                elif any("Mono" in l or "mono" in l for l in libs):
                    info["type"] = ".NET/Mono app"

        # Electron detection via Resources
        resources = p / "Contents" / "Resources"
        if (resources / "app.asar").exists() or (resources / "app").is_dir():
            info["type"] = "Electron app"
            info["details"]["asar"] = str(resources / "app.asar") if (resources / "app.asar").exists() else None

    elif app_path.endswith((".exe", ".dll")):
        info["type"] = "Windows PE"
        file_out = run(["file", app_path])
        if file_out:
            info["details"]["file_type"] = file_out.strip()

    else:
        file_out = run(["file", app_path])
        if file_out:
            info["details"]["file_type"] = file_out.strip()
            if "ELF" in file_out:
                info["type"] = "Linux ELF"
            elif "Mach-O" in file_out:
                info["type"] = "macOS native binary"

    return info


def analyze_binary_strings(binary_path: str) -> List[Dict]:
    findings = []
    result = run(["strings", "-a", binary_path])
    if not result:
        return findings

    hits = []
    for i, line in enumerate(result.splitlines()):
        if DANGEROUS_STRINGS.search(line) and len(line) > 6:
            hits.append({"line": i, "value": line[:200]})

    if hits:
        findings.append(finding(
            "DAPP-003",
            "Hardcoded Secrets / Sensitive Strings in Binary",
            "HIGH",
            f"Found {len(hits)} potentially sensitive strings embedded in the binary.",
            evidence={"matches": hits[:20]},
            recommendation="Remove hardcoded credentials. Use OS keychain or env-based secret injection."
        ))

    # Check for interesting URLs / endpoints
    urls = [l.strip() for l in result.splitlines()
            if re.match(r"https?://\S+", l.strip()) and len(l.strip()) > 10]
    if urls:
        findings.append(finding(
            "DAPP-003",
            "Embedded URLs / API Endpoints",
            "INFO",
            f"Found {len(urls)} hardcoded URLs in binary.",
            evidence={"urls": urls[:30]},
            recommendation="Review endpoints for sensitive internal services exposed in client binary."
        ))

    return findings


def analyze_electron_app(app_path: str) -> List[Dict]:
    findings = []
    p = Path(app_path)
    resources = p / "Contents" / "Resources"

    # Check for asar — suggest extraction
    asar_path = resources / "app.asar"
    app_dir = resources / "app"

    source_roots = []
    if app_dir.is_dir():
        source_roots.append(app_dir)

    if not source_roots and not asar_path.exists():
        return findings

    if asar_path.exists() and not app_dir.is_dir():
        findings.append(finding(
            "DAPP-003",
            "Electron ASAR Archive Present (Source Not Extracted)",
            "INFO",
            "App ships as app.asar. Extract with: npx @electron/asar extract app.asar ./app-extracted",
            evidence={"asar": str(asar_path)},
            recommendation="Extract and review JavaScript source for secrets and dangerous Electron config."
        ))
        return findings

    for source_root in source_roots:
        js_files = list(source_root.rglob("*.js"))
        json_files = list(source_root.rglob("*.json"))

        for fpath in js_files + json_files:
            try:
                content = fpath.read_text(errors="ignore")
            except Exception:
                continue

            # Dangerous Electron config flags
            for m in ELECTRON_DANGEROUS.finditer(content):
                flag = m.group(0)
                fid_map = {
                    "nodeIntegration": "DAPP-006",
                    "contextIsolation": "DAPP-007",
                    "webSecurity": "DAPP-008",
                }
                fid = next((v for k, v in fid_map.items() if k.lower() in flag.lower()), "DAPP-006")
                severity = "CRITICAL" if fid == "DAPP-008" else "HIGH"
                findings.append(finding(
                    fid,
                    f"Electron Dangerous Config: {flag.split(':')[0].strip()}",
                    severity,
                    f"Dangerous Electron option '{flag}' found in {fpath.name}. "
                    "nodeIntegration=true + contextIsolation=false enables XSS→RCE.",
                    evidence={"file": str(fpath.relative_to(app_path)), "match": flag},
                    recommendation="Set nodeIntegration:false, contextIsolation:true, webSecurity:true. "
                                   "Use contextBridge for renderer↔main IPC."
                ))

            # Secrets in JS source
            for m in DANGEROUS_STRINGS.finditer(content):
                line_start = content.rfind("\n", 0, m.start()) + 1
                line_end = content.find("\n", m.end())
                snippet = content[line_start:line_end][:200]
                if any(c in snippet for c in "=:\"'`"):
                    findings.append(finding(
                        "DAPP-003",
                        f"Potential Secret in Electron Source: {fpath.name}",
                        "HIGH",
                        f"Sensitive keyword found in JS source.",
                        evidence={"file": str(fpath.name), "snippet": snippet.strip()},
                        recommendation="Move secrets out of JS source. Use main process env vars or keychain."
                    ))
                    break  # one per file

            # eval() usage (code injection surface)
            if re.search(r"\beval\s*\(", content):
                findings.append(finding(
                    "DAPP-008",
                    f"eval() Usage in Electron Source: {fpath.name}",
                    "HIGH",
                    f"eval() found in {fpath.name}. Combined with nodeIntegration it enables RCE.",
                    evidence={"file": str(fpath.name)},
                    recommendation="Remove eval() usage. Use structured IPC via contextBridge instead."
                ))

    return findings


def analyze_local_storage(app_name: str) -> List[Dict]:
    findings = []
    home = Path.home()

    search_paths = [
        home / "Library" / "Application Support" / app_name,
        home / "Library" / "Preferences",
        home / "Library" / "Containers",
        home / "Library" / "Caches" / app_name,
    ]

    # Check plist files
    plist_matches = []
    pref_dir = home / "Library" / "Preferences"
    if pref_dir.exists():
        for pf in pref_dir.glob(f"*{app_name.lower()}*.plist"):
            result = run(["plutil", "-p", str(pf)])
            if result and DANGEROUS_STRINGS.search(result):
                for line in result.splitlines():
                    if DANGEROUS_STRINGS.search(line):
                        plist_matches.append({"file": str(pf.name), "line": line.strip()[:200]})

    if plist_matches:
        findings.append(finding(
            "DAPP-005",
            "Sensitive Data in Plist File",
            "HIGH",
            f"Found {len(plist_matches)} sensitive entries in app plist files.",
            evidence={"matches": plist_matches[:10]},
            recommendation="Encrypt sensitive plist values or store in macOS Keychain instead."
        ))

    # SQLite databases
    sqlite_files = []
    for search_path in search_paths:
        if search_path.exists():
            sqlite_files.extend(list(search_path.rglob("*.sqlite")) +
                                list(search_path.rglob("*.db")) +
                                list(search_path.rglob("*.sqlite3")))

    if sqlite_files:
        findings.append(finding(
            "DAPP-005",
            f"SQLite Databases Found ({len(sqlite_files)} files)",
            "MEDIUM",
            f"App stores data in SQLite databases. Review for unencrypted sensitive data.",
            evidence={"files": [str(f) for f in sqlite_files[:10]]},
            recommendation="Review SQLite contents. Encrypt sensitive tables or use Keychain for secrets."
        ))

    # macOS code signing check
    app_candidates = list(Path("/Applications").glob(f"*{app_name}*.app")) if Path("/Applications").exists() else []
    for app in app_candidates[:1]:
        sig_result = run(["codesign", "-v", str(app)])
        if sig_result and ("not signed" in sig_result.lower() or "invalid" in sig_result.lower()):
            findings.append(finding(
                "DAPP-014",
                "Application Not Properly Code-Signed",
                "HIGH",
                f"{app.name} has invalid or missing code signature.",
                evidence={"app": str(app), "output": sig_result[:300]},
                recommendation="Ensure app is signed with a valid Developer ID certificate and hardened runtime enabled."
            ))

        ent_result = run(["codesign", "-d", "--entitlements", ":-", str(app)])
        if ent_result:
            dangerous_ents = [
                "com.apple.security.cs.allow-unsigned-executable-memory",
                "com.apple.security.cs.disable-library-validation",
                "com.apple.security.cs.allow-jit",
            ]
            found_ents = [e for e in dangerous_ents if e in ent_result]
            if found_ents:
                findings.append(finding(
                    "DAPP-014",
                    "Dangerous macOS Entitlements",
                    "HIGH",
                    f"App has {len(found_ents)} dangerous entitlements that weaken security guarantees.",
                    evidence={"entitlements": found_ents},
                    recommendation="Remove unnecessary security exception entitlements. "
                                   "Avoid allow-unsigned-executable-memory and disable-library-validation."
                ))

    return findings


def check_binary_hardening(binary_path: str) -> List[Dict]:
    findings = []

    # Check PIE (Position Independent Executable)
    otool_out = run(["otool", "-Iv", binary_path])
    if otool_out:
        if "__stack_chk" not in otool_out:
            findings.append(finding(
                "BIRE-011",
                "Missing Stack Canaries",
                "MEDIUM",
                "Binary does not reference __stack_chk_fail, suggesting stack canaries are disabled.",
                evidence={"binary": binary_path},
                recommendation="Compile with -fstack-protector-strong."
            ))

    file_out = run(["file", binary_path])
    if file_out and "PIE" not in file_out and "position independent" not in file_out.lower():
        if "Mach-O" in file_out or "ELF" in file_out:
            findings.append(finding(
                "BIRE-010",
                "Binary May Lack PIE/ASLR",
                "MEDIUM",
                "Binary file type output does not confirm PIE enabled.",
                evidence={"file_output": file_out.strip()},
                recommendation="Compile with -pie (macOS) or -fPIE -pie (Linux)."
            ))

    return findings


# ---------------------------------------------------------------------------
# Traffic interception helpers
# ---------------------------------------------------------------------------

def set_system_proxy(host: str = "127.0.0.1", port: int = 8080, enable: bool = True) -> bool:
    interface = "Wi-Fi"
    if enable:
        r1 = run(["networksetup", "-setwebproxy", interface, host, str(port)])
        r2 = run(["networksetup", "-setsecurewebproxy", interface, host, str(port)])
        return r1 is not None and r2 is not None
    else:
        run(["networksetup", "-setwebproxystate", interface, "off"])
        run(["networksetup", "-setsecurewebproxystate", interface, "off"])
        return True


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_profile(args: argparse.Namespace) -> int:
    info = profile_app(args.app)
    if args.output == "json":
        print(json.dumps(info, indent=2))
    else:
        print(f"\n[App Profile]")
        print(f"  Path: {info['path']}")
        print(f"  Type: {info['type']}")
        for k, v in info.get("details", {}).items():
            if isinstance(v, list):
                print(f"  {k}: {', '.join(v[:5])}{'...' if len(v) > 5 else ''}")
            else:
                print(f"  {k}: {v}")
    return 0


def cmd_intercept(args: argparse.Namespace) -> int:
    mitmdump = tool_path("mitmdump")
    if not mitmdump:
        print("[!] mitmdump not found. Install: brew install mitmproxy")
        return 1

    port = args.port
    out_file = args.output_file or f"/tmp/desktop_app_{datetime.now().strftime('%Y%m%d_%H%M%S')}.mitm"

    print(f"[*] Setting system proxy → 127.0.0.1:{port}")
    if not set_system_proxy(port=port, enable=True):
        print("[!] Failed to set system proxy. Run manually:")
        print(f"    networksetup -setwebproxy Wi-Fi 127.0.0.1 {port}")
        print(f"    networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 {port}")

    print(f"[*] Starting mitmdump on port {port}, writing to {out_file}")
    print(f"[*] CA cert: ~/.mitmproxy/mitmproxy-ca-cert.pem — trust it in Keychain if needed")
    print(f"[*] Press Ctrl+C to stop\n")

    try:
        subprocess.run([mitmdump, "--listen-port", str(port), "-w", out_file])
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n[*] Restoring system proxy settings...")
        set_system_proxy(enable=False)
        print(f"[+] Traffic saved to {out_file}")
        print(f"[*] Analyze with: python3 agent.py analyze-traffic --file {out_file}")

    return 0


def cmd_analyze_traffic(args: argparse.Namespace) -> int:
    mitmdump = tool_path("mitmdump")
    if not mitmdump:
        print("[!] mitmdump not found.")
        return 1

    out_file = args.file
    if not Path(out_file).exists():
        print(f"[!] File not found: {out_file}")
        return 1

    # Use mitmdump to read and filter the capture
    script = '''
import mitmproxy.io
import sys

findings = []
with open(sys.argv[1], "rb") as f:
    reader = mitmproxy.io.FlowReader(f)
    for flow in reader.stream():
        if hasattr(flow, "request"):
            url = flow.request.pretty_url
            # Check for sensitive headers
            auth = flow.request.headers.get("Authorization", "")
            cookie = flow.request.headers.get("Cookie", "")
            if auth:
                findings.append(f"[AUTH HEADER] {url}: {auth[:80]}")
            if "http://" in url and not url.startswith("http://127"):
                findings.append(f"[CLEARTEXT] {url}")
            if flow.request.method in ("POST","PUT","PATCH"):
                body = flow.request.get_text(strict=False)
                if any(k in body.lower() for k in ["password","secret","token","api_key"]):
                    findings.append(f"[SENSITIVE BODY] {flow.request.method} {url}: {body[:200]}")

for f in findings:
    print(f)
'''

    print(f"[*] Analyzing {out_file}...")
    r = run([sys.executable, "-c", script, out_file], timeout=60)
    if r:
        print(r)
    else:
        print(f"[*] Use: mitmdump -r {out_file} to replay and inspect manually")
    return 0


def cmd_static(args: argparse.Namespace) -> int:
    binary = args.binary
    if not Path(binary).exists():
        print(f"[!] Binary not found: {binary}")
        return 1

    findings = []
    findings.extend(analyze_binary_strings(binary))
    findings.extend(check_binary_hardening(binary))

    if args.output == "json":
        print(json.dumps(findings, indent=2))
    else:
        _render_findings("Static Analysis", findings)
    return 0


def cmd_electron(args: argparse.Namespace) -> int:
    app_path = args.app
    if not Path(app_path).exists():
        print(f"[!] App not found: {app_path}")
        return 1

    findings = analyze_electron_app(app_path)

    if args.output == "json":
        print(json.dumps(findings, indent=2))
    else:
        _render_findings("Electron Analysis", findings)
    return 0


def cmd_local_storage(args: argparse.Namespace) -> int:
    findings = analyze_local_storage(args.app_name)

    if args.output == "json":
        print(json.dumps(findings, indent=2))
    else:
        _render_findings("Local Storage Analysis", findings)
    return 0


def cmd_assess(args: argparse.Namespace) -> int:
    app_path = args.app
    if not Path(app_path).exists():
        print(f"[!] App path not found: {app_path}")
        return 1

    print(f"[*] Assessing: {app_path}")
    all_findings: List[Dict] = []

    print("[*] Profiling app...")
    profile = profile_app(app_path)

    print("[*] Analyzing app type-specific issues...")
    if profile["type"] == "Electron app":
        all_findings.extend(analyze_electron_app(app_path))

    binary = profile.get("details", {}).get("binary", app_path)
    if Path(binary).is_file():
        print("[*] Analyzing binary strings...")
        all_findings.extend(analyze_binary_strings(binary))
        print("[*] Checking binary hardening...")
        all_findings.extend(check_binary_hardening(binary))

    app_name = Path(app_path).stem
    print(f"[*] Analyzing local storage for '{app_name}'...")
    all_findings.extend(analyze_local_storage(app_name))

    report = {
        "tool": "performing-desktop-application-penetration-test",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "app": app_path,
        "app_type": profile["type"],
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


def cmd_report(args: argparse.Namespace) -> int:
    print("[*] Run 'assess' to generate findings, then use --output-file to save report.")
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
    lines = []
    lines.append("# Desktop Application Penetration Test Report")
    lines.append(f"\n**Generated:** {report['generated_at']}  ")
    lines.append(f"**Target:** {report['app']}  ")
    lines.append(f"**App Type:** {report['app_type']}  ")
    lines.append(f"**Findings:** {report['finding_count']}  ")
    lines.append("\n## Severity Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
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
        description="Desktop Application Penetration Test — authorized use only"
    )
    parser.add_argument("--output", choices=["text", "json"], default="text")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("profile", help="Identify app type and linked libraries")
    p.add_argument("--app", required=True, help="Path to .app bundle or binary")
    p.add_argument("--output", choices=["text", "json"], default="text")

    p = sub.add_parser("intercept", help="Start mitmproxy and set system proxy")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--output-file", help="Write capture to file (default: /tmp/...mitm)")

    p = sub.add_parser("analyze-traffic", help="Analyze mitmproxy capture file")
    p.add_argument("--file", required=True)

    p = sub.add_parser("static", help="Static binary analysis (strings, hardening)")
    p.add_argument("--binary", required=True)
    p.add_argument("--output", choices=["text", "json"], default="text")

    p = sub.add_parser("electron", help="Analyze Electron app for dangerous config and secrets")
    p.add_argument("--app", required=True)
    p.add_argument("--output", choices=["text", "json"], default="text")

    p = sub.add_parser("local-storage", help="Analyze app local storage (plist, SQLite, keychain)")
    p.add_argument("--app-name", required=True)
    p.add_argument("--output", choices=["text", "json"], default="text")

    p = sub.add_parser("assess", help="Full assessment of a desktop app")
    p.add_argument("--app", required=True)
    p.add_argument("--output-file", help="Write markdown report to file")
    p.add_argument("--output", choices=["text", "json"], default="text")

    sub.add_parser("report", help="Generate report (use assess --output-file instead)")

    args = parser.parse_args()

    dispatch = {
        "profile": cmd_profile,
        "intercept": cmd_intercept,
        "analyze-traffic": cmd_analyze_traffic,
        "static": cmd_static,
        "electron": cmd_electron,
        "local-storage": cmd_local_storage,
        "assess": cmd_assess,
        "report": cmd_report,
    }

    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
