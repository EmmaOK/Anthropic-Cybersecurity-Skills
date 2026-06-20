#!/usr/bin/env python3
"""
Dynamic Analysis with Frida — agent.py
Authorized penetration testing use only.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}

FRIDA_BIN = "/Users/emmanuelokonkwo/security-tools/bin/frida"
FRIDA_PS_BIN = "/Users/emmanuelokonkwo/security-tools/bin/frida-ps"
FRIDA_TRACE_BIN = "/Users/emmanuelokonkwo/security-tools/bin/frida-trace"
OBJECTION_BIN = "/Users/emmanuelokonkwo/security-tools/bin/objection"

# ---------------------------------------------------------------------------
# Built-in hook scripts
# ---------------------------------------------------------------------------

HOOK_SSL_BYPASS_MACOS = """\
// ssl_bypass_macos.js — bypass SecTrustEvaluateWithError on macOS
(function() {
    var fn = Module.findExportByName("Security", "SecTrustEvaluateWithError");
    if (fn) {
        Interceptor.replace(fn, new NativeCallback(function(trust, error) {
            if (error && !error.isNull()) {
                Memory.writePointer(error, ptr(0));
            }
            return 1;
        }, "bool", ["pointer", "pointer"]));
        console.log("[+] SecTrustEvaluateWithError hooked — SSL pinning bypassed");
    } else {
        console.log("[-] SecTrustEvaluateWithError not found");
    }
    // Also hook SecTrustEvaluate (older API)
    var fn2 = Module.findExportByName("Security", "SecTrustEvaluate");
    if (fn2) {
        Interceptor.attach(fn2, {
            onLeave: function(retval) { retval.replace(0); }
        });
        console.log("[+] SecTrustEvaluate hooked");
    }
})();
"""

HOOK_CRYPTO_MACOS = """\
// hook_crypto_macos.js — intercept CommonCrypto and OpenSSL
(function() {
    function hexBytes(ptr, len) {
        try { return Array.from(Memory.readByteArray(ptr, Math.min(len, 32)))
                         .map(b => b.toString(16).padStart(2,'0')).join(' '); }
        catch(e) { return '<unreadable>'; }
    }
    // CommonCrypto
    var CCCrypt = Module.findExportByName(null, "CCCrypt");
    if (CCCrypt) {
        Interceptor.attach(CCCrypt, {
            onEnter: function(args) {
                var op  = args[0].toInt32() === 0 ? "ENCRYPT" : "DECRYPT";
                var alg = ["AES","DES","3DES","CAST","RC4","RC2","Blowfish"][args[1].toInt32()] || args[1].toInt32();
                var kl  = args[6].toInt32();
                console.log("[CCCrypt] op=" + op + " alg=" + alg + " keyLen=" + kl +
                            " key=" + hexBytes(args[5], kl));
            }
        });
        console.log("[+] CCCrypt hooked");
    }
    // SSL_read / SSL_write
    ["SSL_write","SSL_read"].forEach(function(name) {
        var addr = Module.findExportByName(null, name);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    this.buf = args[1];
                    this.len = args[2].toInt32();
                },
                onLeave: function(retval) {
                    var n = Math.min(retval.toInt32(), 256);
                    if (n > 0) {
                        try {
                            console.log("[" + name + "] " + Memory.readUtf8String(this.buf, n));
                        } catch(e) {
                            console.log("[" + name + "] " + hexBytes(this.buf, n));
                        }
                    }
                }
            });
            console.log("[+] " + name + " hooked");
        }
    });
})();
"""

HOOK_CREDENTIALS = """\
// hook_credentials.js — intercept file open, NSURLCredential, and auth callbacks
(function() {
    // open() — watch for password file reads
    var openFn = Module.findExportByName(null, "open");
    if (openFn) {
        Interceptor.attach(openFn, {
            onEnter: function(args) {
                try {
                    var p = args[0].readUtf8String();
                    if (p && /password|credential|keychain|secret/i.test(p)) {
                        console.log("[open] " + p);
                        console.log("  " + Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).slice(0,3).join("\\n  "));
                    }
                } catch(e) {}
            }
        });
    }
    // NSURLCredential (ObjC)
    if (ObjC.available) {
        try {
            var NSURLCredential = ObjC.classes.NSURLCredential;
            var m = NSURLCredential["+ credentialWithUser:password:persistence:"];
            if (m) {
                Interceptor.attach(m.implementation, {
                    onEnter: function(args) {
                        var user = ObjC.Object(args[2]).toString();
                        var pass = ObjC.Object(args[3]).toString();
                        console.log("[NSURLCredential] user=" + user + " pass=" + pass);
                    }
                });
                console.log("[+] NSURLCredential hooked");
            }
        } catch(e) { console.log("[-] NSURLCredential hook error: " + e); }
    }
})();
"""

HOOK_MEMORY_SCAN = """\
// memory_scan.js — scan readable memory regions for sensitive patterns
(function() {
    var keywords = ["password","secret","Bearer ","api_key","Authorization:","token"];
    var hits = 0;
    Process.enumerateRanges("r--").forEach(function(range) {
        if (range.size < 8 || range.size > 1024*1024*10) return;
        keywords.forEach(function(kw) {
            var pattern = kw.split("").map(function(c) {
                return c.charCodeAt(0).toString(16).padStart(2,"0");
            }).join(" ");
            try {
                Memory.scanSync(range.base, range.size, pattern).forEach(function(m) {
                    hits++;
                    if (hits <= 50) {
                        try {
                            console.log("[MEMSCAN] '" + kw + "' @ " + m.address +
                                        " -> " + Memory.readUtf8String(m.address, 80));
                        } catch(e) {
                            console.log("[MEMSCAN] '" + kw + "' @ " + m.address);
                        }
                    }
                });
            } catch(e) {}
        });
    });
    console.log("[MEMSCAN] Total hits: " + hits);
})();
"""

HOOK_AUTH_BYPASS = """\
// auth_bypass.js — patch common boolean auth check patterns
// WARNING: Only use on authorized targets
(function() {
    if (!ObjC.available) {
        console.log("[-] ObjC not available, skipping ObjC auth hooks");
        return;
    }
    // Hook methods containing "isLicensed", "isPremium", "isActivated", "checkAuth"
    var patterns = ["isLicensed", "isPremium", "isActivated", "isAuthenticated",
                    "checkLicense", "validateLicense", "isExpired"];
    ObjC.enumerateLoadedClasses({
        onMatch: function(name, owner) {
            patterns.forEach(function(pat) {
                try {
                    var cls = ObjC.classes[name];
                    var methods = cls.$ownMethods;
                    methods.filter(m => m.toLowerCase().includes(pat.toLowerCase())).forEach(function(m) {
                        var impl = cls[m];
                        if (impl) {
                            Interceptor.attach(impl.implementation, {
                                onLeave: function(retval) {
                                    if (retval.toInt32() === 0) {
                                        console.log("[AUTH_BYPASS] " + name + " " + m + " → patched to true");
                                        retval.replace(1);
                                    }
                                }
                            });
                        }
                    });
                } catch(e) {}
            });
        },
        onComplete: function() {}
    });
    console.log("[+] ObjC auth bypass hooks installed");
})();
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd: List[str], timeout: int = 30, stdin_input: Optional[str] = None) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           input=stdin_input)
        return r.stdout + r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def check_frida() -> bool:
    if not Path(FRIDA_BIN).exists():
        print(f"[!] frida not found at {FRIDA_BIN}")
        print("    Activate venv: source /Users/emmanuelokonkwo/security-tools/bin/activate")
        return False
    return True


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


def write_temp_script(content: str, suffix: str = ".js") -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.flush()
    return f.name


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_list_processes(args: argparse.Namespace) -> int:
    if not check_frida():
        return 1

    result = run([FRIDA_PS_BIN, "-l", "-a"])
    if not result:
        print("[!] frida-ps failed.")
        return 1

    if args.filter:
        lines = [l for l in result.splitlines()
                 if args.filter.lower() in l.lower() or "PID" in l]
        print("\n".join(lines))
    else:
        print(result)
    return 0


def cmd_hook(args: argparse.Namespace) -> int:
    if not check_frida():
        return 1

    script_path = args.script
    if not Path(script_path).exists():
        print(f"[!] Script not found: {script_path}")
        return 1

    target = args.target
    cmd = [FRIDA_BIN]

    if args.pid:
        cmd += ["-p", str(args.pid)]
    elif args.spawn:
        cmd += ["-f", target, "--no-pause"]
    else:
        cmd += ["-n", target]

    cmd += ["-l", script_path]

    print(f"[*] Attaching to '{target}' with script {script_path}")
    print(f"[*] Press Ctrl+C to detach\n")

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        pass
    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    if not check_frida():
        return 1

    patterns = [p.strip() for p in args.pattern.split(",")]
    cmd = [FRIDA_TRACE_BIN, "-n", args.target]

    for pat in patterns:
        cmd += ["-i", f"*{pat}*"]

    if args.objc:
        for pat in patterns:
            cmd += ["-m", f"-[* *{pat}*]"]
            cmd += ["-m", f"+[* *{pat}*]"]

    print(f"[*] Tracing '{args.target}' for patterns: {', '.join(patterns)}")
    print(f"[*] Press Ctrl+C to stop\n")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        pass
    return 0


def cmd_ssl_bypass(args: argparse.Namespace) -> int:
    if not check_frida():
        return 1

    script_path = write_temp_script(HOOK_SSL_BYPASS_MACOS)
    target = args.target

    print(f"[*] Injecting SSL bypass into '{target}'")

    if args.proxy_port:
        print(f"[*] Configure your proxy at 127.0.0.1:{args.proxy_port}")
        print(f"[*] mitmproxy: mitmdump --listen-port {args.proxy_port} -w /tmp/ssl_capture.mitm")

    cmd = [FRIDA_BIN, "-n", target, "-l", script_path, "--no-pause"]

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        pass
    finally:
        os.unlink(script_path)
    return 0


def cmd_memory_search(args: argparse.Namespace) -> int:
    if not check_frida():
        return 1

    script_content = HOOK_MEMORY_SCAN
    if args.pattern:
        keywords = [p.strip() for p in args.pattern.split(",")]
        kw_js = json.dumps(keywords)
        script_content = script_content.replace(
            '["password","secret","Bearer ","api_key","Authorization:","token"]',
            kw_js
        )

    script_path = write_temp_script(script_content)
    target = args.target

    print(f"[*] Scanning memory of '{target}' for sensitive patterns...")

    cmd = [FRIDA_BIN, "-n", target, "-l", script_path, "--no-pause",
           "-e", "setTimeout(() => { process.exit(0); }, 10000);"]

    output = run(cmd, timeout=30)
    os.unlink(script_path)

    findings_list = []
    if output:
        hits = [l for l in output.splitlines() if "[MEMSCAN]" in l]
        print(f"[*] Memory scan output:")
        for h in hits:
            print(f"  {h}")

        if any("password" in h.lower() or "bearer" in h.lower() or "secret" in h.lower()
               for h in hits):
            findings_list.append(finding(
                "FRDA-003",
                "Sensitive Tokens/Credentials Found in Process Memory",
                "HIGH",
                f"Memory scan found {len(hits)} hits for sensitive patterns in process '{target}'.",
                evidence={"hits": hits[:20]},
                recommendation="Ensure credentials are zeroed from memory after use. "
                               "Use SecureZeroMemory / explicit_bzero."
            ))

    if args.output == "json":
        print(json.dumps(findings_list, indent=2))

    return 0


def cmd_crypto_intercept(args: argparse.Namespace) -> int:
    if not check_frida():
        return 1

    script_path = write_temp_script(HOOK_CRYPTO_MACOS)
    target = args.target

    print(f"[*] Intercepting crypto operations in '{target}'")
    print(f"[*] Watching: CCCrypt, SSL_read, SSL_write")
    print(f"[*] Press Ctrl+C to stop\n")

    cmd = [FRIDA_BIN, "-n", target, "-l", script_path, "--no-pause"]
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        pass
    finally:
        os.unlink(script_path)
    return 0


def cmd_credential_hook(args: argparse.Namespace) -> int:
    if not check_frida():
        return 1

    script_path = write_temp_script(HOOK_CREDENTIALS)
    target = args.target

    print(f"[*] Hooking credential APIs in '{target}'")
    print(f"[*] Watching: open(), NSURLCredential, file access patterns")
    print(f"[*] Press Ctrl+C to stop\n")

    cmd = [FRIDA_BIN, "-n", target, "-l", script_path, "--no-pause"]
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        pass
    finally:
        os.unlink(script_path)
    return 0


def cmd_objection(args: argparse.Namespace) -> int:
    if not Path(OBJECTION_BIN).exists():
        print(f"[!] objection not found at {OBJECTION_BIN}")
        return 1

    target = args.gadget
    cmd = [OBJECTION_BIN, "--gadget", target, "explore"]

    print(f"[*] Launching objection against '{target}'")
    print(f"[*] Useful commands:")
    print(f"    env                    # app directories")
    print(f"    memory list modules    # loaded modules")
    print(f"    ios keychain dump      # Keychain items")
    print(f"    ios sslpinning disable # bypass SSL pinning")
    print(f"    ios cookies get        # HTTP cookies")
    print(f"    memory search --string 'Bearer '")
    print()

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        pass
    return 0


def cmd_assess(args: argparse.Namespace) -> int:
    if not check_frida():
        return 1

    target = args.target
    findings_list: List[Dict] = []

    print(f"[*] Dynamic assessment of '{target}'")
    print(f"[*] Note: target process must be running\n")

    # Check process exists
    ps_out = run([FRIDA_PS_BIN, "-l"])
    if ps_out and target.lower() not in ps_out.lower():
        print(f"[!] Process '{target}' not found in running processes.")
        print(f"[*] Running processes:")
        print(ps_out[:500])
        return 1

    # Run memory scan
    print("[*] Scanning process memory for credentials...")
    script_path = write_temp_script(HOOK_MEMORY_SCAN)
    cmd = [FRIDA_BIN, "-n", target, "-l", script_path, "--no-pause",
           "-e", "setTimeout(() => { process.exit(0); }, 8000);"]
    output = run(cmd, timeout=20)
    os.unlink(script_path)

    if output:
        hits = [l for l in output.splitlines() if "[MEMSCAN]" in l and "Total" not in l]
        if hits:
            findings_list.append(finding(
                "FRDA-003",
                "Credentials Found in Process Memory",
                "HIGH",
                f"Found {len(hits)} sensitive pattern matches in process memory.",
                evidence={"hits": hits[:15]},
                recommendation="Zero credentials from memory immediately after use."
            ))

    report = {
        "tool": "performing-dynamic-analysis-with-frida",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "finding_count": len(findings_list),
        "severity_summary": _severity_counts(findings_list),
        "findings": findings_list,
        "next_steps": [
            f"python3 agent.py ssl-bypass --target '{target}' --proxy-port 8080",
            f"python3 agent.py crypto-intercept --target '{target}'",
            f"python3 agent.py credential-hook --target '{target}'",
            f"python3 agent.py objection --gadget '{target}'",
            f"python3 agent.py trace --target '{target}' --pattern 'crypt,auth,password'",
        ]
    }

    if args.output_file:
        out = _render_markdown(report)
        Path(args.output_file).write_text(out)
        print(f"[+] Report written to {args.output_file}")
    else:
        _render_findings("Dynamic Assessment", findings_list)
        print("\n[*] Suggested next steps:")
        for s in report["next_steps"]:
            print(f"    {s}")

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
    lines = ["# Dynamic Analysis Report (Frida)"]
    lines.append(f"\n**Generated:** {report['generated_at']}  ")
    lines.append(f"**Target:** {report['target']}  ")
    lines.append(f"**Findings:** {report['finding_count']}  ")
    lines.append("\n## Severity Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = report["severity_summary"].get(sev, 0)
        if c:
            lines.append(f"| {SEVERITY_ICON[sev]} {sev} | {c} |")
    lines.append("\n## Findings\n")
    for f in sorted(report.get("findings", []),
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
    if report.get("next_steps"):
        lines.append("\n## Suggested Next Steps\n")
        for s in report["next_steps"]:
            lines.append(f"- `{s}`")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="agent.py",
        description="Dynamic Analysis with Frida — authorized use only"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("list-processes", help="List running processes")
    p.add_argument("--filter", help="Filter by name")
    p.add_argument("--output", choices=["text", "json"], default="text")

    p = sub.add_parser("hook", help="Attach Frida and run a hook script")
    p.add_argument("--target", required=True, help="Process name or bundle ID")
    p.add_argument("--script", required=True, help="Path to JS hook script")
    p.add_argument("--pid", type=int, help="Attach by PID instead of name")
    p.add_argument("--spawn", action="store_true", help="Spawn the process instead of attaching")

    p = sub.add_parser("trace", help="Trace function calls matching pattern")
    p.add_argument("--target", required=True)
    p.add_argument("--pattern", required=True, help="Comma-separated patterns (e.g. crypt,auth,password)")
    p.add_argument("--objc", action="store_true", help="Also hook ObjC methods")

    p = sub.add_parser("ssl-bypass", help="Inject SSL pinning bypass")
    p.add_argument("--target", required=True)
    p.add_argument("--proxy-port", type=int, help="mitmproxy port to use alongside bypass")

    p = sub.add_parser("memory-search", help="Scan process memory for sensitive strings")
    p.add_argument("--target", required=True)
    p.add_argument("--pattern", help="Comma-separated keywords (default: password,secret,Bearer,...)")
    p.add_argument("--output", choices=["text", "json"], default="text")

    p = sub.add_parser("crypto-intercept", help="Hook CommonCrypto and OpenSSL calls")
    p.add_argument("--target", required=True)

    p = sub.add_parser("credential-hook", help="Hook file open and NSURLCredential for credential capture")
    p.add_argument("--target", required=True)

    p = sub.add_parser("objection", help="Launch objection interactive shell")
    p.add_argument("--gadget", required=True, help="Process name or bundle ID")

    p = sub.add_parser("assess", help="Automated dynamic assessment (memory scan + suggestions)")
    p.add_argument("--target", required=True)
    p.add_argument("--output-file", help="Write markdown report to file")
    p.add_argument("--output", choices=["text", "json"], default="text")

    args = parser.parse_args()

    dispatch = {
        "list-processes": cmd_list_processes,
        "hook": cmd_hook,
        "trace": cmd_trace,
        "ssl-bypass": cmd_ssl_bypass,
        "memory-search": cmd_memory_search,
        "crypto-intercept": cmd_crypto_intercept,
        "credential-hook": cmd_credential_hook,
        "objection": cmd_objection,
        "assess": cmd_assess,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
