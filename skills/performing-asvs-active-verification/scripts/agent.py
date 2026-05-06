#!/usr/bin/env python3
"""OWASP ASVS v4.0.3 — Active verification orchestrator."""
import argparse
import json
import os
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

VERIFY_TLS = os.environ.get("SKIP_TLS_VERIFY", "").lower() not in ("1", "true", "yes")
SEVERITY_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "PASS": 0}

# Maps each ASVS chapter to the sub-skill agent that covers it (where one exists).
# Chapters without a dedicated skill are covered by inline probes below.
SKILL_CHAPTERS = {
    "V2": {
        "title": "Authentication",
        "skill": "testing-api-authentication-weaknesses",
        "args_fn": lambda url, token, out: [url, *(["--token", token] if token else [])],
        "control_map": {
            "weak_password": "V2.1.1",
            "no_mfa": "V2.2.1",
            "no_rate_limit": "V2.4.5",
            "default_credentials": "V2.1.5",
            "jwt_none_algorithm": "V2.6.2",
            "jwt_weak_secret": "V2.6.3",
        },
    },
    "V4": {
        "title": "Access Control",
        "skill": "testing-api-for-broken-object-level-authorization",
        "args_fn": lambda url, token, out: [url, *(["--token", token] if token else [])],
        "control_map": {
            "bola": "V4.1.1",
            "idor": "V4.1.2",
            "horizontal_privilege_escalation": "V4.1.3",
        },
    },
    "V5": {
        "title": "Validation, Sanitization, and Encoding",
        "skill": "exploiting-api-injection-vulnerabilities",
        "args_fn": lambda url, token, out: [
            "--url", url + "/api/data",
            "--params", "url,redirect,input,query,cmd,path",
            *(["--token", token] if token else []),
            "--output", out,
        ],
        "control_map": {
            "sqli": "V5.3.4",
            "xss": "V5.3.3",
            "ssrf": "V5.2.6",
            "os_injection": "V5.3.8",
            "path_traversal": "V5.3.9",
            "xxe": "V5.3.10",
        },
    },
    "V13": {
        "title": "API and Web Service",
        "skill": "conducting-api-security-testing",
        "args_fn": lambda url, token, out: [
            "--base-url", url,
            *(["--token", token] if token else []),
            "--output", out,
        ],
        "control_map": {
            "missing_auth": "V13.1.1",
            "cors_misconfiguration": "V13.2.3",
            "graphql_introspection": "V13.4.1",
            "http_verb_tampering": "V13.2.1",
            "mass_assignment": "V13.2.5",
        },
    },
}


def run_skill(chapter_id, chapter_def, target_url, token, timeout):
    skill_path = ROOT / "skills" / chapter_def["skill"] / "scripts" / "agent.py"
    if not skill_path.exists():
        return {
            "chapter": chapter_id,
            "title": chapter_def["title"],
            "skill": chapter_def["skill"],
            "status": "SKIPPED",
            "severity": "INFO",
            "controls_checked": 0,
            "controls_failed": 0,
            "failing_controls": [],
            "error": f"agent.py not found: {skill_path}",
        }

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_file = tmp.name

    args = chapter_def["args_fn"](target_url, token, out_file)
    cmd = [sys.executable, str(skill_path)] + args
    start = datetime.now(timezone.utc)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=str(ROOT)
        )
        duration = (datetime.now(timezone.utc) - start).total_seconds()
        exit_code = result.returncode

        raw_findings = []
        overall = "UNKNOWN"
        try:
            with open(out_file) as f:
                data = json.load(f)
            raw_findings = data.get("findings", [])
            overall = data.get("overall_risk", "UNKNOWN")
        except Exception:
            pass

        severity = overall if overall in SEVERITY_WEIGHTS else ("HIGH" if exit_code == 1 else "PASS")
        cmap = chapter_def.get("control_map", {})

        failing = []
        for fi in raw_findings:
            fi_sev = fi.get("severity", "INFO")
            if fi_sev in ("INFO", None):
                continue
            test_name = fi.get("test", fi.get("check", ""))
            control_id = next(
                (v for k, v in cmap.items() if k in test_name.lower()),
                f"{chapter_id}.?.?"
            )
            failing.append({
                "control_id": control_id,
                "description": fi.get("detail", fi.get("description", test_name)),
                "severity": fi_sev,
            })

        return {
            "chapter": chapter_id,
            "title": chapter_def["title"],
            "skill": chapter_def["skill"],
            "status": "FINDING" if exit_code == 1 else "PASS",
            "severity": severity,
            "duration_seconds": round(duration, 1),
            "controls_checked": max(len(cmap), len(raw_findings)),
            "controls_failed": len(failing),
            "failing_controls": failing,
        }

    except subprocess.TimeoutExpired:
        return {
            "chapter": chapter_id,
            "title": chapter_def["title"],
            "skill": chapter_def["skill"],
            "status": "TIMEOUT",
            "severity": "MEDIUM",
            "controls_checked": 0,
            "controls_failed": 0,
            "failing_controls": [],
            "error": f"Timed out after {timeout}s",
        }
    except Exception as e:
        return {
            "chapter": chapter_id,
            "title": chapter_def["title"],
            "skill": chapter_def["skill"],
            "status": "ERROR",
            "severity": "INFO",
            "controls_checked": 0,
            "controls_failed": 0,
            "failing_controls": [],
            "error": str(e),
        }
    finally:
        try:
            os.unlink(out_file)
        except Exception:
            pass


def http_get(url, token=None, timeout=10):
    headers = {"User-Agent": "SecurityAssessment/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        ctx = None
        if not VERIFY_TLS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, dict(resp.headers), resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), ""
    except Exception:
        return 0, {}, ""


def http_post(url, data, token=None, timeout=10):
    headers = {"Content-Type": "application/json", "User-Agent": "SecurityAssessment/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        ctx = None
        if not VERIFY_TLS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, dict(resp.headers), resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), ""
    except Exception:
        return 0, {}, ""


# ── Inline probes ──────────────────────────────────────────────────────────────

def probe_v3_session(base_url, token):
    """V3: Session Management"""
    failing = []
    _, headers, _ = http_get(base_url, token=token)

    set_cookie = headers.get("Set-Cookie", "")
    if set_cookie:
        if "HttpOnly" not in set_cookie:
            failing.append({"control_id": "V3.4.1", "description": "Session cookie missing HttpOnly flag", "severity": "HIGH"})
        if "Secure" not in set_cookie:
            failing.append({"control_id": "V3.4.2", "description": "Session cookie missing Secure flag", "severity": "HIGH"})
        if "SameSite" not in set_cookie:
            failing.append({"control_id": "V3.4.3", "description": "Session cookie missing SameSite attribute", "severity": "MEDIUM"})

    status, _, _ = http_get(base_url.rstrip("/") + "/logout", token=token)
    if status not in (200, 302, 204, 404, 405):
        failing.append({"control_id": "V3.3.1", "description": f"Logout endpoint returned unexpected {status}", "severity": "LOW"})

    return _chapter_result("V3", "Session Management", failing, controls_checked=5)


def probe_v6_crypto(base_url, token):
    """V6: Stored Cryptography — infer from response patterns"""
    failing = []
    _, _, body = http_get(base_url, token=token)

    plaintext_patterns = ["password=", "passwd=", "secret=", "api_key=", "apikey="]
    for p in plaintext_patterns:
        if p in body.lower():
            failing.append({"control_id": "V6.2.1", "description": f"Potential plaintext credential pattern '{p}' in response", "severity": "CRITICAL"})
            break

    return _chapter_result("V6", "Stored Cryptography", failing, controls_checked=4)


def probe_v7_error(base_url, token):
    """V7: Error Handling and Logging"""
    failing = []

    paths = ["/nonexistent-path-xyzzy", "/api/v999/notreal", "/%00", "/api/error-test"]
    for path in paths:
        _, _, body = http_get(base_url.rstrip("/") + path, token=token)
        lower = body.lower()
        if any(kw in lower for kw in ["traceback", "stack trace", "exception", "at line", "sqlstate", "mysql_error", "ora-"]):
            failing.append({"control_id": "V7.4.1", "description": f"Stack trace or DB error exposed on {path}", "severity": "MEDIUM"})
            break
        if any(kw in lower for kw in ["/home/", "/usr/", "c:\\", "/var/www", "/app/"]):
            failing.append({"control_id": "V7.4.1", "description": f"Internal path disclosed on {path}", "severity": "MEDIUM"})
            break

    return _chapter_result("V7", "Error Handling and Logging", failing, controls_checked=3)


def probe_v8_data(base_url, token):
    """V8: Data Protection"""
    failing = []

    sensitive_patterns = [
        ("ssn", "V8.2.1"), ("social security", "V8.2.1"),
        ("credit_card", "V8.3.1"), ("card_number", "V8.3.1"),
        ("cvv", "V8.3.2"), ("date_of_birth", "V8.3.3"),
        ("private_key", "V8.2.2"), ("-----BEGIN", "V8.2.2"),
    ]
    _, _, body = http_get(base_url, token=token)
    lower = body.lower()
    for pattern, control_id in sensitive_patterns:
        if pattern.lower() in lower:
            failing.append({
                "control_id": control_id,
                "description": f"Sensitive data pattern '{pattern}' detected in response",
                "severity": "HIGH",
            })

    return _chapter_result("V8", "Data Protection", failing, controls_checked=6)


def probe_v9_tls(base_url, token):
    """V9: Communications Security"""
    failing = []

    if base_url.startswith("http://"):
        failing.append({"control_id": "V9.1.1", "description": "Application served over HTTP (no TLS)", "severity": "CRITICAL"})

    _, headers, _ = http_get(base_url, token=token)

    hsts = headers.get("Strict-Transport-Security", "")
    if not hsts:
        failing.append({"control_id": "V9.1.2", "description": "Missing Strict-Transport-Security header", "severity": "MEDIUM"})
    elif "max-age" in hsts:
        try:
            age = int(hsts.split("max-age=")[1].split(";")[0].strip())
            if age < 31536000:
                failing.append({"control_id": "V9.1.3", "description": f"HSTS max-age {age}s is below recommended 1 year", "severity": "LOW"})
        except Exception:
            pass

    return _chapter_result("V9", "Communications Security", failing, controls_checked=4)


def probe_v10_malicious(base_url, token):
    """V10: Malicious Code — behavioural signals only (no static analysis possible remotely)"""
    failing = []

    suspicious_headers = ["x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version"]
    _, headers, _ = http_get(base_url, token=token)
    exposed = [h for h in suspicious_headers if h in {k.lower() for k in headers}]
    if exposed:
        failing.append({"control_id": "V10.3.2", "description": f"Technology disclosure headers present: {exposed}", "severity": "LOW"})

    return _chapter_result("V10", "Malicious Code", failing, controls_checked=2)


def probe_v11_logic(base_url, token):
    """V11: Business Logic"""
    failing = []
    import time

    endpoints = ["/checkout", "/purchase", "/register", "/vote", "/promo/redeem"]
    for ep in endpoints:
        url = base_url.rstrip("/") + ep
        statuses = []
        for _ in range(10):
            s, _, _ = http_post(url, {"test": True}, token=token)
            statuses.append(s)
            time.sleep(0.05)
        success_count = sum(1 for s in statuses if s in (200, 201, 202))
        got_429 = 429 in statuses
        if success_count >= 9 and not got_429:
            failing.append({
                "control_id": "V11.1.6",
                "description": f"No rate limiting on {ep} — {success_count}/10 requests succeeded",
                "severity": "HIGH",
            })
            break

    return _chapter_result("V11", "Business Logic", failing, controls_checked=4)


def probe_v12_files(base_url, token):
    """V12: Files and Resources"""
    failing = []

    traversal_paths = [
        "/download?file=../../etc/passwd",
        "/static/../../../etc/passwd",
        "/api/file?path=../../../etc/shadow",
    ]
    for path in traversal_paths:
        _, _, body = http_get(base_url.rstrip("/") + path, token=token)
        if "root:" in body or "daemon:" in body:
            failing.append({
                "control_id": "V12.3.1",
                "description": f"Path traversal possible via {path}",
                "severity": "CRITICAL",
            })
            break

    _, headers, _ = http_get(base_url, token=token)
    csp = headers.get("Content-Security-Policy", "")
    if not csp:
        failing.append({"control_id": "V12.1.1", "description": "Missing Content-Security-Policy header", "severity": "MEDIUM"})

    return _chapter_result("V12", "Files and Resources", failing, controls_checked=4)


def probe_v14_config(base_url, token):
    """V14: Configuration"""
    failing = []
    _, headers, _ = http_get(base_url, token=token)

    security_headers = {
        "X-Content-Type-Options": ("V14.4.1", "MEDIUM"),
        "X-Frame-Options": ("V14.4.2", "MEDIUM"),
        "Content-Security-Policy": ("V14.4.3", "MEDIUM"),
        "Referrer-Policy": ("V14.4.6", "LOW"),
        "Permissions-Policy": ("V14.4.7", "LOW"),
    }
    existing = {k.lower() for k in headers}
    for hdr, (control_id, sev) in security_headers.items():
        if hdr.lower() not in existing:
            failing.append({"control_id": control_id, "description": f"Missing security header: {hdr}", "severity": sev})

    cors_origin = headers.get("Access-Control-Allow-Origin", "")
    if cors_origin == "*":
        failing.append({"control_id": "V14.5.3", "description": "CORS allows all origins (*)", "severity": "HIGH"})

    cors_creds = headers.get("Access-Control-Allow-Credentials", "")
    if cors_origin == "*" and cors_creds.lower() == "true":
        failing.append({"control_id": "V14.5.3", "description": "CORS wildcard with credentials=true — browser blocks but misconfigured", "severity": "HIGH"})

    return _chapter_result("V14", "Configuration", failing, controls_checked=7)


def _chapter_result(chapter_id, title, failing, controls_checked):
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    if failing:
        severity = next((s for s in sev_order if any(f["severity"] == s for f in failing)), "LOW")
    else:
        severity = "PASS"
    return {
        "chapter": chapter_id,
        "title": title,
        "skill": None,
        "status": "FINDING" if failing else "PASS",
        "severity": severity,
        "controls_checked": controls_checked,
        "controls_failed": len(failing),
        "failing_controls": failing,
    }


INLINE_PROBES = {
    "V3": probe_v3_session,
    "V6": probe_v6_crypto,
    "V7": probe_v7_error,
    "V8": probe_v8_data,
    "V9": probe_v9_tls,
    "V10": probe_v10_malicious,
    "V11": probe_v11_logic,
    "V12": probe_v12_files,
    "V14": probe_v14_config,
}

ALL_CHAPTERS = ["V2", "V3", "V4", "V5", "V6", "V7", "V8", "V9", "V10", "V11", "V12", "V13", "V14"]


def print_summary(chapter_results, target_url, level):
    print(f"\nOWASP ASVS v4.0.3 Active Verification — {target_url} (Level {level})")
    print("═" * 72)
    for r in chapter_results:
        icon = "✗" if r["status"] == "FINDING" else ("?" if r["status"] in ("TIMEOUT", "ERROR", "SKIPPED") else "✓")
        n = r["controls_failed"]
        label = f"{n} failing control{'s' if n != 1 else ''}" if n else "0 failing controls"
        print(f" {r['chapter']:<5} {r['title']:<35} {icon} {r['severity']:<10} {label}")
    print("═" * 72)


def main():
    parser = argparse.ArgumentParser(
        description="OWASP ASVS v4.0.3 — Active verification orchestrator"
    )
    parser.add_argument("--target-url", required=True, help="Base URL of the target application")
    parser.add_argument("--token", default=None, help="Bearer token for authenticated probes")
    parser.add_argument("--level", type=int, choices=[1, 2, 3], default=2,
                        help="ASVS verification level to assess against (default: 2)")
    parser.add_argument("--chapters", default=None,
                        help="Comma-separated subset: V2,V3,...V14 (default: all)")
    parser.add_argument("--output", default="asvs_report.json", help="Output JSON report file")
    parser.add_argument("--timeout", type=int, default=55,
                        help="Per-skill-agent timeout in seconds (default: 55)")
    args = parser.parse_args()

    selected = None
    if args.chapters:
        selected = {c.strip().upper() for c in args.chapters.split(",")}

    chapters_to_run = [c for c in ALL_CHAPTERS if selected is None or c in selected]
    chapter_results = []
    start_time = datetime.now(timezone.utc)

    for ch in chapters_to_run:
        if ch in SKILL_CHAPTERS:
            print(f"  Running {ch} — {SKILL_CHAPTERS[ch]['title']} (skill agent) ...", flush=True)
            result = run_skill(ch, SKILL_CHAPTERS[ch], args.target_url, args.token, args.timeout)
        elif ch in INLINE_PROBES:
            chapter_titles = {
                "V3": "Session Management", "V6": "Stored Cryptography",
                "V7": "Error Handling and Logging", "V8": "Data Protection",
                "V9": "Communications Security", "V10": "Malicious Code",
                "V11": "Business Logic", "V12": "Files and Resources",
                "V14": "Configuration",
            }
            print(f"  Running {ch} — {chapter_titles.get(ch, ch)} (inline probes) ...", flush=True)
            result = INLINE_PROBES[ch](args.target_url, args.token)
        else:
            continue
        chapter_results.append(result)

    total_checked = sum(r["controls_checked"] for r in chapter_results)
    total_failed = sum(r["controls_failed"] for r in chapter_results)
    total_passed = total_checked - total_failed

    all_failing = [f for r in chapter_results for f in r.get("failing_controls", [])]
    counts = {s: sum(1 for f in all_failing if f["severity"] == s) for s in SEVERITY_WEIGHTS}

    max_sev = max((SEVERITY_WEIGHTS.get(r["severity"], 0) for r in chapter_results), default=0)
    sev_names = {v: k for k, v in SEVERITY_WEIGHTS.items()}
    overall_sev = sev_names.get(max_sev, "PASS")
    conformance = "PASS" if total_failed == 0 else "FAIL"

    summary = {
        "total_controls_checked": total_checked,
        "controls_passed": total_passed,
        "controls_failed": total_failed,
        "critical": counts.get("CRITICAL", 0),
        "high": counts.get("HIGH", 0),
        "medium": counts.get("MEDIUM", 0),
        "low": counts.get("LOW", 0),
        "asvs_conformance": conformance,
        "overall_severity": overall_sev,
    }

    report = {
        "methodology": "OWASP ASVS v4.0.3 Active Verification — performing-asvs-active-verification v1.0",
        "assessment_timestamp": start_time.isoformat(),
        "target_url": args.target_url,
        "asvs_level": args.level,
        "chapters_tested": [r["chapter"] for r in chapter_results],
        "summary": summary,
        "chapters": chapter_results,
    }

    print_summary(chapter_results, args.target_url, args.level)
    print(f"\nASVS Conformance: {conformance}  |  {total_failed} failing controls  |  Report: {args.output}\n")
    print(json.dumps(report, indent=2))

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    if overall_sev in ("CRITICAL", "HIGH"):
        sys.exit(1)


if __name__ == "__main__":
    main()
