#!/usr/bin/env python3
"""OWASP ZAP DAST — Phantom skill agent.

Auto-detects ZAP daemon (REST API) or falls back to Docker.
Scan types: baseline (passive), full (spider + active), api (OpenAPI-driven).
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# ZAP risk code → internal severity
ZAP_RISK_MAP = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}

# ZAP confidence code → label
ZAP_CONF_MAP = {"4": "CONFIRMED", "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "FALSE_POSITIVE"}

# CWE ID → (OWASP Top 10 2021, ASVS chapter)
CWE_MAP = {
    "89":   ("A03:2021 — Injection",                       "V5"),
    "79":   ("A03:2021 — Injection",                       "V5"),
    "78":   ("A03:2021 — Injection",                       "V5"),
    "94":   ("A03:2021 — Injection",                       "V5"),
    "918":  ("A10:2021 — SSRF",                            "V5"),
    "22":   ("A01:2021 — Broken Access Control",           "V12"),
    "611":  ("A03:2021 — Injection",                       "V5"),
    "352":  ("A01:2021 — Broken Access Control",           "V4"),
    "287":  ("A07:2021 — Identification and Authentication Failures", "V2"),
    "306":  ("A07:2021 — Identification and Authentication Failures", "V2"),
    "798":  ("A07:2021 — Identification and Authentication Failures", "V2"),
    "384":  ("A07:2021 — Identification and Authentication Failures", "V3"),
    "614":  ("A02:2021 — Cryptographic Failures",          "V3"),
    "319":  ("A02:2021 — Cryptographic Failures",          "V9"),
    "311":  ("A02:2021 — Cryptographic Failures",          "V6"),
    "326":  ("A02:2021 — Cryptographic Failures",          "V6"),
    "327":  ("A02:2021 — Cryptographic Failures",          "V6"),
    "200":  ("A05:2021 — Security Misconfiguration",       "V7"),
    "209":  ("A05:2021 — Security Misconfiguration",       "V7"),
    "16":   ("A05:2021 — Security Misconfiguration",       "V14"),
    "1021": ("A05:2021 — Security Misconfiguration",       "V14"),
    "693":  ("A05:2021 — Security Misconfiguration",       "V14"),
    "829":  ("A06:2021 — Vulnerable and Outdated Components", "V14"),
    "116":  ("A03:2021 — Injection",                       "V5"),
    "601":  ("A01:2021 — Broken Access Control",           "V14"),
    "285":  ("A01:2021 — Broken Access Control",           "V4"),
    "918":  ("A10:2021 — SSRF",                            "V5"),
}

DEFAULT_OWASP = "A05:2021 — Security Misconfiguration"
DEFAULT_ASVS  = "V14"

DOCKER_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
DOCKER_IMAGE_ALT = "owasp/zap2docker-stable"


# ── ZAP daemon helpers ─────────────────────────────────────────────────────────

def zap_get(zap_url, path, api_key=None, params=None):
    qs = {}
    if api_key:
        qs["apikey"] = api_key
    if params:
        qs.update(params)
    url = zap_url.rstrip("/") + path
    if qs:
        url += "?" + urllib.parse.urlencode(qs)
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception:
        return 0, {}


def detect_daemon(zap_url, api_key):
    status, body = zap_get(zap_url, "/JSON/core/view/version/", api_key=api_key)
    if status == 200 and "version" in body:
        return body["version"]
    return None


def daemon_scan(target_url, zap_url, api_key, scan_type, token, openapi_file, timeout_mins):
    print(f"  ZAP daemon detected at {zap_url}", flush=True)

    # New session
    zap_get(zap_url, "/JSON/core/action/newSession/", api_key=api_key,
            params={"name": "phantom_scan", "overwrite": "true"})

    if token:
        zap_get(zap_url, "/JSON/replacer/action/addRule/", api_key=api_key, params={
            "description": "bearer_token",
            "enabled": "true",
            "matchType": "REQ_HEADER",
            "matchString": "Authorization",
            "replacement": f"Bearer {token}",
            "initiators": "",
        })

    if scan_type == "api" and openapi_file:
        zap_get(zap_url, "/JSON/openapi/action/importFile/", api_key=api_key,
                params={"file": str(Path(openapi_file).resolve()), "target": target_url})

    # Spider
    print("  Spidering target ...", flush=True)
    _, spider_resp = zap_get(zap_url, "/JSON/spider/action/scan/", api_key=api_key,
                             params={"url": target_url, "maxChildren": "10", "recurse": "true"})
    spider_id = spider_resp.get("scan", "0")
    deadline = time.time() + timeout_mins * 60
    while time.time() < deadline:
        _, st = zap_get(zap_url, "/JSON/spider/view/status/", api_key=api_key,
                        params={"scanId": spider_id})
        progress = int(st.get("status", 0))
        if progress >= 100:
            break
        time.sleep(5)

    if scan_type in ("full", "api"):
        print("  Active scanning target ...", flush=True)
        _, ascan_resp = zap_get(zap_url, "/JSON/ascan/action/scan/", api_key=api_key,
                                params={"url": target_url, "recurse": "true", "inScopeOnly": "false"})
        ascan_id = ascan_resp.get("scan", "0")
        while time.time() < deadline:
            _, st = zap_get(zap_url, "/JSON/ascan/view/status/", api_key=api_key,
                            params={"scanId": ascan_id})
            progress = int(st.get("status", 0))
            if progress >= 100:
                break
            time.sleep(10)

    _, alerts_resp = zap_get(zap_url, "/JSON/core/view/alerts/", api_key=api_key,
                             params={"baseurl": target_url, "start": "0", "count": "5000"})
    raw_alerts = alerts_resp.get("alerts", [])

    _, ver = zap_get(zap_url, "/JSON/core/view/version/", api_key=api_key)
    return ver.get("version", "unknown"), raw_alerts


# ── Docker helpers ─────────────────────────────────────────────────────────────

def docker_available():
    return shutil.which("docker") is not None


def docker_scan(target_url, scan_type, token, openapi_file, timeout_mins, work_dir):
    report_path = Path(work_dir) / "zap_report.json"

    image = DOCKER_IMAGE
    scan_script = {
        "baseline": "zap-baseline.py",
        "full":     "zap-full-scan.py",
        "api":      "zap-api-scan.py",
    }[scan_type]

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{work_dir}:/zap/wrk:rw",
        image,
        scan_script,
        "-t", target_url,
        "-J", "/zap/wrk/zap_report.json",
        "-T", str(timeout_mins),
        "-I",  # don't fail on warnings
    ]

    if scan_type == "api" and openapi_file:
        host_of = Path(openapi_file).resolve()
        cmd.extend(["-f", "openapi", "-d"])
        # Mount spec file too
        cmd = (
            cmd[:4]
            + ["-v", f"{host_of}:/zap/wrk/openapi_spec.yaml:ro"]
            + cmd[4:]
        )

    if token:
        cmd.extend(["-z", f"replacer.full_list(0).description=bearer&"
                          f"replacer.full_list(0).enabled=true&"
                          f"replacer.full_list(0).matchtype=REQ_HEADER&"
                          f"replacer.full_list(0).matchstring=Authorization&"
                          f"replacer.full_list(0).replacement=Bearer {token}"])

    print(f"  Running: {' '.join(cmd[:6])} ...", flush=True)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_mins * 60 + 120,
        )
        print(f"  Docker exit code: {result.returncode}", flush=True)
    except subprocess.TimeoutExpired:
        print("  Docker scan timed out — reading partial report if available", flush=True)
    except FileNotFoundError:
        return None, None, "Docker not found — install Docker or start ZAP daemon"

    if not report_path.exists():
        # Try alt image if main image failed
        cmd[cmd.index(image)] = DOCKER_IMAGE_ALT
        print(f"  Retrying with {DOCKER_IMAGE_ALT} ...", flush=True)
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_mins * 60 + 120)
        except Exception:
            pass

    if not report_path.exists():
        return None, None, "ZAP Docker report not found — check Docker image and target reachability"

    try:
        with open(report_path) as f:
            data = json.load(f)
    except Exception as e:
        return None, None, f"Failed to parse ZAP JSON report: {e}"

    zap_version = data.get("@version", "unknown")
    raw_alerts = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            instances = alert.get("instances", [{"uri": target_url, "method": "GET", "evidence": ""}])
            for inst in instances:
                raw_alerts.append({**alert, **inst})

    return zap_version, raw_alerts, None


# ── Alert normalisation ────────────────────────────────────────────────────────

def normalise_alerts(raw_alerts):
    findings = []
    seen = {}
    for a in raw_alerts:
        conf_code = str(a.get("confidence", a.get("@confidence", "2")))
        if conf_code == "0":
            continue  # skip confirmed false positives

        risk_code = str(a.get("riskcode", a.get("@riskcode", "0")))
        severity = ZAP_RISK_MAP.get(risk_code, "INFO")
        cwe = str(a.get("cweid", a.get("@cweid", "")))
        owasp, asvs = CWE_MAP.get(cwe, (DEFAULT_OWASP, DEFAULT_ASVS))

        alert_name = a.get("alert", a.get("name", "Unknown"))
        url = a.get("uri", a.get("url", ""))
        method = a.get("method", "GET")
        param = a.get("param", "")

        dedup_key = f"{alert_name}:{url}:{param}"
        if dedup_key in seen:
            seen[dedup_key]["count"] += 1
            continue

        finding = {
            "alert": alert_name,
            "severity": severity,
            "confidence": ZAP_CONF_MAP.get(conf_code, "MEDIUM"),
            "owasp_top10": owasp,
            "asvs_chapter": asvs,
            "cwe_id": cwe or "N/A",
            "url": url,
            "method": method,
            "param": param,
            "evidence": a.get("evidence", "")[:200],
            "description": a.get("desc", a.get("description", ""))[:500],
            "solution": a.get("solution", "")[:300],
            "count": 1,
        }
        seen[dedup_key] = finding
        findings.append(finding)

    findings.sort(key=lambda f: SEVERITY_WEIGHTS.get(f["severity"], 0), reverse=True)
    return findings


def print_summary(findings, target_url, scan_type, zap_mode):
    counts = {s: 0 for s in SEVERITY_WEIGHTS}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"\nOWASP ZAP {scan_type.title()} Scan — {target_url} [{zap_mode}]")
    print("═" * 60)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts[sev]:
            print(f"  {sev:<12} {counts[sev]} alert{'s' if counts[sev] != 1 else ''}")
    print("═" * 60)

    for f in findings[:20]:
        print(f"  [{f['severity']:<8}] {f['alert'][:40]:<42} {f['url'][:40]}")
    if len(findings) > 20:
        print(f"  ... and {len(findings) - 20} more (see report file)")
    print()


def main():
    parser = argparse.ArgumentParser(description="OWASP ZAP DAST — Phantom skill agent")
    parser.add_argument("--target-url", required=True, help="Base URL of the target application")
    parser.add_argument("--scan-type", choices=["baseline", "full", "api"], default="baseline",
                        help="Scan type: baseline (passive), full (spider+active), api (OpenAPI-driven)")
    parser.add_argument("--zap-url", default="http://localhost:8080",
                        help="ZAP daemon URL (default: http://localhost:8080)")
    parser.add_argument("--zap-api-key", default="", help="ZAP API key (if daemon requires one)")
    parser.add_argument("--token", default=None, help="Bearer token for authenticated scanning")
    parser.add_argument("--openapi-file", default=None, help="OpenAPI/Swagger spec for api scan type")
    parser.add_argument("--timeout", type=int, default=20,
                        help="Scan timeout in minutes (default: 20; baseline needs ~5, full needs ~30+)")
    parser.add_argument("--output", default="zap_report.json", help="Output JSON report file")
    args = parser.parse_args()

    start_time = datetime.now(timezone.utc)
    zap_mode = "unknown"
    error_msg = None

    print(f"  Detecting ZAP at {args.zap_url} ...", flush=True)
    version = detect_daemon(args.zap_url, args.zap_api_key)

    if version:
        zap_mode = "daemon"
        print(f"  ZAP daemon v{version} detected", flush=True)
        zap_version, raw_alerts = daemon_scan(
            args.target_url, args.zap_url, args.zap_api_key,
            args.scan_type, args.token, args.openapi_file, args.timeout
        )
    elif docker_available():
        zap_mode = "docker"
        print("  No ZAP daemon — using Docker", flush=True)
        work_dir = tempfile.mkdtemp(prefix="zap_work_")
        try:
            zap_version, raw_alerts, error_msg = docker_scan(
                args.target_url, args.scan_type, args.token,
                args.openapi_file, args.timeout, work_dir
            )
        finally:
            import shutil as _sh
            _sh.rmtree(work_dir, ignore_errors=True)
    else:
        print("ERROR: ZAP daemon not reachable and Docker not available.", file=sys.stderr)
        print("  Start ZAP daemon: zap.sh -daemon -port 8080", file=sys.stderr)
        print("  Or install Docker and pull: docker pull ghcr.io/zaproxy/zaproxy:stable", file=sys.stderr)
        sys.exit(2)

    if error_msg or raw_alerts is None:
        print(f"ERROR: {error_msg or 'Scan failed'}", file=sys.stderr)
        sys.exit(2)

    findings = normalise_alerts(raw_alerts)

    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_WEIGHTS}
    max_sev = max((SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings), default=0)
    sev_names = {v: k for k, v in SEVERITY_WEIGHTS.items()}
    overall_risk = sev_names.get(max_sev, "PASS") if findings else "PASS"

    summary = {
        "total_alerts": len(findings),
        "critical": counts.get("CRITICAL", 0),
        "high": counts.get("HIGH", 0),
        "medium": counts.get("MEDIUM", 0),
        "low": counts.get("LOW", 0),
        "info": counts.get("INFO", 0),
        "overall_risk": overall_risk,
    }

    report = {
        "methodology": "OWASP ZAP DAST — conducting-zap-security-scan v1.0",
        "assessment_timestamp": start_time.isoformat(),
        "target_url": args.target_url,
        "scan_type": args.scan_type,
        "zap_mode": zap_mode,
        "zap_version": zap_version or "unknown",
        "summary": summary,
        "findings": findings,
        "recommendation": (
            "Remediate HIGH/CRITICAL findings immediately. "
            "Review all injection findings (V5/A03) and access control issues (V4/A01). "
            "Run performing-asvs-active-verification alongside this report for full ASVS control mapping."
        ),
    }

    print_summary(findings, args.target_url, args.scan_type, zap_mode)
    print(json.dumps(report, indent=2))

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)


if __name__ == "__main__":
    main()
