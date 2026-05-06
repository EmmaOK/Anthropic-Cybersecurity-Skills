#!/usr/bin/env python3
"""OWASP API6:2023 — Unrestricted Access to Sensitive Business Flows tester."""
import argparse
import json
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone

VERIFY_TLS = __import__('os').environ.get("SKIP_TLS_VERIFY", "").lower() not in ("1", "true", "yes")

DEFAULT_ENDPOINTS = [
    "/register", "/signup", "/checkout", "/order", "/purchase",
    "/promo/redeem", "/coupon/apply", "/referral/invite",
    "/vote", "/rate", "/review", "/reset-password", "/otp/send",
]

WORKFLOW_SEQUENCES = [
    {"name": "checkout_flow", "steps": ["/cart", "/checkout", "/payment", "/confirm"]},
    {"name": "registration_flow", "steps": ["/register/init", "/register/verify", "/register/complete"]},
    {"name": "password_reset_flow", "steps": ["/reset-password/request", "/reset-password/verify", "/reset-password/set"]},
]

SEVERITY_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def make_request(url, token=None, method="GET", data=None):
    headers = {"Content-Type": "application/json", "User-Agent": "SecurityAssessment/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        ctx = None
        if not VERIFY_TLS:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return resp.status, dict(resp.headers), resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), ""
    except Exception:
        return 0, {}, ""


def rate_limit_probe(base_url, endpoint, token, count=50):
    url = base_url.rstrip("/") + endpoint
    statuses = []
    rate_limit_headers = []
    got_429 = False

    for _ in range(count):
        status, headers, _ = make_request(url, token=token, method="POST", data={"test": True})
        statuses.append(status)
        rl_headers = [k for k in headers if "ratelimit" in k.lower() or "retry-after" in k.lower()]
        rate_limit_headers.extend(rl_headers)
        if status == 429:
            got_429 = True
            break
        time.sleep(0.05)

    succeeded = sum(1 for s in statuses if s in (200, 201, 202, 204))
    has_rl_headers = len(set(rate_limit_headers)) > 0

    if not got_429 and succeeded >= count * 0.9 and not has_rl_headers:
        severity = "CRITICAL"
        detail = f"No rate limiting — {succeeded}/{count} requests succeeded with no throttling"
    elif not got_429 and succeeded >= count * 0.5:
        severity = "HIGH"
        detail = f"Weak rate limiting — {succeeded}/{count} requests succeeded before throttling"
    elif has_rl_headers and got_429:
        severity = "INFO"
        detail = "Rate limiting enforced — 429 received with rate limit headers"
    else:
        severity = "LOW"
        detail = f"Partial rate limiting — {succeeded}/{count} requests succeeded"

    return {
        "endpoint": endpoint,
        "test": "rate_limit_probe",
        "requests_sent": len(statuses),
        "requests_succeeded": succeeded,
        "http_429_triggered": got_429,
        "rate_limit_header_present": has_rl_headers,
        "severity": severity,
        "detail": detail,
    }


def quota_probe(base_url, endpoint, token, repetitions=10):
    url = base_url.rstrip("/") + endpoint
    succeeded = 0
    for _ in range(repetitions):
        status, _, _ = make_request(url, token=token, method="POST", data={"action": "repeat_test"})
        if status in (200, 201, 202):
            succeeded += 1
        time.sleep(0.1)

    if succeeded >= repetitions:
        severity = "CRITICAL"
        detail = f"No per-user quota — same action repeated {repetitions} times successfully"
    elif succeeded > repetitions // 2:
        severity = "HIGH"
        detail = f"Weak per-user quota — {succeeded}/{repetitions} repetitions allowed"
    else:
        severity = "INFO"
        detail = f"Per-user quota enforced — only {succeeded}/{repetitions} repetitions allowed"

    return {
        "endpoint": endpoint,
        "test": "per_user_quota",
        "repetitions_attempted": repetitions,
        "repetitions_succeeded": succeeded,
        "severity": severity,
        "detail": detail,
    }


def workflow_bypass_probe(base_url, token, sequence):
    results = []
    last_step = sequence["steps"][-1]
    url = base_url.rstrip("/") + last_step
    status, _, _ = make_request(url, token=token, method="POST", data={"bypass_test": True})

    if status in (200, 201, 202):
        severity = "CRITICAL"
        detail = f"Workflow step bypass — called {last_step} without completing prior steps, got {status}"
    elif status in (400, 422):
        severity = "INFO"
        detail = f"Workflow enforced — {last_step} rejected bypass attempt with {status}"
    else:
        severity = "LOW"
        detail = f"Ambiguous response {status} to workflow bypass on {last_step}"

    results.append({
        "workflow": sequence["name"],
        "bypass_endpoint": last_step,
        "test": "workflow_step_bypass",
        "http_status": status,
        "severity": severity,
        "detail": detail,
    })
    return results


def bot_detection_probe(base_url, endpoint, token):
    url = base_url.rstrip("/") + endpoint
    status, headers, _ = make_request(url, token=token, method="POST", data={})

    captcha_signals = any(
        k.lower() in ("x-captcha", "x-recaptcha", "cf-challenge") or
        "captcha" in headers.get(k, "").lower()
        for k in headers
    )
    bot_headers = any(
        "fingerprint" in k.lower() or "challenge" in k.lower() or "bot" in k.lower()
        for k in headers
    )

    if not captcha_signals and not bot_headers:
        severity = "MEDIUM"
        detail = "No bot detection signals detected on endpoint"
    else:
        severity = "INFO"
        detail = "Bot detection signals present"

    return {
        "endpoint": endpoint,
        "test": "bot_detection",
        "captcha_signal_present": captcha_signals,
        "bot_challenge_header": bot_headers,
        "severity": severity,
        "detail": detail,
    }


def main():
    parser = argparse.ArgumentParser(description="OWASP API6:2023 — Unrestricted Business Flow tester")
    parser.add_argument("--target-url", required=True, help="Base URL of the target API")
    parser.add_argument("--token", default=None, help="Bearer token for authentication")
    parser.add_argument("--endpoints", default=None,
                        help="Comma-separated list of business endpoints to test")
    parser.add_argument("--output", default="api6_report.json", help="Output JSON report file")
    args = parser.parse_args()

    endpoints = [e.strip() for e in args.endpoints.split(",")] if args.endpoints else DEFAULT_ENDPOINTS
    findings = []
    start = datetime.now(timezone.utc)

    for ep in endpoints:
        findings.append(rate_limit_probe(args.target_url, ep, args.token))
        findings.append(quota_probe(args.target_url, ep, args.token))
        findings.append(bot_detection_probe(args.target_url, ep, args.token))

    for seq in WORKFLOW_SEQUENCES:
        findings.extend(workflow_bypass_probe(args.target_url, args.token, seq))

    reportable = [f for f in findings if f["severity"] not in ("INFO",)]
    max_sev = max((SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings), default=0)
    sev_names = {v: k for k, v in SEVERITY_WEIGHTS.items()}
    overall_risk = sev_names.get(max_sev, "PASS")

    report = {
        "methodology": "OWASP API6:2023 — Unrestricted Access to Sensitive Business Flows — testing-api-for-unrestricted-business-flows v1.0",
        "assessment_timestamp": start.isoformat(),
        "target_url": args.target_url,
        "endpoints_tested": len(endpoints),
        "total_findings": len(reportable),
        "findings": findings,
        "overall_risk": overall_risk,
        "recommendation": (
            "Implement per-user rate limiting and per-IP quotas on all sensitive business endpoints. "
            "Enforce workflow step sequencing via server-side session state. "
            "Add CAPTCHA or behavioural bot detection on registration, login, and high-value actions."
        ),
    }

    print(json.dumps(report, indent=2))
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)


if __name__ == "__main__":
    main()
