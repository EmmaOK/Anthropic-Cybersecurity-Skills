#!/usr/bin/env python3
"""ASI07 - Securing Inter-Agent Communication: Audit agent-to-agent channels for spoofing and replay risks."""
import argparse
import hashlib
import hmac
import json
import re
import sys
import time
import uuid

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_HTTPX = False

OWASP_ID = "ASI07"
TOOL_NAME = "phantom-inter-agent-comms"

# Security controls to check for in inter-agent API responses
SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS not set — protocol downgrade attack possible", "HIGH"),
    ("X-Content-Type-Options", "Content-Type sniffing protection missing", "LOW"),
    ("Content-Security-Policy", "CSP not set", "LOW"),
]

# Message fields required for authenticated inter-agent messages
REQUIRED_MESSAGE_FIELDS = [
    "sender_id", "recipient_id", "message_id", "timestamp",
    "signature", "nonce",
]

# JWT structure check
JWT_PATTERN = re.compile(r'^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$')


def http_get(url, headers=None, timeout=10):
    h = headers or {}
    try:
        if HAS_HTTPX:
            r = httpx.get(url, headers=h, timeout=timeout, follow_redirects=False)
            return r.status_code, dict(r.headers), r.text
        else:
            req = urllib.request.Request(url, headers=h)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.status, dict(resp.headers), resp.read().decode()
            except urllib.error.HTTPError as e:
                return e.code, dict(e.headers), e.read().decode()
    except Exception as e:
        return 0, {}, str(e)


def http_post(url, payload, headers=None, timeout=10):
    data = json.dumps(payload).encode()
    h = {"Content-Type": "application/json", **(headers or {})}
    try:
        if HAS_HTTPX:
            r = httpx.post(url, content=data, headers=h, timeout=timeout, follow_redirects=False)
            return r.status_code, dict(r.headers), r.text
        else:
            req = urllib.request.Request(url, data=data, headers=h)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.status, dict(resp.headers), resp.read().decode()
            except urllib.error.HTTPError as e:
                return e.code, dict(e.headers), e.read().decode()
    except Exception as e:
        return 0, {}, str(e)


def probe_tls(target_url):
    """Check TLS enforcement and security headers."""
    findings = []
    fid = 1

    # Check if HTTP (non-TLS) is accepted
    http_url = target_url.replace("https://", "http://", 1)
    if http_url != target_url:  # was HTTPS
        status, headers, body = http_get(http_url)
        if status not in (0, 301, 302, 308) and status > 0:
            findings.append({
                "id": f"{OWASP_ID}-{fid:03d}",
                "title": "Agent Communication Channel Accepts Plaintext HTTP",
                "severity": "CRITICAL",
                "description": (
                    "The inter-agent communication endpoint responds to plaintext HTTP requests. "
                    "Agent messages are transmitted without encryption, enabling eavesdropping and MITM attacks."
                ),
                "evidence": f"HTTP (non-TLS) request to {http_url} returned HTTP {status}.",
                "remediation": (
                    "Enforce HTTPS-only communication with a permanent HTTP→HTTPS redirect (308). "
                    "Set Strict-Transport-Security: max-age=31536000; includeSubDomains. "
                    "Implement mutual TLS (mTLS) for agent-to-agent channels."
                ),
            })
            fid += 1
    else:
        # Check if using HTTP at all
        if target_url.startswith("http://"):
            findings.append({
                "id": f"{OWASP_ID}-{fid:03d}",
                "title": "Inter-Agent Endpoint Uses Plaintext HTTP",
                "severity": "CRITICAL",
                "description": "The agent communication URL uses HTTP, not HTTPS. All agent messages are transmitted in plaintext.",
                "evidence": f"URL: {target_url}",
                "remediation": "Migrate to HTTPS with TLS 1.2+ minimum. Consider mTLS for agent identity verification.",
            })
            fid += 1

    # Check security headers
    status, headers, body = http_get(target_url)
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for header_name, label, severity in SECURITY_HEADERS:
        if header_name.lower() not in headers_lower:
            findings.append({
                "id": f"{OWASP_ID}-{fid:03d}",
                "title": f"Missing Security Header: {header_name}",
                "severity": severity,
                "description": label,
                "evidence": f"Header '{header_name}' absent from response to {target_url}",
                "remediation": f"Add '{header_name}' to all agent API responses.",
            })
            fid += 1

    return findings, fid


def probe_message_authentication(target_url, endpoint):
    """Test message signing and replay attack resistance."""
    findings = []
    fid = 1
    full_url = target_url.rstrip("/") + "/" + endpoint.lstrip("/")

    # Test 1: Message without signature
    msg_no_sig = {
        "sender_id": "agent-probe",
        "recipient_id": "target-agent",
        "message_id": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "payload": {"action": "status_check"},
        # No 'signature' field
    }
    status, headers, body = http_post(full_url, msg_no_sig)
    if status == 200:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "Agent Accepts Unsigned Messages",
            "severity": "CRITICAL",
            "description": (
                "The agent API accepted a message without a cryptographic signature. "
                "Any process that can reach this endpoint can spoof messages from any agent."
            ),
            "evidence": f"POST to {full_url} without 'signature' field → HTTP {status}.",
            "remediation": (
                "Require HMAC-SHA256 or RSA/ECDSA signature on all inter-agent messages. "
                "Reject any message missing the 'signature' field with HTTP 401. "
                "Use asymmetric keys: each agent has a keypair; public keys registered in an agent registry."
            ),
        })
        fid += 1

    # Test 2: Replay attack — resend a valid-looking message with old timestamp
    old_timestamp = int(time.time()) - 3600  # 1 hour ago
    replay_msg = {
        "sender_id": "agent-probe",
        "recipient_id": "target-agent",
        "message_id": str(uuid.uuid4()),
        "timestamp": old_timestamp,
        "nonce": "replayed-nonce-12345",
        "signature": "fake-sig-for-replay-test",
        "payload": {"action": "status_check"},
    }
    status2, _, body2 = http_post(full_url, replay_msg)
    if status2 == 200:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "Agent Accepts Replayed Messages (Old Timestamp)",
            "severity": "HIGH",
            "description": (
                "The agent accepted a message with a timestamp 1 hour in the past. "
                "Replay attacks allow an attacker to re-execute captured agent instructions."
            ),
            "evidence": f"Message with timestamp {old_timestamp} (1h ago) → HTTP {status2}.",
            "remediation": (
                "Reject messages with timestamps older than 30 seconds (clock skew tolerance). "
                "Maintain a nonce cache and reject duplicate nonce values within the validity window. "
                "Use monotonic message sequence numbers per sender."
            ),
        })
        fid += 1

    # Test 3: Missing required authentication headers
    auth_headers_to_test = ["Authorization", "X-Agent-Signature", "X-Agent-ID", "X-Message-ID"]
    missing_auth = []
    for hdr in auth_headers_to_test:
        status3, resp_headers, _ = http_post(full_url, {"test": True})
        if status3 == 200 and hdr.lower() not in {k.lower() for k in resp_headers}:
            missing_auth.append(hdr)

    if missing_auth:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "Inter-Agent Responses Missing Authentication Headers",
            "severity": "MEDIUM",
            "description": f"Response headers do not include expected agent authentication fields: {missing_auth}",
            "evidence": f"Headers absent: {missing_auth}",
            "remediation": (
                "Include X-Agent-ID and X-Message-Signature headers on all outbound agent responses. "
                "This enables recipient agents to verify the response origin."
            ),
        })
        fid += 1

    return findings, fid


def analyze_message_log(log_file, findings, fid):
    """Check a message log for security issues."""
    try:
        with open(log_file) as f:
            messages = [json.loads(line) for line in f if line.strip()]
    except Exception as e:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "Could Not Parse Message Log",
            "severity": "INFO",
            "description": str(e),
            "evidence": log_file,
            "remediation": "Provide a JSONL file with inter-agent message records.",
        })
        return findings, fid + 1

    # Check each message for required security fields
    missing_sig = sum(1 for m in messages if "signature" not in m)
    missing_nonce = sum(1 for m in messages if "nonce" not in m)
    missing_ts = sum(1 for m in messages if "timestamp" not in m)

    if missing_sig > 0:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": f"{missing_sig}/{len(messages)} Messages Lack Signatures",
            "severity": "CRITICAL",
            "description": "Unsigned inter-agent messages cannot be authenticated and are trivially spoofable.",
            "evidence": f"{missing_sig} of {len(messages)} messages have no 'signature' field.",
            "remediation": "Mandate message signing for all inter-agent messages. Migrate existing unsigned channels.",
        })
        fid += 1

    if missing_nonce > 0:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": f"{missing_nonce}/{len(messages)} Messages Lack Nonces (Replay Risk)",
            "severity": "HIGH",
            "description": "Messages without nonces are vulnerable to replay attacks.",
            "evidence": f"{missing_nonce} of {len(messages)} messages missing 'nonce' field.",
            "remediation": "Include a cryptographically random 128-bit nonce in every inter-agent message.",
        })
        fid += 1

    # Check for duplicate message IDs (replay indicator)
    msg_ids = [m.get("message_id") for m in messages if "message_id" in m]
    duplicates = [mid for mid in set(msg_ids) if msg_ids.count(mid) > 1]
    if duplicates:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "Duplicate Message IDs Detected (Possible Replay Attack)",
            "severity": "HIGH",
            "description": f"Found {len(duplicates)} message IDs appearing more than once in the log.",
            "evidence": f"Duplicate IDs: {duplicates[:5]}",
            "remediation": "Reject messages with duplicate message_id values. Maintain a seen-ID cache per agent session.",
        })
        fid += 1

    return findings, fid


def main():
    p = argparse.ArgumentParser(description="ASI07 Inter-Agent Communication Security Audit")
    p.add_argument("--agent-url", required=True, help="Inter-agent API base URL")
    p.add_argument("--message-endpoint", default="/messages", help="Message receive endpoint path")
    p.add_argument("--log", default=None, help="JSONL agent message log to analyze")
    p.add_argument("--output", default="asi07_report.json")
    args = p.parse_args()

    target = args.agent_url.rstrip("/")
    findings = []

    tls_findings, fid = probe_tls(target)
    findings.extend(tls_findings)

    msg_findings, fid2 = probe_message_authentication(target, args.message_endpoint)
    # Re-index IDs
    for mf in msg_findings:
        mf["id"] = f"{OWASP_ID}-{fid:03d}"
        fid += 1
    findings.extend(msg_findings)

    if args.log:
        findings, fid = analyze_message_log(args.log, findings, fid)

    if not findings:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "No Critical Inter-Agent Communication Weaknesses Detected",
            "severity": "INFO",
            "description": "Probes completed without detecting signature bypass or replay vulnerabilities.",
            "evidence": f"Target: {target}",
            "remediation": "Conduct message log analysis with --log flag for deeper replay attack detection.",
        })

    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1

    report = {
        "tool": TOOL_NAME, "target": target, "owasp_id": OWASP_ID,
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
