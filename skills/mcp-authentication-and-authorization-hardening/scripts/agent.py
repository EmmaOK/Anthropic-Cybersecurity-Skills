#!/usr/bin/env python3
"""MCP02 - Auth & Authorization Hardening: Probe MCP server for missing/weak authentication."""
import argparse
import json
import os
import sys

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_HTTPX = False

OWASP_ID = "MCP02"
TOOL_NAME = "phantom-mcp-auth-hardening"

WEAK_TOKEN_PATTERNS = ["test", "demo", "changeme", "secret", "password", "12345", "admin", "mcp-token"]


def _post(url, payload, headers=None, timeout=10):
    h = {"Content-Type": "application/json", **(headers or {})}
    data = json.dumps(payload).encode()
    try:
        if HAS_HTTPX:
            r = httpx.post(url, content=data, headers=h, timeout=timeout)
            return r.status_code, r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        else:
            req = urllib.request.Request(url, data=data, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read())
    except Exception as e:
        return None, {"error": str(e)}


def _get(url, headers=None, timeout=5):
    h = headers or {}
    try:
        if HAS_HTTPX:
            r = httpx.get(url, headers=h, timeout=timeout)
            return r.status_code, r.text
        else:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode()
    except Exception as e:
        return None, str(e)


def probe_unauthenticated(target):
    findings = []
    rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    status, body = _post(target, rpc)
    if status == 200 and "result" in body:
        findings.append({
            "id": f"{OWASP_ID}-001",
            "title": "Unauthenticated Tool Listing Allowed",
            "severity": "CRITICAL",
            "description": "MCP server returned tool list without any authentication credentials.",
            "evidence": f"POST {target} → HTTP 200, tools returned: {len(body.get('result',{}).get('tools',[]))}",
            "remediation": "Require Bearer token or API key for all MCP JSON-RPC endpoints. Return HTTP 401 for unauthenticated requests.",
        })
    return findings


def probe_weak_tokens(target):
    findings = []
    rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    for tok in WEAK_TOKEN_PATTERNS:
        status, body = _post(target, rpc, headers={"Authorization": f"Bearer {tok}"})
        if status == 200 and "result" in body:
            findings.append({
                "id": f"{OWASP_ID}-002",
                "title": f"Weak Token Accepted: '{tok}'",
                "severity": "CRITICAL",
                "description": f"Server accepted a well-known weak/default token '{tok}' as valid authentication.",
                "evidence": f"Authorization: Bearer {tok} → HTTP 200",
                "remediation": "Reject all known-weak tokens. Use cryptographically random tokens ≥32 bytes. Rotate default credentials.",
            })
    return findings


def probe_scope_bypass(target):
    findings = []
    token = os.environ.get("MCP_API_TOKEN", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    # Call a write/execute tool without scope claim
    for method in ["tools/call", "resources/write", "admin/reset"]:
        rpc = {"jsonrpc": "2.0", "id": 1, "method": method, "params": {"name": "test", "arguments": {}}}
        status, body = _post(target, rpc, headers=headers)
        if status == 200 and "result" in body and "error" not in body:
            findings.append({
                "id": f"{OWASP_ID}-003",
                "title": f"Missing Scope Enforcement on '{method}'",
                "severity": "HIGH",
                "description": f"Method '{method}' succeeded without scope validation.",
                "evidence": f"POST {method} → HTTP 200",
                "remediation": "Implement OAuth2 scope checks. Require 'tools:write' or 'admin' scope for privileged methods.",
            })
    return findings


def probe_error_verbosity(target):
    findings = []
    rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "' OR 1=1--", "arguments": {}}}
    status, body = _post(target, rpc, headers={"Authorization": "Bearer invalid"})
    err_str = json.dumps(body)
    if any(kw in err_str.lower() for kw in ["stack", "traceback", "exception", "at line", "file \""]):
        findings.append({
            "id": f"{OWASP_ID}-004",
            "title": "Verbose Error Disclosure on Auth Failure",
            "severity": "MEDIUM",
            "description": "Server returns stack traces or internal details on authentication errors.",
            "evidence": err_str[:300],
            "remediation": "Return generic error messages (HTTP 401/403) without internal stack traces.",
        })
    return findings


def main():
    p = argparse.ArgumentParser(description="MCP02 Auth & Authorization Hardening Probe")
    p.add_argument("--server-url", required=True, help="MCP server base URL")
    p.add_argument("--output", default="mcp02_report.json")
    args = p.parse_args()

    target = args.server_url.rstrip("/")
    findings = []
    findings += probe_unauthenticated(target)
    findings += probe_weak_tokens(target)
    findings += probe_scope_bypass(target)
    findings += probe_error_verbosity(target)

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
