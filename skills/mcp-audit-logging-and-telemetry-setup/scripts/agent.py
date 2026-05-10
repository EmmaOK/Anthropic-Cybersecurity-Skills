#!/usr/bin/env python3
"""MCP09 - Audit Logging & Telemetry: Verify MCP server audit trail completeness and integrity."""
import argparse
import json
import sys
import time
import uuid

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    import urllib.request
    HAS_HTTPX = False

OWASP_ID = "MCP09"
TOOL_NAME = "phantom-mcp-audit-logging"

# Expected fields in a complete MCP audit log entry
REQUIRED_LOG_FIELDS = [
    "timestamp", "session_id", "tool_name", "arguments", "result_summary",
    "caller_identity", "duration_ms",
]

# Controls to verify
AUDIT_CONTROLS = [
    "timestamp_present",
    "caller_identity_logged",
    "arguments_logged",
    "result_logged",
    "error_events_logged",
    "log_integrity_protected",
    "session_correlation",
    "sensitive_args_redacted",
]


def jsonrpc(url, method, params=None, headers=None):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    h = {"Content-Type": "application/json", **(headers or {})}
    try:
        if HAS_HTTPX:
            r = httpx.post(url, content=payload, headers=h, timeout=10)
            return r.status_code, r.json()
        else:
            req = urllib.request.Request(url, data=payload, headers=h)
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
    except Exception as e:
        return 0, {"error": str(e)}


def probe_audit_endpoint(target):
    """Check if server exposes an audit/log endpoint."""
    audit_paths = ["/audit", "/logs", "/telemetry", "/events", "/activity"]
    reachable = []
    for path in audit_paths:
        status, resp = jsonrpc(f"{target}{path}", "ping")
        if status not in (0, 404, 405):
            reachable.append((path, status))
    return reachable


def generate_canary_call(target):
    """Make a traceable call with a unique marker and check if it appears in any log endpoint."""
    canary_id = f"audit-canary-{uuid.uuid4().hex[:8]}"
    # First get tools
    _, tool_resp = jsonrpc(target, "tools/list")
    tools = tool_resp.get("result", {}).get("tools", []) if "result" in tool_resp else []
    if not tools:
        return None, canary_id

    # Call first tool with canary in a string argument
    tool = tools[0]
    tool_name = tool.get("name", "")
    schema = tool.get("inputSchema", {})
    props = schema.get("properties", {})
    # Find a string parameter
    test_args = {}
    for param_name, param_schema in props.items():
        if param_schema.get("type") == "string":
            test_args[param_name] = canary_id
            break
    if not test_args:
        test_args = {"input": canary_id}

    status, resp = jsonrpc(target, "tools/call", params={"name": tool_name, "arguments": test_args})
    return resp, canary_id


def check_log_file(log_path):
    """Analyze an existing log file for completeness and integrity."""
    findings = []
    fid = 1
    try:
        with open(log_path) as f:
            entries = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    # Try treating the whole file as JSON array
                    pass

        if not entries:
            # Try JSON array format
            with open(log_path) as f:
                data = json.load(f)
                if isinstance(data, list):
                    entries = data

        missing_fields_count = 0
        sensitive_exposure_count = 0
        SENSITIVE_PATTERNS = ["password", "token", "secret", "api_key", "credential", "auth"]

        for entry in entries[:100]:  # Sample up to 100 entries
            entry_str = json.dumps(entry).lower()
            missing = [f for f in REQUIRED_LOG_FIELDS if f not in entry and f.replace("_", "") not in entry_str]
            if len(missing) > 2:
                missing_fields_count += 1

            # Check for sensitive data not redacted
            for sensitive in SENSITIVE_PATTERNS:
                if sensitive in entry_str:
                    args_str = json.dumps(entry.get("arguments", entry.get("args", {}))).lower()
                    if sensitive in args_str and "***" not in args_str and "redact" not in args_str:
                        sensitive_exposure_count += 1

        if missing_fields_count > 0:
            findings.append({
                "id": f"{OWASP_ID}-{fid:03d}",
                "title": "Audit Log Entries Missing Required Fields",
                "severity": "HIGH",
                "description": f"{missing_fields_count} of {min(len(entries), 100)} sampled log entries are missing required audit fields.",
                "evidence": f"Required fields: {REQUIRED_LOG_FIELDS} | Sample size: {min(len(entries), 100)}",
                "remediation": (
                    "Enforce a structured log schema for all MCP tool invocations. "
                    "Each entry must include: timestamp (ISO 8601), session_id, tool_name, caller identity, "
                    "argument summary, result summary, and duration_ms."
                ),
            })
            fid += 1

        if sensitive_exposure_count > 0:
            findings.append({
                "id": f"{OWASP_ID}-{fid:03d}",
                "title": "Sensitive Parameters Logged Without Redaction",
                "severity": "CRITICAL",
                "description": f"{sensitive_exposure_count} log entries contain potentially sensitive parameters logged in plaintext.",
                "evidence": f"Patterns found unredacted: {SENSITIVE_PATTERNS}",
                "remediation": (
                    "Implement log sanitisation middleware that redacts credential-like values before writing. "
                    "Use structured logging with explicit field allowlists. "
                    "Never log the values of parameters named: token, password, secret, api_key, credential."
                ),
            })
            fid += 1

        if not findings:
            findings.append({
                "id": f"{OWASP_ID}-{fid:03d}",
                "title": "Log File Analysis: No Critical Issues in Sampled Entries",
                "severity": "INFO",
                "description": f"Sampled {min(len(entries), 100)} entries. Fields and redaction appear adequate.",
                "evidence": log_path,
                "remediation": "Verify log integrity protection (HMAC signatures) and off-host forwarding to SIEM.",
            })

    except Exception as e:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "Could Not Parse Log File",
            "severity": "INFO",
            "description": str(e),
            "evidence": log_path,
            "remediation": "Provide a JSONL or JSON array log file.",
        })
    return findings


def main():
    p = argparse.ArgumentParser(description="MCP09 Audit Logging & Telemetry Audit")
    p.add_argument("--server-url", required=True, help="MCP server base URL")
    p.add_argument("--log-file", default=None, help="Path to existing MCP audit log file (JSONL or JSON array)")
    p.add_argument("--output", default="mcp09_report.json")
    args = p.parse_args()

    target = args.server_url.rstrip("/")
    findings = []
    fid = 1

    # 1. Check for audit endpoint exposure
    audit_endpoints = probe_audit_endpoint(target)
    if not audit_endpoints:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "No Audit/Telemetry Endpoint Detected",
            "severity": "MEDIUM",
            "description": (
                "No accessible audit, log, or telemetry endpoint was found on the MCP server. "
                "Without centralized log access, security teams cannot investigate incidents."
            ),
            "evidence": f"Probed paths: /audit, /logs, /telemetry, /events, /activity on {target}",
            "remediation": (
                "Implement a /telemetry or structured log export endpoint (restricted to admin role). "
                "Forward all MCP tool invocation events to a SIEM (Splunk, Elastic, Sentinel). "
                "Implement OpenTelemetry traces for all tool calls."
            ),
        })
        fid += 1

    # 2. Make a traceable canary call and check response for correlation ID
    canary_resp, canary_id = generate_canary_call(target)
    if canary_resp is not None:
        resp_str = json.dumps(canary_resp)
        if canary_id not in resp_str:
            # Check if server returns any trace/correlation ID
            if not any(field in resp_str.lower() for field in ["trace_id", "request_id", "correlation_id", "x-request-id"]):
                findings.append({
                    "id": f"{OWASP_ID}-{fid:03d}",
                    "title": "Tool Responses Lack Correlation/Trace IDs",
                    "severity": "MEDIUM",
                    "description": (
                        "MCP tool call responses do not include trace IDs or correlation IDs. "
                        "Without these, distributed tracing and incident forensics are severely hampered."
                    ),
                    "evidence": f"Canary call with ID '{canary_id}' returned no trace correlation. Response: {resp_str[:300]}",
                    "remediation": (
                        "Add X-Request-ID and X-Trace-ID headers to all MCP responses. "
                        "Include a request_id field in all JSON-RPC responses. "
                        "Implement W3C Trace Context (traceparent header) for distributed tracing."
                    ),
                })
                fid += 1

    # 3. Check for logging gaps — call a tool that should produce an error and verify structured error logging
    _, err_resp = jsonrpc(target, "tools/call", params={"name": "nonexistent_tool_xyz", "arguments": {}})
    err_str = json.dumps(err_resp)
    if "error" in err_resp and "id" not in err_str:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "Error Responses Lack Structured Error IDs",
            "severity": "LOW",
            "description": "Error responses from the MCP server do not include structured error identifiers.",
            "evidence": err_str[:300],
            "remediation": "Add error codes and error IDs to all JSON-RPC error responses to enable correlation in SIEM.",
        })
        fid += 1

    # 4. Analyze provided log file
    if args.log_file:
        log_findings = check_log_file(args.log_file)
        for lf in log_findings:
            lf["id"] = f"{OWASP_ID}-{fid:03d}"
            findings.append(lf)
            fid += 1

    if not findings:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "Basic Audit Telemetry Checks Passed",
            "severity": "INFO",
            "description": "No critical audit logging gaps detected in automated probes.",
            "evidence": f"Target: {target}",
            "remediation": "Conduct manual review of log completeness and SIEM forwarding configuration.",
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
