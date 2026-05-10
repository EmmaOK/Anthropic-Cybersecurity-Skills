#!/usr/bin/env python3
"""MCP06 - Command Injection Prevention: Test MCP tools for command injection vulnerabilities."""
import argparse
import json
import sys

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    import urllib.request
    HAS_HTTPX = False

OWASP_ID = "MCP06"
TOOL_NAME = "phantom-mcp-cmd-injection"

# Injection payloads for shell, SQL, LDAP, path traversal, template injection
INJECTION_PAYLOADS = [
    # Shell injection
    ("; id", "shell", "Semicolon command separator"),
    ("| id", "shell", "Pipe command injection"),
    ("`id`", "shell", "Backtick command substitution"),
    ("$(id)", "shell", "Dollar-paren command substitution"),
    ("\nid\n", "shell", "Newline injection (split bypass)"),
    ("&& id", "shell", "AND chained command"),
    ("|| id", "shell", "OR chained command"),
    # Path traversal
    ("../../etc/passwd", "path", "Unix path traversal"),
    ("..\\..\\windows\\system32\\cmd.exe", "path", "Windows path traversal"),
    ("/tmp/safe/../../etc/shadow", "path", "Path traversal with safe prefix"),
    # Template injection
    ("{{7*7}}", "template", "Jinja2/Twig template injection"),
    ("${7*7}", "template", "EL/Freemarker template injection"),
    ("<%= 7*7 %>", "template", "ERB/JSP template injection"),
    # SSRF
    ("http://169.254.169.254/latest/meta-data/", "ssrf", "AWS IMDS SSRF"),
    ("file:///etc/passwd", "ssrf", "File URI SSRF"),
    # SQL
    ("' OR '1'='1", "sql", "SQL single-quote injection"),
    ("1; DROP TABLE tools--", "sql", "SQL DDL injection"),
]

# Strings in tool responses that indicate command execution succeeded
EXECUTION_INDICATORS = [
    "uid=", "root:", "/bin/bash", "/bin/sh",
    "49",  # 7*7 = 49 template injection
    "root:x:0:", "/etc/passwd", "shadow",
    "ami-id", "instance-id",  # AWS IMDS
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


def get_injectable_params(tool):
    """Return list of parameters likely to be passed to shell/FS/SQL."""
    schema = tool.get("inputSchema", {})
    props = schema.get("properties", {})
    injectable = []
    HIGH_RISK = {"command", "cmd", "shell", "exec", "path", "filepath", "filename",
                 "query", "sql", "url", "endpoint", "host", "target", "input", "script"}
    for param_name, param_schema in props.items():
        if param_name.lower() in HIGH_RISK:
            injectable.append(param_name)
        elif param_schema.get("type") == "string":
            injectable.append(param_name)
    return injectable[:5]  # Limit to 5 params per tool


def probe_tool(target, tool, findings, fid):
    name = tool.get("name", "unknown")
    injectable = get_injectable_params(tool)
    if not injectable:
        return fid

    for param in injectable:
        for payload, category, label in INJECTION_PAYLOADS:
            args = {param: payload}
            # Add required params with dummy values
            schema = tool.get("inputSchema", {})
            required = schema.get("required", [])
            for req_param in required:
                if req_param not in args:
                    args[req_param] = "test"

            status, resp = jsonrpc(target, "tools/call", params={"name": name, "arguments": args})
            resp_str = json.dumps(resp).lower()

            # Check for execution indicators in response
            triggered = [ind for ind in EXECUTION_INDICATORS if ind.lower() in resp_str]
            if triggered:
                findings.append({
                    "id": f"{OWASP_ID}-{fid:03d}",
                    "title": f"CONFIRMED: {label} in tool '{name}' param '{param}'",
                    "severity": "CRITICAL",
                    "description": (
                        f"Tool '{name}' parameter '{param}' is vulnerable to {category} injection. "
                        f"The injected payload produced detectable output in the server response."
                    ),
                    "evidence": (
                        f"Payload: {repr(payload)}\n"
                        f"Triggered indicators: {triggered}\n"
                        f"Response snippet: {json.dumps(resp)[:400]}"
                    ),
                    "remediation": (
                        "Use parameterized APIs and subprocess.run() with list arguments (no shell=True). "
                        "Apply strict input allowlisting for path and command parameters. "
                        "Run MCP tools in sandboxed containers with no-network, read-only FS policies. "
                        "Validate inputs against a strict allowlist before passing to any OS/DB call."
                    ),
                })
                fid += 1
                break  # One confirmed injection per param is enough

    return fid


def main():
    p = argparse.ArgumentParser(description="MCP06 Command Injection Prevention Audit")
    p.add_argument("--server-url", required=True, help="MCP server base URL")
    p.add_argument("--token", default=None, help="Bearer token for authenticated calls")
    p.add_argument("--dry-run", action="store_true", help="List injectable tools without sending payloads")
    p.add_argument("--output", default="mcp06_report.json")
    args = p.parse_args()

    target = args.server_url.rstrip("/")
    findings = []
    fid = 1

    # Fetch tools
    resp_status, resp = jsonrpc(target, "tools/list")
    tools = []
    if "result" in resp:
        tools = resp["result"].get("tools", [])

    if not tools:
        findings.append({
            "id": f"{OWASP_ID}-000",
            "title": "No tools retrieved for injection testing",
            "severity": "INFO",
            "description": "Server returned no tools or is unreachable.",
            "evidence": str(resp)[:300],
            "remediation": "Ensure MCP server is running and tools/list is accessible.",
        })

    injectable_summary = []
    for tool in tools:
        name = tool.get("name", "unknown")
        params = get_injectable_params(tool)
        if params:
            injectable_summary.append({"tool": name, "injectable_params": params})
            if not args.dry_run:
                fid = probe_tool(target, tool, findings, fid)

    if args.dry_run and injectable_summary:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "Injectable Parameter Surface (Dry Run)",
            "severity": "INFO",
            "description": f"Found {len(injectable_summary)} tools with potentially injectable parameters. Run without --dry-run to probe.",
            "evidence": json.dumps(injectable_summary, indent=2)[:800],
            "remediation": "Review each tool's parameter handling for injection risks.",
        })

    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1

    report = {
        "tool": TOOL_NAME, "target": target, "owasp_id": OWASP_ID,
        "tools_scanned": len(tools),
        "injectable_surface": injectable_summary,
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
