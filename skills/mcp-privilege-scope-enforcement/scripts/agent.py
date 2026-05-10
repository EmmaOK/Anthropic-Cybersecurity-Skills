#!/usr/bin/env python3
"""MCP03 - Privilege Scope Enforcement: Test if MCP server enforces declared tool scopes."""
import argparse
import json
import os
import sys

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    import urllib.request
    HAS_HTTPX = False

OWASP_ID = "MCP03"
TOOL_NAME = "phantom-mcp-privilege-scope"

PRIVILEGED_SCOPES = ["admin", "write", "delete", "execute", "system", "root"]
OVERLY_BROAD_CLAIMS = ["*", "all", "full", "unrestricted", "any"]


def jsonrpc(url, method, params=None, headers=None, timeout=10):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    h = {"Content-Type": "application/json", **(headers or {})}
    try:
        if HAS_HTTPX:
            r = httpx.post(url, content=payload, headers=h, timeout=timeout)
            return r.status_code, r.json() if "json" in r.headers.get("content-type", "") else {}
        else:
            req = urllib.request.Request(url, data=payload, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read())
    except Exception as e:
        return None, {"error": str(e)}


def get_tools(target, headers):
    status, body = jsonrpc(target, "tools/list", headers=headers)
    if status == 200 and "result" in body:
        return body["result"].get("tools", [])
    return []


def check_schema_scope_declarations(tools):
    findings = []
    for tool in tools:
        name = tool.get("name", "unknown")
        schema = tool.get("inputSchema", {})
        desc = tool.get("description", "")
        props = schema.get("properties", {})
        for prop, defn in props.items():
            if prop.lower() in ("scope", "permission", "role", "access_level"):
                enum_vals = defn.get("enum", [])
                for val in enum_vals:
                    if str(val).lower() in OVERLY_BROAD_CLAIMS:
                        findings.append({
                            "id": f"{OWASP_ID}-{len(findings)+1:03d}",
                            "title": f"Overly Broad Scope Value in Tool Schema: '{name}.{prop}'",
                            "severity": "HIGH",
                            "description": f"Tool '{name}' declares '{val}' as a valid scope value in its input schema.",
                            "evidence": f"inputSchema.properties.{prop}.enum = {enum_vals}",
                            "remediation": "Replace wildcard/broad scope values with explicit, fine-grained permission names.",
                        })
    return findings


def probe_scope_escalation(target, tools, headers):
    findings = []
    for tool in tools[:5]:  # Test first 5 tools to limit requests
        name = tool.get("name", "unknown")
        schema = tool.get("inputSchema", {})
        props = schema.get("properties", {})
        for scope_key in ("scope", "permission", "role"):
            if scope_key in props:
                for broad_val in OVERLY_BROAD_CLAIMS:
                    rpc_params = {"name": name, "arguments": {scope_key: broad_val}}
                    status, body = jsonrpc(target, "tools/call", rpc_params, headers=headers)
                    if status == 200 and "result" in body and "error" not in body:
                        findings.append({
                            "id": f"{OWASP_ID}-{len(findings)+100:03d}",
                            "title": f"Scope Escalation Accepted: tool='{name}' {scope_key}='{broad_val}'",
                            "severity": "CRITICAL",
                            "description": (
                                f"MCP server accepted a privileged scope value '{broad_val}' "
                                f"for tool '{name}' without enforcement."
                            ),
                            "evidence": f"tools/call {name} {scope_key}={broad_val} → HTTP 200, result={str(body)[:200]}",
                            "remediation": "Validate all scope claims server-side. Reject calls where claimed scope exceeds the token's granted scopes.",
                        })
    return findings


def check_missing_scope_metadata(tools):
    findings = []
    for tool in tools:
        name = tool.get("name", "unknown")
        desc = tool.get("description", "")
        schema = tool.get("inputSchema", {})
        # Privileged tools should declare required scopes
        if any(kw in name.lower() or kw in desc.lower() for kw in PRIVILEGED_SCOPES):
            if "scope" not in json.dumps(schema).lower() and "permission" not in json.dumps(schema).lower():
                findings.append({
                    "id": f"{OWASP_ID}-{len(findings)+200:03d}",
                    "title": f"Privileged Tool Missing Scope Declaration: '{name}'",
                    "severity": "MEDIUM",
                    "description": f"Tool '{name}' appears privileged but declares no required scope/permission in its schema.",
                    "evidence": f"name='{name}', description='{desc[:150]}'",
                    "remediation": "Add explicit scope requirements to tool schemas. Document required OAuth2 scopes in tool metadata.",
                })
    return findings


def main():
    p = argparse.ArgumentParser(description="MCP03 Privilege Scope Enforcement")
    p.add_argument("--server-url", required=True)
    p.add_argument("--output", default="mcp03_report.json")
    args = p.parse_args()

    target = args.server_url.rstrip("/")
    token = os.environ.get("MCP_API_TOKEN", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    tools = get_tools(target, headers)
    findings = []
    findings += check_schema_scope_declarations(tools)
    findings += probe_scope_escalation(target, tools, headers)
    findings += check_missing_scope_metadata(tools)

    if not tools:
        findings.append({"id": f"{OWASP_ID}-E001", "title": "No tools retrieved", "severity": "INFO",
                         "description": "Could not fetch tool list. Check --server-url and auth.", "evidence": target, "remediation": "Verify server is running."})

    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1

    report = {"tool": TOOL_NAME, "target": target, "owasp_id": OWASP_ID,
              "tools_scanned": len(tools), "findings": findings, "summary": {"total": len(findings), **sev}}
    print(json.dumps(report, indent=2))
    if args.output:
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2)

    sys.exit(1 if sev["CRITICAL"] > 0 or sev["HIGH"] > 0 else 0)


if __name__ == "__main__":
    main()
