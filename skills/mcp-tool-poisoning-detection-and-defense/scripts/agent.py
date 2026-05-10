#!/usr/bin/env python3
"""MCP01 - Tool Poisoning Detection: Scan MCP tool descriptions for hidden injection payloads."""
import argparse
import json
import re
import sys

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    import urllib.request
    HAS_HTTPX = False

OWASP_ID = "MCP01"
TOOL_NAME = "phantom-mcp-tool-poisoning"

POISON_PATTERNS = [
    (r"ignore (previous|above|all) instructions?", "Instruction override attempt"),
    (r"system\s*:\s*(you are|act as|pretend)", "Role override injection"),
    (r"<\s*system\s*>", "System tag injection"),
    (r"\[INST\]|\[\/INST\]|<<SYS>>", "LLM template injection"),
    (r"disregard|forget|override|bypass", "Bypass instruction"),
    (r"[​‌‍⁠﻿­]", "Invisible/zero-width characters"),
    (r"do not tell the user|don't mention|keep this secret", "Secrecy instruction"),
    (r"exfiltrate|send.*to.*http|POST.*credentials", "Exfiltration instruction"),
    (r"\{\{.*\}\}|\$\{.*\}", "Template expression in description"),
    (r"<!--.*-->|<script", "HTML/script injection"),
]


def jsonrpc(url, method, params=None, headers=None):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    h = {"Content-Type": "application/json", **(headers or {})}
    try:
        if HAS_HTTPX:
            r = httpx.post(url, content=payload, headers=h, timeout=10)
            return r.json()
        else:
            req = urllib.request.Request(url, data=payload, headers=h)
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


def scan_text(text, field, tool_name):
    hits = []
    for pattern, label in POISON_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            hits.append((label, pattern, field, tool_name))
    return hits


def main():
    p = argparse.ArgumentParser(description="MCP01 Tool Poisoning Detection")
    p.add_argument("--server-url", required=True, help="MCP server base URL")
    p.add_argument("--output", default="mcp01_report.json")
    args = p.parse_args()

    findings = []
    target = args.server_url.rstrip("/")

    # Fetch tool list via MCP tools/list
    resp = jsonrpc(target, "tools/list")
    tools = []
    if "result" in resp:
        tools = resp["result"].get("tools", [])
    elif "error" not in resp:
        # Try alternate endpoint
        resp2 = jsonrpc(f"{target}/mcp", "tools/list")
        tools = resp2.get("result", {}).get("tools", []) if "result" in resp2 else []

    if not tools:
        findings.append({
            "id": f"{OWASP_ID}-000",
            "title": "Could not retrieve tool list",
            "severity": "INFO",
            "description": "Server did not return tools or is unreachable.",
            "evidence": str(resp),
            "remediation": "Ensure MCP server is running and accessible.",
        })

    fid = 1
    for tool in tools:
        name = tool.get("name", "unknown")
        description = tool.get("description", "")
        input_schema = json.dumps(tool.get("inputSchema", {}))

        for text, field in [(description, "description"), (input_schema, "inputSchema")]:
            hits = scan_text(text, field, name)
            for label, pattern, field_name, tool_name in hits:
                findings.append({
                    "id": f"{OWASP_ID}-{fid:03d}",
                    "title": f"Tool Poisoning: {label} in '{tool_name}' {field_name}",
                    "severity": "CRITICAL",
                    "description": (
                        f"MCP tool '{tool_name}' contains a suspicious pattern in its {field_name} "
                        f"that could manipulate AI agents consuming this tool definition."
                    ),
                    "evidence": f"Pattern '{pattern}' matched in {field_name}: {text[:300]}",
                    "remediation": (
                        "Remove all instruction-like language from tool descriptions. "
                        "Tool descriptions should only describe the tool's function. "
                        "Implement a tool description allowlist/sanitiser in the MCP server."
                    ),
                })
                fid += 1

        # Check for excessive permissions claimed in description
        if re.search(r"(full|complete|unrestricted|root|admin|superuser) (access|control|permission)", description, re.I):
            findings.append({
                "id": f"{OWASP_ID}-{fid:03d}",
                "title": f"Excessive Permission Claim in tool '{name}'",
                "severity": "HIGH",
                "description": f"Tool '{name}' claims excessive permissions in its description.",
                "evidence": description[:300],
                "remediation": "Apply least-privilege principle. Tool descriptions must not claim broad permissions.",
            })
            fid += 1

    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1

    report = {
        "tool": TOOL_NAME, "target": target, "owasp_id": OWASP_ID,
        "tools_scanned": len(tools), "findings": findings,
        "summary": {"total": len(findings), **sev},
    }
    print(json.dumps(report, indent=2))
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)

    sys.exit(1 if sev["CRITICAL"] > 0 or sev["HIGH"] > 0 else 0)


if __name__ == "__main__":
    main()
