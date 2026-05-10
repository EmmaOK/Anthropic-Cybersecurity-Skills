#!/usr/bin/env python3
"""MCP08 - Intent Flow Subversion Detection: Detect goal hijacking in MCP agent context flows."""
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

OWASP_ID = "MCP08"
TOOL_NAME = "phantom-mcp-intent-subversion"

# Patterns in tool responses that attempt to redirect agent objectives
SUBVERSION_PATTERNS = [
    (r"(ignore|forget|disregard).{0,30}(original|previous|user|goal|task|instruction)", "Goal erasure attempt"),
    (r"(new|updated|revised|corrected).{0,20}(goal|objective|task|instruction|mission)", "Goal replacement injection"),
    (r"(instead|rather).{0,30}(do|perform|execute|run|call)", "Action redirection"),
    (r"do not (tell|inform|notify|report|mention).{0,30}(user|human|operator)", "Secrecy from user instruction"),
    (r"(send|upload|post|exfiltrate).{0,30}(to|at).{0,30}(http|url|endpoint|server)", "Exfiltration instruction"),
    (r"(before|first|after).{0,20}(calling|running|executing).{0,30}(also|then|additionally)", "Side-channel action injection"),
    (r"your (real|actual|true|new) (purpose|goal|mission|objective|function)", "Role/objective override"),
    (r"(agent|assistant|you).{0,20}(must|should|will|shall).{0,20}(always|never|only)", "Behavioral override mandate"),
    (r"<\s*(goal|objective|instruction|system|task)\s*>", "Tagged instruction injection in response"),
    (r"\[OVERRIDE\]|\[INJECT\]|\[REDIRECT\]|\[NEW_GOAL\]", "Explicit override marker"),
    (r"(forward|relay|pass).{0,30}(all|every|each).{0,30}(message|response|output|result)", "Data relay instruction"),
    (r"when.{0,20}(user|human).{0,20}(asks|says|requests).{0,20}(respond|say|claim|pretend)", "Conditional deception trigger"),
]

# Risky tool call sequences that suggest intent hijacking
SUSPICIOUS_CALL_SEQUENCES = [
    (["read", "send"], "Read-then-exfiltrate pattern"),
    (["list", "delete"], "Enumerate-then-destroy pattern"),
    (["get", "post"], "Retrieve-then-exfiltrate pattern"),
    (["search", "email"], "Search-then-notify-attacker pattern"),
]


def jsonrpc(url, method, params=None):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    h = {"Content-Type": "application/json"}
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


def scan_for_subversion(text, source):
    hits = []
    for pattern, label in SUBVERSION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            hits.append((label, pattern, source))
    return hits


def probe_context_resources(target):
    """Fetch MCP resources/prompts and check for intent hijacking content."""
    findings = []
    fid = 1

    for endpoint in ["resources/list", "prompts/list"]:
        resp = jsonrpc(target, endpoint)
        resp_text = json.dumps(resp)
        hits = scan_for_subversion(resp_text, endpoint)
        for label, pattern, source in hits:
            findings.append({
                "id": f"{OWASP_ID}-{fid:03d}",
                "title": f"Intent Subversion Pattern in '{source}': {label}",
                "severity": "CRITICAL",
                "description": (
                    f"MCP server's {source} response contains content that attempts to redirect agent intent. "
                    f"Pattern detected: {label}. This is an indirect prompt injection via MCP context."
                ),
                "evidence": f"Pattern: {pattern} | Source: {source} | Response snippet: {resp_text[:400]}",
                "remediation": (
                    "Treat all MCP resource/prompt content as untrusted. "
                    "Apply intent consistency monitoring: compare declared user goal with actual tool calls. "
                    "Implement confirmation gates for any tool call that deviates from stated task scope. "
                    "Use provenance tracking — tag each context chunk with its origin and apply trust levels. "
                    "Block tool calls to network/write APIs triggered by resource content without user confirmation."
                ),
            })
            fid += 1

    # Check resource contents individually
    resp = jsonrpc(target, "resources/list")
    resources = resp.get("result", {}).get("resources", []) if "result" in resp else []
    for resource in resources[:10]:  # Limit to avoid abuse
        uri = resource.get("uri", "")
        read_resp = jsonrpc(target, "resources/read", params={"uri": uri})
        content_text = json.dumps(read_resp)
        hits = scan_for_subversion(content_text, f"resource:{uri}")
        for label, pattern, source in hits:
            findings.append({
                "id": f"{OWASP_ID}-{fid:03d}",
                "title": f"Intent Hijacking in Resource Content: {label}",
                "severity": "CRITICAL",
                "description": (
                    f"Resource '{uri}' contains content attempting to subvert agent intent: {label}. "
                    "Attackers embed goal-hijacking instructions in MCP resources to redirect agents."
                ),
                "evidence": f"URI: {uri} | Pattern: {pattern} | Content: {content_text[:400]}",
                "remediation": (
                    "Validate all resource content against an intent alignment model before injecting into agent context. "
                    "Require human review before agents act on instructions sourced from external resources. "
                    "Deploy a dedicated injection classifier on all incoming context chunks."
                ),
            })
            fid += 1

    return findings, fid


def analyze_tool_call_log(log_file, findings, fid):
    """Analyze a JSONL agent log for suspicious tool call sequences."""
    try:
        with open(log_file) as f:
            calls = [json.loads(line) for line in f if line.strip()]
    except Exception as e:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "Could not parse tool call log",
            "severity": "INFO",
            "description": str(e),
            "evidence": log_file,
            "remediation": "Provide a JSONL file with tool call records (each line: {tool, args, result}).",
        })
        return findings, fid + 1

    call_names = [c.get("tool", c.get("name", "")).lower() for c in calls]

    for pattern_seq, label in SUSPICIOUS_CALL_SEQUENCES:
        for i in range(len(call_names) - 1):
            if any(pattern_seq[0] in call_names[i] for _ in [0]) and \
               any(pattern_seq[1] in call_names[i + 1] for _ in [0]):
                findings.append({
                    "id": f"{OWASP_ID}-{fid:03d}",
                    "title": f"Suspicious Tool Call Sequence: {label}",
                    "severity": "HIGH",
                    "description": (
                        f"Agent log shows a '{label}' pattern: tool '{call_names[i]}' immediately followed "
                        f"by '{call_names[i+1]}'. This sequence may indicate intent flow subversion."
                    ),
                    "evidence": f"Sequence at index {i}: {call_names[max(0,i-1):i+3]}",
                    "remediation": (
                        "Implement tool call sequence validation. "
                        "Require explicit user confirmation before destructive or exfiltration-adjacent calls. "
                        "Log and alert on anomalous cross-category tool call chains."
                    ),
                })
                fid += 1

    return findings, fid


def main():
    p = argparse.ArgumentParser(description="MCP08 Intent Flow Subversion Detection")
    p.add_argument("--server-url", required=True, help="MCP server base URL")
    p.add_argument("--log", default=None, help="JSONL agent tool call log to analyze for suspicious sequences")
    p.add_argument("--output", default="mcp08_report.json")
    args = p.parse_args()

    target = args.server_url.rstrip("/")
    findings, fid = probe_context_resources(target)

    # Also scan tools/list for subversion patterns
    tool_resp = jsonrpc(target, "tools/list")
    tools_text = json.dumps(tool_resp)
    tool_hits = scan_for_subversion(tools_text, "tools/list")
    for label, pattern, source in tool_hits:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": f"Intent Subversion in Tool Definition: {label}",
            "severity": "CRITICAL",
            "description": f"Tool definition contains goal-hijacking language: {label}.",
            "evidence": f"Pattern: {pattern} | tools/list snippet: {tools_text[:400]}",
            "remediation": "Remove all imperative/redirect language from tool descriptions. Tool descriptions must describe function only.",
        })
        fid += 1

    if args.log:
        findings, fid = analyze_tool_call_log(args.log, findings, fid)

    if not findings:
        findings.append({
            "id": f"{OWASP_ID}-{fid:03d}",
            "title": "No Intent Subversion Patterns Detected",
            "severity": "INFO",
            "description": "Scanned tool definitions and resource content showed no detectable goal hijacking.",
            "evidence": "Probed: tools/list, resources/list, prompts/list",
            "remediation": "Continue monitoring with agent execution logs. Static scans miss dynamic injection.",
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
