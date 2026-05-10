#!/usr/bin/env python3
"""ASI04 - Agentic Tool Misuse Detection: Parse agent logs for tool calls outside declared scope."""
import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

OWASP_ID = "ASI04"
TOOL_NAME = "phantom-agentic-tool-misuse"

# Tool combinations that are suspicious when used together
SUSPICIOUS_COMBOS = [
    ({"file_read", "network_request"}, "File read followed by network call — potential exfiltration"),
    ({"execute_code", "file_write"}, "Code execution followed by file write — potential payload drop"),
    ({"web_search", "execute_code"}, "Web search followed by code execution — potential remote payload fetch"),
    ({"memory_store", "email_send"}, "Memory store followed by email — potential data leakage"),
]

# Tool name patterns that are high-risk regardless of context
HIGH_RISK_TOOL_PATTERNS = [
    (r"(exec|shell|cmd|bash|powershell|subprocess)", "Shell execution tool"),
    (r"(delete|drop|truncate|destroy|remove).*file", "Destructive file operation"),
    (r"(send|post|upload).*credential", "Credential transmission tool"),
    (r"(admin|root|sudo|privilege)", "Privileged operation tool"),
]

RATE_THRESHOLD = 10  # calls to same tool within any 60-second window = suspicious


def parse_log(log_path: str) -> list[dict]:
    path = Path(log_path)
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            entries.append({"raw": line})
    return entries


def extract_tool_calls(entries: list[dict]) -> list[dict]:
    calls = []
    for e in entries:
        # Support common agent log schemas
        if isinstance(e, dict):
            tool = e.get("tool") or e.get("tool_name") or e.get("function") or e.get("action")
            ts = e.get("timestamp") or e.get("ts") or e.get("time", "")
            args = e.get("args") or e.get("parameters") or e.get("input") or {}
            if tool:
                calls.append({"tool": str(tool), "timestamp": str(ts), "args": args, "raw": e})
    return calls


def check_against_manifest(calls: list[dict], manifest: dict) -> list[dict]:
    allowed = set(manifest.get("allowed_tools", []))
    findings = []
    for c in calls:
        if allowed and c["tool"] not in allowed:
            findings.append({
                "id": f"{OWASP_ID}-{len(findings)+1:03d}",
                "title": f"Unauthorized Tool Call: '{c['tool']}'",
                "severity": "HIGH",
                "description": f"Agent called tool '{c['tool']}' which is not in the declared allowed_tools manifest.",
                "evidence": json.dumps(c["raw"])[:300],
                "remediation": "Enforce tool allowlists at the orchestration layer. Reject calls to tools not declared in the agent manifest.",
            })
    return findings


def check_rate_storms(calls: list[dict]) -> list[dict]:
    findings = []
    by_tool: dict[str, list] = defaultdict(list)
    for c in calls:
        by_tool[c["tool"]].append(c)

    for tool, tool_calls in by_tool.items():
        if len(tool_calls) > RATE_THRESHOLD:
            findings.append({
                "id": f"{OWASP_ID}-R{len(findings)+1:03d}",
                "title": f"Tool Rate Storm: '{tool}' called {len(tool_calls)} times",
                "severity": "MEDIUM",
                "description": f"Tool '{tool}' was called {len(tool_calls)} times — possible retry storm or misuse loop.",
                "evidence": f"call_count={len(tool_calls)}, tool={tool}",
                "remediation": "Implement per-tool rate limiting. Add circuit breakers that halt agent execution after N consecutive calls.",
            })
    return findings


def check_suspicious_combos(calls: list[dict]) -> list[dict]:
    findings = []
    tool_set = {c["tool"] for c in calls}
    for combo, desc in SUSPICIOUS_COMBOS:
        if combo.issubset(tool_set):
            findings.append({
                "id": f"{OWASP_ID}-C{len(findings)+1:03d}",
                "title": f"Suspicious Tool Combination: {desc}",
                "severity": "HIGH",
                "description": f"Agent used the tool combination {combo} — {desc}",
                "evidence": f"tools_used={list(tool_set)}",
                "remediation": "Audit agent goals vs actual tool usage. Require human approval for combinations involving data access + external comms.",
            })
    return findings


def check_high_risk_tools(calls: list[dict]) -> list[dict]:
    findings = []
    seen = set()
    for c in calls:
        for pattern, desc in HIGH_RISK_TOOL_PATTERNS:
            if re.search(pattern, c["tool"], re.IGNORECASE) and c["tool"] not in seen:
                seen.add(c["tool"])
                findings.append({
                    "id": f"{OWASP_ID}-H{len(findings)+1:03d}",
                    "title": f"High-Risk Tool Used: '{c['tool']}' ({desc})",
                    "severity": "HIGH",
                    "description": f"Tool '{c['tool']}' matches high-risk pattern '{pattern}' ({desc}).",
                    "evidence": json.dumps(c["raw"])[:300],
                    "remediation": "Apply least-privilege: remove high-risk tools from agent manifests unless strictly required. Log and alert on every invocation.",
                })
    return findings


def main():
    p = argparse.ArgumentParser(description="ASI04 Agentic Tool Misuse Detection")
    p.add_argument("--log-file", required=True, help="Agent execution log (JSONL)")
    p.add_argument("--manifest", help="JSON file with allowed_tools list")
    p.add_argument("--output", default="asi04_tool_misuse_report.json")
    args = p.parse_args()

    entries = parse_log(args.log_file)
    calls = extract_tool_calls(entries)

    findings = []
    if args.manifest:
        manifest = json.loads(Path(args.manifest).read_text())
        findings += check_against_manifest(calls, manifest)

    findings += check_rate_storms(calls)
    findings += check_suspicious_combos(calls)
    findings += check_high_risk_tools(calls)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

    report = {
        "tool": TOOL_NAME, "owasp_id": OWASP_ID,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "log_file": args.log_file, "total_tool_calls": len(calls),
        "findings": findings,
        "summary": {"total": len(findings), **counts},
    }
    print(json.dumps(report, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2))
    sys.exit(1 if counts["CRITICAL"] > 0 or counts["HIGH"] > 0 else 0)


if __name__ == "__main__":
    main()
