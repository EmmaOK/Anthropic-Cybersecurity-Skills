#!/usr/bin/env python3
"""ASI09 - Agentic Cascading Failure Prevention: Detect retry storms and missing circuit breakers."""
import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

OWASP_ID = "ASI09"
TOOL_NAME = "phantom-cascading-failure"

RETRY_STORM_THRESHOLD = 5       # same tool called N+ times consecutively = storm
FAILURE_CHAIN_DEPTH = 3         # N cascading errors = propagation chain
CIRCUIT_BREAKER_CONTROLS = [
    ("circuit_breaker_enabled", "CRITICAL", "No circuit breaker configured — cascading failures not stopped"),
    ("max_retries", "HIGH", "No retry limit — agent can retry indefinitely"),
    ("retry_backoff", "MEDIUM", "No exponential backoff — retry storms likely"),
    ("failure_threshold", "MEDIUM", "No failure threshold — circuit breaker never trips"),
    ("timeout_ms", "MEDIUM", "No per-tool timeout — slow tools block agent indefinitely"),
    ("fallback_handler", "HIGH", "No fallback handler — failures propagate with no degraded response"),
]

ERROR_PATTERNS = [
    r"(error|exception|fail|timeout|refused|unavailable)",
    r"(retry|retrying|attempt\s+\d+|retry_count\s*[=:]\s*\d+)",
]


def parse_log(log_path):
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
            entries.append({"raw": line, "text": line})
    return entries


def detect_retry_storms(entries):
    findings = []
    # Extract tool calls with error status
    tool_calls = []
    for e in entries:
        if isinstance(e, dict):
            tool = e.get("tool") or e.get("tool_name") or e.get("action") or ""
            status = e.get("status") or e.get("result") or ""
            is_error = "error" in str(status).lower() or "fail" in str(status).lower()
            if tool:
                tool_calls.append({"tool": str(tool), "error": is_error, "raw": e})

    # Detect consecutive retries of same tool
    consecutive: dict[str, int] = defaultdict(int)
    prev_tool = None
    for call in tool_calls:
        t = call["tool"]
        if t == prev_tool and call["error"]:
            consecutive[t] += 1
        else:
            consecutive[t] = 1
        prev_tool = t

    for tool, count in consecutive.items():
        if count >= RETRY_STORM_THRESHOLD:
            findings.append({
                "id": f"{OWASP_ID}-RS{len(findings)+1:03d}",
                "title": f"Retry Storm: '{tool}' failed {count} consecutive times",
                "severity": "HIGH",
                "description": f"Tool '{tool}' was retried {count} consecutive times after failure — retry storm detected.",
                "evidence": f"tool={tool}, consecutive_failures={count}",
                "remediation": "Implement circuit breaker: stop retrying after 3 failures, apply exponential backoff, trip to OPEN state.",
            })

    return findings


def detect_failure_chains(entries):
    findings = []
    error_seq = []
    for e in entries:
        text = json.dumps(e) if isinstance(e, dict) else str(e)
        has_error = any(re.search(p, text, re.IGNORECASE) for p in ERROR_PATTERNS)
        if has_error:
            error_seq.append(text[:100])
        else:
            if len(error_seq) >= FAILURE_CHAIN_DEPTH:
                findings.append({
                    "id": f"{OWASP_ID}-FC{len(findings)+1:03d}",
                    "title": f"Cascading Failure Chain: {len(error_seq)} consecutive errors",
                    "severity": "HIGH",
                    "description": f"Detected a chain of {len(error_seq)} consecutive errors — cascading failure pattern.",
                    "evidence": " → ".join(error_seq[:3]),
                    "remediation": "Add bulkhead isolation between agent components. Implement fallback responses for downstream failures.",
                })
            error_seq = []

    # Check trailing error chain
    if len(error_seq) >= FAILURE_CHAIN_DEPTH:
        findings.append({
            "id": f"{OWASP_ID}-FC{len(findings)+1:03d}",
            "title": f"Unresolved Cascading Failure: {len(error_seq)} errors at end of log",
            "severity": "CRITICAL",
            "description": f"Log ends with an unresolved chain of {len(error_seq)} consecutive errors.",
            "evidence": " → ".join(error_seq[:3]),
            "remediation": "Implement circuit breaker that opens after N failures and returns cached/fallback responses.",
        })
    return findings


def audit_config(config):
    findings = []
    for key, severity, msg in CIRCUIT_BREAKER_CONTROLS:
        val = config.get(key)
        if val is None or val is False or val == 0 or val == "":
            findings.append({
                "id": f"{OWASP_ID}-CB{len(findings)+1:03d}",
                "title": f"Missing Circuit Breaker Control: {key}",
                "severity": severity,
                "description": msg,
                "evidence": f"config.{key}={val!r}",
                "remediation": f"Configure '{key}'. See: Martin Fowler Circuit Breaker pattern.",
            })
    # Check max_retries is not too high
    max_retries = config.get("max_retries", 0)
    if isinstance(max_retries, (int, float)) and max_retries > 10:
        findings.append({
            "id": f"{OWASP_ID}-CB{len(findings)+1:03d}",
            "title": f"Excessive Retry Limit: max_retries={max_retries}",
            "severity": "MEDIUM",
            "description": f"max_retries={max_retries} is too high — enables prolonged retry storms.",
            "evidence": f"max_retries={max_retries}",
            "remediation": "Set max_retries <= 3. Use exponential backoff with jitter.",
        })
    return findings


def main():
    p = argparse.ArgumentParser(description="ASI09 Agentic Cascading Failure Prevention")
    p.add_argument("--log-file", required=True, help="Agent execution log (JSONL)")
    p.add_argument("--config", help="JSON circuit breaker configuration")
    p.add_argument("--output", default="asi09_cascading_failure_report.json")
    args = p.parse_args()

    entries = parse_log(args.log_file)
    findings = detect_retry_storms(entries) + detect_failure_chains(entries)

    if args.config:
        config = json.loads(Path(args.config).read_text())
        findings += audit_config(config)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

    report = {
        "tool": TOOL_NAME, "owasp_id": OWASP_ID,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "log_entries_analyzed": len(entries),
        "findings": findings, "summary": {"total": len(findings), **counts},
    }
    print(json.dumps(report, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2))
    sys.exit(1 if counts["CRITICAL"] > 0 or counts["HIGH"] > 0 else 0)


if __name__ == "__main__":
    main()
