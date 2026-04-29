#!/usr/bin/env python3
"""
Agent Goal Hijacking Detection Agent

Analyses an agent's conversation/action log against a declared goal to detect
goal drift caused by adversarial content in retrieved documents, tool outputs,
or user messages. Uses keyword overlap scoring and pattern matching to flag
actions that deviate from the stated objective.

Usage:
    agent.py --goal "help the user manage their calendar" --log agent_log.jsonl
    agent.py --goal "summarize customer emails" --log actions.jsonl --output report.json
    agent.py --goal "answer coding questions" --log chat.jsonl --strict

Log format (JSONL, one record per line):
    {"role": "tool_result", "tool": "email_send", "content": "...", "source": "external_doc"}
    {"role": "assistant", "content": "I will now send an email to...", "action": "email_send"}
    {"role": "user",      "content": "Summarize my inbox"}

Based on OWASP Agentic Top 10 (ASI01:2026 Agent Goal Hijack).
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Injection patterns that indicate goal hijacking attempts ──────────────────
HIJACK_PATTERNS = [
    r"(?i)(ignore|disregard|forget).{0,30}(previous|prior|above|original).{0,20}(instructions?|task|goal|objective)",
    r"(?i)(new|revised|updated).{0,20}(task|objective|goal|instruction):",
    r"(?i)(you (are|must|should) now|act as|switch to).{0,40}",
    r"(?i)(instead (of|,)).{0,40}(do|perform|execute|send|delete|forward)",
    r"(?i)(hidden|secret|real) (instruction|task|command|order)",
    r"(?i)system:\s*(ignore|override|bypass)",
    r"(?i)\[INJECT\]|\[OVERRIDE\]|\[NEW TASK\]",
]

# ── High-risk actions that require goal alignment validation ──────────────────
HIGH_RISK_ACTIONS = {
    "email_send", "send_email", "file_delete", "delete_file", "payment_initiate",
    "make_payment", "create_user", "modify_permissions", "shell_exec", "bash",
    "exfiltrate", "forward_email", "share_document", "post_message",
}


def tokenize(text: str) -> set[str]:
    return set(re.sub(r"[^a-z0-9\s]", " ", text.lower()).split())


def goal_overlap(goal_tokens: set[str], action_text: str, threshold: float) -> tuple[float, bool]:
    action_tokens = tokenize(action_text)
    if not action_tokens:
        return 0.0, False
    overlap = len(goal_tokens & action_tokens) / len(action_tokens)
    return round(overlap, 3), overlap >= threshold


def scan_log(log_path: str, goal: str, threshold: float, strict: bool) -> dict:
    path = Path(log_path)
    if not path.exists():
        return {"error": f"Log file not found: {log_path}"}

    goal_tokens = tokenize(goal)
    goal_keywords = {t for t in goal_tokens if len(t) > 3}

    drift_events = []
    injection_events = []
    total_entries = 0

    with open(path) as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            total_entries += 1

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                entry = {"role": "unknown", "content": line}

            content = entry.get("content", "")
            role = entry.get("role", "")
            action = entry.get("action", entry.get("tool", ""))
            source = entry.get("source", "unknown")

            # Check for injection patterns in all external content
            if role in ("tool_result", "user", "document", "retrieved") or source != "assistant":
                for pattern in HIJACK_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        injection_events.append({
                            "line": i + 1,
                            "role": role,
                            "source": source,
                            "pattern_matched": pattern[:70],
                            "content_preview": content[:200],
                            "severity": "HIGH",
                            "type": "INJECTION_PATTERN",
                        })
                        break

            # Check goal alignment for assistant actions
            if role == "assistant" or action:
                overlap, aligned = goal_overlap(goal_keywords, content + " " + action, threshold)
                is_high_risk = action.lower() in HIGH_RISK_ACTIONS if action else False

                if not aligned and (is_high_risk or strict):
                    drift_events.append({
                        "line": i + 1,
                        "role": role,
                        "action": action,
                        "goal_overlap": overlap,
                        "threshold": threshold,
                        "content_preview": content[:200],
                        "severity": "CRITICAL" if is_high_risk else "MEDIUM",
                        "type": "GOAL_DRIFT",
                        "detail": (
                            f"High-risk action '{action}' taken with low goal alignment ({overlap:.2f})"
                            if is_high_risk
                            else f"Assistant action has low goal overlap ({overlap:.2f} < {threshold})"
                        ),
                    })

    return {
        "total_log_entries": total_entries,
        "goal": goal,
        "alignment_threshold": threshold,
        "injection_events": len(injection_events),
        "goal_drift_events": len(drift_events),
        "injection_findings": injection_events,
        "drift_findings": drift_events,
        "risk": (
            "CRITICAL" if any(e["severity"] == "CRITICAL" for e in drift_events)
            else "HIGH" if injection_events or drift_events
            else "LOW"
        ),
    }


def generate_report(args, scan_result: dict) -> dict:
    return {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "log_file": args.log,
        "declared_goal": args.goal,
        "scan_result": scan_result,
        "recommendation": (
            "Goal hijacking indicators detected — review flagged log entries, "
            "enforce confirmation gates before high-risk actions, and add provenance "
            "tracking for external context sources."
            if scan_result.get("risk") in ("CRITICAL", "HIGH")
            else "No goal hijacking patterns detected in the provided log."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="Agent Goal Hijacking Detection Agent")
    parser.add_argument("--goal", required=True, help="Declared goal of the agent (quoted string)")
    parser.add_argument("--log", required=True, help="Agent action/conversation log in JSONL format")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.15,
        help="Minimum keyword overlap ratio for goal alignment (default: 0.15)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Flag all low-overlap actions, not just high-risk ones",
    )
    parser.add_argument("--output", default="goal_hijacking_report.json")
    args = parser.parse_args()

    print(f"[*] Declared goal: {args.goal}")
    print(f"[*] Scanning log: {args.log}")
    print(f"[*] Alignment threshold: {args.threshold}")

    scan_result = scan_log(args.log, args.goal, args.threshold, args.strict)
    report = generate_report(args, scan_result)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\n[*] Report saved to {args.output}")

    if scan_result.get("risk") in ("CRITICAL", "HIGH"):
        sys.exit(1)


if __name__ == "__main__":
    main()
