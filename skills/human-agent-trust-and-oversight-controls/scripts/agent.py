#!/usr/bin/env python3
"""ASI07 - Human-Agent Trust & Oversight Controls: Audit agent config for approval gates and kill-switch."""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

OWASP_ID = "ASI07"
TOOL_NAME = "phantom-human-agent-oversight"

HIGH_IMPACT_ACTIONS = [
    "delete", "drop", "destroy", "format", "wipe",
    "send_email", "send_message", "post", "publish",
    "transfer", "payment", "purchase", "withdraw",
    "deploy", "rollback", "shutdown", "restart",
    "create_user", "delete_user", "grant_permission",
    "execute_code", "run_script", "shell",
]

OVERSIGHT_CONTROLS = [
    ("human_approval_required", "CRITICAL", "No human approval gate configured for any actions"),
    ("interrupt_mechanism", "HIGH", "No interrupt/pause mechanism — agent cannot be stopped mid-task"),
    ("kill_switch", "HIGH", "No kill switch — agent cannot be terminated immediately"),
    ("audit_log_enabled", "HIGH", "Audit logging not enabled — no record of agent decisions"),
    ("max_autonomous_steps", "MEDIUM", "No limit on autonomous steps — agent can loop indefinitely"),
    ("confirmation_timeout_s", "MEDIUM", "No confirmation timeout set — pending approvals never expire"),
]

# Log patterns indicating autonomous high-impact actions (no approval)
AUTO_ACTION_PATTERNS = [
    (r"(executed|completed|performed).{0,50}(delete|destroy|send|deploy|payment|transfer)", "HIGH", "High-impact action executed without approval log entry"),
    (r"(approval|confirm|authorized).{0,100}(skip|bypass|auto|automatic)", "CRITICAL", "Approval mechanism bypassed"),
    (r"(kill|stop|halt|interrupt).{0,50}(fail|error|refused|not found)", "HIGH", "Kill switch failed or unavailable"),
    (r"step_count\s*[=:]\s*([5-9][0-9]|[1-9][0-9]{2,})", "MEDIUM", "High autonomous step count detected"),
]


def audit_config(config):
    findings = []
    for key, severity, msg in OVERSIGHT_CONTROLS:
        val = config.get(key)
        if val is None or val is False or val == 0 or val == "":
            findings.append({
                "id": f"{OWASP_ID}-{len(findings)+1:03d}",
                "title": f"Missing Oversight Control: {key}",
                "severity": severity,
                "description": msg,
                "evidence": f"config.{key}={val!r}",
                "remediation": f"Configure '{key}' in your agent oversight settings. Reference: OWASP Agentic ASI07.",
            })

    # Check that high-impact actions have approval gates
    approval_gates = config.get("approval_gates", {})
    tools = config.get("tools", config.get("allowed_tools", []))
    for tool in tools:
        tool_name = tool if isinstance(tool, str) else tool.get("name", "")
        for action in HIGH_IMPACT_ACTIONS:
            if action in tool_name.lower():
                if not approval_gates.get(tool_name) and not approval_gates.get("*"):
                    findings.append({
                        "id": f"{OWASP_ID}-{len(findings)+1:03d}",
                        "title": f"High-Impact Tool Without Approval Gate: '{tool_name}'",
                        "severity": "HIGH",
                        "description": f"Tool '{tool_name}' performs high-impact action '{action}' but has no approval gate.",
                        "evidence": f"tool={tool_name}, approval_gates={list(approval_gates.keys())}",
                        "remediation": "Add human approval gates for all destructive, financial, and communication tools.",
                    })
    return findings


def scan_log(log_path):
    findings = []
    path = Path(log_path)
    if not path.exists():
        return [{"id": f"{OWASP_ID}-E001", "title": "Log file not found", "severity": "MEDIUM",
                 "description": f"Log file {log_path} does not exist.", "evidence": log_path,
                 "remediation": "Ensure agent audit logs are enabled and persisted."}]

    content = path.read_text(errors="replace")
    approval_events = len(re.findall(r"(approval|authorized|confirmed|human.approved)", content, re.I))
    total_actions = len(re.findall(r"(executed|completed|performed|action)", content, re.I))

    if total_actions > 10 and approval_events == 0:
        findings.append({
            "id": f"{OWASP_ID}-L001",
            "title": "No Human Approval Events in Log",
            "severity": "HIGH",
            "description": f"Log contains {total_actions} action events but 0 approval events — agent may be acting fully autonomously.",
            "evidence": f"total_actions={total_actions}, approval_events={approval_events}",
            "remediation": "Implement mandatory human approval logging for all agent decisions.",
        })

    for pattern, severity, desc in AUTO_ACTION_PATTERNS:
        m = re.search(pattern, content, re.IGNORECASE)
        if m:
            findings.append({
                "id": f"{OWASP_ID}-L{len(findings)+1:03d}",
                "title": f"Oversight Violation: {desc}",
                "severity": severity,
                "description": desc,
                "evidence": content[max(0, m.start()-100):m.end()+100].strip()[:300],
                "remediation": "Ensure human oversight is enforced in the orchestration layer, not just configuration.",
            })
    return findings


def main():
    p = argparse.ArgumentParser(description="ASI07 Human-Agent Trust & Oversight Controls")
    p.add_argument("--config", help="JSON agent configuration file")
    p.add_argument("--log-file", help="Agent execution log (JSON/JSONL/text)")
    p.add_argument("--output", default="asi07_oversight_report.json")
    args = p.parse_args()
    if not args.config and not args.log_file:
        print("[ASI07] Provide --config or --log-file", file=sys.stderr)
        sys.exit(2)
    findings = []
    if args.config:
        config = json.loads(Path(args.config).read_text())
        findings += audit_config(config)
    if args.log_file:
        findings += scan_log(args.log_file)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1
    report = {
        "tool": TOOL_NAME, "owasp_id": OWASP_ID,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings, "summary": {"total": len(findings), **counts},
    }
    print(json.dumps(report, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2))
    sys.exit(1 if counts["CRITICAL"] > 0 or counts["HIGH"] > 0 else 0)


if __name__ == "__main__":
    main()
