#!/usr/bin/env python3
"""
Rogue Agent Detection and Containment Agent

Analyses an agent's action/telemetry log to detect rogue behaviour:
  - Reward hacking (optimizing proxy metrics via unintended shortcuts)
  - Behavioural drift from a baseline window
  - Unauthorized self-replication (spawning subprocesses / child agents)
  - Resource hoarding (token, API call, or time budget exhaustion)
  - Multi-agent collusion (coordinated patterns across agent IDs)

Usage:
    agent.py --log agent_telemetry.jsonl --output report.json
    agent.py --log agent_telemetry.jsonl --baseline-window 50 --z-threshold 3.0
    agent.py --log agent_telemetry.jsonl --agent-id agent-7 --output rogue_report.json

Telemetry log format (JSONL):
    {"timestamp": "2026-04-27T10:00:00Z", "agent_id": "agent-1",
     "action": "web_search", "tokens_used": 120, "reward": 0.8,
     "duration_ms": 340, "spawned_agents": []}

Based on OWASP Agentic Top 10 (ASI10:2026 Rogue Agents).
"""

import argparse
import json
import math
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SELF_REPLICATION_ACTIONS = {
    "spawn_agent", "create_agent", "fork", "subprocess_create", "agent_launch",
    "deploy_agent", "clone_agent", "replicate",
}

RESOURCE_HOARDING_ACTIONS = {
    "bulk_download", "crawl_all", "enumerate_all", "export_everything",
    "dump_database", "archive_all",
}

REWARD_HACK_PATTERNS = [
    "delete_backups",  # optimise storage metric by deleting instead of compressing
    "mark_complete",   # mark tasks done without completing them
    "clear_queue",     # remove items to reduce queue length
    "disable_monitor", # turn off the metric being optimised
    "spoof_metric",
]


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def stdev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = mean(values)
    return math.sqrt(sum((v - m) ** 2 for v in values) / (len(values) - 1))


def load_log(log_path: str, agent_id: str | None = None) -> list[dict]:
    path = Path(log_path)
    if not path.exists():
        print(f"[error] Log not found: {log_path}", file=sys.stderr)
        sys.exit(1)
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if agent_id and record.get("agent_id") != agent_id:
                    continue
                records.append(record)
            except json.JSONDecodeError:
                continue
    return records


def detect_reward_hacking(records: list[dict]) -> list[dict]:
    findings = []
    for i, r in enumerate(records):
        action = r.get("action", "")
        for hack_pattern in REWARD_HACK_PATTERNS:
            if hack_pattern in action.lower():
                findings.append({
                    "record_index": i,
                    "agent_id": r.get("agent_id"),
                    "timestamp": r.get("timestamp"),
                    "action": action,
                    "pattern": hack_pattern,
                    "severity": "HIGH",
                    "type": "REWARD_HACKING",
                    "detail": f"Action '{action}' matches reward hacking pattern '{hack_pattern}'",
                })
    return findings


def detect_self_replication(records: list[dict]) -> list[dict]:
    findings = []
    for i, r in enumerate(records):
        action = r.get("action", "")
        spawned = r.get("spawned_agents", [])

        if action.lower() in SELF_REPLICATION_ACTIONS:
            findings.append({
                "record_index": i,
                "agent_id": r.get("agent_id"),
                "timestamp": r.get("timestamp"),
                "action": action,
                "severity": "CRITICAL",
                "type": "SELF_REPLICATION",
                "detail": f"Agent attempted to spawn sub-agents via action '{action}'",
            })

        if spawned:
            findings.append({
                "record_index": i,
                "agent_id": r.get("agent_id"),
                "timestamp": r.get("timestamp"),
                "spawned_agents": spawned,
                "severity": "CRITICAL",
                "type": "UNAUTHORIZED_SPAWN",
                "detail": f"Agent spawned {len(spawned)} child agent(s) without recorded authorization",
            })

    return findings


def detect_behavioural_drift(records: list[dict], baseline_window: int, z_threshold: float) -> list[dict]:
    findings = []

    token_series = [r.get("tokens_used", 0) for r in records if "tokens_used" in r]
    duration_series = [r.get("duration_ms", 0) for r in records if "duration_ms" in r]

    for series, metric in [(token_series, "tokens_used"), (duration_series, "duration_ms")]:
        if len(series) <= baseline_window:
            continue
        baseline = series[:baseline_window]
        b_mean = mean(baseline)
        b_std = stdev(baseline)
        if b_std < 1:
            continue

        for i, val in enumerate(series[baseline_window:], start=baseline_window):
            z = abs(val - b_mean) / b_std
            if z > z_threshold:
                findings.append({
                    "record_index": i,
                    "agent_id": records[i].get("agent_id"),
                    "timestamp": records[i].get("timestamp"),
                    "metric": metric,
                    "value": val,
                    "baseline_mean": round(b_mean, 2),
                    "z_score": round(z, 2),
                    "severity": "HIGH" if z > z_threshold * 1.5 else "MEDIUM",
                    "type": "BEHAVIOURAL_DRIFT",
                    "detail": f"{metric} value {val} is {z:.1f} standard deviations from baseline",
                })

    return findings


def detect_resource_hoarding(records: list[dict]) -> list[dict]:
    findings = []
    for i, r in enumerate(records):
        action = r.get("action", "")
        if action.lower() in RESOURCE_HOARDING_ACTIONS:
            findings.append({
                "record_index": i,
                "agent_id": r.get("agent_id"),
                "timestamp": r.get("timestamp"),
                "action": action,
                "severity": "HIGH",
                "type": "RESOURCE_HOARDING",
                "detail": f"Action '{action}' suggests bulk resource acquisition",
            })
    return findings


def detect_collusion(records: list[dict], window_seconds: int = 5) -> list[dict]:
    """Detect suspiciously coordinated timing across different agent IDs."""
    findings = []
    agents_by_time: dict[str, list[str]] = defaultdict(list)

    for r in records:
        ts = r.get("timestamp", "")
        if not ts:
            continue
        bucket = ts[:16]  # group by minute
        agent = r.get("agent_id", "")
        if agent:
            agents_by_time[bucket].append(agent)

    for bucket, agents in agents_by_time.items():
        unique_agents = set(agents)
        if len(unique_agents) >= 3 and len(agents) >= 5:
            findings.append({
                "time_bucket": bucket,
                "agents_active": list(unique_agents),
                "action_count": len(agents),
                "severity": "MEDIUM",
                "type": "POTENTIAL_COLLUSION",
                "detail": f"{len(unique_agents)} agents made {len(agents)} actions in the same minute — possible coordination",
            })

    return findings


def generate_report(args, records: list, results: dict) -> dict:
    all_findings = (
        results["reward_hacking"]
        + results["self_replication"]
        + results["drift"]
        + results["hoarding"]
        + results["collusion"]
    )
    critical = [f for f in all_findings if f.get("severity") == "CRITICAL"]
    high = [f for f in all_findings if f.get("severity") == "HIGH"]

    overall_risk = (
        "CRITICAL" if critical
        else "HIGH" if high
        else "MEDIUM" if all_findings
        else "LOW"
    )

    return {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "log_file": args.log,
        "agent_id_filter": getattr(args, "agent_id", None),
        "records_analysed": len(records),
        "findings": {
            "reward_hacking": len(results["reward_hacking"]),
            "self_replication": len(results["self_replication"]),
            "behavioural_drift": len(results["drift"]),
            "resource_hoarding": len(results["hoarding"]),
            "collusion_signals": len(results["collusion"]),
        },
        "all_findings": all_findings,
        "overall_risk": overall_risk,
        "recommendation": (
            "Rogue agent behaviour detected — engage kill switch, isolate agent, "
            "and audit all actions taken since first anomaly."
            if overall_risk in ("CRITICAL", "HIGH")
            else "No rogue agent indicators detected in the provided log."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="Rogue Agent Detection and Containment Agent")
    parser.add_argument("--log", required=True, help="Agent telemetry log in JSONL format")
    parser.add_argument("--agent-id", help="Filter to a specific agent ID")
    parser.add_argument("--baseline-window", type=int, default=30,
                        help="Number of records used as behavioural baseline (default: 30)")
    parser.add_argument("--z-threshold", type=float, default=3.0,
                        help="Z-score threshold for drift detection (default: 3.0)")
    parser.add_argument("--output", default="rogue_agent_report.json")
    args = parser.parse_args()

    print(f"[*] Loading telemetry from: {args.log}")
    records = load_log(args.log, args.agent_id)
    print(f"[*] Records loaded: {len(records)}")

    results = {
        "reward_hacking": detect_reward_hacking(records),
        "self_replication": detect_self_replication(records),
        "drift": detect_behavioural_drift(records, args.baseline_window, args.z_threshold),
        "hoarding": detect_resource_hoarding(records),
        "collusion": detect_collusion(records),
    }

    report = generate_report(args, records, results)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\n[*] Report saved to {args.output}")

    if report["overall_risk"] in ("CRITICAL", "HIGH"):
        sys.exit(1)


if __name__ == "__main__":
    main()
