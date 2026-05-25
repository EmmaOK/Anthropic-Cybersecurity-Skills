#!/usr/bin/env python3
"""
AI Incident Readiness Assessment Agent

Scores an AI application's readiness to respond to security incidents across
five dimensions: Observability, Rollback Capability, Kill Switches,
Least-Privilege Posture, and Playbook Activation.

Subcommands:
  template  — Generate a blank readiness_config.json to fill in
  assess    — Score a filled-in config; output dimension scores and overall rating
  report    — Generate a prioritized remediation plan from an assessment

Usage:
    agent.py template --system "My AI App" --output readiness_config.json
    agent.py assess   --config  readiness_config.json --output readiness_assessment.json
    agent.py report   --assessment readiness_assessment.json --output remediation_plan.json

Exit codes:
    0 — overall readiness score >= 60 (AMBER or better)
    1 — overall readiness score < 60 (RED or CRITICAL) — use as CI deployment gate
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Control definitions — 25 controls across 5 dimensions
# Each entry: id, dimension, label, description, severity, remediation, companion_skill
# ---------------------------------------------------------------------------

CONTROLS: list[dict] = [
    # ── Observability (6) ──────────────────────────────────────────────────
    {
        "id": "OBS-01", "dimension": "observability",
        "key": "agent_telemetry_enabled",
        "label": "Agent telemetry enabled",
        "description": "Every agent action (tool calls, token usage, decisions) is emitted as structured telemetry.",
        "severity": "CRITICAL",
        "gap_detail": "Without agent telemetry there is no basis for anomaly detection or post-incident forensics.",
        "action": "Instrument the agent framework with OpenTelemetry spans for every tool call, model invocation, and decision branch.",
        "companion_skill": "ai-evaluation-security-and-observability-hardening",
    },
    {
        "id": "OBS-02", "dimension": "observability",
        "key": "llm_api_gateway_logging",
        "label": "LLM API gateway logging enabled",
        "description": "Every request and response at the LLM API gateway is logged with full prompt/completion content.",
        "severity": "CRITICAL",
        "gap_detail": "Prompt injection and goal hijacking are invisible without gateway-level logging.",
        "action": "Enable request/response logging on the LLM gateway (AWS Bedrock, Azure APIM, or custom proxy). Mask PII before storage.",
        "companion_skill": "ai-evaluation-security-and-observability-hardening",
    },
    {
        "id": "OBS-03", "dimension": "observability",
        "key": "tool_call_logging",
        "label": "Tool call arguments and results logged",
        "description": "Full tool call arguments and return values are captured for every tool invocation.",
        "severity": "HIGH",
        "gap_detail": "Data exfiltration via tool calls is undetectable without argument-level logging.",
        "action": "Add a middleware layer to the tool executor that logs tool name, arguments, result, and latency for every call.",
        "companion_skill": "ai-agent-framework-security",
    },
    {
        "id": "OBS-04", "dimension": "observability",
        "key": "logs_ingested_into_siem",
        "label": "Logs flowing into SIEM or log aggregator",
        "description": "Agent telemetry, gateway logs, and tool call logs are centrally aggregated and searchable.",
        "severity": "HIGH",
        "gap_detail": "Scattered logs across services make incident correlation impossible under time pressure.",
        "action": "Configure log shipping to a central SIEM (Splunk, Elastic, Sentinel). Verify end-to-end with a test event.",
        "companion_skill": "ai-evaluation-security-and-observability-hardening",
    },
    {
        "id": "OBS-05", "dimension": "observability",
        "key": "behavioral_baselines_established",
        "label": "Behavioral baselines established for each agent",
        "description": "Statistical profiles of normal tool call volumes, resource consumption, and output patterns exist for each agent.",
        "severity": "HIGH",
        "gap_detail": "Anomaly detection is impossible without a baseline — every alert will be a false positive or missed entirely.",
        "action": "Run each agent in staging for at least 7 days under representative load. Compute mean and stddev for tool call rates, token usage, and API call frequency. Store as baseline JSON.",
        "companion_skill": "rogue-agent-detection-and-containment",
    },
    {
        "id": "OBS-06", "dimension": "observability",
        "key": "log_retention_72h_or_more",
        "label": "Log retention >= 72 hours at full fidelity",
        "description": "Complete logs are retained for at least 72 hours before any compression or sampling.",
        "severity": "MEDIUM",
        "gap_detail": "Most AI incidents are detected hours after the triggering event — 72h retention is the minimum for viable forensics.",
        "action": "Set log retention policy to >= 72h at full fidelity. Extend to 30 days in hot storage for regulated environments.",
        "companion_skill": "ai-evaluation-security-and-observability-hardening",
    },

    # ── Rollback Capability (5) ────────────────────────────────────────────
    {
        "id": "ROL-01", "dimension": "rollback_capability",
        "key": "model_checkpoints_signed_and_stored",
        "label": "Model checkpoints signed and stored",
        "description": "Every promoted model version has a SHA-256 checksum and cryptographic signature stored in the model registry.",
        "severity": "CRITICAL",
        "gap_detail": "Without signed checkpoints, rollback destination integrity cannot be verified — you may restore to a poisoned version.",
        "action": "Implement checkpoint signing in the model promotion pipeline. Store signatures in the model registry alongside the artifact.",
        "companion_skill": "llm-data-and-model-poisoning-defense",
    },
    {
        "id": "ROL-02", "dimension": "rollback_capability",
        "key": "rag_corpus_snapshots_available",
        "label": "RAG corpus snapshots available and checksummed",
        "description": "Point-in-time snapshots of the RAG vector database and source documents exist with integrity checksums.",
        "severity": "HIGH",
        "gap_detail": "Indirect prompt injection via poisoned RAG documents cannot be eradicated without a clean corpus to restore from.",
        "action": "Schedule daily RAG corpus snapshots. Store source document checksums in a provenance manifest alongside each snapshot.",
        "companion_skill": "rag-pipeline-security-and-data-provenance",
    },
    {
        "id": "ROL-03", "dimension": "rollback_capability",
        "key": "mcp_tool_manifest_versioned_in_vcs",
        "label": "MCP tool manifests versioned in version control",
        "description": "Every MCP tool schema is tracked in Git with signed tags on each production deployment.",
        "severity": "HIGH",
        "gap_detail": "MCP tool compromise cannot be eradicated without a trusted previous version to restore from.",
        "action": "Store MCP tool manifests in Git. Tag every production deployment. Implement a manifest hash check in the deployment pipeline.",
        "companion_skill": "mcp-tool-poisoning-detection-and-defense",
    },
    {
        "id": "ROL-04", "dimension": "rollback_capability",
        "key": "rollback_tested_in_last_90_days",
        "label": "Rollback procedure tested within last 90 days",
        "description": "A full rollback (model and/or RAG corpus) has been executed and verified in staging within the last 90 days.",
        "severity": "CRITICAL",
        "gap_detail": "Untested rollbacks routinely fail under incident conditions — the most common readiness gap.",
        "action": "Schedule quarterly rollback drills. Document target version, execution steps, time-to-restore, and verification method. File the result.",
        "companion_skill": "ai-incident-response-playbook",
    },
    {
        "id": "ROL-05", "dimension": "rollback_capability",
        "key": "rollback_time_under_30min_documented",
        "label": "Rollback time < 30 minutes — documented and verified",
        "description": "The runbook documents restore time; timing has been verified in a drill to be under 30 minutes.",
        "severity": "MEDIUM",
        "gap_detail": "Rollbacks that take hours extend the blast radius of an active incident significantly.",
        "action": "Time the rollback drill end-to-end. If > 30 min, identify the bottleneck (checkpoint size, registry latency, approval steps) and optimize.",
        "companion_skill": "ai-incident-response-playbook",
    },

    # ── Kill Switches (4) ──────────────────────────────────────────────────
    {
        "id": "KSW-01", "dimension": "kill_switches",
        "key": "per_agent_kill_switch_exists",
        "label": "Per-agent kill switch implemented",
        "description": "Each production agent has a registered kill switch that can terminate it and revoke its credentials.",
        "severity": "CRITICAL",
        "gap_detail": "Without a kill switch, containing a rogue or hijacked agent requires manual intervention that takes minutes — not seconds.",
        "action": "Implement AgentKillSwitch from rogue-agent-detection-and-containment. Register every production agent PID or pod name at startup.",
        "companion_skill": "rogue-agent-detection-and-containment",
    },
    {
        "id": "KSW-02", "dimension": "kill_switches",
        "key": "kill_switch_tested_in_staging",
        "label": "Kill switch tested in staging environment",
        "description": "The kill switch has been executed against a live staging agent and confirmed to terminate it within the target time.",
        "severity": "CRITICAL",
        "gap_detail": "Kill switches that exist in code but have never fired in the target environment routinely fail at the worst moment.",
        "action": "Execute the kill switch against a staging agent. Record activation time (target: < 60s). Document the test run with timestamp and outcome.",
        "companion_skill": "rogue-agent-detection-and-containment",
    },
    {
        "id": "KSW-03", "dimension": "kill_switches",
        "key": "emergency_halt_all_agents_capability",
        "label": "Emergency halt-all-agents capability exists",
        "description": "A single command or button can terminate all running agents simultaneously in case of a fleet-wide incident.",
        "severity": "HIGH",
        "gap_detail": "Multi-agent collusion or a shared injection vector may require halting the entire agent fleet at once.",
        "action": "Implement emergency_halt_all() from rogue-agent-detection-and-containment. Wire it to a runbook step and a Slack slash command or PagerDuty webhook.",
        "companion_skill": "rogue-agent-detection-and-containment",
    },
    {
        "id": "KSW-04", "dimension": "kill_switches",
        "key": "kill_switch_activates_under_60s",
        "label": "Kill switch activation time < 60 seconds — verified",
        "description": "Measured time from trigger to agent process termination and credential revocation is under 60 seconds.",
        "severity": "HIGH",
        "gap_detail": "A 5-minute kill time allows a rogue agent to exfiltrate gigabytes or spawn dozens of subprocesses before containment.",
        "action": "Measure and record kill switch activation time during staging test. If > 60s, identify the slow step (credential revocation API, pod deletion grace period) and optimize.",
        "companion_skill": "rogue-agent-detection-and-containment",
    },

    # ── Least-Privilege Posture (5) ────────────────────────────────────────
    {
        "id": "LPP-01", "dimension": "least_privilege",
        "key": "tool_manifests_audited_for_scope",
        "label": "Tool manifests audited for least-privilege scope",
        "description": "Every agent's tool manifest has been reviewed; each tool is justified against the agent's declared task.",
        "severity": "HIGH",
        "gap_detail": "Overly broad tool manifests are the primary enabler of excessive agency and data exfiltration incidents.",
        "action": "Run llm-excessive-agency-prevention against each agent's tool manifest. Remove any tool not required by the declared task.",
        "companion_skill": "llm-excessive-agency-prevention",
    },
    {
        "id": "LPP-02", "dimension": "least_privilege",
        "key": "network_egress_policies_applied",
        "label": "Network egress policies restrict agent outbound traffic",
        "description": "Container or pod network policies allow agent egress only to an explicit allowlist of internal endpoints.",
        "severity": "CRITICAL",
        "gap_detail": "Without egress restrictions, any injected instruction can exfiltrate data to an attacker-controlled endpoint.",
        "action": "Apply a Kubernetes NetworkPolicy (or equivalent) that denies all egress except to explicitly allowlisted service endpoints. Verify with a test curl to an external IP.",
        "companion_skill": "ai-workload-infrastructure-hardening",
    },
    {
        "id": "LPP-03", "dimension": "least_privilege",
        "key": "no_agent_with_wildcard_permissions",
        "label": "No agent runs with wildcard tool or IAM permissions",
        "description": "No agent has access to wildcard tool scopes, admin IAM roles, or catch-all resource policies.",
        "severity": "CRITICAL",
        "gap_detail": "Wildcard permissions turn any agent compromise into a full system compromise.",
        "action": "Audit IAM policies and tool manifests for wildcards. Replace each wildcard with the minimum specific permissions the agent needs.",
        "companion_skill": "llm-excessive-agency-prevention",
    },
    {
        "id": "LPP-04", "dimension": "least_privilege",
        "key": "human_approval_gates_for_sensitive_tools",
        "label": "Human approval gates for sensitive tool calls",
        "description": "Tool calls that touch external endpoints, sensitive data, or destructive operations require explicit human approval before execution.",
        "severity": "HIGH",
        "gap_detail": "Fully autonomous sensitive actions remove the last human checkpoint that could catch a goal-hijacked or injected agent.",
        "action": "Identify tools classified as sensitive (network egress, data write, credential access). Wire them through the approvals workflow before execution.",
        "companion_skill": "ai-incident-response-playbook",
    },
    {
        "id": "LPP-05", "dimension": "least_privilege",
        "key": "credential_rotation_policy_exists",
        "label": "Credential rotation policy defined and automated",
        "description": "All credentials available to agents (API keys, DB passwords, cloud keys) rotate on a defined schedule, with immediate rotation capability for incidents.",
        "severity": "HIGH",
        "gap_detail": "Compromised credentials that are never rotated extend the attacker's access window indefinitely.",
        "action": "Implement automated credential rotation using a secrets manager (Vault, AWS Secrets Manager). Document the emergency rotation runbook for incident use.",
        "companion_skill": "ai-workload-infrastructure-hardening",
    },

    # ── Playbook Activation (5) ────────────────────────────────────────────
    {
        "id": "PBK-01", "dimension": "playbook_activation",
        "key": "playbooks_mapped_to_ai_threat_types",
        "label": "IR playbooks mapped to each AI threat type",
        "description": "Documented IR playbooks exist for each AI-specific incident type: prompt injection, goal hijacking, model poisoning, MCP compromise, rogue agent, data exfiltration.",
        "severity": "CRITICAL",
        "gap_detail": "General IT IR playbooks do not cover AI-specific containment steps (session flushing, kill switch activation, RAG corpus rollback).",
        "action": "Deploy ai-incident-response-playbook. Verify all six incident types are covered and linked from the incident command runbook.",
        "companion_skill": "ai-incident-response-playbook",
    },
    {
        "id": "PBK-02", "dimension": "playbook_activation",
        "key": "team_trained_on_ai_ir_playbooks",
        "label": "Team trained on AI-specific IR playbooks",
        "description": "Every on-call engineer and SOC analyst has reviewed the AI IR playbooks and knows which to invoke for which incident type.",
        "severity": "HIGH",
        "gap_detail": "Playbooks that only the author understands are useless during a 2am incident with the author unavailable.",
        "action": "Run a 90-minute training session covering the six AI IR playbook types. Record attendance. Include in on-call onboarding.",
        "companion_skill": "ai-incident-response-playbook",
    },
    {
        "id": "PBK-03", "dimension": "playbook_activation",
        "key": "approvals_workflow_configured",
        "label": "Approvals workflow configured for sensitive containment actions",
        "description": "The incident response approvals workflow is configured to require sign-off before executing destructive containment steps.",
        "severity": "MEDIUM",
        "gap_detail": "Without an approvals workflow, containment actions taken under pressure have no audit trail and no second pair of eyes.",
        "action": "Configure the approvals workflow (Phantom's approvals.py or equivalent). Define which containment actions require approval and who can approve.",
        "companion_skill": "ai-incident-response-playbook",
    },
    {
        "id": "PBK-04", "dimension": "playbook_activation",
        "key": "incident_command_structure_defined",
        "label": "Incident command structure defined for AI incidents",
        "description": "Roles are defined for AI security incidents: incident commander, AI platform lead, security analyst, comms lead, and executive escalation path.",
        "severity": "HIGH",
        "gap_detail": "AI incidents without a command structure devolve into coordination failures — multiple people taking conflicting containment actions.",
        "action": "Define an AI incident command card. Include: who declares an incident, who owns containment, who owns communications, and the escalation chain.",
        "companion_skill": "ai-incident-response-playbook",
    },
    {
        "id": "PBK-05", "dimension": "playbook_activation",
        "key": "playbook_tested_in_tabletop_exercise",
        "label": "AI IR playbook tested in a tabletop exercise",
        "description": "At least one tabletop exercise has been run against an AI-specific scenario (e.g. prompt injection, rogue agent) within the last 6 months.",
        "severity": "HIGH",
        "gap_detail": "Untested playbooks always have gaps — tabletop exercises surface them before a real incident does.",
        "action": "Run a 2-hour tabletop exercise against a prompt injection or rogue agent scenario. Document gaps found and update the playbook.",
        "companion_skill": "ai-incident-response-playbook",
    },
]

DIMENSIONS = ["observability", "rollback_capability", "kill_switches", "least_privilege", "playbook_activation"]

DIMENSION_LABELS = {
    "observability": "Observability",
    "rollback_capability": "Rollback Capability",
    "kill_switches": "Kill Switches",
    "least_privilege": "Least-Privilege Posture",
    "playbook_activation": "Playbook Activation",
}

# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def risk_label(score: int) -> str:
    if score >= 80:
        return "GREEN"
    if score >= 60:
        return "AMBER"
    if score >= 40:
        return "RED"
    return "CRITICAL"


def deployment_recommendation(overall_score: int, dim_scores: dict) -> str:
    critical_dims = [d for d, s in dim_scores.items() if s["risk"] == "CRITICAL"]
    if overall_score < 60:
        return (
            f"BLOCK — overall score {overall_score}/100 is below the 60-point deployment threshold. "
            f"Resolve all P1 gaps before promoting to production."
        )
    if critical_dims:
        labels = ", ".join(DIMENSION_LABELS[d] for d in critical_dims)
        return (
            f"CONDITIONAL — overall score is acceptable but {labels} "
            f"{'is' if len(critical_dims) == 1 else 'are'} CRITICAL. "
            f"Accept risk explicitly or remediate before deployment."
        )
    return f"PROCEED with monitoring — overall score {overall_score}/100 meets the minimum bar. Address AMBER gaps within 30 days."


def priority_label(severity: str, dim_score: int) -> str:
    if severity == "CRITICAL" or dim_score < 40:
        return "P1"
    if severity == "HIGH" or dim_score < 60:
        return "P2"
    if severity == "MEDIUM":
        return "P3"
    return "P4"


def resolution_deadline(priority: str) -> str:
    return {
        "P1": "Immediate — block production deployment",
        "P2": "Within 2 weeks",
        "P3": "Within 30 days",
        "P4": "Next sprint",
    }.get(priority, "Scheduled")


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_template(args: argparse.Namespace) -> int:
    template = {
        "system_name": args.system,
        "assessed_by": "",
        "assessment_date": datetime.now(timezone.utc).date().isoformat(),
        "_instructions": (
            "Set each control to true ONLY if it is verified to exist and function — "
            "not just planned or documented. Run: agent.py assess --config <this file>"
        ),
        "dimensions": {},
    }
    for dim in DIMENSIONS:
        dim_controls = {c["key"]: False for c in CONTROLS if c["dimension"] == dim}
        template["dimensions"][dim] = dim_controls

    output = json.dumps(template, indent=2)
    print(output)
    if args.output:
        Path(args.output).write_text(output + "\n")
        print(f"\n[template written to {args.output}]", file=sys.stderr)
    return 0


def cmd_assess(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    if not config_path.exists():
        print(json.dumps({"error": f"Config file not found: {args.config}"}))
        return 1

    config = json.loads(config_path.read_text())
    user_dims = config.get("dimensions", {})

    now = datetime.now(timezone.utc).isoformat()
    dim_scores: dict[str, dict] = {}
    all_gaps: list[dict] = []

    for dim in DIMENSIONS:
        dim_controls = [c for c in CONTROLS if c["dimension"] == dim]
        user_answers = user_dims.get(dim, {})
        passed = 0
        gaps = []

        for ctrl in dim_controls:
            value = user_answers.get(ctrl["key"], False)
            if value is True:
                passed += 1
            else:
                gaps.append({
                    "control_id": ctrl["id"],
                    "control": ctrl["label"],
                    "severity": ctrl["severity"],
                    "gap_detail": ctrl["gap_detail"],
                })

        total = len(dim_controls)
        score = round((passed / total) * 100) if total else 0
        dim_scores[dim] = {
            "label": DIMENSION_LABELS[dim],
            "score": score,
            "risk": risk_label(score),
            "passed": passed,
            "total": total,
            "gaps": gaps,
        }
        all_gaps.extend(gaps)

    scores_only = [s["score"] for s in dim_scores.values()]
    overall = round(sum(scores_only) / len(scores_only)) if scores_only else 0

    report = {
        "system_name": config.get("system_name", "Unknown"),
        "assessed_by": config.get("assessed_by", ""),
        "assessed_at": now,
        "overall_score": overall,
        "overall_risk": risk_label(overall),
        "deployment_recommendation": deployment_recommendation(overall, dim_scores),
        "dimensions": dim_scores,
        "total_controls": len(CONTROLS),
        "total_passed": sum(s["passed"] for s in dim_scores.values()),
        "total_gaps": len(all_gaps),
    }

    output = json.dumps(report, indent=2)
    print(output)
    if args.output:
        Path(args.output).write_text(output + "\n")

    return 0 if overall >= 60 else 1


def cmd_report(args: argparse.Namespace) -> int:
    assessment_path = Path(args.assessment)
    if not assessment_path.exists():
        print(json.dumps({"error": f"Assessment file not found: {args.assessment}"}))
        return 1

    assessment = json.loads(assessment_path.read_text())
    dim_scores = assessment.get("dimensions", {})

    remediation: list[dict] = []

    for ctrl in CONTROLS:
        dim = ctrl["dimension"]
        dim_data = dim_scores.get(dim, {})
        dim_score = dim_data.get("score", 0)

        # Check if this control is a gap (appears in dim_data["gaps"])
        gap_ids = {g["control_id"] for g in dim_data.get("gaps", [])}
        if ctrl["id"] not in gap_ids:
            continue

        priority = priority_label(ctrl["severity"], dim_score)
        remediation.append({
            "priority": priority,
            "control_id": ctrl["id"],
            "dimension": DIMENSION_LABELS[dim],
            "dimension_score": dim_score,
            "control": ctrl["label"],
            "severity": ctrl["severity"],
            "gap_detail": ctrl["gap_detail"],
            "action": ctrl["action"],
            "companion_skill": ctrl["companion_skill"],
            "resolution_deadline": resolution_deadline(priority),
        })

    # Sort: P1 first, then by severity weight, then by dimension score ascending
    severity_weight = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    priority_weight = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    remediation.sort(key=lambda x: (
        priority_weight.get(x["priority"], 9),
        severity_weight.get(x["severity"], 9),
        x["dimension_score"],
    ))

    # Group by companion skill to surface "fix-one-close-many" opportunities
    skill_groups: dict[str, list[str]] = {}
    for item in remediation:
        skill = item["companion_skill"]
        skill_groups.setdefault(skill, []).append(item["control_id"])

    quick_wins = [
        {"companion_skill": skill, "closes_controls": ids}
        for skill, ids in sorted(skill_groups.items(), key=lambda x: -len(x[1]))
        if len(ids) > 1
    ]

    report = {
        "system_name": assessment.get("system_name", "Unknown"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall_score": assessment.get("overall_score"),
        "overall_risk": assessment.get("overall_risk"),
        "deployment_recommendation": assessment.get("deployment_recommendation"),
        "total_gaps": len(remediation),
        "by_priority": {
            p: len([r for r in remediation if r["priority"] == p])
            for p in ["P1", "P2", "P3", "P4"]
        },
        "quick_wins": quick_wins,
        "remediation_plan": remediation,
    }

    output = json.dumps(report, indent=2)
    print(output)
    if args.output:
        Path(args.output).write_text(output + "\n")

    overall = assessment.get("overall_score", 100)
    return 0 if overall >= 60 else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="AI Incident Readiness Assessment Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # template
    t = sub.add_parser("template", help="Generate a blank readiness_config.json")
    t.add_argument("--system", default="My AI App", help="Name of the AI system being assessed")
    t.add_argument("--output", help="Write template to this file path")

    # assess
    a = sub.add_parser("assess", help="Score a filled-in readiness config")
    a.add_argument("--config", required=True, help="Path to filled-in readiness_config.json")
    a.add_argument("--output", help="Write assessment JSON to this file path")

    # report
    r = sub.add_parser("report", help="Generate a prioritized remediation plan from an assessment")
    r.add_argument("--assessment", required=True, help="Path to assessment JSON from 'assess'")
    r.add_argument("--output", help="Write remediation plan to this file path")

    args = parser.parse_args()
    dispatch = {"template": cmd_template, "assess": cmd_assess, "report": cmd_report}
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
