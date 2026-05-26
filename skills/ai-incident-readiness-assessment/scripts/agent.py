#!/usr/bin/env python3
"""
AI Incident Readiness Assessment Agent

Scores an AI application's readiness to respond to security incidents across
five dimensions: Observability, Rollback Capability, Kill Switches,
Least-Privilege Posture, and Playbook Activation.

Subcommands:
  template           — Generate a blank readiness_config.json to fill in (machine format)
  assess             — Score a filled-in config; output dimension scores and overall rating
  report             — Generate a prioritized remediation plan from an assessment
  questionnaire      — Generate a human-readable Markdown questionnaire for project owners
  score-questionnaire — Parse a filled-in questionnaire and produce a scored assessment

Usage:
    agent.py template              --system "My AI App" --output readiness_config.json
    agent.py assess                --config readiness_config.json --output assessment.json
    agent.py report                --assessment assessment.json --output remediation_plan.json
    agent.py questionnaire         --system "My AI App" --owner "Jane Smith" --output questionnaire.md
    agent.py score-questionnaire   --questionnaire filled_questionnaire.md --output assessment.json

Exit codes:
    0 — overall readiness score >= 60 (AMBER or better)
    1 — overall readiness score < 60 (RED or CRITICAL) — use as CI deployment gate
"""

import argparse
import json
import re
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
# Questionnaire — plain-language questions mapped to control keys
# ---------------------------------------------------------------------------

QUESTIONNAIRE_SECTIONS = [
    {
        "dimension": "observability",
        "title": "Section 1: Observability",
        "intro": (
            "This section checks whether your team can see what the AI is doing in real time "
            "and reconstruct events after an incident. Without visibility, any security problem "
            "is invisible until it causes damage."
        ),
        "questions": [
            {
                "key": "agent_telemetry_enabled",
                "number": "1.1",
                "title": "Agent Activity Logging",
                "question": (
                    "Does the AI agent record every action it takes — every tool it calls, "
                    "every decision it makes, every response it produces — as structured logs?"
                ),
                "what_counts": (
                    "Yes: structured JSON/JSONL logs per tool call, stored somewhere retrievable. "
                    "No: only error logs, or no logging at all."
                ),
                "evidence_prompt": "Link to logging config, example log entry, or monitoring dashboard.",
            },
            {
                "key": "llm_api_gateway_logging",
                "number": "1.2",
                "title": "LLM API Gateway Logging",
                "question": (
                    "Are the full prompts sent to the AI model and its responses logged "
                    "at the API gateway or proxy layer — before the agent acts on them?"
                ),
                "what_counts": (
                    "Yes: request/response bodies captured at a gateway or proxy with PII masking. "
                    "No: only application-level logs, or no prompt/completion logging."
                ),
                "evidence_prompt": "Gateway config, proxy setup, or logging middleware reference.",
            },
            {
                "key": "tool_call_logging",
                "number": "1.3",
                "title": "Tool Call Argument Logging",
                "question": (
                    "Are the full arguments passed to each tool call — and the results returned — "
                    "captured in your logs?"
                ),
                "what_counts": (
                    "Yes: argument-level capture for every tool invocation, not just the tool name. "
                    "No: only tool names logged, or no tool-level logging."
                ),
                "evidence_prompt": "Log sample showing tool name + arguments + result.",
            },
            {
                "key": "logs_ingested_into_siem",
                "number": "1.4",
                "title": "Centralised Log Aggregation",
                "question": (
                    "Are logs from all parts of the AI system (agent, API gateway, tools) "
                    "collected in a single place where your security team can search them?"
                ),
                "what_counts": (
                    "Yes: logs ship to a SIEM, Splunk, Elastic, CloudWatch Logs Insights, "
                    "or equivalent centralised store. "
                    "No: logs live only on individual servers or services."
                ),
                "evidence_prompt": "Name of the log aggregation platform and which services feed into it.",
            },
            {
                "key": "behavioral_baselines_established",
                "number": "1.5",
                "title": "Behavioural Baselines",
                "question": (
                    "Have you measured what 'normal' looks like for this AI agent — "
                    "typical tool call rates, resource usage, and output patterns — "
                    "so that unusual behaviour stands out?"
                ),
                "what_counts": (
                    "Yes: documented baseline metrics (e.g. 'agent calls search_items ~40 times/hour') "
                    "stored and used to configure alerts. "
                    "No: no baseline established; anomaly detection is not configured."
                ),
                "evidence_prompt": "Baseline document or alert threshold configuration.",
            },
            {
                "key": "log_retention_72h_or_more",
                "number": "1.6",
                "title": "Log Retention Policy",
                "question": (
                    "Are full-fidelity logs kept for at least 72 hours before any "
                    "compression, sampling, or deletion?"
                ),
                "what_counts": (
                    "Yes: written retention policy of >= 72 hours at full fidelity. "
                    "No: logs roll over faster, are sampled, or no retention policy exists."
                ),
                "evidence_prompt": "Retention policy document or log storage config.",
            },
        ],
    },
    {
        "dimension": "rollback_capability",
        "title": "Section 2: Rollback Capability",
        "intro": (
            "This section checks whether you can restore the AI system to a known-good state "
            "after an incident — whether that means rolling back the model, the data it reads from, "
            "or the tools it uses."
        ),
        "questions": [
            {
                "key": "model_checkpoints_signed_and_stored",
                "number": "2.1",
                "title": "Model / Configuration Version Control",
                "question": (
                    "Is every version of your AI model configuration — including the system prompt, "
                    "model parameters, and any fine-tuning — stored with a checksum or signature "
                    "so you can verify and restore a previous version?"
                ),
                "what_counts": (
                    "Yes: model artifacts or configuration files are versioned, tagged, and "
                    "integrity-checked in a registry or version control system. "
                    "No: configuration lives only in environment variables or undocumented settings."
                ),
                "evidence_prompt": "Model registry URL, Git tag strategy, or versioning runbook.",
            },
            {
                "key": "rag_corpus_snapshots_available",
                "number": "2.2",
                "title": "Knowledge Base / RAG Corpus Snapshots",
                "question": (
                    "If your AI reads from a knowledge base, document store, or vector database, "
                    "are point-in-time snapshots of that data available so you can restore a "
                    "clean version if documents are tampered with?"
                ),
                "what_counts": (
                    "Yes: scheduled snapshots exist with checksums. "
                    "No: no snapshots; or not applicable (agent does not use a knowledge base)."
                ),
                "evidence_prompt": "Snapshot schedule and storage location, or 'N/A — no RAG'.",
            },
            {
                "key": "mcp_tool_manifest_versioned_in_vcs",
                "number": "2.3",
                "title": "Tool Definition Version Control",
                "question": (
                    "Are the definitions of all tools available to the AI agent — what they do, "
                    "what parameters they accept — tracked in version control with a record "
                    "of every change?"
                ),
                "what_counts": (
                    "Yes: tool manifests or schemas are in Git with tagged production deployments. "
                    "No: tool definitions are not versioned or only exist at runtime."
                ),
                "evidence_prompt": "Git repository and tagging convention for tool manifests.",
            },
            {
                "key": "rollback_tested_in_last_90_days",
                "number": "2.4",
                "title": "Rollback Drill",
                "question": (
                    "Has your team actually performed a rollback — restoring the AI system "
                    "to a previous version — within the last 90 days, in a test or staging environment?"
                ),
                "what_counts": (
                    "Yes: a documented drill was completed with a record of who ran it, "
                    "what was restored, and how long it took. "
                    "No: rollback has never been tested, or was tested more than 90 days ago."
                ),
                "evidence_prompt": "Date of last drill, who ran it, and what was restored.",
            },
            {
                "key": "rollback_time_under_30min_documented",
                "number": "2.5",
                "title": "Rollback Time Target",
                "question": (
                    "Has the rollback procedure been timed, and is the end-to-end time "
                    "documented as under 30 minutes?"
                ),
                "what_counts": (
                    "Yes: timed during a drill, documented result is < 30 min. "
                    "No: never timed, or documented time exceeds 30 minutes."
                ),
                "evidence_prompt": "Drill record showing measured restore time.",
            },
        ],
    },
    {
        "dimension": "kill_switches",
        "title": "Section 3: Kill Switches",
        "intro": (
            "This section checks whether your team can stop the AI agent quickly — within 60 seconds — "
            "if it starts doing something harmful. A kill switch that has never been tested "
            "should be treated as non-existent."
        ),
        "questions": [
            {
                "key": "per_agent_kill_switch_exists",
                "number": "3.1",
                "title": "Kill Switch Implementation",
                "question": (
                    "Is there a pre-built, single command or button that can immediately stop "
                    "the AI agent and revoke its access credentials — without requiring a developer "
                    "to manually find and kill a process?"
                ),
                "what_counts": (
                    "Yes: a script, admin endpoint, or runbook step exists that terminates "
                    "the agent and revokes credentials in one action. "
                    "No: stopping the agent requires SSH access, finding PIDs manually, "
                    "or multiple steps that take more than a few minutes."
                ),
                "evidence_prompt": "Script location, admin endpoint URL, or runbook section reference.",
            },
            {
                "key": "kill_switch_tested_in_staging",
                "number": "3.2",
                "title": "Kill Switch Test Record",
                "question": (
                    "Has the kill switch been executed against a running instance of the agent "
                    "in a staging or test environment, with the result documented?"
                ),
                "what_counts": (
                    "Yes: a test run record exists showing the date, who ran it, "
                    "and the measured time from trigger to confirmed termination. "
                    "No: never tested."
                ),
                "evidence_prompt": "Date of last test, engineer name, measured termination time in seconds.",
            },
            {
                "key": "emergency_halt_all_agents_capability",
                "number": "3.3",
                "title": "Fleet-Wide Emergency Halt",
                "question": (
                    "If multiple AI agents are running, is there a single command or action "
                    "that can stop all of them simultaneously?"
                ),
                "what_counts": (
                    "Yes: an 'emergency halt all' mechanism exists and is documented. "
                    "No: each agent must be stopped individually. "
                    "N/A: only one agent runs."
                ),
                "evidence_prompt": "Command or runbook reference, or 'N/A — single agent'.",
            },
            {
                "key": "kill_switch_activates_under_60s",
                "number": "3.4",
                "title": "Kill Switch Speed",
                "question": (
                    "Has the time from triggering the kill switch to confirmed agent termination "
                    "and credential revocation been measured at under 60 seconds?"
                ),
                "what_counts": (
                    "Yes: timed during a staging test, documented result is < 60 seconds. "
                    "No: never timed, or measured time exceeds 60 seconds."
                ),
                "evidence_prompt": "Measured time from test record (seconds).",
            },
        ],
    },
    {
        "dimension": "least_privilege",
        "title": "Section 4: Least-Privilege Posture",
        "intro": (
            "This section checks whether the AI agent has been given only the access it needs "
            "to do its job — nothing more. Overly broad permissions are the most common enabler "
            "of data exfiltration and unexpected agent behaviour."
        ),
        "questions": [
            {
                "key": "tool_manifests_audited_for_scope",
                "number": "4.1",
                "title": "Tool Access Review",
                "question": (
                    "Has someone reviewed the complete list of tools and APIs available to the "
                    "AI agent and confirmed that each one is required for the agent's declared purpose?"
                ),
                "what_counts": (
                    "Yes: a documented review exists, signed off by a technical lead, "
                    "with unjustified tools removed. "
                    "No: no review has been done; the agent has access to whatever was convenient."
                ),
                "evidence_prompt": "Date of review, reviewer name, and resulting tool manifest.",
            },
            {
                "key": "network_egress_policies_applied",
                "number": "4.2",
                "title": "Network Egress Restrictions",
                "question": (
                    "Is the AI agent's ability to make outbound network calls restricted to "
                    "a defined allowlist of internal services — blocking calls to arbitrary "
                    "external URLs?"
                ),
                "what_counts": (
                    "Yes: a network policy (firewall rule, Kubernetes NetworkPolicy, security group) "
                    "blocks all outbound traffic except to an explicit allowlist. "
                    "No: the agent can make outbound calls to any URL."
                ),
                "evidence_prompt": "Network policy config or firewall rule reference.",
            },
            {
                "key": "no_agent_with_wildcard_permissions",
                "number": "4.3",
                "title": "No Wildcard Permissions",
                "question": (
                    "Does the AI agent have any permissions defined with wildcards — "
                    "such as 'access all S3 buckets', 'call any API', or admin-level IAM roles?"
                ),
                "what_counts": (
                    "No wildcards: all permissions are specific and scoped to named resources. "
                    "Wildcards present: the agent has one or more wildcard or admin-level permissions."
                ),
                "evidence_prompt": "IAM policy or permission manifest showing specific (non-wildcard) scopes.",
            },
            {
                "key": "human_approval_gates_for_sensitive_tools",
                "number": "4.4",
                "title": "Human Approval for Sensitive Actions",
                "question": (
                    "Before the AI agent can take actions that modify data, send messages, "
                    "or call external services, does a human have to explicitly approve the action?"
                ),
                "what_counts": (
                    "Yes: a confirmation step exists for write/sensitive operations "
                    "before they are executed. "
                    "No: the agent acts immediately without human confirmation."
                ),
                "evidence_prompt": "Description of the confirmation flow or UI screenshot.",
            },
            {
                "key": "credential_rotation_policy_exists",
                "number": "4.5",
                "title": "Credential Rotation Policy",
                "question": (
                    "Is there a defined policy for rotating credentials (API keys, passwords, tokens) "
                    "that the AI agent uses — including a procedure to rotate them immediately "
                    "during a security incident?"
                ),
                "what_counts": (
                    "Yes: rotation schedule documented, automated where possible, "
                    "and an emergency rotation runbook exists. "
                    "No: no rotation policy; credentials are rotated ad hoc or never."
                ),
                "evidence_prompt": "Rotation policy document or secrets manager configuration.",
            },
        ],
    },
    {
        "dimension": "playbook_activation",
        "title": "Section 5: Incident Response Readiness",
        "intro": (
            "This section checks whether your team is prepared to respond to an AI-specific "
            "security incident. General IT incident response playbooks do not cover AI-specific "
            "scenarios — prompt injection, a rogue agent, or tampered tools require different "
            "containment steps."
        ),
        "questions": [
            {
                "key": "playbooks_mapped_to_ai_threat_types",
                "number": "5.1",
                "title": "AI-Specific IR Playbooks",
                "question": (
                    "Does your team have documented response procedures specifically for "
                    "AI security incidents — covering scenarios such as the agent receiving "
                    "injected instructions, the agent taking unexpected actions, or a tool "
                    "the agent uses being tampered with?"
                ),
                "what_counts": (
                    "Yes: written playbooks exist for at least three AI threat types "
                    "with specific containment steps. "
                    "No: only a general IT IR plan exists; no AI-specific playbooks."
                ),
                "evidence_prompt": "Link to or name of AI IR playbook document.",
            },
            {
                "key": "team_trained_on_ai_ir_playbooks",
                "number": "5.2",
                "title": "Team Training",
                "question": (
                    "Has every engineer and analyst who could be on-call for this AI system "
                    "reviewed the AI incident response playbooks and been trained on how to use them?"
                ),
                "what_counts": (
                    "Yes: training session completed, attendance recorded. "
                    "No: playbooks exist but only the author has read them."
                ),
                "evidence_prompt": "Training date, attendees list, or onboarding checklist reference.",
            },
            {
                "key": "approvals_workflow_configured",
                "number": "5.3",
                "title": "Approvals Workflow for Containment",
                "question": (
                    "For high-impact containment actions — such as terminating the agent, "
                    "rotating all credentials, or rolling back the system — is there a workflow "
                    "that requires a second person to approve before the action is taken?"
                ),
                "what_counts": (
                    "Yes: a documented approval step exists for destructive containment actions, "
                    "with an audit trail. "
                    "No: one person can take all containment actions unilaterally with no record."
                ),
                "evidence_prompt": "Approvals workflow tool or process description.",
            },
            {
                "key": "incident_command_structure_defined",
                "number": "5.4",
                "title": "Incident Command Roles",
                "question": (
                    "For an AI security incident, are the following roles defined: "
                    "who declares the incident, who owns containment, who handles external "
                    "communications, and who is the executive escalation point?"
                ),
                "what_counts": (
                    "Yes: named roles with backups, documented in a one-page incident command card. "
                    "No: roles are assumed informally or not defined at all."
                ),
                "evidence_prompt": "Incident command card or RACI reference.",
            },
            {
                "key": "playbook_tested_in_tabletop_exercise",
                "number": "5.5",
                "title": "Tabletop Exercise",
                "question": (
                    "Has the team run a practice scenario — a 'tabletop exercise' — where they "
                    "walked through responding to a simulated AI security incident (e.g. "
                    "prompt injection, rogue agent) within the last 6 months?"
                ),
                "what_counts": (
                    "Yes: exercise run within 6 months, with an after-action report documenting "
                    "gaps found and addressed. "
                    "No: no tabletop exercise has been run."
                ),
                "evidence_prompt": "Date of last exercise, scenario used, and after-action report reference.",
            },
        ],
    },
]

# Maps question key → control key (1:1 here, but explicit for clarity)
_KEY_MAP = {q["key"]: q["key"]
            for section in QUESTIONNAIRE_SECTIONS
            for q in section["questions"]}


def _parse_answer(answer_line: str) -> bool | None:
    """Return True/False/None from a filled-in answer line."""
    clean = answer_line.strip().upper()
    if re.search(r"\b(YES|TRUE|CONFIRMED|DONE|COMPLETE|Y)\b", clean):
        return True
    if re.search(r"\b(NO|FALSE|NOT\s+DONE|MISSING|N/A|NA|N)\b", clean):
        return False
    return None  # could not parse


# ---------------------------------------------------------------------------
# Subcommand: questionnaire
# ---------------------------------------------------------------------------

def cmd_questionnaire(args: argparse.Namespace) -> int:
    now = datetime.now(timezone.utc).date().isoformat()
    lines = []

    lines += [
        "# AI Incident Readiness Questionnaire",
        "",
        "> **Instructions for project owners**",
        "> ",
        "> Complete every question honestly. Only mark **YES** if the control exists,",
        "> works, and has been verified — not just planned or documented in a ticket.",
        "> For each YES answer, provide the evidence requested so the security team",
        "> can verify it. If a question does not apply to your system, answer **N/A**",
        "> and explain why.",
        "> ",
        "> Return the completed form to the security team. Your answers will be scored",
        "> automatically. A score below 60/100 will block production deployment.",
        "",
        "---",
        "",
        "## Project Information",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| **Project / System Name** | {args.system} |",
        f"| **Project Owner** | {args.owner} |",
        f"| **Engineering Lead** | _(fill in)_ |",
        f"| **Date Completed** | _(fill in)_ |",
        f"| **Reviewed By (Security)** | _(fill in)_ |",
        f"| **Questionnaire Version** | 1.0 |",
        f"| **Issued** | {now} |",
        "",
        "---",
        "",
    ]

    for section in QUESTIONNAIRE_SECTIONS:
        lines += [
            f"## {section['title']}",
            "",
            f"_{section['intro']}_",
            "",
        ]
        for q in section["questions"]:
            lines += [
                f"### {q['number']} {q['title']}",
                "",
                f"**Question:** {q['question']}",
                "",
                f"**What counts as YES:** {q['what_counts']}",
                "",
                "**Answer:** <!-- YES / NO / PARTIAL / N/A -->",
                "",
                f"**Evidence / Notes:** _{q['evidence_prompt']}_",
                "",
                "---",
                "",
            ]

    lines += [
        "## Declaration",
        "",
        "I confirm that the answers above are accurate to the best of my knowledge.",
        "Controls marked YES have been verified to exist and function — not merely planned.",
        "",
        "**Signature:** ___________________________",
        "",
        "**Date:** ___________________________",
        "",
    ]

    output = "\n".join(lines)
    print(output)
    if args.output:
        Path(args.output).write_text(output + "\n")
        print(f"\n[questionnaire written to {args.output}]", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Subcommand: score-questionnaire
# ---------------------------------------------------------------------------

def cmd_score_questionnaire(args: argparse.Namespace) -> int:
    q_path = Path(args.questionnaire)
    if not q_path.exists():
        print(json.dumps({"error": f"File not found: {args.questionnaire}"}))
        return 1

    text = q_path.read_text()

    # Extract project name from the table
    system_name = args.system or "Unknown"
    name_match = re.search(r"\|\s*\*\*Project.*?\*\*\s*\|\s*(.+?)\s*\|", text)
    if name_match:
        candidate = name_match.group(1).strip()
        if candidate and "fill in" not in candidate.lower():
            system_name = candidate

    # Parse each answer block: look for lines containing the answer comment marker
    answer_blocks = re.findall(
        r"###\s+[\d.]+\s+(.+?)\n.*?\*\*Answer:\*\*\s*<!--\s*(.*?)\s*-->",
        text, re.DOTALL
    )

    # Build a key → answer map by matching section/question order
    all_questions = [
        q for section in QUESTIONNAIRE_SECTIONS for q in section["questions"]
    ]

    parsed_answers: dict[str, bool] = {}
    unresolved: list[str] = []

    for i, (title_raw, answer_raw) in enumerate(answer_blocks):
        if i >= len(all_questions):
            break
        ctrl_key = all_questions[i]["key"]
        value = _parse_answer(answer_raw)
        if value is None:
            unresolved.append(ctrl_key)
            parsed_answers[ctrl_key] = False  # default to False if unparseable
        else:
            parsed_answers[ctrl_key] = value

    # Build a config compatible with cmd_assess
    config = {
        "system_name": system_name,
        "assessed_by": f"parsed from questionnaire: {q_path.name}",
        "dimensions": {},
    }
    for section in QUESTIONNAIRE_SECTIONS:
        dim = section["dimension"]
        config["dimensions"][dim] = {
            q["key"]: parsed_answers.get(q["key"], False)
            for q in section["questions"]
        }

    # Write temp config and call assess logic directly
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        json.dump(config, tmp)
        tmp_path = tmp.name

    class _FakeArgs:
        def __init__(self, config, output):
            self.config = config
            self.output = output

    result_code = cmd_assess(_FakeArgs(tmp_path, args.output))
    Path(tmp_path).unlink(missing_ok=True)

    if unresolved:
        print(
            f"\n[score-questionnaire] {len(unresolved)} answer(s) could not be parsed "
            f"(defaulted to NO): {unresolved}",
            file=sys.stderr,
        )

    return result_code


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

    # questionnaire
    q = sub.add_parser("questionnaire",
                       help="Generate a human-readable Markdown questionnaire for project owners")
    q.add_argument("--system", default="[Project Name]", help="Name of the AI system")
    q.add_argument("--owner", default="[Project Owner]", help="Project owner name")
    q.add_argument("--output", help="Write questionnaire to this .md file path")

    # score-questionnaire
    sq = sub.add_parser("score-questionnaire",
                        help="Parse a filled-in questionnaire and produce a scored assessment")
    sq.add_argument("--questionnaire", required=True, help="Path to filled-in .md questionnaire")
    sq.add_argument("--system", help="Override system name extracted from questionnaire")
    sq.add_argument("--output", help="Write assessment JSON to this file path")

    args = parser.parse_args()
    dispatch = {
        "template": cmd_template,
        "assess": cmd_assess,
        "report": cmd_report,
        "questionnaire": cmd_questionnaire,
        "score-questionnaire": cmd_score_questionnaire,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
