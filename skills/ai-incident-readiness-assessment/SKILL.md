---
name: ai-incident-readiness-assessment
description: >-
  Assesses whether an AI application has the controls, artifacts, and capabilities
  in place to respond effectively to AI-specific security incidents before they occur.
  Scores five dimensions of readiness: Observability (telemetry and behavioral baselines),
  Rollback Capability (signed checkpoints and tested restore procedures), Kill Switches
  (per-agent termination tested in staging), Least-Privilege Posture (tool manifests,
  egress policies, approval gates), and Playbook Activation (AI-specific IR playbooks,
  team training, tabletop exercises). Each dimension is scored 0–100; an overall
  composite score drives a RAG risk rating (GREEN ≥ 80, AMBER 60–79, RED 40–59,
  CRITICAL < 40). Outputs a prioritized remediation plan mapping each gap to the
  companion skill that closes it. Activates before deploying an AI agent or LLM
  application to production, after a security incident as a readiness retrospective,
  or as part of a periodic AI security review cycle. Pairs with ai-incident-response-playbook
  (downstream — used once an incident is declared) and ai-governance-and-regulatory-compliance
  (upstream — organizational governance posture).
domain: cybersecurity
subdomain: ai-security
tags:
  - incident-response
  - ai-security
  - readiness-assessment
  - kill-switch
  - observability
  - least-privilege
  - rollback
  - playbook
  - OWASP-LLM-Top10
  - OWASP-Agentic-Top10
  - MAESTRO
  - PICERL
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - GV.OC-01
  - ID.IM-02
  - PR.PS-04
  - RS.MA-01
  - RC.RP-01
nist_ai_rmf:
  - GOVERN-6.1
  - MANAGE-2.2
  - MANAGE-3.1
  - MANAGE-4.1
atlas_techniques:
  - AML.T0054
  - AML.T0068
d3fend_techniques:
  - Process Spawn Analysis
  - Restore Access
  - Network Traffic Filtering
---
# AI Incident Readiness Assessment

## When to Use

- Before promoting an AI agent or LLM application from staging to production
- After an AI security incident, as a readiness retrospective to identify what was missing
- As part of a periodic AI security review cycle (quarterly recommended)
- When onboarding a new AI system into a SOC or security operations programme
- Before a red-team exercise against an AI system — to confirm you can actually respond to what they find

**Do not use** as a substitute for a full threat model — run `performing-maestro-threat-modeling` or `threat-modeling-for-ai-ml-systems` first to understand which threats apply before assessing readiness to respond to them.

## Prerequisites

- Knowledge of the AI system's architecture: agent framework, model hosting, RAG pipeline (if any), MCP tools (if any)
- Access to the deployment environment to verify controls exist (not just documented)
- A completed `readiness_config.json` (generate a blank one with `agent.py template`)
- No external dependencies — stdlib only

## Workflow

### Step 1: Generate a blank assessment config

```bash
python agent.py template --system "My AI App" --output readiness_config.json
```

This writes a `readiness_config.json` with all 25 controls set to `false`. Open it and set each control to `true` only if it is verified to exist and function — not just planned or documented.

The config covers five dimensions:

```json
{
  "system_name": "My AI App",
  "assessed_by": "",
  "dimensions": {
    "observability": {
      "agent_telemetry_enabled": false,
      "llm_api_gateway_logging": false,
      "tool_call_logging": false,
      "logs_ingested_into_siem": false,
      "behavioral_baselines_established": false,
      "log_retention_72h_or_more": false
    },
    "rollback_capability": {
      "model_checkpoints_signed_and_stored": false,
      "rag_corpus_snapshots_available": false,
      "mcp_tool_manifest_versioned_in_vcs": false,
      "rollback_tested_in_last_90_days": false,
      "rollback_time_under_30min_documented": false
    },
    "kill_switches": {
      "per_agent_kill_switch_exists": false,
      "kill_switch_tested_in_staging": false,
      "emergency_halt_all_agents_capability": false,
      "kill_switch_activates_under_60s": false
    },
    "least_privilege": {
      "tool_manifests_audited_for_scope": false,
      "network_egress_policies_applied": false,
      "no_agent_with_wildcard_permissions": false,
      "human_approval_gates_for_sensitive_tools": false,
      "credential_rotation_policy_exists": false
    },
    "playbook_activation": {
      "playbooks_mapped_to_ai_threat_types": false,
      "team_trained_on_ai_ir_playbooks": false,
      "approvals_workflow_configured": false,
      "incident_command_structure_defined": false,
      "playbook_tested_in_tabletop_exercise": false
    }
  }
}
```

### Step 2: Score the filled-in config

```bash
python agent.py assess --config readiness_config.json --output readiness_assessment.json
```

Each dimension is scored independently:

```python
def score_dimension(controls: dict) -> dict:
    total = len(controls)
    passed = sum(1 for v in controls.values() if v is True)
    score = round((passed / total) * 100) if total else 0
    return {
        "score": score,
        "passed": passed,
        "total": total,
        "risk_level": risk_label(score),
    }

def risk_label(score: int) -> str:
    if score >= 80: return "GREEN"
    if score >= 60: return "AMBER"
    if score >= 40: return "RED"
    return "CRITICAL"
```

Overall composite score is the unweighted mean of all five dimension scores. The script exits with code 1 when the overall score is below 60 (RED/CRITICAL) — suitable as a CI gate on AI system deployments.

### Step 3: Generate a prioritized remediation report

```bash
python agent.py report --assessment readiness_assessment.json --output remediation_plan.json
```

The report ranks every failing control by severity (CRITICAL gaps first), maps each to a concrete remediation action, and cross-references the companion skill that implements the fix.

**Remediation priority logic:**

| Condition | Priority | Expected resolution |
|---|---|---|
| Dimension score < 40 | P1 — Immediate | Block production deployment |
| Dimension score 40–59 | P2 — Urgent | Within 2 weeks |
| Dimension score 60–79 | P3 — Planned | Within 30 days |
| Individual control false in otherwise GREEN dimension | P4 — Scheduled | Next sprint |

### Step 4: Verify controls are real, not just documented

The most common readiness failure is controls that exist on paper but have never been tested. For each `true` in your config, verify:

```python
VERIFICATION_QUESTIONS = {
    "kill_switch_tested_in_staging": (
        "When was it last tested? Who ran it? What is the kill time in seconds? "
        "Show the test run log."
    ),
    "rollback_tested_in_last_90_days": (
        "What version was restored? From what checkpoint? How long did it take? "
        "Show the rollback runbook execution record."
    ),
    "behavioral_baselines_established": (
        "Where are the baselines stored? What tool call volumes and resource "
        "thresholds were used? When were they last updated?"
    ),
    "playbook_tested_in_tabletop_exercise": (
        "Which playbook? When? Who participated? What gaps were identified? "
        "Show the after-action report."
    ),
}
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Incident Readiness** | The state of having controls, artifacts, and tested capabilities in place before an AI security incident occurs |
| **Observability** | The ability to detect anomalous AI behaviour through telemetry, logs, and behavioral baselines — a prerequisite for identifying any incident type |
| **Rollback Capability** | The ability to restore a known-good model checkpoint, RAG corpus, or MCP tool manifest within a defined time window |
| **Kill Switch** | A pre-registered, tested mechanism to immediately halt an agent's execution — must be verified to work in the target environment, not just exist in code |
| **Least-Privilege Posture** | Every agent runs with only the tools, network access, and credentials required for its declared task — no wildcards |
| **Playbook Activation** | IR playbooks exist, are mapped to specific AI threat types, and the team has practiced executing them |
| **RAG Risk Rating** | GREEN (≥ 80) / AMBER (60–79) / RED (40–59) / CRITICAL (< 40) overall readiness score |

## Tools & Systems

| Tool | Gap it closes |
|------|--------------|
| **ai-incident-response-playbook** | Playbook Activation dimension — provides the six AI-specific IR playbooks |
| **rogue-agent-detection-and-containment** | Kill Switches dimension — provides kill-switch implementation and behavioral baselines |
| **ai-evaluation-security-and-observability-hardening** | Observability dimension — hardens telemetry and eval pipelines |
| **rag-pipeline-security-and-data-provenance** | Rollback Capability — RAG corpus snapshots and provenance controls |
| **llm-excessive-agency-prevention** | Least-Privilege Posture — tool manifest auditing and least-privilege enforcement |
| **ai-agent-framework-security** | Least-Privilege Posture — tool allowlisting and approval gates in orchestration frameworks |
| **mcp-tool-poisoning-detection-and-defense** | Rollback Capability — MCP tool manifest versioning and integrity verification |

## Common Scenarios

- **Pre-production gate**: A new LLM-powered customer service agent scores 38/100 overall — Kill Switches (0/4) and Playbook Activation (0/5) are CRITICAL. Deployment is blocked by the CI exit code until those dimensions reach 60.
- **Post-incident retrospective**: Following a prompt injection incident, a readiness assessment reveals that behavioral baselines were never established (Observability: 50) and no AI-specific IR playbook existed (Playbook Activation: 20). The remediation plan directs the team to `ai-evaluation-security-and-observability-hardening` and `ai-incident-response-playbook`.
- **Quarterly review**: An AI platform team runs assessments across three deployed agents. Agent A scores GREEN (85); Agent B scores AMBER (65) with a gap in rollback testing; Agent C scores RED (45) because it was deployed before kill switches were wired up. The report surfaces C as P1 with a 2-week remediation deadline.

## Output Format

```json
{
  "system_name": "Customer Service LLM Agent",
  "assessed_at": "2026-05-25T10:00:00Z",
  "assessed_by": "security-team",
  "overall_score": 52,
  "overall_risk": "RED",
  "deployment_recommendation": "BLOCK — overall score below 60. Resolve P1 gaps before production.",
  "dimensions": {
    "observability":       { "score": 67, "risk": "AMBER", "passed": 4, "total": 6 },
    "rollback_capability": { "score": 40, "risk": "RED",   "passed": 2, "total": 5 },
    "kill_switches":       { "score": 25, "risk": "CRITICAL", "passed": 1, "total": 4 },
    "least_privilege":     { "score": 60, "risk": "AMBER", "passed": 3, "total": 5 },
    "playbook_activation": { "score": 20, "risk": "CRITICAL", "passed": 1, "total": 5 }
  },
  "remediation_plan": [
    {
      "priority": "P1",
      "dimension": "kill_switches",
      "control": "kill_switch_tested_in_staging",
      "gap": "Kill switch has never been tested — unknown whether it works in the target environment",
      "action": "Execute kill switch against a staging agent; record activation time and confirm < 60s",
      "companion_skill": "rogue-agent-detection-and-containment",
      "resolution_deadline": "Immediate — block production"
    }
  ]
}
```
