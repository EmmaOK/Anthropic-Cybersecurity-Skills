# /ai-design-review

Full Phase 1 security design review for AI/ML and agentic systems.
Covers all 8 activities from the [Organization] AI Security Lifecycle — Phase 1 (Design & Architecture).
Intended for: Platform team, Data Science team, any team integrating Claude/LLMs.

**Usage:** `/ai-design-review $ARGUMENTS`
**Example:** `/ai-design-review "Customer support agent using Claude with tool access to CRM and billing"`

---

You are an AI security architect conducting a full Phase 1 design review for the system described in $ARGUMENTS.

Complete all 8 steps below in order. Do not skip any step. Track progress as you go.

---

## Step 1 — Classify the architecture

Ask the user for (or infer from the description):
- **System name** (used as filename prefix throughout)
- **Architecture type** — one of: `single`, `multi`, `hierarchical`, `agentic`/`task_oriented`, `rag`, `human_in_loop`, `self_learning`
- **Data classification** — PII / financial / health / IP / public
- **Customer-facing?** — yes / no
- **Team** — which Bitbucket/Ivanti team owns this?

Create a `security/` directory in the project if it doesn't exist.

---

## Step 2 — MAESTRO 7-layer threat model

**Skill:** `performing-maestro-threat-modeling`

Run via `run_skill_agent`:
```
args: ["init", "--system", "<name>", "--arch-type", "<arch-type>"]
```
Save the output file. Then:
```
args: ["analyze", "--assessment", "<output-file>"]
args: ["report",  "--assessment", "<output-file>"]
```

Extract and present:
- Total threats identified (by MAESTRO layer L1–L7)
- CRITICAL and HIGH threats only
- Which layers have the most risk for this architecture type

Save final report JSON to `security/maestro-<system>.json`.

---

## Step 3 — OWASP LLM Top 10 + ATLAS taxonomy

**Skill:** `threat-modeling-for-ai-ml-systems`

Run via `run_skill_agent`:
```
args: ["init", "--system", "<name>", "--arch-type", "<arch-type>"]
args: ["analyze", "--assessment", "<output-file>"]
args: ["report",  "--assessment", "<output-file>"]
```

Cross-reference HIGH/CRITICAL MAESTRO threats from Step 2 against the OWASP LLM categories.
Load the corresponding prevention skill for each:

| MAESTRO finding | OWASP LLM category | Load this skill |
|---|---|---|
| Prompt injection in user input | LLM01 | `detecting-ai-model-prompt-injection-attacks` |
| Tool/function call overreach | LLM06 | `llm-excessive-agency-prevention` |
| Training data manipulation | LLM04 | `llm-data-and-model-poisoning-defense` |
| System prompt exposure | LLM07 | `llm-system-prompt-leakage-prevention` |
| PII/credentials in output | LLM02 | `llm-sensitive-information-disclosure-prevention` |
| Unsanitized LLM output in downstream code | LLM02 | `llm-output-validation-and-sanitization` |

For each matched skill, extract the **design-time control** (what must be decided before build, not tested after).

Save to `security/owasp-llm-<system>.json`.

---

## Step 4 — Compliance gap assessment

**Skill:** `ai-governance-and-regulatory-compliance`

Run via `run_skill_agent`:
```
args: ["assess", "--system", "<name>", "--risk-tier", "high", "--framework", "all"]
```

If data classification is PII or health, add `--framework eu-ai-act`. Save checklist JSON.
Then score it:
```
args: ["score", "--checklist", "<checklist-file>"]
```

Present:
- EU AI Act obligations that apply (Articles 9, 13, 14, 15)
- NIST AI RMF gaps (GOVERN, MAP, MEASURE, MANAGE)
- ISO 42001 clause gaps

Save to `security/compliance-<system>.json`.

---

## Step 5 — LLM provider supply chain risk

**Skill:** `llm-supply-chain-vulnerability-assessment` (guidance only — no executable script)

Use `load_skill` to retrieve the full SKILL.md. Extract and present:
- Model provider trust assumptions the team is making (Anthropic API, fine-tuned model, self-hosted)
- Plugin/integration supply chain risks for any third-party tools the agent will call
- Key design decisions required:
  - [ ] Model version pinning strategy defined?
  - [ ] Provider outage fallback designed?
  - [ ] Third-party plugin vetting process defined?
  - [ ] Fine-tuning dataset provenance documented?

Record answers in the design review summary (no automated script output for this step).

---

## Step 6 — Incident readiness questionnaire

**Skill:** `ai-incident-readiness-assessment`

At design time, generate the questionnaire so the team answers it now — not after an incident.

Run via `run_skill_agent`:
```
args: ["questionnaire", "--output", "security/incident-readiness-questionnaire-<system>.md"]
```

Present the questionnaire to the user. Ask them to answer each question inline.
Once answered, score it:
```
args: ["score-questionnaire", "--questionnaire", "security/incident-readiness-questionnaire-<system>.md"]
```

Present:
- Readiness score (0–100)
- Gaps that must be closed before first production deploy
- "Required before deploy" items (add to the design review checklist)

Save scored output to `security/incident-readiness-<system>.json`.

---

## Step 7 — Agent identity and privilege boundaries

**Skill:** `agent-identity-and-privilege-governance`

This skill audits agent tokens and privilege configurations. At design time, use it to define the identity model.

Use `load_skill` to extract the privilege design requirements. Then present the team with these design decisions to make now:

```
Agent Identity Design Checklist — <system>
──────────────────────────────────────────
[ ] Agent identity: how does this agent authenticate? (JWT / service account / role)
[ ] Token lifetime: what is the max token TTL?
[ ] Privilege scope: list every permission this agent needs (principle of least privilege)
[ ] Privilege escalation paths: are any tool calls able to elevate permissions?
[ ] Cross-agent trust: does this agent call other agents? If so, how is trust established?
[ ] Human escalation: which agent actions require a human to approve before execution?
```

If the team already has a JWT/token spec, run:
```
args: ["--agent-token", "<JWT>", "--output", "security/identity-audit-<system>.json"]
```

Otherwise record design decisions as free text in the design review.

---

## Step 8 — Kill switch and graduated containment design

**Skill:** `ai-agent-kill-switch-and-graduated-response`

At design time, scaffold the kill switch so it's built in from day one — not bolted on after an incident.

Run via `run_skill_agent`:
```
args: ["scaffold", "--output-dir", "security/kill-switch-<system>/"]
```

This generates the kill switch configuration files. Present the scaffolded files to the user and explain:
- Level 1: rate limiting / slow down (soft signal)
- Level 2: disable non-critical tools (partial containment)
- Level 3: read-only mode (halt writes)
- Level 4: full shutdown (emergency stop)

Ask the team to define what **triggers** each level for their specific system. Record in `security/kill-switch-<system>/trigger-definitions.md`.

Also run the simulation to confirm the logic:
```
args: ["simulate", "--config", "security/kill-switch-<system>/kill_switch_config.json"]
```

---

## Step 9 — Human oversight gates

**Skill:** `human-agent-trust-and-oversight-controls`

Use `load_skill` to extract oversight design requirements. Then present:

```
Human Oversight Design — <system>
──────────────────────────────────
Actions that ALWAYS require human approval (define these now):
[ ] <action 1 — e.g. "send external email">
[ ] <action 2 — e.g. "write to production database">
[ ] <action 3 — e.g. "make payment API call">

Escalation thresholds (define the criteria):
[ ] Confidence threshold below which agent pauses and asks for confirmation: ____%
[ ] Max consecutive tool calls before requiring human check-in: ____
[ ] Anomaly detection: what "unexpected" behaviour triggers a human review?

Audit trail requirements:
[ ] Every agent decision logged? yes / no
[ ] Human override decisions recorded? yes / no
[ ] Log retention period: ____
```

If the team has an existing agent config JSON, run:
```
args: ["--config", "<agent-config.json>", "--output", "security/oversight-audit-<system>.json"]
```

---

## Final Output — Design Review Summary

Write `security/design-review-<system>.md` with this structure:

```markdown
# AI Security Design Review — <System Name>
**Date:** <today>  
**Team:** <team>  
**Reviewer:** Claude Code + Phantom MCP (phantom-mcp.tstsecurity.[org].engineering)  
**Architecture:** <type>  
**Data classification:** <classification>

## Phase 1 Checklist

| # | Activity | Skill | Status | Top Finding |
|---|---|---|---|---|
| 1 | MAESTRO 7-layer threat model | performing-maestro-threat-modeling | ✅ | <top finding> |
| 2 | OWASP LLM Top 10 + ATLAS | threat-modeling-for-ai-ml-systems | ✅ | <top finding> |
| 3 | Compliance gap (EU AI Act / NIST / ISO) | ai-governance-and-regulatory-compliance | ✅ | <gap count> gaps |
| 4 | LLM supply chain risk | llm-supply-chain-vulnerability-assessment | ✅ | <decision pending> |
| 5 | Incident readiness | ai-incident-readiness-assessment | ✅ | Score: <n>/100 |
| 6 | Agent identity + privilege boundaries | agent-identity-and-privilege-governance | ✅ | <open items> |
| 7 | Kill switch + containment | ai-agent-kill-switch-and-graduated-response | ✅ | Scaffold generated |
| 8 | Human oversight gates | human-agent-trust-and-oversight-controls | ✅ | <open items> |

## Threat Summary
- Total threats identified: <n>
- CRITICAL: <n> | HIGH: <n> | MEDIUM: <n>

## Required Before Build Starts
- [ ] <item from MAESTRO CRITICAL threats>
- [ ] <item from compliance gaps>
- [ ] <item from incident readiness gaps>
- [ ] Kill switch triggers defined (Step 8)
- [ ] Human approval list finalised (Step 9)

## Required Before First Production Deploy
- [ ] <items from incident readiness score>
- [ ] Kill switch smoke-tested

## Artifacts
- `security/maestro-<system>.json`
- `security/owasp-llm-<system>.json`
- `security/compliance-<system>.json`
- `security/incident-readiness-questionnaire-<system>.md`
- `security/incident-readiness-<system>.json`
- `security/kill-switch-<system>/`

## Sign-off
- [ ] Security team review (@security-team)
- [ ] Design doc updated with threat model link
- [ ] CRITICAL/HIGH risks created in Ivanti
- [ ] Required-before-build items scheduled in sprint
```

---

## Escalation

Stop and immediately notify the security team if any of the following are found:
- MAESTRO CRITICAL finding with no available control
- Compliance: EU AI Act Article 9 risk management system not feasible
- Incident readiness score below 40/100
- No kill switch mechanism technically possible for this architecture
- Agent has unconstrained write access to external systems with no human gate
