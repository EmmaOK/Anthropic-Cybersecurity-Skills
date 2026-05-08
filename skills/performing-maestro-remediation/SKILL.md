---
name: performing-maestro-remediation
description: >-
  Orchestrates remediation planning across all MAESTRO framework layers by consolidating
  audit outputs from 12 layer-specific security auditors into a single prioritized,
  phased remediation roadmap. Accepts audit JSON files from any combination of MAESTRO
  layer auditors (L1–L7 and cross-layer), normalizes findings across differing report
  formats, deduplicates, and generates a four-phase plan grouped by MAESTRO layer and
  severity. Surfaces quick-win CRITICAL controls and calculates an overall residual risk
  score. Designed to bridge threat identification (performing-maestro-threat-modeling)
  with systematic control implementation across Foundation Models, Data Operations, Agent
  Frameworks, Deployment, Evaluation, Security & Compliance, and Agent Ecosystem layers.
domain: cybersecurity
subdomain: ai-security
tags:
  - MAESTRO
  - remediation
  - agentic-ai
  - ai-security
  - multi-agent
  - risk-management
  - security-controls
  - orchestration
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - ID.RA-05
  - RS.MI-01
  - RS.MI-02
  - GV.RM-04
  - PR.IP-01
atlas_techniques:
  - AML.T0043
  - AML.T0051
  - AML.T0054
  - AML.T0056
nist_ai_rmf:
  - MANAGE-1.1
  - MANAGE-2.2
  - MANAGE-3.1
  - MEASURE-2.7
d3fend_techniques:
  - Application Hardening
  - Software Bill of Materials
  - User Behavior Analysis
---
# Performing MAESTRO Remediation

## When to Use

- After running one or more MAESTRO layer audits and needing a single consolidated view of all findings
- Prioritizing which controls to implement first across a multi-layer agentic AI system
- Generating a remediation roadmap for a security review, board report, or sprint planning session
- Tracking remediation progress across multiple teams responsible for different MAESTRO layers
- Comparing residual risk before and after implementing a remediation phase

**Do not use** as a substitute for the individual layer auditors — run the relevant auditors first to generate the input JSON files this skill consumes.

## Prerequisites

- Python 3.9+ (no external dependencies — stdlib only)
- One or more audit output JSON files from any of these MAESTRO layer auditors:
  - `adversarial-robustness-and-evasion-defense` → L1 probe/backdoor-scan outputs
  - `ai-model-extraction-and-reprogramming-defense` → L1 model API audit
  - `ai-data-operations-availability-and-integrity` → L2 data ops audit
  - `rag-pipeline-security-and-data-provenance` → L2 RAG pipeline audit
  - `ai-agent-framework-security` → L3 framework audit
  - `ai-workload-infrastructure-hardening` → L4 infra scan
  - `ai-evaluation-security-and-observability-hardening` → L5 eval/telemetry audits
  - `ai-governance-and-regulatory-compliance` → L6 compliance score
  - `ai-security-tool-adversarial-defense` → L6 threat-side audit
  - `ai-agent-ecosystem-security` → L7 ecosystem audit
  - `ai-explainability-and-formal-verification` → Cross-layer XAI/verification/reputation audits

## Workflow

### 1. Run individual MAESTRO layer audits

Generate the audit input files from whichever layers apply to your system:

```bash
# L3 — Agent Framework
python skills/ai-agent-framework-security/scripts/agent.py audit \
  --config framework_config.json --output framework_audit.json

# L7 — Agent Ecosystem
python skills/ai-agent-ecosystem-security/scripts/agent.py audit \
  --config ecosystem_config.json --output ecosystem_audit.json

# L6 — Security Tool Adversarial Defense
python skills/ai-security-tool-adversarial-defense/scripts/agent.py audit \
  --config security_tool_config.json --output security_tool_audit.json

# L2 — Data Operations
python skills/ai-data-operations-availability-and-integrity/scripts/agent.py audit \
  --config data_ops_config.json --output data_ops_audit.json
```

Run as many or as few auditors as apply to your system. All outputs are JSON files that this skill can consume.

### 2. Generate the consolidated remediation plan

```bash
python skills/performing-maestro-remediation/scripts/agent.py plan \
  --audits framework_audit.json ecosystem_audit.json security_tool_audit.json data_ops_audit.json \
  --title "Payment Processing AI Agent" \
  --output maestro_remediation_plan.json
```

Pass all audit JSON files via `--audits`. The script:
- Infers the source skill from each file's `methodology` field
- Normalizes findings across differing report formats
- Deduplicates on `(finding_id, resource)` key
- Sorts all findings by severity then layer
- Groups into four remediation phases

### 3. Review the phased plan

The output `maestro_remediation_plan.json` groups findings into four phases:

| Phase | Timeline | Severity |
|---|---|---|
| Phase 1 | 0–2 weeks | CRITICAL |
| Phase 2 | 2–6 weeks | HIGH |
| Phase 3 | 6–12 weeks | MEDIUM |
| Phase 4 | 12+ weeks | LOW |

Within each phase, findings are grouped by MAESTRO layer so teams can work in parallel. The `quick_wins` array surfaces the five CRITICAL controls with the most actionable, concise remediations.

### 4. Apply fixes and re-audit

For auditors that support a `fix` subcommand (ecosystem, framework, security-tool), generate a corrected config:

```bash
python skills/ai-agent-framework-security/scripts/agent.py fix \
  --audit framework_audit.json \
  --config framework_config.json \
  --output-dir remediation-output/
```

After implementing fixes, re-run the auditors and regenerate the plan to measure residual risk reduction.

## Key Concepts

| Concept | Description |
|---|---|
| Phased Remediation | Findings sorted by severity into four time-boxed phases, allowing teams to prioritize without being overwhelmed |
| Deduplication | Findings with the same `(id, resource)` pair appearing in multiple audit files are merged to avoid double-counting |
| Layer-parallel Execution | Within a phase, findings are grouped by MAESTRO layer so L2 and L6 teams can work simultaneously |
| Quick Wins | CRITICAL findings with concise remediations that can close the highest-risk gaps with least implementation effort |
| Residual Risk | The overall risk level remaining after applying Phase 1 fixes — the plan exits with code 1 until this is MEDIUM or lower |
| Skill Inference | The orchestrator reads each audit file's `methodology` field to identify which MAESTRO skill produced it, enabling traceability |

## Tools & Systems

| Tool | Purpose |
|---|---|
| `performing-maestro-remediation/scripts/agent.py plan` | Consolidate audit JSONs into phased plan |
| `ai-agent-framework-security/scripts/agent.py fix` | Generate corrected framework config from audit findings |
| `ai-agent-ecosystem-security/scripts/agent.py fix` | Generate corrected ecosystem config from audit findings |
| `ai-security-tool-adversarial-defense/scripts/agent.py fix` | Generate corrected security tool config from audit findings |
| `performing-maestro-threat-modeling` | Upstream threat identification step producing the initial threat register |

## Common Scenarios

**Full MAESTRO sweep before production launch:**
Run all 11 layer auditors, then consolidate with this skill. Review Phase 1 CRITICAL findings with the security team, assign owners by layer, and gate launch on Phase 1 completion.

**Partial audit (new component only):**
If you added a new agent framework integration, run only `ai-agent-framework-security` and pass its output to `--audits`. The plan will scope to L3 findings only.

**Cross-team sprint planning:**
Run the full consolidation and share `by_layer` breakdown with team leads. Each team (infra, data, MLOps) takes ownership of findings in their layer for the sprint.

**Regression check after remediation sprint:**
Re-run affected layer auditors, regenerate the plan, and compare `total_findings` and `by_severity` against the prior plan to measure progress.

## Output Format

```json
{
  "plan_timestamp": "2026-05-02T10:00:00+00:00",
  "title": "Payment Processing AI Agent",
  "methodology": "MAESTRO Remediation Orchestrator — performing-maestro-remediation v1.0",
  "audit_sources": [
    {
      "file": "framework_audit.json",
      "skill": "ai-agent-framework-security",
      "methodology": "MAESTRO Layer 3 (Agent Frameworks) — ai-agent-framework-security v1.0",
      "findings_loaded": 14,
      "overall_risk": "CRITICAL"
    }
  ],
  "skills_covered": ["ai-agent-ecosystem-security", "ai-agent-framework-security"],
  "layers_covered": ["L3", "L7"],
  "total_findings": 27,
  "by_severity": { "CRITICAL": 6, "HIGH": 16, "MEDIUM": 4, "LOW": 1 },
  "by_layer": { "L3": 14, "L7": 13 },
  "overall_risk": "CRITICAL",
  "phases": [
    {
      "phase": 1,
      "label": "Immediate (0–2 weeks)",
      "total_items": 6,
      "layers_affected": ["L3", "L7"],
      "by_layer": {
        "L3": [
          {
            "id": "FWK-005",
            "severity": "CRITICAL",
            "control": "Tool allowlisting",
            "remediation": "Define an explicit tool allowlist; reject any tool_name not in the approved set at the framework layer before dispatch",
            "source_skill": "ai-agent-framework-security"
          }
        ]
      }
    }
  ],
  "quick_wins": [
    {
      "id": "ECO-001",
      "severity": "CRITICAL",
      "layer": "L7",
      "control": "Registry entry integrity signing",
      "remediation": "Sign all registry entries with publisher private keys (Sigstore/cosign); verify signatures at agent discovery and invocation time",
      "source_skill": "ai-agent-ecosystem-security"
    }
  ],
  "recommendation": "6 CRITICAL findings across 2 MAESTRO layers. Start with Phase 1 (6 items) — all CRITICAL controls must be resolved before production deployment."
}
```
