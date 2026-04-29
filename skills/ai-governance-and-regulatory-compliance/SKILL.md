---
name: ai-governance-and-regulatory-compliance
description: >-
  Generates and scores structured compliance checklists for AI systems against the EU AI
  Act, NIST AI RMF 1.0, and ISO/IEC 42001:2023 frameworks. Covers MAESTRO Layer 6
  (Security & Compliance) requirements — risk classification, transparency obligations,
  human oversight controls, data governance, bias and fairness monitoring, explainability
  for audit, incident reporting requirements, and conformity assessment documentation.
  Produces a compliance gap report with remediation priorities tailored to the system's
  risk tier (high-risk, limited-risk, minimal-risk under EU AI Act) and deployment context.
domain: cybersecurity
subdomain: ai-security
tags:
  - EU-AI-Act
  - NIST-AI-RMF
  - ISO-42001
  - ai-governance
  - compliance
  - MAESTRO
  - bias-governance
  - explainability
  - regulatory-compliance
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - GV.OC-01
  - GV.OC-03
  - GV.RM-02
  - GV.RM-04
  - ID.RA-06
nist_ai_rmf:
  - GOVERN-1.1
  - GOVERN-1.7
  - GOVERN-4.2
  - GOVERN-6.1
  - GOVERN-6.2
  - MAP-1.1
  - MEASURE-2.5
  - MANAGE-3.1
d3fend_techniques:
  - Audit Log Analysis
  - User Behavior Analysis
---
# AI Governance and Regulatory Compliance

## When to Use

- Performing a pre-deployment compliance assessment for an AI system against EU AI Act, NIST AI RMF, or ISO 42001
- Identifying governance gaps in an existing AI system (missing bias monitoring, insufficient audit trails, unclear accountability)
- Preparing documentation for a conformity assessment or regulatory audit
- Building the MAESTRO Layer 6 (Security & Compliance) evidence package for a threat model
- Annual compliance refresh after model updates, architectural changes, or regulatory changes

**EU AI Act risk tiers:**
- **High-risk**: AI in critical infrastructure, employment, credit, education, law enforcement, medical devices — requires conformity assessment, registration, human oversight
- **Limited-risk**: Chatbots, AI-generated content — requires transparency disclosures
- **Minimal-risk**: Spam filters, AI in video games — no mandatory requirements

## Prerequisites

- Python 3.9+ (no external dependencies)
- System description: name, use case, risk tier, deployment context

## Workflow

### 1. Assess compliance

```bash
python agent.py assess \
  --system "Loan Underwriting AI" \
  --risk-tier high \
  --framework all \
  --output compliance_report.json
```

Framework options: `eu-ai-act` | `nist-ai-rmf` | `iso-42001` | `all`

Risk tier options: `high` | `limited` | `minimal`

### 2. Review and fill in the checklist

The output includes a `checklist` array with OPEN/COMPLIANT/NOT_APPLICABLE status for each requirement. Edit the JSON to mark requirements as COMPLIANT once controls are verified, then re-run the `score` subcommand:

```bash
python agent.py score --checklist compliance_report.json --output compliance_scored.json
```

## Key Concepts

| Concept | Description |
|---|---|
| EU AI Act High-Risk | Systems affecting fundamental rights, safety, or critical decisions — strictest requirements including conformity assessment and EU database registration |
| NIST AI RMF | GOVERN/MAP/MEASURE/MANAGE functions for AI risk management across the full lifecycle |
| ISO/IEC 42001 | AI management system standard — organizational processes, governance structure, continual improvement |
| Fundamental Rights Impact Assessment (FRIA) | EU AI Act requirement for high-risk systems used by public authorities |
| Post-Market Monitoring | Ongoing data collection and reporting on system performance after deployment |
| Bias and Fairness | Statistical parity, equalized odds, or calibration requirements across protected groups |
| Explainability for Audit | Ability to reconstruct the reasoning behind a specific AI decision for audit or appeal purposes |

## Tools & Systems

| Tool | Purpose |
|---|---|
| agent.py `assess` | Generate framework-specific compliance checklist with severity-weighted gaps |
| agent.py `score` | Score a completed checklist and calculate compliance percentage |
| EU AI Act Article 9–17 | Core high-risk AI requirements reference |
| NIST AI RMF Playbook | Suggested actions for each RMF subcategory |
| ISO 42001 Annex A | AI management system control objectives |

## Common Scenarios

**High-risk AI in financial services (loan underwriting):**
Full checklist includes: risk management system, data governance, technical documentation, transparency, human oversight, accuracy/robustness/cybersecurity requirements, and conformity assessment.

**Limited-risk chatbot:**
Checklist focuses on: transparency disclosure (users must know they're interacting with AI), content labeling.

**Internal AI tool with no public-facing deployment:**
May qualify as minimal-risk if it doesn't fall into Annex III categories — checklist confirms risk tier and documents rationale.

## Output Format

```json
{
  "system": "Loan Underwriting AI",
  "risk_tier": "high",
  "frameworks_assessed": ["eu-ai-act", "nist-ai-rmf", "iso-42001"],
  "total_requirements": 38,
  "compliant": 0,
  "open_gaps": 38,
  "checklist": [
    {
      "id": "EU-HR-001",
      "framework": "eu-ai-act",
      "article": "Article 9",
      "requirement": "Risk management system established and maintained throughout lifecycle",
      "severity": "CRITICAL",
      "status": "OPEN",
      "guidance": "Document risk identification, analysis, estimation, and evaluation procedures. Update after every significant change."
    },
    {
      "id": "NIST-GOV-001",
      "framework": "nist-ai-rmf",
      "function": "GOVERN-1.1",
      "requirement": "Policies, processes, procedures in place for AI risk management",
      "severity": "CRITICAL",
      "status": "OPEN",
      "guidance": "Establish and document AI risk policies that assign accountability and define review cadence."
    }
  ],
  "compliance_score_pct": 0,
  "overall_risk": "CRITICAL",
  "priority_gaps": ["Risk management system", "Technical documentation", "Human oversight mechanism", "Bias monitoring"]
}
```
