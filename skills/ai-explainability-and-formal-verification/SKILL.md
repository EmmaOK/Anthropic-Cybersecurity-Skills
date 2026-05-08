---
name: ai-explainability-and-formal-verification
description: >-
  Implements cross-layer MAESTRO mitigation strategies that have no dedicated
  operational skill: explainability (XAI) auditing to ensure agent decisions are
  reconstructable for forensic investigation and compliance; formal goal verification
  to detect agent goal misalignment and constraint violations before deployment;
  adversarial training assessment to verify robustness controls are actually applied;
  and reputation-based trust scoring design for distributed agent ecosystems (the
  mitigation MAESTRO specifies for Sybil attacks in Layer 7). Addresses the
  cross-layer mitigation gap identified across all MAESTRO layers — these controls
  appear in the MAESTRO mitigation catalogue but are not covered by any single
  layer-specific skill.
domain: cybersecurity
subdomain: ai-security
tags:
  - MAESTRO
  - explainability
  - XAI
  - formal-verification
  - goal-alignment
  - adversarial-training
  - reputation-systems
  - agentic-ai
  - cross-layer
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - ID.RA-03
  - GV.RM-04
  - DE.AE-02
  - RS.AN-01
  - RS.AN-03
atlas_techniques:
  - AML.T0043
  - AML.T0051
  - AML.T0082
  - AML.T0088
nist_ai_rmf:
  - GOVERN-1.1
  - GOVERN-1.7
  - GOVERN-6.1
  - MAP-1.1
  - MEASURE-2.7
  - MANAGE-2.2
d3fend_techniques:
  - User Behavior Analysis
  - Audit Log Analysis
  - Application Hardening
---
# AI Explainability and Formal Verification

## When to Use

- Auditing an AI system's explainability capability before a forensic investigation, regulatory audit, or incident review
- Assessing whether agent goal specifications are formally defined, constraint-checked, and verifiable before deployment
- Evaluating whether adversarial training has actually been applied to the model (not just claimed in documentation)
- Reviewing whether a distributed agent ecosystem's trust/reputation system is designed to resist Sybil attacks
- Building a MAESTRO cross-layer mitigation evidence package that covers Adversarial Training, Formal Verification, XAI, and Safety Monitoring as specified in the MAESTRO mitigation catalogue

**Scope:** This skill audits *posture* — configuration, documentation, and process controls — not live explainability outputs. Use SHAP/LIME tooling directly to generate explanations for specific decisions.

## Prerequisites

- Python 3.9+ (no external dependencies — stdlib only)
- One or more config JSONs for XAI posture, goal verification scope, and/or reputation system design (see Workflow)

## Workflow

### 1. Audit XAI (Explainability) posture

```json
{
  "system_name": "Loan Underwriting Agent",
  "xai": {
    "local_explainability_available": false,
    "global_explainability_available": false,
    "explanation_method": null,
    "explanation_per_decision_logged": false,
    "explanation_accessible_to_auditors": false,
    "counterfactual_explanations": false,
    "feature_importance_documented": false
  },
  "forensic_capability": {
    "decision_reconstruction_possible": false,
    "input_state_logged_per_decision": false,
    "model_version_tracked_per_decision": false,
    "explanation_tamper_evident": false
  },
  "stakeholder_access": {
    "user_facing_explanations": false,
    "regulator_facing_explanations": false,
    "appeal_mechanism_supported": false
  }
}
```

```bash
python agent.py audit-xai --config xai_config.json --output xai_audit.json
```

### 2. Verify formal goal specification

```json
{
  "agent_name": "Trading AI Agent",
  "goal_specification": {
    "goals_formally_defined": false,
    "constraints_formally_specified": false,
    "specification_language": null,
    "constraint_checker_implemented": false,
    "goal_conflicts_analyzed": false,
    "reward_hacking_scenarios_tested": false
  },
  "verification": {
    "formal_proof_available": false,
    "simulation_testing_performed": false,
    "red_team_goal_manipulation_tested": false,
    "invariant_monitoring_in_production": false
  },
  "alignment_testing": {
    "value_alignment_evaluated": false,
    "edge_case_goal_testing": false,
    "human_review_of_goals_performed": false,
    "goal_change_requires_review": false
  }
}
```

```bash
python agent.py verify-goals --manifest agent_goals.json --output goal_verification.json
```

### 3. Audit reputation system design

```json
{
  "ecosystem_name": "Distributed Agent Marketplace",
  "reputation_system": {
    "reputation_scoring_implemented": false,
    "sybil_resistance_mechanism": null,
    "reviewer_identity_verified": false,
    "stake_based_voting": false,
    "reputation_decay_implemented": false,
    "review_anomaly_detection": false,
    "bootstrap_manipulation_protected": false,
    "cross_platform_reputation_checked": false
  },
  "trust_controls": {
    "trust_scores_influence_discovery": false,
    "low_trust_agents_quarantined": false,
    "rapid_reputation_gain_flagged": false,
    "coordinated_rating_detection": false
  }
}
```

```bash
python agent.py reputation-audit --config reputation_config.json --output reputation_audit.json
```

## Key Concepts

| Concept | Description |
|---|---|
| Local Explainability | Explanation of a single model decision (why this input → this output): SHAP values, LIME, counterfactuals |
| Global Explainability | Understanding of overall model behavior (which features matter most across all decisions): feature importance, partial dependence plots |
| Formal Goal Verification | Mathematical specification and proof (or bounded testing) that an agent's goal function satisfies stated constraints and cannot be reward-hacked |
| Constraint Checking | Runtime enforcement of formal constraints on agent actions — blocks goal-misaligned actions before execution |
| Sybil Resistance | Mechanisms preventing one attacker from creating many fake identities to gain disproportionate reputation influence: stake-based voting, identity verification, anomaly detection |
| Adversarial Training Assessment | Verifying that claimed adversarial training was actually applied — checking for adversarial test suite results, training logs, and robustness benchmarks |
| Reputation Decay | Time-based degradation of reputation scores to prevent early-actor advantage and force ongoing legitimate contributions |

## Tools & Systems

| Tool | Purpose |
|---|---|
| agent.py `audit-xai` | Static audit of XAI posture against 11 explainability and forensic controls |
| agent.py `verify-goals` | Static audit of formal goal specification and verification posture against 12 controls |
| agent.py `reputation-audit` | Static audit of reputation system design against 12 Sybil-resistance controls |
| SHAP | SHapley Additive exPlanations — model-agnostic local and global feature importance |
| LIME | Local Interpretable Model-agnostic Explanations — perturbation-based local explanations |
| TLA+ / Alloy | Formal specification languages for goal and constraint verification |
| DiCE | Counterfactual explanation generation for machine learning models |

## Common Scenarios

**High-risk AI in financial services with no per-decision explanations:**
`explanation_per_decision_logged: false` and `decision_reconstruction_possible: false` are both CRITICAL — the system cannot support regulatory audits or customer appeals of adverse credit decisions.

**Autonomous trading agent with informally specified goals:**
`goals_formally_defined: false` and `constraint_checker_implemented: false` are HIGH — the agent can optimize its goal in ways that satisfy the specification text but violate the intent (reward hacking).

**Distributed agent marketplace with no Sybil resistance:**
`sybil_resistance_mechanism: null` and `reviewer_identity_verified: false` are CRITICAL — an attacker with 100 fake accounts can dominate ratings, promoting malicious agents and suppressing legitimate ones.

**Model claimed to use adversarial training with no benchmark evidence:**
`formal_proof_available: false` and no adversarial test suite results — claimed robustness is unverified. The audit flags this as HIGH and recommends requiring ART benchmark results as a deployment gate.

## Output Format

```json
{
  "audit_timestamp": "2026-05-02T10:00:00+00:00",
  "xai_findings": [
    {
      "id": "XAI-001",
      "severity": "CRITICAL",
      "mitigation_category": "Explainable AI (XAI)",
      "control": "Per-decision explanation logging",
      "finding": "explanation_per_decision_logged is false — no explanation is stored for individual agent decisions",
      "remediation": "Log SHAP or LIME explanation alongside each decision; store in tamper-evident log with the input state and model version"
    }
  ],
  "goal_verification_findings": [
    {
      "id": "GOAL-001",
      "severity": "HIGH",
      "mitigation_category": "Formal Verification",
      "control": "Runtime constraint checker",
      "finding": "constraint_checker_implemented is false — agent actions are not validated against formal constraints at runtime",
      "remediation": "Implement a runtime constraint layer that blocks agent actions violating defined invariants before execution"
    }
  ],
  "reputation_findings": [
    {
      "id": "REP-001",
      "severity": "CRITICAL",
      "mitigation_category": "Reputation-Based Trust",
      "control": "Sybil resistance mechanism",
      "finding": "sybil_resistance_mechanism is null — reputation system has no protection against fake-identity manipulation",
      "remediation": "Implement identity verification for reviewers plus coordinated-rating anomaly detection; consider stake-based voting"
    }
  ],
  "by_severity": { "CRITICAL": 4, "HIGH": 8, "MEDIUM": 6, "LOW": 2 },
  "overall_risk": "CRITICAL",
  "maestro_mitigation_coverage": {
    "adversarial_training": "PARTIALLY_ASSESSED",
    "formal_verification": "AUDITED",
    "explainable_ai": "AUDITED",
    "red_teaming": "NOT_IN_SCOPE",
    "safety_monitoring": "NOT_IN_SCOPE",
    "reputation_systems": "AUDITED"
  }
}
```
