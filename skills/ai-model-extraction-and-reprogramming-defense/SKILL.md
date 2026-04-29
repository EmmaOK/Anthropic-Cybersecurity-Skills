---
name: ai-model-extraction-and-reprogramming-defense
description: >-
  Detects and mitigates model extraction (model stealing) attacks where adversaries
  systematically query an AI model API to reproduce its capabilities offline, and
  reprogramming attacks where adversarial prompts or misused fine-tuning APIs
  repurpose a model for malicious tasks. Covers API exposure auditing for extraction-
  resistant controls (rate limiting, query anomaly detection, output perturbation),
  membership inference risk assessment, and behavioral guardrails that enforce output
  policy independently of the model's own reasoning. Maps to MAESTRO Layer 1
  (Foundation Models) threats L1-T02 and L1-T06.
domain: cybersecurity
subdomain: ai-security
tags:
  - model-extraction
  - model-stealing
  - reprogramming-attacks
  - foundation-models
  - MAESTRO
  - LLM-security
  - adversarial-ml
  - API-security
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - ID.RA-01
  - PR.AA-05
  - DE.CM-01
  - DE.AE-02
atlas_techniques:
  - AML.T0056
  - AML.T0043
  - AML.T0068
nist_ai_rmf:
  - GOVERN-1.1
  - MEASURE-2.5
  - MANAGE-2.2
d3fend_techniques:
  - Application Hardening
  - User Behavior Analysis
  - Network Traffic Filtering
---
# AI Model Extraction and Reprogramming Defense

## When to Use

- Auditing a model API deployment for extraction-resistant controls before exposing it publicly
- Assessing whether existing rate limiting, output perturbation, and query anomaly detection are sufficient to deter model stealing
- Evaluating exposure to membership inference attacks (does the model leak whether specific data was in training?)
- Checking that output policy guardrails are enforced independently of the model — not relying solely on "the model will behave"
- Reviewing fine-tuning API access controls to prevent reprogramming attacks

## Prerequisites

- Python 3.9+ (no external dependencies)
- A model API config JSON describing the deployment (see Workflow for schema)

## Workflow

### 1. Create a model API config

```json
{
  "model_name": "fraud-classifier-v2",
  "api_exposure": "public",
  "rate_limiting": {"enabled": false, "per_user_rpm": null, "anomaly_detection": false},
  "auth": {"required": true, "type": "api_key", "per_tenant_limits": false},
  "output_controls": {
    "perturbation": false,
    "policy_layer": false,
    "logit_masking": false,
    "confidence_rounding": false
  },
  "fine_tuning_api": {"exposed": true, "access_control": false, "data_validation": false},
  "monitoring": {"query_logging": true, "consistency_monitoring": false, "extraction_alerts": false},
  "membership_inference": {"differential_privacy": false, "output_generalization": false}
}
```

### 2. Audit for extraction and reprogramming controls

```bash
python agent.py audit --config model_api_config.json --output model_audit.json
```

### 3. Review findings and apply mitigations

Focus on: missing rate limiting (most impactful extraction enabler), absent output policy layer (reprogramming risk), and unprotected fine-tuning API access.

## Key Concepts

| Concept | Description |
|---|---|
| Model Stealing / Extraction | Systematically querying a model API to reproduce its decision boundaries offline using the responses as a training signal |
| Reprogramming Attack | Repurposing a model for a different (malicious) task via adversarial prompts crafted to activate alternate behaviors |
| Output Perturbation | Adding calibrated noise to model outputs to prevent exact reproduction while preserving utility |
| Policy Layer | An external guardrail that validates/filters model outputs independently of the model's own judgment |
| Membership Inference | Determining whether specific data points were in the training set via differential outputs |
| Confidence Rounding | Reducing output precision (e.g., returning "HIGH/MEDIUM/LOW" instead of 0.9847) to reduce extraction signal |

## Tools & Systems

| Tool | Purpose |
|---|---|
| agent.py `audit` | Static config audit against 14 extraction/reprogramming controls |
| Rate limiting middleware | Primary extraction deterrent — implement at API gateway level |
| Model watermarking | Embedded signals that survive extraction, enabling stolen model identification |
| Output policy layer | LLM-as-judge or rule-based filter that validates outputs independently |

## Common Scenarios

**Public API with no rate limiting:**
The audit flags this as CRITICAL — no rate limiting means extraction is trivially easy.

**Fine-tuning API with no access control:**
An attacker with fine-tuning access can reprogram the model; flagged as CRITICAL.

**Model returns raw logits or high-precision probabilities:**
Flagged as HIGH — high-precision outputs maximize extraction signal quality.

## Output Format

```json
{
  "model_name": "fraud-classifier-v2",
  "total_checks": 14,
  "findings": [
    {
      "id": "EXT-001", "severity": "CRITICAL",
      "control": "API rate limiting",
      "finding": "rate_limiting.enabled is false — unlimited queries allow trivial model extraction",
      "remediation": "Implement per-user and per-IP rate limits; add anomaly detection for systematic querying"
    }
  ],
  "by_severity": { "CRITICAL": 2, "HIGH": 5, "MEDIUM": 3, "LOW": 1 },
  "overall_risk": "CRITICAL",
  "extraction_risk_score": "HIGH",
  "reprogramming_risk_score": "CRITICAL"
}
```
