---
name: adversarial-robustness-and-evasion-defense
description: >-
  Evaluates and hardens AI foundation models against adversarial example attacks
  (inputs crafted to force incorrect predictions), model-weight backdoor attacks
  (hidden triggers embedded in model weights distinct from training data poisoning),
  and sponge attacks (adversarially crafted inputs that exploit model complexity to
  exhaust inference compute). Audits model API deployments for adversarial robustness
  controls, input anomaly detection, and inference cost governance. Covers robustness
  evaluation framework design, backdoor indicator testing via output consistency
  probes, and sponge defense configuration. Maps to MAESTRO Layer 1 (Foundation
  Models) threats L1-T01 (Adversarial Examples), L1-T03 (Backdoor Attacks in model
  weights), and L1-T07 (DoS / Sponge Attacks) not addressed by existing Layer 1
  skills (ai-model-extraction-and-reprogramming-defense covers L1-T02 and L1-T06;
  llm-data-and-model-poisoning-defense covers L1-T05 training-phase data poisoning).
domain: cybersecurity
subdomain: ai-security
tags:
  - MAESTRO
  - adversarial-examples
  - backdoor-detection
  - sponge-attacks
  - foundation-models
  - adversarial-robustness
  - evasion-attacks
  - LLM-security
  - agentic-ai
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - ID.RA-01
  - PR.PS-04
  - DE.AE-02
  - DE.CM-01
  - RS.AN-01
atlas_techniques:
  - AML.T0043
  - AML.T0051
  - AML.T0054
  - AML.T0056
nist_ai_rmf:
  - GOVERN-1.1
  - MEASURE-2.5
  - MEASURE-2.7
  - MANAGE-2.2
d3fend_techniques:
  - Application Hardening
  - User Behavior Analysis
  - Network Traffic Filtering
---
# Adversarial Robustness and Evasion Defense

## When to Use

- Auditing a model API deployment for adversarial robustness controls (input anomaly detection, preprocessing defenses, robustness benchmarks)
- Assessing whether a third-party or fine-tuned model may contain weight-level backdoors (activation triggers, consistency anomalies)
- Checking that model inference infrastructure is defended against sponge attacks that exhaust GPU compute
- Building a MAESTRO Layer 1 (Foundation Models) L1-T01/L1-T03/L1-T07 evidence package for a threat model
- Reviewing a newly deployed or updated model for adversarial regression before production promotion

**Distinct from `llm-data-and-model-poisoning-defense`:** That skill covers poisoning of training *data* pipelines and behavioral testing for dataset-level poisoning. This skill covers model-*weight*-level backdoors and evasion-style adversarial inputs that exploit learned decision boundaries — no training pipeline access required.

**Distinct from `llm-resource-consumption-and-dos-prevention`:** That skill covers operational rate limits and token budgets. This skill covers *adversarially crafted* inputs that exploit model complexity (sponge attacks) — a specific adversarial vector, not generic overload.

## Prerequisites

- Python 3.9+ (no external dependencies — stdlib only)
- One or more config JSONs for the model API, backdoor scan scope, and/or sponge defense assessment (see Workflow)

## Workflow

### 1. Audit adversarial robustness controls

```json
{
  "model_name": "fraud-classifier-v2",
  "api_exposure": "public",
  "input_preprocessing": {
    "enabled": false,
    "input_smoothing": false,
    "feature_squeezing": false,
    "jpeg_compression_defense": false
  },
  "robustness_training": {
    "adversarial_training_applied": false,
    "certified_defense_applied": false,
    "ensemble_voting": false
  },
  "evasion_detection": {
    "input_anomaly_detection": false,
    "confidence_monitoring": false,
    "distribution_shift_detection": false,
    "out_of_distribution_detection": false
  },
  "robustness_testing": {
    "adversarial_eval_suite": false,
    "fgsm_tested": false,
    "pgd_tested": false,
    "carlini_wagner_tested": false,
    "robustness_benchmarks_run": false
  }
}
```

```bash
python agent.py probe --config model_robustness_config.json --output robustness_audit.json
```

### 2. Audit for backdoor indicators

```json
{
  "model_name": "external-vendor-classifier",
  "model_source": "third_party",
  "backdoor_detection": {
    "output_consistency_tested": false,
    "activation_clustering_analyzed": false,
    "spectral_signatures_checked": false,
    "fine_pruning_evaluated": false,
    "neural_cleanse_run": false
  },
  "model_provenance": {
    "source_verified": false,
    "training_data_audited": false,
    "model_card_available": false,
    "signed_artifact": false
  }
}
```

```bash
python agent.py backdoor-scan --config backdoor_config.json --output backdoor_audit.json
```

### 3. Audit sponge attack defenses

```json
{
  "api_name": "inference-endpoint-v2",
  "sponge_defenses": {
    "input_length_limits": false,
    "input_complexity_scoring": false,
    "per_request_compute_budget": false,
    "timeout_enforcement": false,
    "adversarial_input_detection": false,
    "complexity_anomaly_alerting": false
  }
}
```

```bash
python agent.py sponge-audit --config sponge_config.json --output sponge_audit.json
```

## Key Concepts

| Concept | Description |
|---|---|
| Adversarial Example (L1-T01) | Input with imperceptible perturbations (to humans) that cross a model's decision boundary — causing misclassification. Classic attacks: FGSM, PGD, Carlini-Wagner |
| Model-Weight Backdoor (L1-T03) | Hidden trigger embedded in model weights during training — a specific input pattern activates malicious behavior while the model appears normal on clean inputs |
| Sponge Attack (L1-T07) | Adversarially crafted input that exploits model complexity (e.g., triggering long attention chains, recursive reasoning loops) to exhaust inference compute — GPU-level DoS |
| Adversarial Training | Augmenting training data with adversarial examples so the model learns robust decision boundaries |
| Input Preprocessing Defense | Transformations applied before inference (input smoothing, feature squeezing, JPEG recompression) that degrade adversarial perturbations while preserving clean accuracy |
| Neural Cleanse | Backdoor detection technique: search for minimal trigger patterns that cause all inputs to be classified as a specific target class |
| Certified Defense | Mathematically proven robustness guarantee within an L-infinity ball — e.g., randomized smoothing provides certifiable robustness for classification models |

## Tools & Systems

| Tool | Purpose |
|---|---|
| agent.py `probe` | Static audit of model API configuration for adversarial robustness controls |
| agent.py `backdoor-scan` | Static audit of model provenance and backdoor detection posture |
| agent.py `sponge-audit` | Static audit of inference infrastructure sponge attack defenses |
| ART (Adversarial Robustness Toolbox) | IBM Research library for generating and evaluating adversarial attacks |
| CleverHans | TF/PyTorch library for adversarial example generation and defense benchmarking |
| Neural Cleanse | Backdoor detection via reverse-engineering trigger patterns |
| Foolbox | Model-agnostic adversarial attack library |

## Common Scenarios

**Third-party model with no provenance documentation:**
`source_verified: false`, `model_card_available: false`, `signed_artifact: false` are all HIGH — the model may contain weight-level backdoors with no way to verify it was trained as claimed.

**Public ML API with no input anomaly detection:**
`input_anomaly_detection: false` combined with `adversarial_eval_suite: false` is HIGH — adversarial inputs are indistinguishable from normal traffic and will not trigger alerts.

**Inference endpoint without compute budgets or timeouts:**
`per_request_compute_budget: false` and `timeout_enforcement: false` are CRITICAL for sponge — a single adversarial input can pin one GPU thread indefinitely, causing cascade failures across multi-tenant inference.

**Fine-tuned model with no adversarial regression testing:**
`adversarial_eval_suite: false` is HIGH — fine-tuning can degrade robustness of a previously certified base model without detection.

## Output Format

```json
{
  "audit_timestamp": "2026-05-02T10:00:00+00:00",
  "findings": [
    {
      "id": "ADV-001",
      "severity": "CRITICAL",
      "layer": "L1",
      "threat": "Sponge Attacks (L1-T07)",
      "control": "Per-request compute budget",
      "finding": "per_request_compute_budget is false — no ceiling on inference compute per request",
      "remediation": "Set a per-request FLOPs or wall-clock timeout ceiling at the inference serving layer; return 429 when exceeded"
    },
    {
      "id": "ADV-002",
      "severity": "HIGH",
      "layer": "L1",
      "threat": "Model-Weight Backdoor (L1-T03)",
      "control": "Model provenance verification",
      "finding": "source_verified is false and signed_artifact is false — model origin cannot be confirmed",
      "remediation": "Require signed model artifacts from all vendors; verify signatures before loading into production serving"
    },
    {
      "id": "ADV-003",
      "severity": "HIGH",
      "layer": "L1",
      "threat": "Adversarial Examples (L1-T01)",
      "control": "Adversarial evaluation suite",
      "finding": "No adversarial evaluation suite configured — model robustness under FGSM/PGD is unknown",
      "remediation": "Run ART or CleverHans adversarial benchmarks against the model; set minimum accuracy thresholds under L-inf perturbations"
    }
  ],
  "robustness_findings": [],
  "backdoor_findings": [],
  "sponge_findings": [],
  "by_severity": { "CRITICAL": 2, "HIGH": 6, "MEDIUM": 4, "LOW": 2 },
  "overall_risk": "HIGH"
}
```
