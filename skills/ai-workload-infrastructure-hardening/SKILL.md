---
name: ai-workload-infrastructure-hardening
description: >-
  Audits Kubernetes manifests, container images, and infrastructure-as-code configurations
  for security weaknesses specific to AI workload deployments — MAESTRO Layer 4 (Deployment
  & Infrastructure). Detects missing admission controller policies, overprivileged RBAC for
  AI service accounts, unscanned or unsigned container images, IaC misconfigurations that
  expose model weights or vector databases, missing network segmentation between AI components,
  resource hijacking risks (no CPU/memory quotas), and lateral movement paths from agent pods
  to sensitive internal services such as secret stores and CI runners.
domain: cybersecurity
subdomain: ai-security
tags:
  - kubernetes-security
  - container-security
  - IaC-security
  - MAESTRO
  - ai-infrastructure
  - devsecops
  - lateral-movement
  - resource-hijacking
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - PR.PS-01
  - PR.PS-04
  - PR.IR-01
  - DE.CM-01
  - ID.AM-02
atlas_techniques:
  - AML.T0082
  - AML.T0088
nist_ai_rmf:
  - GOVERN-5.2
  - MANAGE-2.4
  - MEASURE-2.9
d3fend_techniques:
  - Software Bill of Materials
  - Firmware Verification
  - Network Traffic Filtering
  - Executable Denylisting
---
# AI Workload Infrastructure Hardening

## When to Use

- Auditing Kubernetes manifests for AI workloads before deployment or during security review
- Scanning infrastructure-as-code (Terraform/CloudFormation) for AI-specific misconfigurations
- Checking whether AI agent pods have proper resource quotas to prevent cryptomining/resource hijacking
- Verifying network segmentation between AI components (agent pods, vector DB, secret stores, LLM API)
- Assessing lateral movement risk from compromised agent pods to other internal services
- Building a MAESTRO Layer 4 evidence package for a threat model

## Prerequisites

- Python 3.9+ (no external dependencies)
- Kubernetes manifest(s) as JSON (use `kubectl get deployment -o json > manifest.json`)
  or a simplified infrastructure config JSON (see Workflow for schema)

## Workflow

### 1. Create an infra config (if not using K8s JSON directly)

```json
{
  "system": "Payment AI Agent Cluster",
  "workloads": [
    {
      "name": "agent-service",
      "image": "myregistry.io/agent:latest",
      "image_signed": false,
      "image_scanned": false,
      "privileged": false,
      "root_user": true,
      "resource_limits": {"cpu": null, "memory": null},
      "service_account": "default",
      "network_policy": false,
      "secrets_mounted": true,
      "secrets_as_env_vars": true
    }
  ],
  "rbac": {"least_privilege": false, "service_account_automation": true},
  "admission_controllers": {"pod_security_standards": false, "image_policy_webhook": false},
  "network": {"agent_to_vectordb_isolated": false, "agent_to_secret_store_isolated": false, "egress_controlled": false},
  "secrets_management": {"vault_integrated": false, "secrets_rotation": false, "no_plaintext_in_configmaps": false}
}
```

### 2. Scan the infrastructure config

```bash
python agent.py scan --config infra_config.json --output infra_audit.json
```

### 3. Scan a raw kubectl export

```bash
kubectl get deployment agent-service -o json > deployment.json
python agent.py scan-k8s --manifest deployment.json --output k8s_audit.json
```

## Key Concepts

| Concept | Description |
|---|---|
| Resource Hijacking | Compromised AI pod used for cryptomining — prevented by CPU/memory resource limits and quotas |
| Lateral Movement | From agent pod to vector DB, secret store, or CI runner via overprivileged service accounts or missing network policies |
| Pod Security Standards | Kubernetes baseline/restricted profiles preventing privileged containers and root execution |
| Admission Controllers | Webhook-based gates that enforce image signing, vulnerability scan status, and security policies at deploy time |
| Secrets as Env Vars | Kubernetes secrets mounted as environment variables are visible in `kubectl describe pod` — use volume mounts or Vault instead |
| Network Policy | Kubernetes network segmentation rules that restrict which pods can communicate with AI infrastructure components |

## Tools & Systems

| Tool | Purpose |
|---|---|
| agent.py `scan` | Static audit of infra config JSON against 16 AI workload security controls |
| agent.py `scan-k8s` | Parse raw kubectl JSON export and check key deployment security fields |
| Kyverno / OPA Gatekeeper | Policy-as-code engines for Kubernetes admission control |
| Trivy / Grype | Container image vulnerability scanners |
| Cosign | Container image signing tool |
| HashiCorp Vault | Secret management — preferred over Kubernetes secrets for AI credentials |

## Common Scenarios

**Agent pod running as root with no resource limits:**
Both are flagged CRITICAL — root execution enables container escape; no limits enable resource hijacking.

**Vector database reachable from any pod in the cluster:**
`agent_to_vectordb_isolated: false` is flagged HIGH — any compromised pod can exfiltrate embeddings.

**Secrets for LLM API keys in environment variables:**
`secrets_as_env_vars: true` is flagged HIGH — visible in pod descriptions and process listings.

## Output Format

```json
{
  "system": "Payment AI Agent Cluster",
  "total_checks": 16,
  "findings": [
    {
      "id": "INFRA-001", "severity": "CRITICAL",
      "control": "Container image signing",
      "finding": "image_signed is false for agent-service — unsigned images accepted by admission controller",
      "remediation": "Sign images with Cosign; configure image policy webhook to reject unsigned images"
    },
    {
      "id": "INFRA-003", "severity": "CRITICAL",
      "control": "Resource limits (anti-hijacking)",
      "finding": "No CPU or memory limits set — pod vulnerable to resource exhaustion and cryptomining",
      "remediation": "Set resource.limits.cpu and resource.limits.memory in pod spec; apply ResourceQuota at namespace level"
    }
  ],
  "by_severity": { "CRITICAL": 4, "HIGH": 6, "MEDIUM": 3, "LOW": 1 },
  "overall_risk": "CRITICAL"
}
```
