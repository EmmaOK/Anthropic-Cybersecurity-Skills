---
name: performing-aks-cluster-penetration-test
description: >-
  Penetration testing of Azure Kubernetes Service (AKS) clusters — auditing RBAC,
  secrets, network policy, pod security, and control-plane components, then chaining
  findings along the AKS kill chain. Mapped to the CIS AKS Benchmark and MITRE ATT&CK.
domain: cybersecurity
subdomain: cloud-security
tags:
  - aks
  - kubernetes
  - azure
  - rbac
  - privilege-escalation
  - cluster-admin
  - pod-security
  - network-policy
  - secret-exposure
  - kill-chain
  - cloud-pentest
  - cis-benchmark
  - T1548.005
  - T1552.007
  - T1078
  - T1610
  - T1557
  - T1611
  - T1190
  - T1210
version: '1.0'
author: emmanuelokonkwo
license: Apache-2.0
---

# Performing AKS Cluster Penetration Test

## Metadata
- **Subdomain:** cloud-security
- **Tags:** `aks` `kubernetes` `azure` `rbac` `privilege-escalation` `cluster-admin` `pod-security` `network-policy` `secret-exposure` `kill-chain` `cloud-pentest` `cis-benchmark` `mitre-attack-cloud`
- **Has Script:** true
- **Script Subcommands:** `collect` · `audit` · `audit-rbac` · `audit-secrets` · `audit-network` · `audit-pods` · `audit-components` · `kill-chain` · `report`
- **MITRE ATT&CK:** T1548.005, T1552.007, T1078, T1610, T1557, T1611, T1190
- **CIS Benchmark:** AKS Benchmark v1.4 §4.1, §5.1, §5.2, §5.3
- **Frameworks:** CIS AKS Benchmark v1.4 · MITRE ATT&CK Enterprise · OWASP Top 10 · NIST SP 800-190

---

## Overview

This skill covers an end-to-end authorized penetration test of an Azure Kubernetes Service (AKS) cluster. It addresses a real-world constraint: AKS management endpoints are not publicly reachable, so the assessment operates against `kubectl` JSON exports collected from an Azure-connected system rather than requiring live cluster access from the assessment machine.

The assessment covers seven attack surfaces: RBAC privilege escalation, credential and secret exposure, pod security bypass, network segmentation gaps, component CVE exploitation, service identity gaps, and full end-to-end kill chain synthesis. The included `agent.py` script automates the analysis of all seven surfaces against a directory of `kubectl` JSON exports.

**Scope:** Any AKS cluster. Validated against clusters running Kubernetes 1.27–1.32 with Azure CNI, Azure Policy / OPA Gatekeeper, and cert-manager.

---

## Authorization Requirements

Before running this assessment:

1. Confirm written authorization from the Azure subscription owner covering:
   - The AKS cluster resource group
   - All namespaces in scope
   - Any connected Azure resources (Storage, Key Vault, ACR)
2. Confirm the engagement type: configuration audit (kubectl exports only) vs. live exploitation.
3. For live exploitation: obtain temporary `cluster-admin` kubeconfig scoped to the assessment period. Revoke after engagement.
4. Document the authorization reference number in every report generated.

> **Never run this skill against a cluster you do not have explicit written authorization to test.**

---

## Prerequisites

### Assessment Machine
- Python 3.8+
- `kubectl` CLI (for live access mode)
- `azure-cli` (for Azure resource assessment)
- `jq` (optional, for quick verification of exports)

### Cluster Access Options

**Option A — Export Mode (recommended for most engagements)**
The AKS API server is not publicly reachable. A user with `cluster-admin` or `view` on the target cluster runs the collection commands (see `collect` subcommand) from an Azure-connected system and shares the output files. The assessment runs entirely against these exports — no live cluster connection needed.

**Option B — Direct Access Mode**
If the assessment machine can reach the AKS API server (VPN, Azure Bastion, or private peering), use a kubeconfig with the minimum role needed:
```bash
# Minimum role for read-only audit:
kubectl create clusterrolebinding pentest-view \
  --clusterrole=view \
  --serviceaccount=default:pentest-sa
```

### Files Needed (Export Mode)
| File | kubectl Command |
|------|----------------|
| `aks_pods.json` | `kubectl get pods -A -o json` |
| `aks_deployments.json` | `kubectl get deployments -A -o json` |
| `aks_crb.json` | `kubectl get clusterrolebindings -o json` |
| `aks_cr.json` | `kubectl get clusterroles -o json` |
| `aks_rb.json` | `kubectl get rolebindings -A -o json` |
| `aks_sa.json` | `kubectl get serviceaccounts -A -o json` |
| `aks_secrets.json` | `kubectl get secrets -A -o json` |
| `aks_netpol.json` | `kubectl get networkpolicies -A -o json` |
| `aks_namespaces.json` | `kubectl get namespaces -o json` |
| `aks_services.json` | `kubectl get services -A -o json` |
| `aks_configmaps.json` | `kubectl get configmaps -A -o json` |
| `aks_ingress.json` | `kubectl get ingress -A -o json` |

> **Encoding note:** `kubectl` on Windows PowerShell outputs UTF-16. The agent.py script handles this automatically via BOM detection.

---

## Assessment Workflow

### Phase 1 — Reconnaissance & Collection

**Objective:** Map the cluster surface: namespaces, workloads, service accounts, exposed services.

```bash
# Generate collection commands:
python3 agent.py collect

# Or collect directly (live access):
kubectl get namespaces -o json > aks_namespaces.json
kubectl get pods -A -o json > aks_pods.json
kubectl get deployments -A -o json > aks_deployments.json
kubectl get services -A -o json > aks_services.json
kubectl get ingress -A -o json > aks_ingress.json
```

Key reconnaissance questions:
- Which namespaces exist beyond `kube-system`?
- What application workloads are running (names reveal technology stack)?
- Which services have `LoadBalancer` or `NodePort` type (externally reachable)?
- Which ingress resources are configured and to what hostnames?

**Encoding fix (Windows exports):**
```python
# If JSON files are UTF-16 (common from PowerShell):
for f in aks_*.json:
    raw = open(f, 'rb').read()
    text = raw.decode('utf-16')
    open(f.replace('.json', '_clean.json'), 'w').write(text)
```

---

### Phase 2 — RBAC Privilege Escalation Analysis

**Objective:** Find paths from any service account or pod to elevated cluster privileges.

**CVSS range:** 9.1–9.8 (if exploitable without prerequisites)
**MITRE:** T1548.005 — Abuse Elevation Control Mechanism: Kubernetes

#### 2.1 — Identify cluster-admin bindings

```bash
kubectl get clusterrolebindings -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
    role = item.get('roleRef', {}).get('name', '')
    if 'cluster-admin' in role or role == 'admin':
        for s in item.get('subjects', []) or []:
            print(f\"BINDING: {item['metadata']['name']}\")
            print(f\"  ROLE:    {role}\")
            print(f\"  SUBJECT: {s.get('kind')}/{s.get('namespace','')}/{s.get('name')}\")
"
```

**Critical pattern — default service account with cluster-admin:**
If the `default` service account in any namespace is bound to `cluster-admin`, every pod that does not explicitly declare a `serviceAccountName` inherits full cluster control. This is the most severe single finding possible in a Kubernetes assessment.

```bash
# Identify affected pods:
kubectl get pods -A -o json | python3 -c "
import json, sys
for p in json.load(sys.stdin)['items']:
    sa = p['spec'].get('serviceAccountName', 'default')
    ns = p['metadata']['namespace']
    if sa == 'default' and ns not in ['kube-system']:
        print(f\"{ns}/{p['metadata']['name']} → uses default SA\")
"
```

#### 2.2 — Check for wildcard permissions in custom roles

```bash
kubectl get clusterroles -o json | python3 -c "
import json, sys
for role in json.load(sys.stdin)['items']:
    name = role['metadata']['name']
    if name.startswith('system:'): continue
    for rule in role.get('rules', []):
        verbs = rule.get('verbs', [])
        resources = rule.get('resources', [])
        if '*' in verbs or '*' in resources:
            print(f'WILDCARD: {name} — verbs={verbs} resources={resources}')
"
```

#### 2.3 — Check automounted service account tokens

```bash
# Pods with automounted tokens (Kubernetes default is true):
kubectl get pods -A -o json | python3 -c "
import json, sys
for p in json.load(sys.stdin)['items']:
    mount = p['spec'].get('automountServiceAccountToken', True)
    ns = p['metadata']['namespace']
    name = p['metadata']['name']
    if mount is not False and ns not in ['kube-system']:
        print(f'{ns}/{name}: token MOUNTED (default)')
"
```

#### 2.4 — Verify token is live inside a pod (live access only)

```bash
# From inside any pod with cluster-admin token:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces
# If this returns a list → cluster-admin confirmed
```

---

### Phase 3 — Credential and Secret Exposure

**Objective:** Extract plaintext credentials from pod environment variables and Kubernetes Secrets.

**CVSS range:** 8.1–9.1
**MITRE:** T1552.007 — Unsecured Credentials: Container API
**CWE:** CWE-798, CWE-312

#### 3.1 — Scan pod env vars for plaintext credentials

```bash
kubectl get pods -A -o json | python3 -c "
import json, sys, re
SENSITIVE = re.compile(r'password|secret|key|token|credential|api_key', re.I)
for pod in json.load(sys.stdin)['items']:
    ns = pod['metadata']['namespace']
    pname = pod['metadata']['name']
    for c in pod['spec'].get('containers', []):
        for e in c.get('env', []):
            name = e.get('name', '')
            if SENSITIVE.search(name) and 'value' in e:
                val = e['value']
                print(f'PLAINTEXT: {ns}/{pname}.{c[\"name\"]}')
                print(f'  {name} = {val[:60]}')
"
```

**High-value targets:**
| Variable Pattern | Credential Type | Impact |
|-----------------|----------------|--------|
| `*_PASSWORD` | Database / service passwords | Direct DB access |
| `*_SECRET` | OAuth / app secrets | Service impersonation |
| `DJANGO_SECRET_KEY` / `django-insecure-*` | Django signing key | Session forgery |
| `*_ADMIN_PASSWORD` | Admin credentials | Full IdP/app admin |
| `*_KEY` | API / storage keys | Resource access |

#### 3.2 — Scan Kubernetes Secrets for high-value data

```bash
kubectl get secrets -A -o json | python3 -c "
import json, sys, base64, re
SENSITIVE = re.compile(r'password|secret|key|token|storage', re.I)
for s in json.load(sys.stdin)['items']:
    ns = s['metadata']['namespace']
    name = s['metadata']['name']
    for k, v in (s.get('data') or {}).items():
        if SENSITIVE.search(k):
            try:
                decoded = base64.b64decode(v).decode(errors='ignore')[:80]
                print(f'{ns}/{name}.{k} = {decoded}')
            except Exception:
                pass
"
```

#### 3.3 — Check for shared secrets across services

A single credential value appearing in multiple pods indicates a shared secret — if one pod is compromised, all services are compromised simultaneously.

```bash
# Find duplicate secret values:
kubectl get pods -A -o json | python3 -c "
import json, sys, collections
counts = collections.defaultdict(list)
for pod in json.load(sys.stdin)['items']:
    for c in pod['spec'].get('containers', []):
        for e in c.get('env', []):
            if 'value' in e and len(e['value']) > 8:
                counts[e['value']].append(f\"{pod['metadata']['namespace']}/{pod['metadata']['name']}.{e['name']}\")
for val, locs in counts.items():
    if len(locs) > 1:
        print(f'SHARED VALUE across {len(locs)} locations:')
        for loc in locs: print(f'  {loc}')
"
```

---

### Phase 4 — Pod and Container Security

**Objective:** Find pods that can escape to the host node or bypass container isolation.

**CVSS range:** 7.5–8.0
**MITRE:** T1611 — Escape to Host

#### 4.1 — Identify privileged pods outside kube-system

```bash
kubectl get pods -A -o json | python3 -c "
import json, sys
for pod in json.load(sys.stdin)['items']:
    ns = pod['metadata']['namespace']
    if ns == 'kube-system': continue  # expected there
    for c in pod['spec'].get('containers', []):
        sc = c.get('securityContext', {})
        if sc.get('privileged'):
            print(f'PRIVILEGED: {ns}/{pod[\"metadata\"][\"name\"]}/{c[\"name\"]}')
        if sc.get('allowPrivilegeEscalation', True):
            print(f'PRIV-ESC-ALLOWED: {ns}/{pod[\"metadata\"][\"name\"]}/{c[\"name\"]}')
        if sc.get('runAsUser') == 0 or not sc.get('runAsNonRoot'):
            print(f'RUNS-AS-ROOT: {ns}/{pod[\"metadata\"][\"name\"]}/{c[\"name\"]}')
"
```

#### 4.2 — Check Pod Security Admission labels

```bash
kubectl get namespaces -o json | python3 -c "
import json, sys
for ns in json.load(sys.stdin)['items']:
    name = ns['metadata']['name']
    labels = ns['metadata'].get('labels', {})
    psa = {k:v for k,v in labels.items() if 'pod-security' in k}
    status = psa if psa else 'NO PSA LABELS — privileged pods unrestricted'
    print(f'{name}: {status}')
"
```

#### 4.3 — Check for dangerous volume mounts

```bash
kubectl get pods -A -o json | python3 -c "
import json, sys
DANGEROUS_PATHS = ['/etc', '/var/run/docker.sock', '/proc', '/sys', '/', '/root']
for pod in json.load(sys.stdin)['items']:
    ns = pod['metadata']['namespace']
    if ns == 'kube-system': continue
    for v in pod['spec'].get('volumes', []):
        hp = v.get('hostPath', {}).get('path', '')
        if any(hp.startswith(d) for d in DANGEROUS_PATHS):
            print(f'DANGEROUS HOSTPATH: {ns}/{pod[\"metadata\"][\"name\"]} mounts {hp}')
"
```

#### 4.4 — Check resource limits

```bash
kubectl get pods -A -o json | python3 -c "
import json, sys
for pod in json.load(sys.stdin)['items']:
    ns = pod['metadata']['namespace']
    for c in pod['spec'].get('containers', []):
        res = c.get('resources', {})
        if not res.get('limits'):
            print(f'NO LIMITS: {ns}/{pod[\"metadata\"][\"name\"]}/{c[\"name\"]}')
"
```

---

### Phase 5 — Network Segmentation Assessment

**Objective:** Identify pod-to-pod paths that should be restricted but are not.

**CVSS range:** 5.3–7.8
**MITRE:** T1557 — Adversary-in-the-Middle · T1210 — Exploitation of Remote Services

#### 5.1 — Check which namespaces have no NetworkPolicies

```bash
kubectl get networkpolicies -A -o json | python3 -c "
import json, sys
covered = set()
for np in json.load(sys.stdin)['items']:
    covered.add(np['metadata']['namespace'])
print('Namespaces WITH NetworkPolicies:', covered)
"
# Compare against all namespaces:
kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'
```

#### 5.2 — Check for empty podSelector (allows all pods)

An empty `podSelector: {}` on an ingress rule means **all pods** in the namespace match — not just the intended target.

```bash
kubectl get networkpolicies -A -o json | python3 -c "
import json, sys
for np in json.load(sys.stdin)['items']:
    ns = np['metadata']['namespace']
    name = np['metadata']['name']
    for rule in np['spec'].get('ingress', []) + np['spec'].get('egress', []):
        for peer in rule.get('from', []) + rule.get('to', []):
            ps = peer.get('podSelector', None)
            if ps == {}:
                print(f'EMPTY SELECTOR: {ns}/{name} — allows ALL pods in namespace')
"
```

#### 5.3 — Test internal reachability (live access only)

```bash
# From a pod in the target namespace, test DB reachability:
kubectl exec -it <any-pod> -n <namespace> -- \
  nc -zv <db-service-name> 5432
# If this succeeds from a pod that shouldn't have DB access → NetworkPolicy gap confirmed
```

#### 5.4 — Check for service mesh (mTLS)

```bash
# Check for Istio:
kubectl get pods -A -o json | python3 -c "
import json, sys
mesh = False
for pod in json.load(sys.stdin)['items']:
    for c in pod['spec'].get('containers', []):
        if any(x in c.get('image','') for x in ['istio', 'linkerd', 'envoy', 'cilium']):
            print(f'MESH SIDECAR: {c[\"image\"]}')
            mesh = True
if not mesh:
    print('NO SERVICE MESH DETECTED — all inter-pod traffic is unencrypted')
"
```

---

### Phase 6 — Component CVE Analysis

**Objective:** Identify running component versions with known exploitable CVEs.

**CVSS range:** 7.5+ for actively exploitable CVEs
**MITRE:** T1190 — Exploit Public-Facing Application

```bash
# Extract all container images:
kubectl get pods -A -o json | python3 -c "
import json, sys
images = set()
for pod in json.load(sys.stdin)['items']:
    for c in pod['spec'].get('containers', []):
        images.add(c.get('image',''))
for img in sorted(images):
    print(img)
"
```

**Known CVE quick-check table:**

| Component | Vulnerable Versions | CVE | CVSS | Check |
|-----------|-------------------|-----|------|-------|
| Argo Workflows | < 3.5.13 / 3.6.2 | CVE-2024-53862 | 7.5 | Image tag contains `argoproj/argocli` |
| Kafka UI | 0.4.0–0.7.1 | CVE-2023-52251 | 9.8 | Image tag contains `provectuslabs/kafka-ui` |
| Kafka UI | 0.4.0–0.7.1 | CVE-2024-32030 | 7.5 | Same image |
| containerd | < 1.6.26 / 1.7.11 | CVE-2023-25173 | 8.8 | Node component |
| ingress-nginx | < 1.9.6 | CVE-2024-7646 | 8.8 | Image tag contains `ingress-nginx` |

```bash
# Check Argo version:
kubectl get pods -A -o json | python3 -c "
import json, sys, re
for pod in json.load(sys.stdin)['items']:
    for c in pod['spec'].get('containers', []):
        img = c.get('image','')
        if 'argoproj' in img or 'argo' in img.lower():
            print(f'ARGO IMAGE: {img}')
            ver = re.search(r'v(\d+\.\d+\.\d+)', img)
            if ver:
                parts = list(map(int, ver.group(1).split('.')))
                if parts[0] < 3 or (parts[0] == 3 and parts[1] < 5):
                    print(f'  VULNERABLE: {ver.group()} < 3.5.13 → CVE-2024-53862 (CVSS 7.5)')
"
```

---

### Phase 7 — Kill Chain Synthesis

**Objective:** Map how individual findings combine into a complete end-to-end attack path from unauthenticated external access to data breach.

This phase requires correlating findings from:
- The AKS cluster assessment (this skill)
- Any concurrent web application assessment (Phase 1 findings)
- Azure resource configuration (storage account permissions, IAM)

**Kill chain template:**

```
STEP 1: INITIAL ACCESS
  Finding: [web app vuln or exposed service]
  Method:  [credential stuffing / ROPC / exposed API]
  Result:  Valid session or code execution entry point

STEP 2: EXECUTION
  Finding: [code execution vector]
  Method:  [XSS / file upload / SSRF / vulnerable component]
  Result:  Code execution inside a pod

STEP 3: PRIVILEGE ESCALATION
  Finding: [RBAC misconfiguration]
  Method:  Read /var/run/secrets/kubernetes.io/serviceaccount/token
           curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/secrets
  Result:  cluster-admin access → read ALL secrets in ALL namespaces

STEP 4: CREDENTIAL HARVEST
  Finding: [plaintext secrets / storage keys in K8s Secrets]
  Result:  Cloud storage key, database passwords, OAuth admin credentials

STEP 5: EXFILTRATION
  Finding: [weak authorization on data endpoints / storage key]
  Method:  az storage blob download-batch --account-key <harvested-key>
  Result:  Full dataset exfiltrated — HIPAA/GDPR reportable breach

ZERO-DAYS REQUIRED: 0
```

---

## Automated Assessment with agent.py

### Installation
```bash
# No dependencies beyond Python 3.8+ stdlib
python3 agent.py --help
```

### Subcommands

#### `collect` — Generate collection commands
Prints the exact `kubectl` commands to run on the Azure-connected system:
```bash
python3 agent.py collect
python3 agent.py collect --namespace hfo-tools  # scope to one namespace
python3 agent.py collect --output-dir /tmp/aks_audit
```

#### `audit` — Full automated assessment
```bash
python3 agent.py audit --dir /tmp/aks_audit
python3 agent.py audit --dir /tmp/aks_audit --namespace hfo-tools
python3 agent.py audit --dir /tmp/aks_audit --output findings.json
```

#### Targeted audits
```bash
python3 agent.py audit-rbac    --dir /tmp/aks_audit
python3 agent.py audit-secrets --dir /tmp/aks_audit
python3 agent.py audit-network --dir /tmp/aks_audit
python3 agent.py audit-pods    --dir /tmp/aks_audit
python3 agent.py audit-components --dir /tmp/aks_audit
```

#### `kill-chain` — Kill chain analysis
```bash
python3 agent.py kill-chain --findings findings.json
python3 agent.py kill-chain --findings findings.json --web-findings web_findings.json
```

#### `report` — Generate report
```bash
python3 agent.py report --findings findings.json              # markdown (default)
python3 agent.py report --findings findings.json --format json
python3 agent.py report --findings findings.json --format md --output aks_report.md
```

---

## Expected Findings by Risk Category

| Finding Pattern | Typical CVSS | Frequency |
|----------------|-------------|-----------|
| default SA → cluster-admin | 9.8 | Very common in Argo/workflow clusters |
| Workflow SA → cluster-admin | 9.1 | Common when Argo is self-provisioned |
| Admin password in env var | 9.1 | Common in containerized IdPs |
| Trivially weak DB passwords | 9.1 | Common in dev-to-prod migrations |
| Storage account key in K8s Secret | 8.1 | Common with legacy Azure integrations |
| No PSA enforcement | 8.0 | Default AKS state — no action taken |
| Outdated Argo Workflows | 7.5 | Common — upgrades disruptive |
| Missing NetworkPolicies | 5.3–7.8 | Default Kubernetes state |
| No resource limits | 5.3 | Common in early-stage clusters |
| Shared inter-service secrets | 7.8 | Common in monolith-to-microservice migrations |

---

## Remediation Priority Framework

Apply fixes in this order to maximize security improvement per unit of effort:

1. **Chain-breaking (Day 1, zero downtime):** Delete dangerous ClusterRoleBindings. Rotate any exposed credentials.
2. **Secret management (Week 1):** Migrate all credentials to Azure Key Vault via Secrets Store CSI driver.
3. **Pod security (Sprint 1):** Enable PSA warn mode → fix violations → enforce. Assign named service accounts.
4. **Network segmentation (Sprint 1):** Fix empty podSelectors. Add NetworkPolicies to unprotected namespaces.
5. **Component updates (Sprint 1–2):** Upgrade CVE-affected components. Start with highest EPSS score.
6. **Service identity (Sprint 2–4):** Deploy Linkerd (mTLS) + Azure Workload Identity (Azure service auth).
7. **Audit logging (Sprint 3–6):** Azure Monitor + Log Analytics + immutable retention.

---

## References

- [CIS AKS Benchmark v1.4](https://www.cisecurity.org/benchmark/kubernetes)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [CVE-2024-53862 — Argo Workflows Auth Bypass](https://nvd.nist.gov/vuln/detail/CVE-2024-53862)
- [Azure Workload Identity documentation](https://azure.github.io/azure-workload-identity/docs/)
- [Linkerd mTLS configuration](https://linkerd.io/2.14/tasks/adding-your-service/)
- [Kubernetes Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [NIST SP 800-190 — Application Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)
