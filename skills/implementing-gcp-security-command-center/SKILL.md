---
name: implementing-gcp-security-command-center
description: >-
  Deploy and operate Google Cloud Security Command Center (SCC) Premium to
  continuously monitor GCP organization assets, detect threats with built-in
  detectors (Event Threat Detection, Container Threat Detection, Virtual Machine
  Threat Detection), enforce security health analytics across all projects, and
  integrate findings with Chronicle SIEM and Pub/Sub for automated response.
  Covers organization-level activation, custom modules, finding export pipelines,
  and compliance posture reporting against CIS GCP Foundations Benchmark.
domain: cybersecurity
subdomain: cloud-security
tags:
  - gcp
  - security-command-center
  - cspm
  - threat-detection
  - asset-inventory
  - compliance
  - google-cloud
version: '1.0'
author: emmanuelokonkwo
license: Apache-2.0
nist_csf:
  - DE.CM-01
  - ID.AM-01
  - ID.AM-05
  - PR.IR-01
  - RS.AN-01
d3fend_techniques:
  - Platform Monitoring
  - Cloud Resource Inventory
---

# Implementing GCP Security Command Center

## When to Use

- When establishing centralized security posture management across a GCP organization
- When enabling automated threat detection for GCP workloads (VMs, containers, serverless)
- When generating compliance evidence against CIS GCP Foundations Benchmark, PCI DSS, or NIST 800-53
- When routing GCP security findings into a SIEM or SOAR platform for automated response
- When auditing asset inventory and identifying publicly exposed resources across all projects

**Do not use** for AWS or Azure posture management (see `implementing-aws-security-hub` or `implementing-azure-defender-for-cloud`), or for application-layer vulnerability scanning of GCP-hosted workloads.

## Prerequisites

- GCP Organization with Organization Admin or Security Admin IAM role
- Security Command Center API enabled at the organization level
- SCC Premium tier activated (required for Event Threat Detection, VMTD, and compliance reports)
- Billing account linked to the organization

## Workflow

### Step 1: Enable SCC at Organization Level

Activate SCC Premium and grant required IAM roles. Organization-level activation is required — project-level SCC is Standard tier only and lacks threat detectors.

```bash
# Set your organization ID
export ORG_ID=$(gcloud organizations list --format='value(name)' | head -1)

# Enable Security Command Center API
gcloud services enable securitycenter.googleapis.com \
  --project=$(gcloud config get-value project)

# Grant SCC Admin role to security team service account
gcloud organizations add-iam-policy-binding $ORG_ID \
  --member="serviceAccount:scc-admin@your-project.iam.gserviceaccount.com" \
  --role="roles/securitycenter.admin"

# Grant findings viewer to SOC analysts (read-only)
gcloud organizations add-iam-policy-binding $ORG_ID \
  --member="group:soc-team@yourcompany.com" \
  --role="roles/securitycenter.findingsViewer"
```

### Step 2: Enable Built-in Threat Detectors

Activate Event Threat Detection (ETD), Container Threat Detection (CTD), and Virtual Machine Threat Detection (VMTD) across the organization.

```bash
# List available built-in services
gcloud scc settings describe --organization=$ORG_ID

# Enable Event Threat Detection (detects brute force, crypto mining, data exfil)
gcloud scc services enable EVENT_THREAT_DETECTION \
  --organization=$ORG_ID

# Enable Container Threat Detection (runtime threats in GKE)
gcloud scc services enable CONTAINER_THREAT_DETECTION \
  --organization=$ORG_ID

# Enable VM Threat Detection (memory threats, crypto mining in VMs)
gcloud scc services enable VIRTUAL_MACHINE_THREAT_DETECTION \
  --organization=$ORG_ID

# Enable Web Security Scanner for App Engine / Cloud Run
gcloud scc services enable WEB_SECURITY_SCANNER \
  --organization=$ORG_ID
```

### Step 3: Configure Security Health Analytics

Security Health Analytics continuously checks resource configurations against CIS GCP Foundations Benchmark and GCP best practices. Enable and review the active detectors.

```bash
# List all Security Health Analytics detectors
gcloud scc settings describe-explicit \
  --organization=$ORG_ID \
  --service=SECURITY_HEALTH_ANALYTICS

# Query current ACTIVE findings from Security Health Analytics
gcloud scc findings list organizations/$ORG_ID \
  --filter="state=ACTIVE AND source_properties.SourceDisplayName='Security Health Analytics'" \
  --format="table(name, category, severity, resource_name, event_time)"

# List CRITICAL findings only
gcloud scc findings list organizations/$ORG_ID \
  --filter="state=ACTIVE AND severity=CRITICAL" \
  --format="json" | python3 -c "
import json, sys
findings = json.load(sys.stdin).get('listFindingsResults', [])
for f in findings:
    finding = f['finding']
    print(f\"{finding['severity']:<10} {finding['category']:<50} {finding.get('resourceName','')}\")
"
```

### Step 4: Export Findings to Pub/Sub for Automated Response

Stream all new and updated SCC findings to a Pub/Sub topic so downstream SOAR or Lambda-style Cloud Functions can trigger automated remediation.

```bash
# Create a Pub/Sub topic for SCC findings
gcloud pubsub topics create scc-findings-export \
  --project=your-security-project

# Create a continuous export from SCC to Pub/Sub
gcloud scc notifications create scc-all-active-findings \
  --organization=$ORG_ID \
  --description="Export all active HIGH/CRITICAL findings" \
  --pubsub-topic=projects/your-security-project/topics/scc-findings-export \
  --filter="state=ACTIVE AND (severity=HIGH OR severity=CRITICAL)"

# Verify the notification config
gcloud scc notifications list --organization=$ORG_ID

# Subscribe and inspect exported finding payloads
gcloud pubsub subscriptions create scc-findings-sub \
  --topic=scc-findings-export \
  --project=your-security-project

gcloud pubsub subscriptions pull scc-findings-sub \
  --auto-ack --limit=5 --format=json
```

### Step 5: Create Custom SCC Modules

Write custom ETD modules in YARA-L 2.0 to detect organization-specific threat patterns not covered by built-in detectors.

```bash
# Create a custom ETD module (YARA-L 2.0 rule for detecting IAM key creation outside CI/CD)
cat > custom_iam_key_detection.yaral << 'EOF'
rule iam_key_created_outside_cicd {
  meta:
    author = "security-team"
    description = "Detects IAM service account key creation by non-CI/CD principals"
    severity = "HIGH"
    type = "THREAT"

  events:
    $e.metadata.event_type = "USER_RESOURCE_ACCESS"
    $e.target.resource.type = "SERVICE_ACCOUNT_KEY"
    $e.metadata.product_event_type = "google.iam.admin.v1.CreateServiceAccountKey"
    not re.regex($e.principal.user.email_addresses[0], `.*@cloudbuild\.gserviceaccount\.com`)
    not re.regex($e.principal.user.email_addresses[0], `.*@developer\.gserviceaccount\.com`)

  condition:
    $e
}
EOF

# Upload the custom module
gcloud scc custom-modules etd create \
  --organization=$ORG_ID \
  --display-name="IAM Key Creation Outside CICD" \
  --enablement-state=ENABLED \
  --custom-config-from-file=custom_iam_key_detection.yaral
```

### Step 6: Generate Compliance Posture Reports

Pull CIS GCP Foundations Benchmark v2.0 compliance data and export it for audit evidence.

```bash
# List compliance findings grouped by CIS control
gcloud scc findings list organizations/$ORG_ID \
  --filter="state=ACTIVE AND source_properties.ComplianceStandards:CIS-GCP" \
  --format="table(finding.category,finding.severity,finding.resource_name,finding.event_time)" \
  --page-size=500 > cis_gcp_findings.txt

# Generate a posture report (requires SCC Premium + Posture service)
gcloud scc postures list \
  --parent=organizations/$ORG_ID

# Export findings to BigQuery for long-term compliance trending
gcloud scc big-query-exports create scc-bq-compliance \
  --organization=$ORG_ID \
  --dataset=projects/your-security-project/datasets/scc_findings \
  --filter="state=ACTIVE" \
  --description="All active SCC findings for compliance trending"
```

## Key Concepts

| Term | Definition |
|---|---|
| Security Command Center | GCP-native CSPM and threat detection platform operating at the organization level |
| Event Threat Detection | Built-in ETD service that analyzes Cloud Logging in near real-time for threats like crypto mining, data exfiltration, and brute force |
| Container Threat Detection | Runtime threat detection for GKE workloads using kernel-level behavioral monitoring |
| VMTD | Virtual Machine Threat Detection; analyzes VM memory at the hypervisor level without requiring an agent |
| Security Health Analytics | Continuously evaluates GCP resource configurations against CIS benchmarks and GCP best practices |
| Finding | A SCC security observation with severity, state, category, affected resource, and event time |
| Notification Config | A Pub/Sub streaming export rule that forwards matching SCC findings to a topic in near real-time |
| Custom ETD Module | User-authored YARA-L 2.0 rule that extends Event Threat Detection with organization-specific detections |
| SCC Posture | Policy-as-code framework within SCC Premium for defining and enforcing security guardrails across projects |

## Tools & Systems

- **Google Cloud Security Command Center**: Core CSPM and threat detection platform
- **Cloud Logging**: Data source for Event Threat Detection log analysis
- **Pub/Sub**: Streaming finding export bus for downstream SOAR/automation integration
- **BigQuery**: Long-term finding storage for compliance trending and custom dashboards
- **Chronicle SIEM**: Google's cloud SIEM; SCC Premium findings feed directly into Chronicle for correlated investigation
- **gcloud CLI**: Primary interface for SCC configuration and finding queries
- **Cloud Functions / Cloud Run**: Serverless compute for automated remediation triggered by Pub/Sub finding events

## Common Scenarios

### Scenario: Crypto Mining Detected on a GKE Node

**Context**: VMTD flags memory-resident crypto mining on a production GKE node. The finding appears in SCC with severity CRITICAL.

**Approach**:
1. Pub/Sub export routes the finding to a Cloud Function within 30 seconds
2. The function cordon/drain the affected node using the Kubernetes API
3. Capture a memory snapshot via Cloud Monitoring for forensic analysis
4. Terminate the node and let the managed node pool replace it
5. Remediate the exploit path (overly permissive workload identity or exposed node port) identified in the SCC finding's `sourceProperties`

### Scenario: CIS Benchmark Compliance Below 70%

**Context**: A quarterly audit finds the GCP organization scoring 64% on CIS GCP Foundations Benchmark v2.0. The top failures are public Cloud Storage buckets, disabled Cloud Audit Logs, and overly broad IAM bindings.

**Approach**:
1. Export all FAILED CIS findings to BigQuery for prioritization by project and control ID
2. Use Organization Policy constraints to enforce `storage.publicAccessPrevention` across all projects
3. Enable Data Access audit logs org-wide via a single Organization-level audit config update
4. Run Recommender API to identify and remove unused IAM bindings
5. Track week-over-week compliance score improvement via a BigQuery + Looker Studio dashboard

## Output Format

```json
{
  "organization": "organizations/123456789",
  "report_date": "2026-06-06",
  "scc_tier": "PREMIUM",
  "active_findings_summary": {
    "CRITICAL": 12,
    "HIGH": 47,
    "MEDIUM": 203,
    "LOW": 891
  },
  "detectors_enabled": [
    "EVENT_THREAT_DETECTION",
    "CONTAINER_THREAT_DETECTION",
    "VIRTUAL_MACHINE_THREAT_DETECTION",
    "SECURITY_HEALTH_ANALYTICS",
    "WEB_SECURITY_SCANNER"
  ],
  "cis_gcp_compliance": {
    "benchmark": "CIS GCP Foundations Benchmark v2.0",
    "passing_controls": 58,
    "failing_controls": 34,
    "score_percent": 63
  },
  "top_categories": [
    {"category": "PUBLIC_BUCKET_ACL", "count": 23, "severity": "CRITICAL"},
    {"category": "AUDIT_LOGGING_DISABLED", "count": 18, "severity": "HIGH"},
    {"category": "OPEN_FIREWALL", "count": 14, "severity": "HIGH"},
    {"category": "KMS_KEY_NOT_ROTATED", "count": 9, "severity": "MEDIUM"}
  ],
  "notification_configs": [
    {"name": "scc-all-active-findings", "pubsub_topic": "projects/security-proj/topics/scc-findings-export"}
  ]
}
```
