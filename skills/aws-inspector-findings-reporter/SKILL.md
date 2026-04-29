---
name: aws-inspector-findings-reporter
description: >-
  Pulls vulnerability findings from AWS Inspector v2 via the boto3 API and generates
  structured monthly reports aggregated by severity, resource type (EC2/ECR/Lambda),
  region, and AWS account. Enriches findings with CISA Known Exploited Vulnerability (KEV)
  catalog cross-reference and EPSS exploit-probability scores embedded in Inspector findings.
  Produces trend comparison reports across two reporting periods to track remediation velocity.
  Designed for scheduled automation (Lambda, GitHub Actions cron) and CI gating — exits with
  code 1 when CRITICAL findings are present.
domain: cybersecurity
subdomain: vulnerability-management
tags:
  - aws-inspector
  - vulnerability-management
  - reporting
  - boto3
  - EPSS
  - CISA-KEV
  - cloud-security
  - automation
  - monthly-reporting
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - ID.RA-01
  - ID.RA-05
  - DE.CM-08
  - RS.AN-07
d3fend_techniques:
  - Network Vulnerability Assessment
  - Vulnerability Scanning
---
# AWS Inspector Findings Reporter

## When to Use

- Generating monthly vulnerability reports from AWS Inspector v2 across one or more AWS accounts
- Automating scheduled reporting from Lambda, GitHub Actions, or a cron job
- Identifying findings associated with actively exploited CVEs (CISA KEV catalog) or high-exploit-probability vulnerabilities (EPSS ≥ 0.7)
- Tracking remediation velocity by comparing the current month's report against the previous month
- CI/CD pipeline gating — block deployments when CRITICAL findings are present (exit code 1)

**Do not use** as a replacement for Inspector's native suppression rules or for findings that require manual triage. Trend reports require two saved report JSON files; the script does not query historical Inspector data directly.

## Prerequisites

- AWS credentials configured (`~/.aws/credentials`, environment variables, or IAM instance role)
- IAM permissions: `inspector2:ListFindings`, `inspector2:ListCoverage`
- AWS Inspector v2 enabled in each target region
- Python 3.9+
- `boto3` installed: `pip install boto3`
- Internet access for CISA KEV catalog fetch (optional; disable with omitting `--kev`)

## Workflow

### 1. Generate the monthly report

```bash
python agent.py report \
  --start-date 2026-03-01 \
  --end-date   2026-03-31 \
  --regions    us-east-1,us-west-2,eu-west-1 \
  --kev \
  --output     report_march_2026.json
```

For multi-account orgs, assume the delegated-admin role first:
```bash
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT_ID:role/InspectorReadOnly \
  --role-session-name monthly-report --profile org-master
# then export the returned credentials and run agent.py
```

### 2. Compare to previous month (trends)

```bash
python agent.py trends \
  --current  report_march_2026.json \
  --previous report_feb_2026.json \
  --output   trends_march_2026.json
```

### 3. Automate monthly via GitHub Actions

```yaml
on:
  schedule:
    - cron: '0 6 1 * *'   # 06:00 UTC on the 1st of each month
jobs:
  inspector-report:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.INSPECTOR_ROLE_ARN }}
          aws-region: us-east-1
      - run: pip install boto3
      - run: |
          python skills/aws-inspector-findings-reporter/scripts/agent.py report \
            --regions us-east-1,us-west-2 \
            --kev \
            --output report_$(date +%Y-%m).json
      - uses: actions/upload-artifact@v4
        with:
          name: inspector-report
          path: report_*.json
```

## Key Concepts

| Concept | Description |
|---|---|
| Inspector v2 | AWS managed vulnerability scanner for EC2 instances, ECR container images, and Lambda functions |
| EPSS | Exploit Prediction Scoring System — probability (0–1) that a CVE will be exploited in the wild within 30 days |
| CISA KEV | Known Exploited Vulnerabilities catalog — CVEs with confirmed active exploitation; highest remediation priority |
| `inspectorScore` | AWS's risk score combining CVSS base score, network reachability, and exploitability factors |
| Finding status | `ACTIVE` (open), `SUPPRESSED` (muted by rule), `CLOSED` (patched/resolved) |
| `filterCriteria` | boto3 filter object for `list_findings`; supports date ranges, severities, account IDs, resource types |

## Tools & Systems

| Tool | Purpose |
|---|---|
| `boto3` `inspector2` client | Pull findings via `list_findings` paginator |
| CISA KEV JSON feed | Cross-reference actively exploited CVEs; fetched via `urllib.request` (stdlib) |
| EPSS data | Embedded in Inspector finding `packageVulnerabilityDetails.epss.score` |
| GitHub Actions / Lambda | Automation runtime for scheduled monthly execution |
| AWS STS `assume-role` | Multi-account access in AWS Organizations |

## Common Scenarios

**Flag actively exploited CVEs:**
```bash
python agent.py report --start-date 2026-03-01 --end-date 2026-03-31 --kev
# Report includes kev_findings[] — treat every KEV finding as P0
```

**Scope to a single resource type (ECR only):**
Use Inspector console to export ECR-only findings to JSON, then pass as a findings file; or filter `by_resource_type` from the report output post-generation.

**Detect regression (severity increased vs prior month):**
```bash
python agent.py trends --current report_march.json --previous report_feb.json
# severity_trend shows INCREASED/DECREASED/UNCHANGED per severity band
```

**CI gate — block merge on CRITICAL:**
```yaml
- run: python agent.py report --regions us-east-1 --output report.json
  # exits 1 if CRITICAL findings > 0; GitHub Actions will fail the job
```

## Output Format

```json
{
  "report_timestamp": "2026-04-01T06:00:00+00:00",
  "period": {
    "start": "2026-03-01T00:00:00+00:00",
    "end":   "2026-03-31T00:00:00+00:00"
  },
  "regions_scanned": ["us-east-1", "us-west-2"],
  "total_findings": 214,
  "overall_risk": "CRITICAL",
  "metrics": {
    "by_severity": {
      "CRITICAL": 12,
      "HIGH":     47,
      "MEDIUM":   98,
      "LOW":      57,
      "INFORMATIONAL": 0
    },
    "by_resource_type": {
      "AWS_EC2_INSTANCE": 103,
      "AWS_ECR_CONTAINER_IMAGE": 88,
      "AWS_LAMBDA_FUNCTION": 23
    },
    "by_region": {
      "us-east-1": 156,
      "us-west-2": 58
    },
    "by_account": { "123456789012": 214 },
    "by_status": {
      "ACTIVE": 186,
      "SUPPRESSED": 10,
      "CLOSED": 18
    },
    "kev_findings_count": 4,
    "kev_findings": [
      {
        "finding_arn": "arn:aws:inspector2:us-east-1:...",
        "cve": "CVE-2024-3400",
        "severity": "CRITICAL",
        "resource_id": "i-0abc123def456",
        "resource_type": "AWS_EC2_INSTANCE",
        "region": "us-east-1"
      }
    ],
    "high_epss_findings_count": 8,
    "high_epss_findings": [
      {
        "cve": "CVE-2024-3400",
        "epss_score": 0.974,
        "severity": "CRITICAL",
        "resource_id": "i-0abc123def456"
      }
    ],
    "top_cves": [
      { "cve": "CVE-2024-1234", "affected_resources": 23 },
      { "cve": "CVE-2023-9876", "affected_resources": 17 }
    ]
  },
  "kev_enriched": true,
  "recommendation": "12 CRITICAL and 47 HIGH findings require immediate attention."
}
```

Trends report format:
```json
{
  "total_findings_delta": -12,
  "severity_delta": { "CRITICAL": -2, "HIGH": -5, "MEDIUM": +3, "LOW": -8 },
  "severity_trend": {
    "CRITICAL": "DECREASED",
    "HIGH": "DECREASED",
    "MEDIUM": "INCREASED",
    "LOW": "DECREASED"
  },
  "remediation_velocity": { "closed_this_period": 18 },
  "summary": "CRITICAL: -2, HIGH: -5 vs previous period. Total findings moved from 226 to 214."
}
```
