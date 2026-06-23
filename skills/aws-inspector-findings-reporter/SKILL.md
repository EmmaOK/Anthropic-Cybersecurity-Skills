---
name: aws-inspector-findings-reporter
description: >-
  Pulls vulnerability findings from AWS Inspector v2 via the boto3 API and generates
  structured monthly reports aggregated by severity, resource type (EC2/ECR/Lambda),
  region, and AWS account. Supports multi-account organizations with team-based grouping:
  a teams.json config maps account IDs to team names, and the script assumes a cross-account
  IAM role in each account (sts:AssumeRole) to collect findings independently, then produces
  per-team breakdowns alongside the overall report. Optionally writes a separate JSON report
  file per team (--split-by-team). Enriches findings with CISA Known Exploited Vulnerability
  (KEV) catalog cross-reference and EPSS exploit-probability scores. Produces trend comparison
  reports across two reporting periods, including per-team deltas. Designed for scheduled
  automation (Lambda, GitHub Actions cron) and CI gating — exits with code 1 when CRITICAL
  findings are present.
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
- Grouping findings from multiple AWS accounts by team (e.g. platform, security, data, frontend) using a `teams.json` config, with per-team severity/KEV/CVE breakdowns and optional per-team report files
- Automating scheduled reporting from Lambda, GitHub Actions, or a cron job
- Identifying findings associated with actively exploited CVEs (CISA KEV catalog) or high-exploit-probability vulnerabilities (EPSS ≥ 0.7)
- Tracking remediation velocity by comparing the current month's report against the previous month
- CI/CD pipeline gating — block deployments when CRITICAL findings are present (exit code 1)

**Do not use** as a replacement for Inspector's native suppression rules or for findings that require manual triage. Trend reports require two saved report JSON files; the script does not query historical Inspector data directly.

## Prerequisites

- AWS credentials configured (`~/.aws/credentials`, environment variables, or IAM instance role)
- IAM permissions: `inspector2:ListFindings`
- Cross-account team mode: `sts:AssumeRole` on the target role in each member account
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

### 2. Team-grouped report (multi-account)

Create `teams.json` mapping each team to its AWS account IDs:
```json
{
  "platform":  ["123456789012", "234567890123"],
  "security":  ["345678901234"],
  "data":      ["456789012345", "567890123456"],
  "frontend":  ["678901234567"]
}
```

Run with `--role-name` to assume a cross-account IAM role in each account:
```bash
python agent.py report \
  --team-config teams.json \
  --role-name   InspectorReadOnly \
  --regions     us-east-1,us-west-2 \
  --kev \
  --split-by-team \
  --output      report_march_2026.json
```

`--split-by-team` writes separate files per team alongside the combined report:
`report_march_2026_platform.json`, `report_march_2026_security.json`, etc.

If you are the Inspector **delegated admin** in an AWS Organization, all member-account findings flow through your credentials automatically — omit `--role-name` and the script groups findings from the pull using the account IDs in `teams.json`.

### 3. Compare to previous month (trends)

```bash
python agent.py trends \
  --current  report_march_2026.json \
  --previous report_feb_2026.json \
  --output   trends_march_2026.json
```

### 4. Automate monthly via GitHub Actions

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

**Report grouped by team across four AWS accounts:**
```bash
python agent.py report \
  --team-config teams.json \
  --role-name   InspectorReadOnly \
  --regions     us-east-1,us-west-2 \
  --kev --split-by-team \
  --output      report_march_2026.json
# Writes combined report + one file per team; by_team section shows each team's
# severity breakdown, KEV hits, and top CVEs separately
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
  "recommendation": "12 CRITICAL and 47 HIGH findings require immediate attention.",
  "by_team": {
    "platform": {
      "accounts": ["123456789012", "234567890123"],
      "total_findings": 134,
      "overall_risk": "CRITICAL",
      "metrics": { "by_severity": { "CRITICAL": 9, "HIGH": 31, "MEDIUM": 62, "LOW": 32, "INFORMATIONAL": 0 }, "..." : "..." }
    },
    "security": {
      "accounts": ["345678901234"],
      "total_findings": 28,
      "overall_risk": "HIGH",
      "metrics": { "by_severity": { "CRITICAL": 0, "HIGH": 10, "MEDIUM": 14, "LOW": 4, "INFORMATIONAL": 0 }, "..." : "..." }
    },
    "data":     { "...": "..." },
    "frontend": { "...": "..." }
  }
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
