---
name: generating-security-assessment-report
description: >-
  Generates professional security assessment reports from any Phantom skill's
  JSON output — OWASP API Top 10, ASVS active verification, ZAP DAST scans,
  or raw finding lists. Produces a fully self-contained HTML report with cover
  page, executive summary, risk distribution chart, per-finding detail cards
  mapped to OWASP Top 10 / ASVS / CWE, and print-optimized CSS so the user
  can save to PDF in one browser click. Optionally generates a true PDF via
  fpdf2 (pip install fpdf2) when available. Accepts multiple JSON inputs and
  merges them into a single unified report. Designed to be invoked by Phantom
  from natural language: "generate a report from my scan results",
  "create a PDF pentest report for https://...", or "combine my ZAP and ASVS
  results into one report".
domain: cybersecurity
subdomain: application-security
tags:
  - reporting
  - pdf
  - html
  - pentest-report
  - owasp
  - asvs
  - compliance
  - T1590
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - ID.RA-01
  - RS.AN-01
  - RC.CO-01
d3fend_techniques:
  - Application Hardening
---
# Generating a Security Assessment Report

## When to Use

Activate this skill when the user says any of the following (or similar):
- "generate a report from my scan results"
- "create a PDF pentest report"
- "combine my ZAP and ASVS results into one report"
- "make a professional security report"
- "export findings as HTML / PDF"
- "create an executive summary of my security findings"
- "generate a report for the security team"

## Prerequisites

- One or more JSON report files from any Phantom skill
- Python 3.8+ (stdlib — HTML always works)
- `pip install fpdf2` for true PDF output (optional — HTML prints to PDF perfectly)

## Workflow

### Step 1: Run one or more Phantom skills to get JSON outputs

```bash
python skills/performing-owasp-api-security-assessment/scripts/agent.py \
  --target-url https://app.example.com --output owasp_api.json

python skills/performing-asvs-active-verification/scripts/agent.py \
  --target-url https://app.example.com --output asvs.json

python skills/conducting-zap-security-scan/scripts/agent.py \
  --target-url https://app.example.com --output zap.json
```

### Step 2: Generate the report

```bash
# Single input → HTML
python agent.py --input owasp_api.json --output report.html

# Multiple inputs merged → HTML + PDF
python agent.py \
  --input owasp_api.json asvs.json zap.json \
  --title "Q2 2026 Security Assessment" \
  --target "https://app.example.com" \
  --author "Security Team" \
  --format both \
  --output security_report.html
```

### Step 3: Save as PDF

- **HTML route** (always works): open `report.html` in Chrome/Safari → Cmd+P → Save as PDF
- **PDF route** (if fpdf2 installed): `--format pdf` generates `report.pdf` directly

## Output Sections

| Section | Content |
|---|---|
| Cover page | Title, target, date, author, overall risk badge |
| Executive summary | Risk distribution bar, total findings by severity, top 5 critical issues |
| Findings | Per-finding cards grouped by severity — OWASP, ASVS, CWE, URL, evidence, remediation |
| Methodology | Tools used, scan scope, assessment date range |

## Supported Input Formats

| Source skill | JSON key detected |
|---|---|
| `performing-owasp-api-security-assessment` | `results[].findings[]` |
| `performing-asvs-active-verification` | `chapters[].failing_controls[]` |
| `conducting-zap-security-scan` | `findings[]` |
| `testing-api-*` / other skills | `findings[]` |
| Raw finding list | `findings[]` with `severity`, `detail` keys |

## Output Format

```
security_report.html   — self-contained HTML (no external dependencies)
security_report.pdf    — PDF (only with fpdf2 installed)
```

The HTML is fully self-contained — all CSS is inline, no CDN calls, works offline,
and renders correctly when emailed or shared.
