---
name: conducting-zap-security-scan
description: >-
  Drives OWASP ZAP (Zed Attack Proxy) programmatically to run spider, passive,
  and active security scans against a target web application or API. Auto-detects
  whether ZAP is already running as a daemon (REST API at localhost:8080) and falls
  back to Docker (ghcr.io/zaproxy/zaproxy:stable) when no daemon is found — so it
  works with zero pre-installed tooling as long as Docker is available. Supports
  three scan types: baseline (passive only, ~2-5 min), full (spider + active scan,
  10-60 min), and api (OpenAPI/Swagger-driven API scan). Normalizes all ZAP alerts
  to the project's severity scale (CRITICAL/HIGH/MEDIUM/LOW/INFO), maps each finding
  to OWASP Top 10 (2021), ASVS v4.0.3 chapter, and CWE ID, then produces a unified
  JSON report. Designed to complement performing-asvs-active-verification — Phantom
  can invoke both for comprehensive coverage. Exits with code 1 on HIGH or CRITICAL
  findings for CI/CD gate use.
domain: cybersecurity
subdomain: application-security
tags:
  - zap
  - owasp-zap
  - dast
  - dynamic-analysis
  - spider
  - active-scan
  - owasp-top-10
  - asvs
  - T1190
  - T1078
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - ID.RA-01
  - ID.RA-03
  - DE.CM-01
  - RS.AN-01
d3fend_techniques:
  - Dynamic Analysis
  - Application Hardening
  - Content Validation
  - Network Traffic Filtering
---
# Conducting a ZAP Security Scan

## When to Use

Activate this skill when the user says any of the following (or similar):
- "run a ZAP scan on https://..."
- "scan my app with OWASP ZAP"
- "do a DAST scan on my API"
- "run a dynamic security scan"
- "spider and scan https://... with ZAP"
- "run a full ZAP assessment on my staging environment"
- "ZAP baseline scan against https://..."

Also activate when:
- `performing-asvs-active-verification` has been run and the user wants deeper injection fuzzing
- A CI/CD pipeline needs an automated DAST gate before production deployment
- A security team wants ZAP's active scanner to supplement the stdlib-only ASVS skill

**Do not use** against production systems without explicit written authorization. ZAP's
active scanner sends malicious payloads including SQL injection strings, XSS payloads,
path traversal sequences, and SSRF probes — all of which appear in access logs and
may trigger WAF alerts or rate limits.

## Prerequisites

**One of:**
- **Docker** (recommended) — `docker pull ghcr.io/zaproxy/zaproxy:stable`
- **ZAP daemon** — ZAP installed locally, running with `-daemon -port 8080`

**Optional:**
- ZAP API key (`--zap-api-key`) if daemon was started with `-config api.key=<key>`
- OpenAPI/Swagger spec file (`--openapi-file`) for API scan mode
- Bearer token (`--token`) for authenticated scanning

## Workflow

### Step 1: Choose scan type and invoke

**Baseline scan** (passive only — fastest, ~2-5 min, safe for CI):
```bash
python agent.py --target-url https://app.example.com \
                --scan-type baseline \
                --output zap_report.json
```

**Full scan** (spider + active — comprehensive, ~10-60 min):
```bash
python agent.py --target-url https://app.example.com \
                --token eyJhbGc... \
                --scan-type full \
                --output zap_report.json
```

**API scan** (OpenAPI-driven — precise for REST APIs):
```bash
python agent.py --target-url https://api.example.com \
                --scan-type api \
                --openapi-file openapi.yaml \
                --token eyJhbGc... \
                --output zap_report.json
```

### Step 2: Mode detection (automatic)

The agent tries the ZAP daemon first:
```
1. GET http://localhost:8080/JSON/core/view/version/ → if 200, use daemon API
2. Otherwise → run Docker container (ghcr.io/zaproxy/zaproxy:stable)
```

Override daemon URL: `--zap-url http://zap.internal:8090`

### Step 3: Scan execution

**Baseline (Docker):**
```
docker run --rm -v /tmp/zap-work:/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable
  zap-baseline.py -t <url> -J /zap/wrk/report.json [-T 120]
```

**Full (daemon API):**
```
POST /JSON/spider/action/scan/?url=<url>     → poll until 100%
POST /JSON/ascan/action/scan/?url=<url>      → poll until 100%
GET  /JSON/core/view/alerts/?baseurl=<url>   → collect findings
```

### Step 4: Normalized report

Every ZAP alert is mapped to:
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO (from ZAP risk code 3/2/1/0)
- **OWASP Top 10 (2021)**: A01–A10
- **ASVS chapter**: V2–V14
- **CWE ID**: from ZAP's cweid field

### Step 5: Combining with ASVS active verification

```bash
# Run both for comprehensive coverage:
python skills/performing-asvs-active-verification/scripts/agent.py \
  --target-url https://app.example.com --token eyJ... --output asvs.json

python skills/conducting-zap-security-scan/scripts/agent.py \
  --target-url https://app.example.com --token eyJ... \
  --scan-type full --output zap.json
```

ZAP adds: deep injection fuzzing, JavaScript-rendered page scanning (via Ajax spider),
full application crawl, hundreds of passive checks, and header analysis across all pages.
The ASVS skill adds: ASVS control ID mapping, session/TLS/crypto/business-logic probes.

## Key Concepts

| Term | Definition |
|---|---|
| DAST | Dynamic Application Security Testing — tests running applications, not source code |
| Spider | Crawls the app by following links; discovers all pages/endpoints |
| Ajax Spider | Uses a headless browser to crawl JavaScript-rendered SPAs |
| Passive scan | Observes traffic from the spider — no attack payloads sent |
| Active scan | Sends attack payloads (SQLi, XSS, etc.) to find vulnerabilities |
| Baseline scan | Spider + passive scan only — safe for CI, won't attack the app |
| ZAP daemon | ZAP running as a background service, controlled via REST API |
| Risk code | ZAP severity: 3=High, 2=Medium, 1=Low, 0=Informational |

## Tools & Systems

- `agent.py` — orchestrator, stdlib only; shells out to Docker or calls ZAP daemon REST API
- Docker image: `ghcr.io/zaproxy/zaproxy:stable` (GitHub Container Registry)
- ZAP REST API: `http://localhost:8080/JSON/...` (when using daemon mode)
- Output: JSON report + stdout summary

## Important: Scan Duration vs Phantom Timeout

Phantom's skill executor has a 60-second per-script timeout. ZAP scans take minutes:
- Baseline: ~2-10 min
- Full: ~10-60 min

**For Phantom invocation**: use `--scan-type baseline` and accept that Phantom will
report a timeout after 60s, but the Docker container continues running in the background
and writes its report to `--output` when complete. Check the report file after a few minutes.

**For CI/CD**: no timeout concern — invoke directly via `python agent.py ...`

## Common Scenarios

**Scenario: CI baseline gate**
Every PR triggers: `python agent.py --target-url https://staging.example.com --scan-type baseline`
Docker pulls ZAP, runs passive scan, exits 1 if any HIGH found. Fast and zero-setup.

**Scenario: Pre-release full scan**
Weekly job runs full active scan on staging. ZAP daemon pre-warmed in CI environment.
Agent detects daemon, skips Docker, runs spider + active scan. Report written to S3.

**Scenario: Phantom-guided deep dive**
User ran ASVS skill, found V5 injection issues. Then asks Phantom "run a ZAP full scan
to confirm the injection findings". Phantom calls this skill, ZAP confirms with specific
URLs and parameter names, provides remediation evidence.

## Output Format

```json
{
  "methodology": "OWASP ZAP DAST — conducting-zap-security-scan v1.0",
  "assessment_timestamp": "2026-05-06T10:00:00Z",
  "target_url": "https://app.example.com",
  "scan_type": "baseline",
  "zap_mode": "docker",
  "zap_version": "D-2026-01-01",
  "summary": {
    "total_alerts": 12,
    "critical": 0, "high": 2, "medium": 5, "low": 4, "info": 1,
    "overall_risk": "HIGH"
  },
  "findings": [
    {
      "alert": "SQL Injection",
      "severity": "HIGH",
      "confidence": "HIGH",
      "owasp_top10": "A03:2021 — Injection",
      "asvs_chapter": "V5",
      "cwe_id": "89",
      "url": "https://app.example.com/api/users",
      "method": "GET",
      "param": "id",
      "evidence": "...",
      "solution": "...",
      "count": 3
    }
  ]
}
```
