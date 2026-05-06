---
name: performing-owasp-api-security-assessment
description: >-
  Runs a complete automated security assessment of a REST or GraphQL API against
  all 10 OWASP API Security Top 10 (2023) risks in a single command. Orchestrates
  12 individual skill agents across four phases — discovery, authentication and
  authorization, data and input validation, and resource and business logic — then
  aggregates results into a unified JSON report with per-risk findings, severity
  scores, and an overall risk rating. Designed to be invoked by Phantom from natural
  language commands such as "test my API for OWASP vulnerabilities", "run an API
  security assessment against https://...", or "check my API for security issues".
  Exits with code 1 when any HIGH or CRITICAL finding is detected, making it
  compatible with CI/CD pipeline security gates.
domain: cybersecurity
subdomain: api-security
tags:
  - owasp-api
  - api-security
  - security-assessment
  - automation
  - orchestration
  - api-testing
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
  - Application Hardening
  - Network Traffic Filtering
  - Credential Hardening
  - Content Validation
---
# Performing OWASP API Security Assessment

## When to Use

Activate this skill when the user says any of the following (or similar):
- "test my API for OWASP vulnerabilities"
- "run OWASP API Top 10 against https://..."
- "perform a full API security assessment"
- "check my API for security issues"
- "scan this API for vulnerabilities"
- "run all API security tests"
- "assess my API against OWASP"

Also activate when:
- A new API is about to go to production and needs a security gate
- A security review requires OWASP API Top 10 evidence
- A bug bounty scope includes an API and full coverage is needed
- CI/CD requires an automated API security check on every release

**Do not use** against production systems without explicit written authorization.
All sub-agents send probing requests including auth bypass attempts, injection payloads,
and rapid sequential requests. This is detectable and will appear in access logs.

## Prerequisites

- Target API base URL (required)
- Valid authentication token — JWT or API key for a test account (recommended)
- Low-privilege token for authorization tests (optional but improves coverage)
- Python 3.8+ (stdlib only for orchestrator; sub-agents also stdlib only)
- Skill library present at `skills/` relative to where the orchestrator runs
- Written authorization to test the target API

## Workflow

### Step 1: Invoke the orchestrator

```bash
python agent.py --target-url https://api.example.com \
                --token eyJhbGc... \
                --low-priv-token eyJhbGc... \
                --output owasp_api_report.json
```

To run a subset of tests:
```bash
python agent.py --target-url https://api.example.com \
                --token eyJ... \
                --tests api1,api2,api7 \
                --output partial_report.json
```

### Step 2: Phase 1 — Discovery

Runs first. Output feeds into later authorization and injection tests.

| OWASP ID | Risk | Skill |
|---|---|---|
| API9:2023 | Improper Inventory Management | `performing-api-inventory-and-discovery` |
| API9:2023 | Shadow / Undocumented Endpoints | `detecting-shadow-api-endpoints` |

### Step 3: Phase 2 — Authentication & Authorization

| OWASP ID | Risk | Skill |
|---|---|---|
| API2:2023 | Broken Authentication | `testing-api-authentication-weaknesses` |
| API1:2023 | Broken Object Level Authorization (BOLA) | `testing-api-for-broken-object-level-authorization` |
| API5:2023 | Broken Function Level Authorization (BFLA) | `exploiting-broken-function-level-authorization` |

### Step 4: Phase 3 — Data & Input Validation

| OWASP ID | Risk | Skill |
|---|---|---|
| API3:2023 | Broken Object Property Level Auth | `exploiting-excessive-data-exposure-in-api` |
| API3:2023 | Mass Assignment | `testing-api-for-mass-assignment-vulnerability` |
| API7:2023 | Server Side Request Forgery | `exploiting-api-injection-vulnerabilities` |
| API8:2023 | Security Misconfiguration | `conducting-api-security-testing` |

### Step 5: Phase 4 — Resource & Business Logic

| OWASP ID | Risk | Skill |
|---|---|---|
| API4:2023 | Unrestricted Resource Consumption | `performing-api-rate-limiting-bypass` |
| API6:2023 | Unrestricted Business Flow Access | `testing-api-for-unrestricted-business-flows` |
| API10:2023 | Unsafe Consumption of APIs | `testing-api-for-unsafe-consumption` |

### Step 6: Aggregate and report

The orchestrator collects all sub-agent outputs, normalizes severity scores, and produces a
unified report. It prints a summary to stdout and writes the full report to the output file.

```
OWASP API Security Assessment — https://api.example.com
═══════════════════════════════════════════════════════
 API1  BOLA                         ✗ HIGH      2 findings
 API2  Broken Authentication        ✓ PASS      0 findings
 API3  Object Property Auth         ✗ CRITICAL  1 finding
 API4  Resource Consumption         ✗ HIGH      3 findings
 API5  BFLA                         ✓ PASS      0 findings
 API6  Business Flow Abuse          ✗ HIGH      2 findings
 API7  SSRF                         ✓ PASS      0 findings
 API8  Misconfiguration             ✗ MEDIUM    4 findings
 API9  Inventory Management         ✗ MEDIUM    6 shadow endpoints
 API10 Unsafe Consumption           ✗ CRITICAL  1 finding
═══════════════════════════════════════════════════════
Overall risk: CRITICAL  |  19 total findings
```

## Key Concepts

| Term | Definition |
|---|---|
| BOLA | Broken Object Level Authorization — accessing another user's object by ID manipulation |
| BFLA | Broken Function Level Authorization — calling admin/privileged endpoints as a regular user |
| Mass Assignment | Sending extra JSON fields to overwrite restricted properties (e.g. `role`, `is_admin`) |
| Shadow endpoint | An API endpoint not documented in the OpenAPI spec but responding to requests |
| Unsafe consumption | Trusting third-party API responses without validation or sanitization |
| Business flow abuse | Exploiting legitimate API features at machine speed to gain unfair advantage |

## Tools & Systems

- `agent.py` — orchestrator, stdlib only, shells out to individual skill agent.py scripts
- 12 individual skill agents — each tests one OWASP API risk; all stdlib only
- Output: JSON report + stdout summary table

## Common Scenarios

**Scenario: Pre-production API security gate**
A team is shipping a new microservice. Before merging to main, CI runs:
`python agent.py --target-url https://staging-api.internal --token $CI_TOKEN --output report.json`
The orchestrator runs all 10 tests. API3 returns CRITICAL (mass assignment allows role escalation).
Exit code 1 blocks the merge. The team fixes the issue and re-runs — exit 0, merge proceeds.

**Scenario: Bug bounty API recon**
A security researcher says "run a full OWASP assessment against https://api.target.com".
Phantom calls `run_skill_agent("performing-owasp-api-security-assessment", ["--target-url", "https://api.target.com"])`.
The orchestrator discovers 3 shadow endpoints, finds BOLA on `/api/v1/invoices/{id}`, and
reports a HIGH finding with the specific object IDs accessed.

**Scenario: Partial test run**
User says "just test my API for injection and auth issues".
Phantom calls the orchestrator with `--tests api2,api7` to run only authentication and SSRF tests.

## Output Format

```json
{
  "methodology": "OWASP API Security Top 10 (2023) — performing-owasp-api-security-assessment v1.0",
  "assessment_timestamp": "2026-05-06T10:00:00Z",
  "target_url": "https://api.example.com",
  "tests_requested": ["api1","api2","api3","api4","api5","api6","api7","api8","api9","api10"],
  "summary": {
    "total_tests": 10,
    "passed": 3,
    "with_findings": 7,
    "critical": 2,
    "high": 3,
    "medium": 2,
    "low": 0,
    "overall_risk": "CRITICAL"
  },
  "results": [
    {
      "owasp_id": "API1:2023",
      "risk": "Broken Object Level Authorization",
      "skill": "testing-api-for-broken-object-level-authorization",
      "status": "FINDING",
      "severity": "HIGH",
      "exit_code": 1,
      "duration_seconds": 12.4,
      "findings": [
        {
          "endpoint": "/api/v1/invoices/1042",
          "method": "GET",
          "detail": "Accessed another user's invoice by incrementing ID",
          "severity": "HIGH"
        }
      ]
    },
    {
      "owasp_id": "API2:2023",
      "risk": "Broken Authentication",
      "skill": "testing-api-authentication-weaknesses",
      "status": "PASS",
      "severity": "NONE",
      "exit_code": 0,
      "duration_seconds": 8.1,
      "findings": []
    }
  ]
}
```
