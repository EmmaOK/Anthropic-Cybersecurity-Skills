---
name: performing-asvs-active-verification
description: >-
  Actively probes a web application or API against the OWASP Application Security
  Verification Standard (ASVS) v4.0.3 requirements in a single command. Orchestrates
  12 verification chapters (V2–V14) via a mix of subprocess skill agents and inline
  HTTP probes, mapping every finding to a specific ASVS control ID (e.g. V2.1.1).
  Produces a unified JSON report with per-chapter pass/fail tallies, failing control
  IDs, and an overall ASVS conformance level (L1/L2/L3/FAIL). Designed to be invoked
  by Phantom from natural language commands such as "run ASVS verification on
  https://...", "assess my app against OWASP ASVS", or "check ASVS compliance for
  my API". Exits with code 1 when any HIGH or CRITICAL finding is detected, making
  it compatible with CI/CD pipeline security gates.
domain: cybersecurity
subdomain: application-security
tags:
  - owasp-asvs
  - asvs
  - compliance
  - active-verification
  - api-security
  - authentication
  - session-management
  - injection
  - T1190
  - T1078
  - T1212
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - ID.RA-01
  - ID.RA-03
  - DE.CM-01
  - PR.AC-01
  - RS.AN-01
d3fend_techniques:
  - Application Hardening
  - Credential Hardening
  - Content Validation
  - Network Traffic Filtering
---
# Performing ASVS Active Verification

## When to Use

Activate this skill when the user says any of the following (or similar):
- "run ASVS verification on https://..."
- "assess my app against OWASP ASVS"
- "check ASVS compliance for my API"
- "test my application against ASVS Level 2"
- "perform an ASVS assessment"
- "validate my app meets OWASP ASVS requirements"
- "ASVS compliance check on https://..."

Also activate when:
- A new application is about to go to production and needs a security gate
- A compliance review requires ASVS v4.0.3 evidence
- A security team needs to baseline an application against ASVS Level 1 or 2
- CI/CD requires an automated ASVS check on every release

**Do not use** against production systems without explicit written authorization.
The probes include authentication bypass attempts, injection payloads, session token analysis,
and security header inspection — all of which appear in access logs.

## Prerequisites

- Target application base URL (required)
- Valid authentication token (JWT or session cookie) — improves coverage for V4, V8, V13
- Login endpoint and test credentials for session management tests (optional)
- Python 3.8+ (stdlib only for orchestrator)
- Skill library present at `skills/` relative to the project root
- Written authorization to test the target application

## Workflow

### Step 1: Invoke the orchestrator

```bash
python agent.py --target-url https://app.example.com \
                --token eyJhbGc... \
                --level 2 \
                --output asvs_report.json
```

To run a subset of chapters:
```bash
python agent.py --target-url https://app.example.com \
                --token eyJ... \
                --chapters V2,V5,V9 \
                --output partial_asvs.json
```

### Step 2: Chapter coverage

| Chapter | Topic | Method |
|---|---|---|
| V2 | Authentication | Skill: `testing-api-authentication-weaknesses` |
| V3 | Session Management | Inline HTTP probes |
| V4 | Access Control | Skill: `testing-api-for-broken-object-level-authorization` |
| V5 | Validation / Injection | Skill: `exploiting-api-injection-vulnerabilities` |
| V6 | Stored Cryptography | Inline header / response analysis |
| V7 | Error Handling & Logging | Inline error-trigger probes |
| V8 | Data Protection | Inline response inspection |
| V9 | Communications Security | TLS / header analysis |
| V10 | Malicious Code | Inline pattern scan |
| V11 | Business Logic | Inline rate-limit and flow probes |
| V12 | Files & Resources | Inline upload / traversal probes |
| V13 | API & Web Services | Skill: `conducting-api-security-testing` |
| V14 | Configuration | Inline security-header and CORS probes |

### Step 3: Aggregate and report

```
OWASP ASVS v4.0.3 Active Verification — https://app.example.com (Level 2)
══════════════════════════════════════════════════════════════════════════
 V2  Authentication              ✗ HIGH     3 failing controls
 V3  Session Management          ✗ MEDIUM   2 failing controls
 V4  Access Control              ✗ HIGH     1 failing control
 V5  Validation / Injection      ✓ PASS     0 failing controls
 V6  Stored Cryptography         ✗ MEDIUM   1 failing control
 V7  Error Handling              ✓ PASS     0 failing controls
 V8  Data Protection             ✓ PASS     0 failing controls
 V9  Communications Security     ✗ MEDIUM   2 failing controls
 V10 Malicious Code              ✓ PASS     0 failing controls
 V11 Business Logic              ✓ PASS     0 failing controls
 V12 Files & Resources           ✗ LOW      1 failing control
 V13 API & Web Services          ✗ HIGH     2 failing controls
 V14 Configuration               ✗ MEDIUM   3 failing controls
══════════════════════════════════════════════════════════════════════════
ASVS Conformance: FAIL  |  15 failing controls  |  Report: asvs_report.json
```

## Key Concepts

| Term | Definition |
|---|---|
| ASVS | Application Security Verification Standard — OWASP framework defining security requirements for web apps |
| Level 1 (L1) | Opportunistic security — automated scanning and basic manual tests; minimum for all apps |
| Level 2 (L2) | Standard security — recommended for most apps handling sensitive data |
| Level 3 (L3) | Advanced security — for critical infrastructure, medical, financial systems |
| Control ID | e.g. V2.1.1 — Chapter.Section.Control number in ASVS v4.0.3 |
| Active verification | Actually sending HTTP requests to the app to verify controls (vs. generating worksheets) |

## Tools & Systems

- `agent.py` — orchestrator, stdlib only, shells out to individual skill agents
- Inline HTTP probes — `urllib.request` for session, error, header, TLS, file checks
- Existing skill agents: `testing-api-authentication-weaknesses`, `testing-api-for-broken-object-level-authorization`, `exploiting-api-injection-vulnerabilities`, `conducting-api-security-testing`
- Output: JSON report + stdout summary table

## Common Scenarios

**Scenario: Pre-production compliance gate**
Team shipping a web app. CI runs:
`python agent.py --target-url https://staging.example.com --token $CI_TOKEN --level 2 --output asvs_report.json`
V4 returns HIGH (BOLA on user resources). Exit code 1 blocks deployment. Team fixes and re-runs.

**Scenario: ASVS Level 1 quick baseline**
Security team baselines a third-party integration:
`python agent.py --target-url https://vendor-api.com --level 1 --chapters V2,V9,V14 --output baseline.json`
Produces lightweight report covering auth, TLS, and configuration for the vendor review.

**Scenario: Phantom natural language invocation**
User says "run ASVS Level 2 check on my staging API at https://staging.api.com".
Phantom calls `run_skill_agent("performing-asvs-active-verification", ["--target-url", "https://staging.api.com", "--level", "2"])`.
Orchestrator runs all 13 chapters, produces unified JSON, Phantom presents chapter-by-chapter summary.

## Output Format

```json
{
  "methodology": "OWASP ASVS v4.0.3 Active Verification — performing-asvs-active-verification v1.0",
  "assessment_timestamp": "2026-05-06T10:00:00Z",
  "target_url": "https://app.example.com",
  "asvs_level": 2,
  "chapters_tested": ["V2", "V3", "V4", "V5", "V6", "V7", "V8", "V9", "V10", "V11", "V12", "V13", "V14"],
  "summary": {
    "total_controls_checked": 80,
    "controls_passed": 65,
    "controls_failed": 15,
    "critical": 0, "high": 3, "medium": 7, "low": 5,
    "asvs_conformance": "FAIL"
  },
  "chapters": [
    {
      "chapter": "V2",
      "title": "Authentication",
      "skill": "testing-api-authentication-weaknesses",
      "status": "FINDING",
      "severity": "HIGH",
      "controls_checked": 8,
      "controls_failed": 3,
      "failing_controls": [
        {"control_id": "V2.1.1", "description": "Passwords ≥12 chars not enforced", "severity": "HIGH"},
        {"control_id": "V2.2.1", "description": "No MFA available", "severity": "MEDIUM"},
        {"control_id": "V2.4.5", "description": "Credential stuffing not rate-limited", "severity": "HIGH"}
      ]
    }
  ]
}
```
