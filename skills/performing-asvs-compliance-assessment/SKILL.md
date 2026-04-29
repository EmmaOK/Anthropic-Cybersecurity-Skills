---
name: performing-asvs-compliance-assessment
description: >-
  Conducts structured security verification of web applications against the OWASP
  Application Security Verification Standard (ASVS) v4.0.3, producing a
  level-by-level conformance report across all 15 control categories. Supports
  all three verification levels: L1 automated checklist suitable for any
  application, L2 thorough verification for most applications handling sensitive
  data, and L3 advanced verification for critical applications requiring the
  highest assurance. Activates for requests involving ASVS assessment, ASVS
  compliance, application security verification, ASVS audit, or OWASP ASVS
  testing.
domain: cybersecurity
subdomain: application-security
tags:
  - OWASP-ASVS
  - application-security
  - compliance
  - web-security
  - ASVS-L1
  - ASVS-L2
  - ASVS-L3
  - security-verification
  - T1190
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - ID.RA-01
  - ID.RA-06
  - PR.PS-01
  - PR.PS-04
  - DE.AE-07
atlas_techniques:
  - AML.T0051
d3fend_techniques:
  - Application Hardening
  - Credential Hardening
  - Software Bill of Materials
nist_ai_rmf:
  - GOVERN-1.1
  - MEASURE-2.6
  - MANAGE-2.2
---
# Performing ASVS Compliance Assessment

## When to Use

- Verifying a web application meets the OWASP ASVS before a production release or compliance audit
- Scoping security testing effort — L1 for low-risk apps, L2 for apps handling PII or financial data, L3 for safety-critical or high-value targets
- Producing auditor-ready evidence for ISO 27001, SOC 2, or PCI-DSS engagements that reference ASVS as the testing methodology
- Evaluating third-party software against a standardized control set before procurement or integration
- Providing development teams with a structured remediation backlog tied to specific ASVS control IDs

**Do not use** against applications without written authorization from the owner. L3 verification includes active exploitation attempts and must be scoped as a penetration test engagement.

## Prerequisites

- Written authorization specifying the target application URL(s), environment (staging/production), and ASVS level (L1/L2/L3)
- **L1:** OWASP ZAP or Burp Suite Community, browser with DevTools, access to application as an unauthenticated and authenticated user
- **L2:** Burp Suite Professional, valid accounts at all privilege levels, access to application source code or API specification (OpenAPI/Swagger), developer-environment access for server-side configuration review
- **L3:** Full L2 access plus source code review capability, threat model, architecture diagrams, and dedicated pentest engagement agreement
- ASVS v4.0.3 checklist spreadsheet (download from `github.com/OWASP/ASVS/tree/v4.0.3`) or equivalent tooling (e.g., `OWASP SecurityRAT`)

## Workflow

### Step 1: Scope and Level Selection

Define the assessment scope and select the appropriate ASVS level:

```bash
# Download the ASVS v4.0.3 checklist
curl -LO https://github.com/OWASP/ASVS/releases/download/v4.0.3_release/OWASP.Application.Security.Verification.Standard.4.0.3-en.csv

# Use the agent script to initialize a blank assessment worksheet
python3 agent.py init \
  --app "Acme Customer Portal" \
  --url "https://portal.acme.internal" \
  --level 2 \
  --output acme_asvs_assessment.json
```

ASVS level selection criteria:

| Level | Suitable For | Verification Depth |
|-------|-------------|-------------------|
| L1 | Low-risk apps, initial triage | Automated scanning + checklist |
| L2 | Apps handling PII, finance, health | L1 + manual testing, config review |
| L3 | Critical infra, medical devices, high-value targets | L2 + source review, threat model validation |

### Step 2: V2 — Authentication Verification

Test authentication controls (ASVS V2.1–V2.9):

```bash
# V2.1 — Password security: check HIBP integration and minimum length enforcement
curl -X POST https://portal.acme.internal/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test@acme.com","password":"password"}'
# Expect: 400 rejection citing compromised password

# V2.2 — Verify account lockout after 5 failed attempts
for i in {1..6}; do
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://portal.acme.internal/api/auth/login \
    -d '{"username":"victim@acme.com","password":"wrong'$i'"}' && echo
done
# Expect: codes 401×5, then 429 or 423 on attempt 6

# V2.4 — Verify password hashing: inspect API response and check server config
# In Burp Suite: intercept POST /api/auth/login, check response for password in cleartext
# Server config check (L2):
ssh admin@app-server "grep -r 'bcrypt\|argon2\|scrypt\|pbkdf2' /app/src/auth/"

# V2.6 — TOTP/FIDO2 MFA availability check
curl https://portal.acme.internal/api/auth/mfa/options
# Expect: totp or webauthn in supported_methods
```

### Step 3: V3 — Session Management Verification

```bash
# V3.2 — Verify session token is regenerated after login (session fixation)
# In Burp Suite Repeater:
# 1. GET /login → capture Set-Cookie: session=BEFORE
# 2. POST /login (valid credentials) → check that Set-Cookie issues a NEW session value

# V3.3 — Verify idle timeout (≤30 min for L2)
SESSION=$(curl -sc cookies.txt -X POST https://portal.acme.internal/api/auth/login \
  -d '{"username":"test@acme.com","password":"ValidP@ss1"}' | jq -r '.session_token')
sleep 1900  # 31 minutes
curl -b cookies.txt https://portal.acme.internal/api/profile
# Expect: 401 Unauthorized

# V3.4 — Verify SameSite cookie attribute
curl -sI https://portal.acme.internal/api/auth/login | grep -i "set-cookie"
# Expect: SameSite=Strict or SameSite=Lax; Secure; HttpOnly

# V3.7 — Verify logout invalidates server-side session
curl -b "session=$SESSION" https://portal.acme.internal/api/profile
# After logout, this request must return 401
```

### Step 4: V4 — Access Control Verification

```bash
# V4.1 — Verify principle of least privilege: test horizontal privilege escalation (IDOR)
# Log in as user A, capture their resource ID, then attempt access as user B
USER_A_TOKEN="eyJ..."
USER_B_TOKEN="eyJ..."
RESOURCE_ID="12345"  # user A's resource

curl -H "Authorization: Bearer $USER_B_TOKEN" \
  https://portal.acme.internal/api/documents/$RESOURCE_ID
# Expect: 403 Forbidden

# V4.2 — Verify admin functions are protected (vertical privilege escalation)
curl -H "Authorization: Bearer $USER_B_TOKEN" \
  https://portal.acme.internal/api/admin/users
# Expect: 403 Forbidden (not 404 — 404 can be used to enumerate admin paths)

# V4.3 — Verify directory listing is disabled
curl https://portal.acme.internal/uploads/
# Expect: 403 or custom error page, not a file listing
```

### Step 5: V5 — Input Validation Verification

```python
# V5.2 — Test server-side input validation (not just client-side)
import requests

TARGET = "https://portal.acme.internal"
payloads = {
    "xss":       "<script>alert(1)</script>",
    "sqli":      "' OR '1'='1",
    "ssti":      "{{7*7}}",
    "xxe":       "<?xml version='1.0'?><!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><x>&xxe;</x>",
    "path_trav": "../../../../etc/passwd",
}

for label, payload in payloads.items():
    r = requests.post(f"{TARGET}/api/search", json={"query": payload}, timeout=10)
    if payload in r.text:
        print(f"[FAIL] V5 {label}: payload reflected in response — insufficient sanitization")
    else:
        print(f"[PASS] V5 {label}: payload not reflected")
```

### Step 6: V6–V15 Systematic Review

For each remaining ASVS chapter, test the L1/L2/L3 requirements:

```bash
# V6 — Cryptography: check TLS configuration
nmap --script ssl-enum-ciphers -p 443 portal.acme.internal | grep -E "TLSv|WEAK|FAIL"
# Expect: TLSv1.2 minimum; no RC4, DES, 3DES, EXPORT ciphers

# V7 — Error handling and logging: trigger an error and check response
curl https://portal.acme.internal/api/nonexistent-endpoint
# Expect: generic error message — no stack traces, framework versions, or file paths

# V8 — Data protection: check sensitive fields in API responses
curl -H "Authorization: Bearer $USER_A_TOKEN" \
  https://portal.acme.internal/api/profile | jq 'keys'
# Expect: no password_hash, api_key, or internal_id fields in response

# V9 — Communication security: verify HSTS is set
curl -sI https://portal.acme.internal | grep -i "strict-transport"
# Expect: Strict-Transport-Security: max-age=31536000; includeSubDomains

# V10 — Malicious code (L2+): review CI pipeline for dependency scanning
cat .github/workflows/*.yml | grep -E "snyk|trivy|dependabot|grype"

# V11 — Business logic (L2+): test workflow bypasses (skip steps, replay requests)
# V12 — Files and resources: test file upload with executable extensions
curl -F "file=@malicious.php;filename=profile.jpg" \
  -H "Authorization: Bearer $USER_A_TOKEN" \
  https://portal.acme.internal/api/profile/avatar

# V13 — API and web service: validate OpenAPI spec vs actual behaviour
docker run --rm -v $(pwd):/spec stoplight/spectral lint /spec/openapi.yaml

# V14 — Configuration: check security headers
curl -sI https://portal.acme.internal | grep -E "X-Frame|X-Content|CSP|Referrer"
```

### Step 7: Generate Conformance Report

```bash
python3 agent.py report \
  --assessment acme_asvs_assessment.json \
  --output acme_asvs_report.json
```

## Key Concepts

| Term | Definition |
|------|-----------|
| ASVS Level | L1 = opportunistic/automated; L2 = standard for most apps; L3 = advanced for critical systems |
| Control ID | V{chapter}.{section}.{requirement} e.g. V2.1.1 = Chapter 2, Section 1, Req 1 |
| Conformance | Pass / Fail / N/A per requirement; final score = passing / applicable controls |
| WSTG | OWASP Web Security Testing Guide — testing procedures; ASVS is the requirements standard |
| SecurityRAT | Tool for generating ASVS worksheets and tracking conformance over time |
| IDOR | Insecure Direct Object Reference — horizontal privilege escalation via predictable IDs |
| Session Fixation | Attacker pre-sets a session token; victim authenticates; attacker reuses it |

## Tools & Systems

| Tool | ASVS Coverage | Notes |
|------|--------------|-------|
| Burp Suite Professional | V2–V5, V13 | Primary proxy for manual testing; Autorize extension for V4 |
| OWASP ZAP | V5, V9, V14 | Free DAST; use for L1 automated baseline |
| `nmap --script ssl-*` | V6 | TLS cipher and certificate audit |
| `testssl.sh` | V6 | Comprehensive TLS/SSL configuration check |
| SecurityRAT | All chapters | JIRA-integrated ASVS worksheet generator |
| `OWASP Dependency-Check` | V10 | Vulnerable dependency scanning for SCA |
| Spectral / Redocly | V13 | OpenAPI spec linting and conformance |
| `nikto` | V7, V14 | HTTP security header and misconfiguration checks |

## Common Scenarios

**Scenario 1: Pre-release L1 triage for a new internal tool**
Run OWASP ZAP active scan against staging, review the generated alerts against the ASVS L1 requirement list, and produce a pass/fail matrix. Typically completes in a half-day and identifies header, cookie, and input issues automatically.

**Scenario 2: PCI-DSS Section 6.2 application security assessment**
Conduct full L2 assessment with Burp Suite Professional. Produce an ASVS conformance report as audit evidence. Map each failed control to a remediation ticket with CVSS severity. PCI-DSS Req 6.2.4 maps directly to V5 (input validation), Req 8.3 to V2 (authentication).

**Scenario 3: Third-party SaaS procurement evaluation**
Use the ASVS L1 questionnaire as a vendor self-assessment form. Request evidence (scan reports, pen test summaries) for L2 controls. Score conformance as a procurement gate — applications scoring below 70% on L2 require a risk acceptance sign-off.

**Scenario 4: Post-breach gap analysis**
Map the breach root cause to the relevant ASVS chapter and run a targeted assessment of that chapter plus adjacent controls. For example, a credential stuffing incident maps to V2.2 (lockout), V2.1 (password strength), and V3.2 (session regeneration).

## Output Format

The `agent.py report` subcommand produces a structured JSON conformance report:

```json
{
  "assessment_timestamp": "2026-04-27T10:00:00Z",
  "application": "Acme Customer Portal",
  "target_url": "https://portal.acme.internal",
  "asvs_version": "4.0.3",
  "level": 2,
  "summary": {
    "total_requirements": 138,
    "applicable": 127,
    "passed": 98,
    "failed": 24,
    "not_tested": 5,
    "conformance_pct": 77.2
  },
  "by_chapter": {
    "V2_Authentication": {"passed": 18, "failed": 4, "conformance_pct": 81.8},
    "V3_Session":        {"passed": 11, "failed": 2, "conformance_pct": 84.6},
    "V4_Access_Control": {"passed": 9,  "failed": 5, "conformance_pct": 64.3},
    "V5_Validation":     {"passed": 14, "failed": 3, "conformance_pct": 82.4}
  },
  "failed_controls": [
    {
      "control_id": "V4.1.3",
      "requirement": "Verify that the principle of least privilege exists",
      "evidence": "User B accessed document owned by User A — HTTP 200 returned",
      "severity": "HIGH",
      "remediation": "Enforce owner-based authorization check in DocumentController.get()"
    }
  ],
  "overall_risk": "HIGH",
  "recommendation": "24 controls failed. Remediate V4 (Access Control) failures before release — 5 IDOR findings represent HIGH risk."
}
```
