---
name: testing-api-for-unrestricted-business-flows
description: >-
  Tests APIs for unrestricted access to sensitive business flows where attackers
  can abuse legitimate features at scale — bulk account creation, inventory hoarding,
  unlimited coupon redemptions, promo code abuse, and multi-step workflow bypasses.
  Probes each business-critical endpoint for missing rate limits, per-user quotas,
  and bot detection signals. Tests step-skipping attacks where later-stage endpoints
  in a multi-step flow (checkout, payment, verification) are called without completing
  earlier required steps. Maps to OWASP API6:2023 Unrestricted Access to Sensitive
  Business Flows. Activates for requests involving business logic testing, flow abuse,
  rate limit bypass on business endpoints, or bot detection assessment.
domain: cybersecurity
subdomain: api-security
tags:
  - api6
  - owasp-api
  - business-logic
  - rate-limiting
  - bot-detection
  - workflow-bypass
  - abuse-prevention
  - T1190
  - T1078
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - ID.RA-01
  - DE.CM-01
  - PR.AC-04
  - RS.AN-01
d3fend_techniques:
  - Network Traffic Filtering
  - User Behavior Analysis
  - Credential Hardening
---
# Testing API for Unrestricted Access to Sensitive Business Flows

## When to Use

- When assessing whether business-critical API endpoints are protected against automated abuse
- When testing if multi-step workflows (registration, checkout, redemption) can be bypassed or skipped
- When verifying that rate limits and quotas exist on high-value actions (purchases, votes, referrals)
- When checking for missing bot detection on endpoints that could be abused at scale
- As part of a full OWASP API Security Top 10 assessment (API6:2023)

**Do not use** against production systems without explicit written authorization. Rate limit probing
sends 50+ requests per endpoint in rapid succession — this is detectable and may trigger alerts.

## Prerequisites

- Target API base URL accessible from the test environment
- Valid authentication token (JWT or API key) for an authorized test account
- List of business-critical endpoints to test (checkout, register, vote, promo, referral, etc.)
- Python 3.8+ (stdlib only — no pip installs required)
- Written authorization to perform security testing

## Workflow

### Step 1: Identify sensitive business flow endpoints

Map endpoints that control high-value or abuse-prone actions:
- Account creation / registration (`POST /users`, `POST /register`)
- Checkout / purchase (`POST /orders`, `POST /checkout`)
- Promo code / coupon redemption (`POST /promo`, `POST /discount`)
- Referral / invite (`POST /referral`, `POST /invite`)
- Voting / rating (`POST /vote`, `POST /rate`)
- Password reset / OTP (`POST /reset`, `POST /otp`)
- Inventory reservation (`POST /reserve`, `PUT /cart`)

If no endpoints are provided, the script attempts to discover them from common paths.

### Step 2: Rate limit probe per endpoint

Send 50 rapid sequential requests to each endpoint and observe responses:
```bash
python agent.py --target-url https://api.example.com \
                --token eyJ... \
                --endpoints /checkout,/promo/redeem,/register \
                --output api6_report.json
```

Indicators of missing rate limiting:
- All 50 requests return 200/201 (no 429 Too Many Requests)
- No `Retry-After`, `X-RateLimit-Remaining`, or `X-RateLimit-Reset` headers
- Response times remain consistent (no throttling backoff)

### Step 3: Per-user quota test

Repeat the same sensitive action 10+ times with the same authenticated user:
- If the API allows unlimited repetitions of a promo redemption → CRITICAL
- If the API allows >3 password reset requests per hour → HIGH
- If the API allows bulk account creation from the same IP → HIGH

### Step 4: Multi-step workflow bypass test

For multi-step flows, attempt to call later-stage endpoints without completing earlier steps:
```
Normal flow: POST /cart → POST /checkout → POST /payment → POST /confirm
Bypass test: POST /confirm directly (skipping /cart, /checkout, /payment)
```

A successful bypass (2xx response without prior steps) = CRITICAL finding.

### Step 5: Bot detection signal check

Inspect responses and request requirements for bot mitigation signals:
- Does the API require a CAPTCHA token on account creation / login?
- Are there behavioural headers checked (`X-Fingerprint`, `X-Request-ID`)?
- Does repeated identical behaviour trigger a challenge or block?
- Is there IP-based throttling (test from same IP with 100 requests)?

### Step 6: Report findings

The script writes a structured JSON report:
```json
{
  "methodology": "OWASP API6:2023 — Unrestricted Access to Sensitive Business Flows",
  "target_url": "https://api.example.com",
  "findings": [
    {
      "endpoint": "/promo/redeem",
      "test": "rate_limit_probe",
      "requests_sent": 50,
      "requests_succeeded": 50,
      "rate_limit_header_present": false,
      "severity": "CRITICAL",
      "detail": "No rate limiting on promo redemption — unlimited abuse possible"
    }
  ],
  "overall_risk": "CRITICAL"
}
```

## Key Concepts

| Term | Definition |
|---|---|
| Business flow abuse | Exploiting legitimate API features at scale to gain unfair advantage |
| Step-skipping | Calling a later workflow endpoint without completing prerequisite steps |
| Rate limiting | Server-enforced cap on requests per time window per user/IP |
| Per-user quota | Maximum number of times a specific action can be performed per account |
| Bot detection | Server-side signals that distinguish automated from human traffic |
| 429 Too Many Requests | HTTP status indicating rate limit enforcement |

## Tools & Systems

- `agent.py` — standalone Python script, stdlib only, no dependencies
- Target API — any REST API accessible from the test environment
- Postman / curl — for manual verification of findings

## Common Scenarios

**Scenario: Unlimited promo code redemption**
An e-commerce API allows a user to redeem the same promo code (`SAVE20`) multiple times.
The agent sends 20 POST /promo/redeem requests with the same code and token. All return 200.
No `X-RateLimit-*` headers present. Finding: CRITICAL — revenue loss at scale.

**Scenario: Registration flood**
A SaaS API allows bulk account creation from one IP. The agent sends 50 POST /register requests
in 10 seconds. All succeed. No CAPTCHA required. Finding: HIGH — enables spam/abuse campaigns.

**Scenario: Checkout step bypass**
The agent calls POST /payment directly without a valid cart session. The API returns 200 and
processes a $0 order. Finding: CRITICAL — order manipulation without valid purchase flow.

## Output Format

```json
{
  "methodology": "OWASP API6:2023 — Unrestricted Access to Sensitive Business Flows — testing-api-for-unrestricted-business-flows v1.0",
  "target_url": "https://api.example.com",
  "endpoints_tested": 3,
  "total_requests": 150,
  "findings": [
    {
      "endpoint": "/promo/redeem",
      "test": "rate_limit_probe",
      "requests_sent": 50,
      "requests_succeeded": 50,
      "rate_limit_header_present": false,
      "http_429_triggered": false,
      "severity": "CRITICAL",
      "detail": "No rate limiting enforced — all 50 requests succeeded"
    },
    {
      "endpoint": "/register",
      "test": "bot_detection",
      "captcha_required": false,
      "ip_throttling": false,
      "severity": "HIGH",
      "detail": "No bot detection signals on registration endpoint"
    }
  ],
  "overall_risk": "CRITICAL",
  "recommendation": "Implement per-user rate limiting (max 3/hour on promo), add CAPTCHA on registration, enforce workflow step sequencing via server-side session state"
}
```
