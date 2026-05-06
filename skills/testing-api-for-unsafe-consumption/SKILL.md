---
name: testing-api-for-unsafe-consumption
description: >-
  Tests APIs that consume data from external or third-party APIs without adequate
  validation, sanitization, or trust boundary enforcement. Probes whether upstream
  API responses can be used to inject malicious content, trigger SSRF via redirect
  chains, bypass schema validation, or leak credentials through proxied responses.
  Uses a local mock upstream server (Python stdlib http.server) to craft malicious
  responses and observe whether the target API propagates the injected content
  downstream. Maps to OWASP API10:2023 Unsafe Consumption of APIs. Activates for
  requests involving third-party API trust testing, upstream injection, SSRF via
  external redirects, or supply chain API security assessment.
domain: cybersecurity
subdomain: api-security
tags:
  - api10
  - owasp-api
  - third-party-api
  - ssrf
  - injection
  - supply-chain
  - upstream-trust
  - T1190
  - T1195
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - ID.RA-01
  - DE.CM-01
  - PR.DS-02
  - ID.SC-02
d3fend_techniques:
  - Content Validation
  - Network Traffic Filtering
  - Software Bill of Materials
---
# Testing API for Unsafe Consumption of Third-Party APIs

## When to Use

- When the target API integrates with external/third-party APIs and passes their responses downstream
- When testing whether the target sanitizes and validates data received from upstream services
- When assessing SSRF risk via redirect chains from external API responses
- When checking if injected content in upstream responses is propagated to end users
- As part of a full OWASP API Security Top 10 assessment (API10:2023)

**Do not use** against production systems without explicit written authorization. This skill
starts a local mock HTTP server on a configurable port to simulate malicious upstream responses.

## Prerequisites

- Target API base URL accessible from the test environment
- Knowledge of which external APIs the target consumes (or an endpoint that proxies external data)
- Valid authentication token for the target API
- Python 3.8+ (stdlib only — `http.server`, `threading`, `json`, `urllib.request`)
- Port available locally for the mock upstream server (default: 9876)
- Written authorization to perform security testing

## Workflow

### Step 1: Identify upstream API consumption points

Find endpoints in the target API that:
- Fetch data from a configurable external URL (e.g. `POST /preview?url=https://...`)
- Proxy or aggregate responses from third-party services (payment, weather, maps, etc.)
- Accept a webhook or callback URL from a client
- Pull user-supplied content from external sources

### Step 2: Start the mock upstream server

The agent starts a local HTTP server that serves crafted malicious responses:
```bash
python agent.py --target-url https://api.example.com \
                --upstream-url http://localhost:9876 \
                --token eyJ... \
                --output api10_report.json
```

The mock server serves payloads for each test type on different paths:
- `/xss` — `{"data": "<script>alert(1)</script>"}`
- `/sqli` — `{"name": "' OR 1=1--"}`
- `/redirect` — HTTP 302 → `http://169.254.169.254/latest/meta-data/`
- `/oversized` — 10MB response body
- `/type-confusion` — `{"count": "not-a-number", "active": "yes"}`

### Step 3: Injection via upstream response

Send the target API an upstream URL pointing to the mock server's injection endpoints.
Observe whether the injected content appears unmodified in the target's response:

```
Test: Does target return XSS payload to the client?
Request: POST /api/preview {"source_url": "http://localhost:9876/xss"}
Response check: Is <script>alert(1)</script> present in response body?
Result: CRITICAL if yes
```

### Step 4: SSRF via upstream redirect

Configure the mock server to redirect to internal/cloud metadata addresses:
- `http://169.254.169.254/latest/meta-data/` (AWS IMDSv1)
- `http://metadata.google.internal/computeMetadata/v1/`
- `http://localhost/admin`

If the target API follows the redirect and returns internal content → CRITICAL SSRF.

### Step 5: Schema and type validation of upstream data

Send upstream responses with:
- Wrong types (`string` where `integer` expected)
- Missing required fields
- Oversized payloads (10MB string in a name field)
- Null bytes and control characters in strings

If the target passes invalid data downstream without rejection → MEDIUM/HIGH.

### Step 6: Credential leakage in proxied responses

If the target proxies upstream API responses directly, check whether:
- API keys or tokens from the upstream response are forwarded to the client
- Internal service URLs or IP addresses appear in proxied responses
- Error messages from upstream APIs expose stack traces or credentials

### Step 7: Report findings

```json
{
  "methodology": "OWASP API10:2023 — Unsafe Consumption of APIs",
  "target_url": "https://api.example.com",
  "findings": [
    {
      "test": "xss_injection_via_upstream",
      "payload": "<script>alert(1)</script>",
      "propagated": true,
      "severity": "HIGH",
      "detail": "XSS payload from upstream response returned unescaped to client"
    }
  ],
  "overall_risk": "HIGH"
}
```

## Key Concepts

| Term | Definition |
|---|---|
| Upstream API | An external or third-party service whose responses the target API consumes |
| Unsafe consumption | Trusting upstream data without validation, sanitization, or type checking |
| SSRF via redirect | Server-Side Request Forgery triggered by following a redirect from an external source |
| Type confusion | Passing a wrong data type from upstream through to downstream systems |
| Content propagation | Forwarding upstream response content to end users without sanitization |
| IMDSv1 | AWS Instance Metadata Service v1 — accessible from EC2 without auth, target of SSRF |

## Tools & Systems

- `agent.py` — standalone Python script using stdlib only (`http.server`, `threading`, `urllib`)
- Mock upstream server — spun up locally on configurable port, serves malicious payloads
- Target API — any REST API that fetches or proxies external data

## Common Scenarios

**Scenario: Link preview SSRF**
A social media API offers a `/preview` endpoint that fetches Open Graph metadata from any URL.
The agent sends `{"url": "http://mock/redirect"}` where the mock redirects to AWS metadata.
The API follows the redirect and returns EC2 instance metadata. Finding: CRITICAL SSRF.

**Scenario: Payment webhook injection**
A payment API calls a merchant-configured webhook URL after payment confirmation.
The agent registers a mock as the webhook and returns `{"status": "refunded"}`.
The target API updates the order status to refunded without verifying the signature.
Finding: CRITICAL — fraudulent refund injection via upstream trust.

**Scenario: Type confusion via aggregator**
An API aggregates weather data and exposes it via `/weather`. The mock returns
`{"temperature": "very hot"}` (string instead of float). The API forwards this to
a frontend that uses the value in a calculation, causing NaN errors. Finding: MEDIUM.

## Output Format

```json
{
  "methodology": "OWASP API10:2023 — Unsafe Consumption of APIs — testing-api-for-unsafe-consumption v1.0",
  "target_url": "https://api.example.com",
  "mock_server_port": 9876,
  "tests_run": 5,
  "findings": [
    {
      "test": "ssrf_via_redirect",
      "mock_redirect_target": "http://169.254.169.254/latest/meta-data/",
      "followed_redirect": true,
      "internal_content_returned": true,
      "severity": "CRITICAL",
      "detail": "API follows upstream redirects to internal cloud metadata service"
    },
    {
      "test": "xss_injection_via_upstream",
      "payload": "<script>alert(1)</script>",
      "propagated": true,
      "severity": "HIGH",
      "detail": "Upstream XSS payload returned unescaped in API response"
    }
  ],
  "overall_risk": "CRITICAL",
  "recommendation": "Validate and sanitize all data received from upstream APIs before use. Block redirect following to private IP ranges. Enforce strict JSON schema validation on upstream responses. Sign and verify webhook payloads."
}
```
