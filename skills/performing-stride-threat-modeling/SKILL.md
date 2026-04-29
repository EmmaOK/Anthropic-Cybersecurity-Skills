---
name: performing-stride-threat-modeling
description: >-
  Conducts tool-agnostic STRIDE threat modeling across any system architecture
  by systematically applying the six STRIDE threat categories (Spoofing,
  Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation
  of Privilege) to each component type in a data flow diagram. Covers the full
  threat identification and prioritization process for web APIs, databases,
  message queues, auth services, cloud storage, and microservices. Activates
  for requests involving STRIDE analysis, threat identification, DFD threat
  review, or secure design assessment without a specific tool dependency.
domain: cybersecurity
subdomain: application-security
tags:
  - STRIDE
  - threat-modeling
  - secure-design
  - DFD
  - OWASP
  - application-security
  - T1190
  - T1078
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - ID.RA-01
  - ID.RA-03
  - ID.IM-04
  - PR.PS-01
  - GV.SC-07
d3fend_techniques:
  - Application Hardening
  - Credential Hardening
  - Network Traffic Filtering
nist_ai_rmf:
  - GOVERN-1.1
  - MEASURE-2.7
  - MANAGE-2.4
---
# Performing STRIDE Threat Modeling

## When to Use

- During the design phase of a new feature, service, or system — before code is written
- When reviewing a pull request that changes trust boundaries, authentication flows, or data paths
- When onboarding a third-party integration or external API into the system
- When updating architecture after a security incident to prevent recurrence
- As part of a security design review gate before production deployment

**Do not use** as a one-off exercise — STRIDE models must be updated whenever architecture changes. A threat model that does not reflect the current system is worse than none (false assurance).

## Prerequisites

- Data flow diagram (DFD) or architecture diagram of the target system (even hand-drawn is sufficient)
- Inventory of system components: processes, data stores, external entities, data flows, trust boundaries
- List of assets to protect (user PII, credentials, payment data, configuration secrets, audit logs)
- 60–90 minutes of focused time with at least one developer who built the system

## Workflow

### Step 1: Build the Component Inventory

Before applying STRIDE, enumerate every element in the system:

```bash
# Use agent.py to scaffold a blank component inventory
python3 agent.py init --system "Payment API" --output payment_components.json

# Or write it manually — one JSON object per component:
cat > components.json << 'EOF'
[
  {"id": "ext-browser",    "type": "external_entity", "name": "End User Browser",       "trust_boundary": "internet"},
  {"id": "proc-api",       "type": "process",         "name": "Payment API (Node.js)",   "trust_boundary": "dmz"},
  {"id": "proc-auth",      "type": "process",         "name": "Auth Service",            "trust_boundary": "internal"},
  {"id": "store-db",       "type": "data_store",      "name": "PostgreSQL (payments)",   "trust_boundary": "internal"},
  {"id": "store-cache",    "type": "data_store",      "name": "Redis (sessions)",        "trust_boundary": "internal"},
  {"id": "ext-stripe",     "type": "external_entity", "name": "Stripe API",              "trust_boundary": "internet"},
  {"id": "flow-api-db",    "type": "data_flow",       "name": "API → DB (SQL queries)",  "encrypted": true},
  {"id": "flow-user-api",  "type": "data_flow",       "name": "User → API (HTTPS)",      "encrypted": true},
  {"id": "flow-api-stripe","type": "data_flow",       "name": "API → Stripe (HTTPS)",    "encrypted": true}
]
EOF
```

### Step 2: Apply STRIDE Per Component Type

Each DFD element type has a natural set of applicable STRIDE categories:

| Element Type | S | T | R | I | D | E |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| External Entity | ✓ | | ✓ | | | |
| Process | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Data Store | | ✓ | ✓ | ✓ | ✓ | |
| Data Flow | | ✓ | | ✓ | ✓ | |

Work through each component systematically using the threat checklist below.

### Step 3: STRIDE Threat Checklist per Component

**S — Spoofing** (Who is the caller? Can they be impersonated?)
```
□ Is the caller authenticated before any action is taken?
□ Are tokens/credentials validated server-side (not trusted from client)?
□ Is mutual authentication required on service-to-service calls?
□ Can an attacker replay a captured authentication credential?
□ Are external entity identities verified (e.g. webhook signatures, API key validation)?
```

**T — Tampering** (Can data be modified in transit or at rest?)
```
□ Is data in transit encrypted with TLS 1.2+?
□ Is data at rest encrypted for sensitive fields (PII, payment data)?
□ Are database writes parameterized to prevent injection?
□ Are file uploads validated before being stored or processed?
□ Are integrity checksums verified on critical data reads?
□ Can a low-privilege user modify another user's data (IDOR)?
```

**R — Repudiation** (Can an actor deny having performed an action?)
```
□ Are all security-relevant events logged (auth, data access, config changes)?
□ Are logs stored in an append-only, tamper-resistant location?
□ Does each log entry include a user ID, timestamp, source IP, and action?
□ Are audit logs retained for a sufficient period (90 days minimum)?
□ Is there a non-repudiation mechanism for financial transactions?
```

**I — Information Disclosure** (Can sensitive data leak to unauthorized parties?)
```
□ Do error messages expose stack traces, file paths, or DB schema?
□ Are API responses filtered to return only necessary fields (no over-fetching)?
□ Are secrets (API keys, credentials) absent from logs, URLs, and Git history?
□ Is PII masked or tokenized in non-production environments?
□ Does caching expose sensitive data across user sessions?
□ Are CORS policies restrictive (not Access-Control-Allow-Origin: *)?
```

**D — Denial of Service** (Can the component be made unavailable?)
```
□ Are rate limits applied on all public-facing endpoints?
□ Is there a maximum payload size enforced on all inputs?
□ Are resource-intensive operations (DB queries, file uploads) protected by quotas?
□ Can an attacker exhaust connection pool or thread pool by holding connections open?
□ Are dependencies (external APIs, queues) protected by timeouts and circuit breakers?
```

**E — Elevation of Privilege** (Can an actor gain more access than intended?)
```
□ Is authorization checked server-side for every request (not just at login)?
□ Are admin functions protected by role checks, not just obscure URLs?
□ Can a regular user access another user's admin panel by manipulating a parameter?
□ Are JWTs validated (signature, expiry, audience) — not just decoded?
□ Can a low-privileged process write to files executed by a high-privileged process?
```

### Step 4: Score and Prioritize Threats (DREAD)

For each identified threat, score on five dimensions (1–3 each):

| Dimension | 1 (Low) | 2 (Medium) | 3 (High) |
|---|---|---|---|
| **D**amage | Minor data exposure | Significant data loss | Full system compromise |
| **R**eproducibility | Requires rare conditions | Requires some skill | Trivially reproducible |
| **E**xploitability | Expert attacker needed | Skilled attacker | Script kiddie |
| **A**ffected users | Single user | Subset of users | All users |
| **D**iscoverability | Requires source access | Requires testing | Visible in UI/docs |

```python
# Score a threat
threat = {
    "id": "T-001",
    "component": "Payment API",
    "stride_category": "Tampering",
    "description": "Attacker submits negative payment amount to increase balance",
    "dread": {"damage": 3, "reproducibility": 3, "exploitability": 3, "affected": 2, "discoverability": 2}
}
dread_score = sum(threat["dread"].values())  # max 15
severity = "CRITICAL" if dread_score >= 12 else "HIGH" if dread_score >= 9 else "MEDIUM" if dread_score >= 6 else "LOW"
```

### Step 5: Generate and Track the Threat Register

```bash
python3 agent.py analyze \
  --components components.json \
  --output threats.json

python3 agent.py report \
  --threats threats.json \
  --output stride_report.json
```

### Step 6: Validate Mitigations

For each threat, document the mitigation and validate it:

```
Threat: T-001 — Negative payment amount (Tampering, CRITICAL)
Mitigation: Server-side validation: amount > 0 enforced in PaymentService.create()
Validation: Unit test PaymentServiceTest.testNegativeAmount() exists and passes
Status: MITIGATED
Evidence: PR #412 — add amount validation; test coverage 100% on payment boundary conditions
```

## Key Concepts

| Term | Definition |
|---|---|
| STRIDE | Microsoft threat category framework: Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege |
| DFD | Data Flow Diagram — shows processes, data stores, external entities, data flows, and trust boundaries |
| Trust boundary | A line in the DFD where data crosses between different security zones (e.g. internet → DMZ) |
| DREAD | Scoring model: Damage, Reproducibility, Exploitability, Affected users, Discoverability |
| Threat register | Structured list of all identified threats with status, owner, and mitigation evidence |
| Residual risk | Remaining risk after mitigations are applied — must be formally accepted by a risk owner |

## Tools & Systems

| Tool | Use |
|---|---|
| Whiteboard / draw.io | DFD creation — tool doesn't matter, completeness does |
| OWASP Threat Dragon | GUI-based STRIDE/LINDDUN with rule engine and PDF reports |
| Microsoft Threat Modeling Tool | Windows-only, STRIDE-native, good for Azure/Microsoft stacks |
| `pytm` | Python library for programmatic DFD + STRIDE threat generation |
| Threagile | YAML-based threat modeling with ATT&CK mapping |
| JIRA / Linear | Track threats as security tickets linked to remediation PRs |

## Common Scenarios

**Scenario 1: Pre-sprint threat review for a new auth flow**
Draw a 5-element DFD (browser → API → auth service → user DB → session cache). Apply STRIDE to each. Takes 60 minutes with the feature team. Produces 8–15 threats, typically 2–3 HIGH that need mitigations before the sprint closes.

**Scenario 2: Third-party integration review**
Map the new integration as an external entity with data flows in/out. Focus on S (is the webhook signature verified?), I (what data is sent to the third party?), and T (can the third party tamper with data we act on?).

**Scenario 3: Post-incident threat model update**
After an IDOR incident, re-run STRIDE on all data stores and processes. Typically surfaces additional E (elevation of privilege) and I (information disclosure) threats that were not mitigated in the original model.

## Output Format

```json
{
  "system": "Payment API",
  "modeled_at": "2026-04-27T10:00:00Z",
  "components_analyzed": 9,
  "threats_identified": 18,
  "summary": {
    "CRITICAL": 2,
    "HIGH": 6,
    "MEDIUM": 7,
    "LOW": 3
  },
  "threats": [
    {
      "id": "T-001",
      "component": "Payment API (proc-api)",
      "stride_category": "Tampering",
      "description": "Attacker submits negative payment amount to increase account balance",
      "dread_score": 13,
      "severity": "CRITICAL",
      "mitigation": "Server-side amount > 0 validation in PaymentService",
      "status": "OPEN",
      "owner": "payments-team"
    }
  ]
}
```
