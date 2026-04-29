---
name: performing-pasta-threat-modeling
description: >-
  Conducts risk-centric threat modeling using the Process for Attack Simulation
  and Threat Analysis (PASTA) methodology across its seven stages: defining
  business objectives, defining technical scope, application decomposition,
  threat analysis, vulnerability and weakness analysis, attack modeling, and
  risk and impact analysis. PASTA produces business-aligned threat intelligence
  rather than a component-level checklist, making it the preferred methodology
  for enterprise, financial services, and regulated environments where risk
  quantification and executive reporting are required. Activates for requests
  involving PASTA methodology, risk-centric threat modeling, business impact
  analysis, or enterprise threat assessment.
domain: cybersecurity
subdomain: compliance-governance
tags:
  - PASTA
  - threat-modeling
  - risk-management
  - business-impact
  - enterprise-security
  - T1190
  - T1078
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - GV.RM-01
  - GV.RM-02
  - ID.RA-01
  - ID.RA-03
  - ID.RA-05
  - ID.IM-04
d3fend_techniques:
  - Application Hardening
  - Credential Hardening
  - Software Bill of Materials
nist_ai_rmf:
  - GOVERN-1.1
  - GOVERN-1.7
  - MEASURE-2.6
  - MANAGE-2.4
---
# Performing PASTA Threat Modeling

## When to Use

- Building a new product or service where security investment must be justified to business stakeholders
- Regulated environments (PCI-DSS, HIPAA, SOC 2) requiring documented risk-based security decisions
- When a STRIDE or DREAD analysis has been completed but executive-level risk reporting is needed
- Before a major release, merger/acquisition technical due diligence, or external audit
- When prioritizing a security backlog against limited engineering budget

**Do not use** when you need a fast, design-phase checklist — PASTA takes 2–5 days for a full engagement. For rapid design review, use STRIDE instead. PASTA is the right choice when business impact quantification matters more than exhaustive control coverage.

## Prerequisites

- Executive sponsor who can articulate business objectives and risk tolerance
- Product/engineering owner who can describe technical scope and architecture
- Existing vulnerability scan results, pen test findings, or threat intelligence (for Stage 5)
- Asset inventory with business impact classifications (revenue impact, regulatory exposure, reputational risk)
- 2–5 days of workshop time with cross-functional stakeholders

## Workflow

### Stage 1: Define Business Objectives

Establish what the business is trying to protect and what failure looks like:

```bash
python3 agent.py stage1 \
  --system "Online Banking Portal" \
  --output pasta_s1.json
```

Document the following:

```yaml
business_objectives:
  system: "Online Banking Portal"
  owner: "Digital Banking Division"
  revenue_impact: "Platform processes $2.4B in annual transactions"
  regulatory_exposure:
    - PCI-DSS v4.0 (card data processing)
    - FFIEC guidance (online banking authentication)
    - GDPR (EU customer data)
  risk_tolerance: LOW  # financial institution — very low appetite
  security_goals:
    - Protect customer funds and account integrity
    - Prevent unauthorized access to account data
    - Maintain 99.9% availability (SLA)
    - Comply with all applicable regulations
  compliance_deadlines:
    - PCI-DSS annual assessment: 2026-09-30
    - SOC 2 Type II renewal: 2026-11-30
```

### Stage 2: Define Technical Scope

Enumerate the system boundary and all components in scope:

```yaml
technical_scope:
  in_scope:
    - Customer-facing web application (React SPA)
    - Mobile apps (iOS/Android)
    - REST API gateway (Kong)
    - Authentication service (OAuth 2.0 + TOTP MFA)
    - Core banking API (internal)
    - Transaction processing service
    - Customer database (PostgreSQL)
    - Session cache (Redis)
    - Notification service (email/SMS)
    - Admin portal
  out_of_scope:
    - Core banking mainframe (separate engagement)
    - ATM network
    - Third-party credit bureau integrations
  external_dependencies:
    - Twilio (SMS MFA)
    - SendGrid (email notifications)
    - Plaid (account linking)
    - AWS (cloud infrastructure)
  deployment:
    - AWS us-east-1 (primary)
    - AWS us-west-2 (DR)
    - On-premise data center (legacy core banking bridge)
```

### Stage 3: Application Decomposition

Map all data flows, trust boundaries, and data classifications:

```python
# Enumerate trust zones and data flows
trust_zones = {
    "internet":      {"trust_level": 0, "components": ["browser", "mobile_app", "external_apis"]},
    "dmz":           {"trust_level": 1, "components": ["api_gateway", "waf", "cdn"]},
    "application":   {"trust_level": 2, "components": ["auth_service", "api_service", "notification_svc"]},
    "data":          {"trust_level": 3, "components": ["postgresql", "redis", "secrets_manager"]},
    "admin":         {"trust_level": 3, "components": ["admin_portal", "bastion_host"]},
}

data_flows = [
    {"from": "browser",       "to": "api_gateway",    "data": "credentials, session tokens", "encrypted": True,  "crosses_boundary": True},
    {"from": "api_gateway",   "to": "auth_service",   "data": "auth tokens",                 "encrypted": True,  "crosses_boundary": True},
    {"from": "auth_service",  "to": "postgresql",     "data": "user records",                "encrypted": True,  "crosses_boundary": True},
    {"from": "api_service",   "to": "postgresql",     "data": "transaction records",         "encrypted": True,  "crosses_boundary": True},
    {"from": "notification",  "to": "twilio",         "data": "OTP codes, account alerts",   "encrypted": True,  "crosses_boundary": True},
]

# Classify data assets by sensitivity
data_assets = [
    {"name": "Customer credentials",   "classification": "SECRET",       "regulatory": ["PCI", "FFIEC"]},
    {"name": "Account balances",       "classification": "CONFIDENTIAL", "regulatory": ["FFIEC", "GDPR"]},
    {"name": "Transaction history",    "classification": "CONFIDENTIAL", "regulatory": ["PCI", "GDPR"]},
    {"name": "Session tokens",         "classification": "SECRET",       "regulatory": []},
    {"name": "Audit logs",             "classification": "INTERNAL",     "regulatory": ["SOC2", "FFIEC"]},
]
```

### Stage 4: Threat Analysis

Identify threat actors, their capabilities, and motivations relevant to this system:

```yaml
threat_actors:
  - name: Financially Motivated Criminal
    sophistication: MEDIUM
    motivation: Steal funds or sell account data
    attack_vectors:
      - Credential stuffing (purchased breach databases)
      - Phishing / social engineering
      - Account takeover via SIM swapping
    relevant_techniques: [T1078, T1110.004, T1566, T1539]

  - name: Nation-State Actor (Financial)
    sophistication: HIGH
    motivation: Economic disruption, intelligence collection
    attack_vectors:
      - Supply chain compromise (third-party library)
      - Spear-phishing of bank employees
      - Zero-day exploitation of banking infrastructure
    relevant_techniques: [T1195.002, T1566.001, T1190]
    known_groups: [APT38, Lazarus Group]

  - name: Malicious Insider
    sophistication: LOW-MEDIUM
    motivation: Financial gain, grievance
    attack_vectors:
      - Abuse of legitimate admin access
      - Exfiltration of customer data
      - Manipulation of transaction records
    relevant_techniques: [T1078.002, T1530, T1565]

  - name: Opportunistic Attacker
    sophistication: LOW
    motivation: Opportunistic fraud, script kiddie
    attack_vectors:
      - Automated vulnerability scanning
      - Known CVE exploitation
      - Default credential attempts
    relevant_techniques: [T1190, T1133, T1110.001]
```

### Stage 5: Vulnerability and Weakness Analysis

Map known vulnerabilities and weaknesses to the attack surface:

```bash
# Aggregate findings from existing security tools
python3 agent.py stage5 \
  --burp-report burp_scan.xml \
  --nessus-report nessus.nessus \
  --dependency-check dependency-check-report.json \
  --output pasta_s5_vulns.json

# Manual weakness categories to review per OWASP Top 10:
WEAKNESSES=(
  "A01 Broken Access Control — IDOR on /api/accounts/{id}"
  "A02 Cryptographic Failures — session tokens not using CSPRNG"
  "A03 Injection — parameterized queries in place, but ORM raw() usage in 3 places"
  "A07 Auth Failures — no lockout on /api/auth/mfa/verify endpoint"
  "A09 Logging Failures — transaction errors not logged to SIEM"
)
```

### Stage 6: Attack Modeling

Model realistic attack scenarios by chaining threat actors + weaknesses:

```python
attack_scenarios = [
    {
        "id": "AS-001",
        "name": "Account Takeover via Credential Stuffing + MFA Bypass",
        "threat_actor": "Financially Motivated Criminal",
        "attack_chain": [
            {"step": 1, "technique": "T1110.004", "action": "Purchase credential list from dark web forum"},
            {"step": 2, "technique": "T1110.001", "action": "Automated credential stuffing against /api/auth/login"},
            {"step": 3, "weakness": "A07",         "action": "Brute-force /api/auth/mfa/verify (no lockout)"},
            {"step": 4, "technique": "T1539",       "action": "Session token extracted; account fully compromised"},
        ],
        "target_assets": ["Customer credentials", "Account balances", "Transaction history"],
        "likelihood": "HIGH",   # credential stuffing lists are commodity
        "entry_point": "/api/auth/login",
    },
    {
        "id": "AS-002",
        "name": "IDOR — Mass Account Balance Enumeration",
        "threat_actor": "Financially Motivated Criminal",
        "attack_chain": [
            {"step": 1, "technique": "T1078",  "action": "Authenticate with valid (own) account"},
            {"step": 2, "weakness": "A01",     "action": "Replace account ID in GET /api/accounts/{id} — returns other users' data"},
            {"step": 3, "technique": "T1530",  "action": "Enumerate 10,000 account IDs; build target list for social engineering"},
        ],
        "target_assets": ["Account balances", "Transaction history"],
        "likelihood": "HIGH",
        "entry_point": "/api/accounts/{id}",
    },
    {
        "id": "AS-003",
        "name": "Supply Chain — Malicious npm Package",
        "threat_actor": "Nation-State Actor",
        "attack_chain": [
            {"step": 1, "technique": "T1195.002", "action": "Compromise a transitive npm dependency"},
            {"step": 2, "technique": "T1195.002", "action": "Backdoor executes on application startup in production"},
            {"step": 3, "technique": "T1041",     "action": "Exfiltrate session tokens and API keys to C2"},
        ],
        "target_assets": ["Session tokens", "Customer credentials"],
        "likelihood": "LOW",   # sophisticated, but high impact
        "entry_point": "Build pipeline / npm install",
    },
]
```

### Stage 7: Risk and Impact Analysis

Quantify risk and produce a prioritized remediation roadmap:

```python
def calculate_risk_score(likelihood: str, business_impact: str) -> dict:
    L = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    I = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    score = L[likelihood] * I[business_impact]
    severity = (
        "CRITICAL" if score >= 12
        else "HIGH" if score >= 6
        else "MEDIUM" if score >= 3
        else "LOW"
    )
    return {"risk_score": score, "severity": severity}

risk_register = [
    {
        "scenario": "AS-001",
        "name": "Account Takeover via Credential Stuffing + MFA Bypass",
        "likelihood": "HIGH",
        "business_impact": "CRITICAL",   # direct financial loss + regulatory penalty
        "financial_exposure": "$2.4M estimated fraud loss per incident",
        "regulatory_exposure": "FFIEC enforcement action, PCI DSS non-compliance",
        **calculate_risk_score("HIGH", "CRITICAL"),
        "remediation": [
            {"control": "Add lockout on /api/auth/mfa/verify (max 5 attempts)", "effort": "LOW",    "priority": 1},
            {"control": "Implement adaptive authentication (device fingerprinting)", "effort": "HIGH", "priority": 2},
            {"control": "Deploy HIBP integration on login to flag breached credentials", "effort": "MEDIUM", "priority": 3},
        ],
    },
]
```

```bash
# Generate the final PASTA report
python3 agent.py report \
  --stage1 pasta_s1.json \
  --scenarios attack_scenarios.json \
  --risks risk_register.json \
  --output pasta_final_report.json
```

## Key Concepts

| Term | Definition |
|---|---|
| PASTA | Process for Attack Simulation and Threat Analysis — 7-stage risk-centric threat modeling methodology |
| Business impact | Financial, regulatory, and reputational consequences of a successful attack |
| Attack scenario | A realistic end-to-end attack chain linking a threat actor, exploit path, and target asset |
| Risk score | Likelihood × Impact — used to prioritize the remediation backlog |
| Threat actor profile | Characterization of an adversary: motivation, sophistication, and preferred attack vectors |
| Residual risk | Risk remaining after mitigations are applied — must be formally accepted by the risk owner |
| Attack tree | Hierarchical diagram showing how an attacker achieves a goal through combinations of sub-goals |

## Tools & Systems

| Tool | Stage | Purpose |
|---|---|---|
| PASTA methodology workbook | All | Workshop facilitation template |
| draw.io / Lucidchart | Stage 3 | Data flow and architecture diagrams |
| Burp Suite / OWASP ZAP | Stage 5 | Vulnerability scan inputs |
| `agent.py` (this skill) | All | Stage scaffolding and report generation |
| MITRE ATT&CK Navigator | Stage 4 | Threat actor TTP mapping |
| FAIR model | Stage 7 | Quantitative financial risk calculation |
| JIRA / Linear | Stage 7 | Risk register and remediation tracking |

## Common Scenarios

**Scenario 1: PCI-DSS pre-assessment**
Use PASTA to produce a documented, risk-ranked threat model that maps to PCI-DSS requirements. The Stage 7 risk register serves as evidence of requirement 12.3.2 (targeted risk analysis).

**Scenario 2: Executive security investment briefing**
PASTA Stage 7 produces financial exposure estimates and ROI-based prioritization that security leaders can present to the board. STRIDE produces a technical control list; PASTA answers "why should we care and how much should we spend?"

**Scenario 3: M&A technical due diligence**
Apply PASTA Stages 1–3 to the acquisition target's systems to assess their threat exposure and regulatory risk before close. Unmitigated CRITICAL scenarios become negotiation points or deal conditions.

## Output Format

```json
{
  "assessment_timestamp": "2026-04-27T10:00:00Z",
  "system": "Online Banking Portal",
  "methodology": "PASTA v2",
  "stages_completed": 7,
  "executive_summary": {
    "attack_scenarios_identified": 12,
    "critical_risks": 3,
    "high_risks": 5,
    "total_financial_exposure": "$8.2M estimated",
    "top_risk": "Account Takeover via MFA Bypass (CRITICAL, score: 12)"
  },
  "risk_register": [
    {
      "scenario_id": "AS-001",
      "name": "Account Takeover via Credential Stuffing + MFA Bypass",
      "likelihood": "HIGH",
      "business_impact": "CRITICAL",
      "risk_score": 12,
      "severity": "CRITICAL",
      "financial_exposure": "$2.4M estimated fraud loss per incident",
      "top_remediation": "Add lockout on /api/auth/mfa/verify"
    }
  ],
  "remediation_roadmap": {
    "30_day": ["MFA lockout", "HIBP integration"],
    "60_day": ["Adaptive authentication", "IDOR fix on /api/accounts"],
    "90_day": ["Supply chain SCA pipeline", "SIEM transaction logging"]
  }
}
```
