# Phantom Autonomy Map — 812 Skills across 30 Subdomains

## Legend

| Level | Meaning |
|---|---|
| 🟢 **Full** | Phantom executes end-to-end — no human approval needed |
| 🟡 **Gated** | Phantom proposes + shows approval UI; human approves before changes execute |
| 🟠 **Assist** | Phantom researches and advises; human executes |
| 🔴 **Human Required** | Legal authorization, physical access, or physical safety risk — Phantom cannot act |

---

## 🟢 Full Autonomy — 389 skills across 13 subdomains

| Subdomain | Skills | Scripted | What Phantom does autonomously | Blocker if any |
|---|---|---|---|---|
| **soc-operations** | 69 | 69 | Alert triage, SIEM queries, playbook execution, escalation scoring, metrics | — |
| **threat-hunting** | 56 | 56 | Hypothesis-driven SIEM/EDR queries, detection rule generation, hunt reports | — |
| **threat-intelligence** | 50 | 50 | IOC enrichment, CVE correlation, threat feed ingestion, attribution, reporting | — |
| **malware-analysis** | 39 | 39 | Sandbox execution, static/dynamic analysis, IOC extraction, YARA generation | — |
| **digital-forensics** | 37 | 37 | Log/memory/disk analysis, timeline reconstruction, artifact extraction | Evidence custody is a human decision |
| **api-security** | 31 | 31 | API discovery, anomaly detection, documentation analysis, authorized DAST | Exploitation of production systems |
| **vulnerability-management** | 29 | 29 | Scan scheduling, KEV/EPSS enrichment, prioritization, remediation tracking | Patch deployment |
| **container-security** | 29 | 29 | Image scanning, runtime audit, policy review, CIS benchmark assessment | Runtime config changes |
| **phishing-defense** | 16 | 16 | Email parsing, URL/attachment inspection, IOC extraction, reporter notification | — |
| **devsecops** | 18 | 18 | SAST/DAST gate enforcement, dependency scanning, secrets detection, pipeline audit | Code merges, deployment approvals |
| **compliance-governance** | 9 | 9 | NIST/ISO/SOC 2 gap analysis, evidence collection, checklist generation | — |
| **supply-chain-security** | 3 | 3 | SBOM analysis, dependency CVE correlation, integrity verification | — |
| **deception-technology** | 3 | 3 | Honeypot alert monitoring, attacker behavior correlation, report generation | Initial honeypot infra deployment |

---

## 🟡 Gated — 258 skills across 8 subdomains

Phantom detects and proposes; the built-in approval workflow presents the action to a human before it executes.

| Subdomain | Skills | Scripted | Autonomous half | Gated half (needs approval) |
|---|---|---|---|---|
| **cloud-security** | 63 | 62 | Misconfiguration detection, posture scoring, IAM audit, CSPM queries | Remediation: SG rule changes, bucket lockdown, IAM policy updates |
| **network-security** | 43 | 43 | Passive monitoring, traffic analysis, detection rules, protocol analysis | Firewall rule changes, ACL modifications, route changes |
| **identity-access-management** | 36 | 36 | Entitlement review, anomaly detection, privilege audit, orphan account discovery | Account changes, privilege grants/revocations, MFA enforcement |
| **web-application-security** | 42 | 42 | WAF review, security header analysis, passive DAST, OWASP Top 10 detection | Active exploitation, authenticated scans on production |
| **incident-response** | 26 | 26 | Evidence collection, timeline reconstruction, IOC correlation, blast radius | Containment: host isolation, credential revocation, IP block |
| **zero-trust-architecture** | 18 | 18 | Maturity assessment, policy gap analysis, micro-segmentation design | Policy enforcement changes, network segmentation modifications |
| **endpoint-security** | 17 | 17 | EDR alert triage, behavioral monitoring, threat detection, telemetry analysis | Quarantine, process termination, endpoint config changes |
| **ransomware-defense** | 13 | 13 | Early detection, IOC hunting, backup integrity check, blast radius estimate | Host isolation, EDR quarantine, backup restoration trigger |

---

## 🟠 Assist — 83 skills across 4 subdomains

Phantom generates analysis, identifies issues, and drafts recommendations. A human reviews and executes.

| Subdomain | Skills | Scripted | Phantom delivers | Human executes |
|---|---|---|---|---|
| **ai-security** | 45 | 23 | Security audits (23 scripted scripts), probe testing, compliance gap reports | Model retraining, architecture redesign, governance decisions (22 skills have no executable script) |
| **cryptography** | 15 | 15 | Algorithm strength analysis, certificate inspection, TLS config audit, key length recommendations | Key generation, key rotation, HSM provisioning |
| **mobile-security** | 13 | 13 | APK/IPA static analysis, permission audit, OWASP MASVS assessment, binary review | Physical device testing, dynamic analysis on hardware, app store submission |
| **application-security** | 10 | 10 | SAST, dependency scanning, ASVS assessment, threat model generation | Code remediation, architectural changes, secure design decisions |

---

## 🔴 Human Required — 82 skills across 5 subdomains

Phantom can support planning and documentation, but cannot execute without a human in the loop due to legal, physical, or safety constraints.

| Subdomain | Skills | Scripted | What Phantom can support | Why human must execute |
|---|---|---|---|---|
| **red-teaming** | 27 | 27 | Scope planning, TTP documentation, OSINT research, report writing | All offensive execution requires a signed Rules of Engagement — unauthorized is criminal |
| **ot-ics-security** | 29 | 29 | Asset inventory review, passive monitoring, compliance gap analysis | Active testing risks physical harm — SCADA/PLC interference can cause equipment damage or injury |
| **penetration-testing** | 22 | 22 | Scoping assistance, tool configuration, report templating, finding classification | All active testing requires a signed authorization document; Phantom won't fire exploits |
| **wireless-security** | 2 | 2 | Protocol documentation, RF security analysis of provided captures | Active RF transmission/injection requires physical proximity + FCC licensing compliance |
| **firmware-analysis** | 2 | 2 | Static analysis of already-extracted firmware images | Physical device extraction (JTAG, UART, chip-off) requires hands-on hardware access |

---

## Summary

| Level | Subdomains | Skills | % of Library |
|---|---|---|---|
| 🟢 Full | 13 | 389 | **48%** |
| 🟡 Gated | 8 | 258 | **32%** |
| 🟠 Assist | 4 | 83 | **10%** |
| 🔴 Human Required | 5 | 82 | **10%** |
| **Total** | **30** | **812** | **100%** |

**80% of the library (647 skills) can be driven by Phantom either fully or with an approval gate.** The remaining 20% is split between research-only assist (10%) and domains that legally or physically require a human operator (10%).

The gated workflow already built into Phantom — where it presents a proposed action and waits for confirmation — covers the entire 🟡 column without any additional infrastructure. The 🔴 column is a hard boundary driven by law (unauthorized pentesting, FCC licensing) and physical safety (OT/ICS).
