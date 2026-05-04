# Phantom Deployment Plan

## What Phantom Is

Phantom is the org's shared cybersecurity capability built on top of a library of 802 security skills
mapped to MITRE ATT&CK, NIST CSF, MITRE ATLAS, MITRE D3FEND, and NIST AI RMF. It serves every
team — developers, architects, security engineers, product managers, and CI/CD pipelines — through
three distinct deployment layers. No team needs to clone or manage this repo directly.

---

## The Three Deployment Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Skill Library (this repo)                 │
│          802 skills · index.json · agent.py scripts         │
└──────────────┬───────────────────────────────────────────────┘
               │ serves
   ┌───────────┼──────────────────────────┐
   ▼           ▼                          ▼
Phantom     Phantom MCP              agent.py scripts
main.py     server (HTTP)            (standalone executables)
   │              │                        │
   ▼              ▼                        ▼
Slack/Teams   Claude Code            CI/CD pipelines
bot or        Enterprise             (GitHub Actions,
internal      org-level              Bitbucket, Jenkins)
web API       MCP + commands
              (/audit /threat
               /remediate)
```

---

## Layer 1 — Developer Security Assistant (Claude Code Enterprise)

**What it does:** Developers get inline security assistance while writing code, without leaving their IDE.

**How it works:**
- Slash commands (`/audit`, `/threat`, `/remediate`) are registered org-wide in the Claude Code Enterprise admin console
- The Phantom MCP server and cve-intel MCP server run as centrally-hosted HTTP services
- Both MCP servers are registered at org level — available in every developer's Claude Code session in every project

**Developer experience:**
- Open any project in Claude Code (React, Python, Java, Go — any language)
- `/audit` — scans dependencies for known vulnerabilities across all detected ecosystems
- `/threat` — analyzes codebase for STRIDE threats; auto-layers MAESTRO + OWASP LLM/Agentic/MCP Top 10 if AI components are detected; saves findings to `threat-report.json`
- `/remediate` — loads `threat-report.json` (or session state) and guides targeted fixes through Phantom skill knowledge; routes each finding to the right skill; reports residual risk

**Who uses this:** All developers, daily, during feature development and code review.

**Infrastructure required:**
- Phantom MCP server deployed as HTTPS service on internal infrastructure
- cve-intel MCP server deployed as HTTPS service on internal infrastructure
- Both registered in Claude Code Enterprise admin console as org-level MCP servers
- `/audit`, `/threat`, `/remediate` registered as org-level slash commands

---

## Layer 2 — Phantom Security Service (API / Chat)

**What it does:** A conversational security expert available to anyone in the org — not just Claude Code users. Teams can ask free-form security questions, get threat models for designs-in-progress, or request compliance gap reports.

**How it works:**
- `phantom/main.py` is deployed as an internal HTTP API or Slack/Teams bot
- It uses the Claude API with dynamic skill loading — when a question is asked, it searches `index.json`, loads relevant SKILL.md files, and answers with expert-level guidance drawn from the skill library
- Seven security personas: general, red-team, appsec, threat-hunting, cloud, forensics, soc

**Example interactions:**
- "We're building a RAG pipeline for customer PII. What are the risks?" → Phantom loads RAG security + MAESTRO L2 + OWASP LLM skills and gives a structured threat brief
- "Is our OAuth implementation correct?" → Phantom loads auth-relevant skills and reviews the described flow
- "We need to pass SOC 2 Type II. Where do we start?" → Phantom loads compliance skills and produces a gap checklist
- "Generate a MAESTRO threat model for our new multi-agent billing system" → Phantom runs the full 7-layer analysis

**Who uses this:** Architects, product managers, security team, developers with design questions, compliance/legal. Any team member who needs security expertise without knowing which tool to use.

**Deployment options (choose one based on org tooling):**
- **Slack/Teams bot** — wraps `phantom/main.py` behind a bot framework; teams @mention Phantom in any channel
- **Internal web app** — simple chat UI over the Phantom API; accessible via SSO
- **CLI tool** — `phantom` command provisioned org-wide via developer platform (Homebrew tap, apt repo, internal tooling)

**Infrastructure required:**
- `phantom/main.py` deployed as a containerized service (Dockerfile provided or easily written)
- `ANTHROPIC_API_KEY` injected via secrets manager (Vault, AWS Secrets Manager, etc.)
- Skill library (`index.json` + `skills/`) mounted or baked into the container image
- Internal DNS / SSO / Slack app registration depending on chosen interface

---

## Layer 3 — Automated CI/CD Security Gates

**What it does:** Phantom skills run automatically on every pull request and on a schedule. No developer action required. Findings block merges when severity is HIGH or CRITICAL.

**How it works:**
- `agent.py` scripts in each skill directory are standalone executables — no Phantom server, no MCP, no Claude API required for most
- CI/CD pipelines call them directly as pipeline steps
- All scripts exit with code 1 on HIGH/CRITICAL findings — native CI gate behavior
- Findings are written to JSON files and uploaded as pipeline artifacts for review

**Standard gates (all projects):**

| Gate | Trigger | Script |
|---|---|---|
| Dependency audit | Any change to a package manifest | Ecosystem-native tools (`npm audit`, `pip audit`, etc.) |
| STRIDE threat scan | PR touching API routes, auth flows, or trust boundaries | `performing-stride-threat-modeling/scripts/agent.py` |
| Secret scanning | Every push | `mcp__cve-intel__scan_repo_secrets` or `git-secrets` |

**Additional gates (AI/ML projects):**

| Gate | Trigger | Script |
|---|---|---|
| LLM output validation | PR touching LLM call sites or prompt templates | `llm-output-validation-and-sanitization/scripts/agent.py` |
| Excessive agency check | PR touching tool definitions or agent manifests | `llm-excessive-agency-prevention/scripts/agent.py` |
| RAG pipeline audit | PR touching ingestion pipeline or vector DB config | `rag-pipeline-security-and-data-provenance/scripts/agent.py` |
| Agent framework audit | PR touching orchestration layer | `ai-agent-framework-security/scripts/agent.py` |
| Infrastructure hardening | PR touching K8s manifests or IaC | `ai-workload-infrastructure-hardening/scripts/agent.py` |

**Scheduled scans (weekly/monthly):**

| Scan | Cadence | Script |
|---|---|---|
| Full MAESTRO audit | Weekly (AI/ML projects) | All layer auditors → `performing-maestro-remediation` |
| Compliance assessment | Monthly | `ai-governance-and-regulatory-compliance/scripts/agent.py` |
| Vulnerability report | Weekly | `aws-inspector-findings-reporter/scripts/agent.py` (AWS) |

**Infrastructure required:**
- Skill library cloned into CI runner image (or checked out as part of pipeline)
- `ANTHROPIC_API_KEY` available as a CI secret (only needed for skills that call the Claude API)
- Pipeline config per team (GitHub Actions workflow, Bitbucket pipeline, Jenkinsfile)

---

## Who Owns What

| Component | Owner | Cadence |
|---|---|---|
| Skill library (this repo) | Security team | Ongoing — add skills as new threats emerge |
| Phantom MCP server (hosted) | Platform/DevOps | Deploy on skill library update |
| cve-intel MCP server (hosted) | Platform/DevOps | Persistent service, auto-restarts |
| Slash commands in Enterprise admin | Security team | Update when command files change |
| Phantom chat service | Platform/DevOps | Persistent service |
| CI/CD gate templates | Security team | Provide as reusable workflow templates per ecosystem |
| `index.json` | Automated (CI) | Regenerated on every merge to main |

---

## Rollout Sequence

**Phase 1 — Claude Code Enterprise (immediate value, lowest effort)**
1. Deploy Phantom MCP server and cve-intel MCP server as internal HTTPS services
2. Register both in Enterprise admin console as org-level MCP servers
3. Register `/audit`, `/threat`, `/remediate` as org-level slash commands
4. All developers immediately have security assistance in their IDE

**Phase 2 — CI/CD gates (automated enforcement)**
1. Security team publishes reusable pipeline templates for each ecosystem
2. Platform team adds standard gates (dependency audit + secret scan) to all new repos via repo templates
3. AI/ML project teams opt in to the AI-specific gates

**Phase 3 — Phantom chat service (broader org access)**
1. Deploy `phantom/main.py` as internal service
2. Choose interface: Slack bot, web app, or CLI
3. Announce to architects, product managers, and security team
4. Run office hours / demo sessions to drive adoption

---

## Security and Access Controls

- All Phantom services sit behind internal SSO — no public exposure
- `ANTHROPIC_API_KEY` managed centrally via secrets manager — developers never handle it
- Skill library is read-only at runtime — no write access from any Phantom service
- CI/CD scripts run with least-privilege runner permissions
- Audit logs from Phantom chat service retained per org data retention policy
