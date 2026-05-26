---
name: ai-agent-secure-by-default
description: >-
  Generates a security-aware CLAUDE.md template for AI projects built with
  Claude Code, embedding incident readiness controls into the development
  workflow from project inception rather than as a post-deployment retrofit.
  The generated CLAUDE.md instructs Claude Code to enforce five categories of
  security practice on every task: structured logging for all agent actions,
  kill switch registration at agent startup, least-privilege tool manifests,
  network egress restrictions, and pre-ship readiness checklists. Adapts
  output to the project's framework (FastAPI, LangChain, AutoGen, CrewAI,
  custom), deployment target (Kubernetes, Docker, serverless, bare server),
  and optional components (RAG pipeline, MCP tools). The goal is to close
  the gap surfaced by ai-incident-readiness-assessment before the project
  reaches production — not after. Activates when a project owner is starting
  a new AI agent project or onboarding Claude Code onto an existing one that
  lacks security guardrails.
domain: cybersecurity
subdomain: ai-security
tags:
  - claude-code
  - secure-by-default
  - ai-security
  - kill-switch
  - observability
  - least-privilege
  - incident-response
  - MAESTRO
  - OWASP-Agentic-Top10
  - ASI10
  - LLM06
  - devsecops
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - PR.PS-01
  - PR.PS-04
  - ID.IM-02
  - RS.MI-01
nist_ai_rmf:
  - GOVERN-1.1
  - GOVERN-6.1
  - MANAGE-2.2
  - MANAGE-4.1
atlas_techniques:
  - AML.T0054
  - AML.T0068
d3fend_techniques:
  - Process Spawn Analysis
  - Network Traffic Filtering
  - Executable Denylisting
---
# AI Agent Secure by Default

## When to Use

- When a project owner is starting a new AI agent project and wants Claude Code to enforce security practices from the first commit
- When onboarding Claude Code onto an existing AI project that lacks kill switches, structured logging, or least-privilege tool manifests
- When a security team wants to standardise the security baseline across multiple AI projects built by different teams
- Before a project reaches the `ai-incident-readiness-assessment` gate — this skill pre-populates the controls that assessment checks

**The core idea:** the `ai-incident-readiness-assessment` scores gaps after the fact. This skill prevents those gaps from forming in the first place by embedding the rules into the project's `CLAUDE.md` so Claude Code enforces them on every task.

## Prerequisites

- Claude Code installed in the project (`claude` CLI or IDE extension)
- Project root identified — the generated `CLAUDE.md` goes here
- Basic knowledge of the project's tech stack (framework, deployment target, optional components)

## Workflow

### Step 1: Generate the CLAUDE.md

```bash
python agent.py generate \
  --system "My AI Agent" \
  --framework fastapi \
  --deployment docker \
  --has-rag \
  --has-mcp \
  --output CLAUDE.md
```

Supported values:

| Flag | Options |
|---|---|
| `--framework` | `fastapi`, `langchain`, `autogen`, `crewai`, `custom` |
| `--deployment` | `kubernetes`, `docker`, `lambda`, `server` |
| `--has-rag` | Flag — include RAG corpus security rules |
| `--has-mcp` | Flag — include MCP tool manifest rules |

### Step 2: Place it in the project root

```bash
cp CLAUDE.md /path/to/your/ai-project/CLAUDE.md
```

Claude Code reads `CLAUDE.md` automatically on every task. The security rules take effect immediately — no configuration required.

### Step 3: What Claude Code will enforce

Once the `CLAUDE.md` is in place, Claude Code will:

- **Refuse to write agent code without kill switch registration** at startup
- **Always add structured logging** for every tool call, model invocation, and decision
- **Flag any tool manifest addition** that isn't justified against the agent's declared purpose
- **Block wildcard permissions** in IAM policies, tool schemas, and API scopes
- **Add a throttle check** to every tool executor before implementing the tool logic
- **Prompt for network egress policy** when writing any code that makes outbound HTTP calls
- **Run the pre-ship checklist** before marking any agent feature as complete

### Step 4: Pair with the readiness assessment

After the project is built, run the readiness assessment to verify the controls were actually implemented:

```bash
python skills/ai-incident-readiness-assessment/scripts/agent.py \
  audit --service-path ./your-agent-service/
```

Any gap surfaced by the audit means the `CLAUDE.md` rule wasn't followed — investigate why and tighten the rule if needed.

## Key Concepts

| Term | Definition |
|------|------------|
| **Secure by Default** | Security controls are the default path, not an opt-in — Claude Code implements them unless explicitly told otherwise by the project owner |
| **Shift Left** | Moving security controls earlier in the development lifecycle — catching missing kill switches at code-write time rather than at production deployment |
| **Pre-ship Checklist** | A set of readiness checks Claude Code runs before marking an agent feature complete — equivalent to a unit test for security controls |
| **CLAUDE.md** | Claude Code's project instruction file — read automatically on every task, making it the ideal place to embed standing security rules |

## Tools & Systems

| Tool | Relationship |
|------|-------------|
| **ai-incident-readiness-assessment** | Downstream — scores the controls this skill instructs Claude Code to build |
| **ai-agent-kill-switch-and-graduated-response** | Referenced in generated CLAUDE.md — provides the kill switch implementation patterns |
| **ai-incident-response-playbook** | Referenced in generated CLAUDE.md — project owner links their playbooks here |
| **llm-excessive-agency-prevention** | Referenced in generated CLAUDE.md — tool manifest auditing rules |
| **rag-pipeline-security-and-data-provenance** | Referenced when `--has-rag` — RAG corpus security rules injected into CLAUDE.md |

## Common Scenarios

- **New greenfield project**: A team starts building a LangChain agent. They run `generate` before writing the first line. Claude Code implements kill switch registration in the `main.py` lifespan handler on the first task, without being asked.
- **Existing project onboarding**: A project passes 12/25 on the readiness assessment. The security team generates a CLAUDE.md and adds it to the repo. On the next PR, Claude Code flags the missing network egress policy and adds it as part of the diff.
- **Multi-team standardisation**: A security team generates one CLAUDE.md per framework type (FastAPI + K8s, LangChain + Docker) and publishes them as organisation templates. All AI projects inherit the same baseline.

## Output Format

```
CLAUDE.md written to: ./CLAUDE.md
Framework  : fastapi
Deployment : kubernetes
Components : rag, mcp
Rules      : 24 security rules embedded
Checklist  : 8 pre-ship items
```
