# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a library of 796 cybersecurity skills for AI agents, mapped to 5 industry frameworks:
- **MITRE ATT&CK Enterprise** — offensive techniques (218 unique techniques, 100% of 14 tactics)
- **NIST Cybersecurity Framework 2.0** — risk management functions/categories
- **MITRE ATLAS v5.5** — AI-specific threats
- **MITRE D3FEND v1.3** — defensive countermeasures
- **NIST AI RMF 1.0** — AI risk management

Skills follow the `agentskills.io` open standard and are compatible with Claude Code, Cursor, GitHub Copilot, and 23+ other AI agent platforms. This is a community project, not affiliated with Anthropic PBC. Apache 2.0 licensed.

### AI Security Coverage (35 skills)
The library includes full coverage of four AI/agentic security frameworks:
- **OWASP LLM Top 10 2025** (LLM01–LLM10) — 9 new skills covering LLM02–LLM10; LLM01 covered by `detecting-ai-model-prompt-injection-attacks`
- **OWASP MCP Top 10 v0.1** (MCP01–MCP10) — 10 skills under `mcp-*` prefix
- **OWASP Top 10 for Agentic Applications 2026** (ASI01–ASI10) — 10 skills under `agent-*`, `agentic-*`, `rogue-*`, `human-agent-*`, `securing-inter-*` prefixes
- **MAESTRO Framework** (7 layers + cross-layer threats) — 6 skills covering all MAESTRO threat domains: `performing-maestro-threat-modeling`, `rag-pipeline-security-and-data-provenance`, `ai-model-extraction-and-reprogramming-defense`, `ai-evaluation-security-and-observability-hardening`, `ai-governance-and-regulatory-compliance`, `ai-workload-infrastructure-hardening`

All 35 AI security skills use `subdomain: ai-security` (an accepted extension to the standard 26 subdomains).

## Key Commands

### Phantom Agent (Claude API-powered chatbot over the skill library)
```bash
cd phantom
pip install anthropic
export ANTHROPIC_API_KEY=sk-...
python main.py
```
Slash commands inside phantom: `/mode <name>`, `/modes`, `/save`, `/load`, `/sessions`, `exit`

Phantom can execute `scripts/agent.py` files directly via the `run_skill_agent` tool. Skills with executable scripts:

**AI red-teaming (new):**
- `llm-system-prompt-leakage-prevention` — `agent.py --model <model> --system-prompt "..."` — runs 11 extraction probes + canary token detection
- `llm-excessive-agency-prevention` — `agent.py --manifest tools.json --function "..." --required tool1,tool2` — audits tool manifest for excess permissions
- `llm-output-validation-and-sanitization` — `agent.py --model <model> --system-prompt "..."` — probes for XSS/SQLi/SSRF/cmd injection in LLM outputs
- `llm-sensitive-information-disclosure-prevention` — `agent.py --model <model> --system-prompt "..."` or `--scan-file log.jsonl` — detects PII/credential leakage
- `llm-data-and-model-poisoning-defense` — `agent.py dataset-scan --dataset data.jsonl` or `agent.py backdoor-probe --model <model>` — scans training data and probes for backdoors
- `agent-goal-hijacking-detection` — `agent.py --goal "..." --log agent.jsonl` — detects goal drift and injection patterns in agent logs
- `rogue-agent-detection-and-containment` — `agent.py --log telemetry.jsonl` — detects reward hacking, self-replication, behavioural drift, and collusion
- `detecting-ai-model-prompt-injection-attacks` — existing script, DeBERTa-based classifier

**Application security:**
- `performing-asvs-compliance-assessment` — `agent.py init --app "Name" --url "https://..." --level 2` then `agent.py report --assessment file.json` — generates ASVS v4.0.3 worksheet and conformance report (no API key required)

**Threat modeling:**
- `performing-stride-threat-modeling` — `agent.py init --system "Name"` → `agent.py analyze --components file.json` → `agent.py report --threats file.json` — applies STRIDE per component type; generates prioritized threat register (no API key required)
- `performing-pasta-threat-modeling` — `agent.py scaffold --system "Name"` → `agent.py analyze --worksheet file.json` → `agent.py report --risks file.json` — 7-stage risk-centric PASTA with business impact scoring (no API key required)
- `threat-modeling-for-ai-ml-systems` — `agent.py init --system "Name" --arch-type agentic|rag|llm_app|training_pipeline|multi_agent` → `agent.py analyze` → `agent.py report` — applies OWASP LLM/Agentic Top 10 + MITRE ATLAS taxonomy to AI components (no API key required)
- `performing-maestro-threat-modeling` — `agent.py init --system "Name" --arch-type single|multi|hierarchical|distributed|conversational|task_oriented|human_in_loop|self_learning` → `agent.py analyze --assessment file.json` → `agent.py report --assessment file.json` — applies MAESTRO 7-layer framework (54 threats per typical multi-agent system, 5 cross-layer threats); highlights architecture-pattern-specific risks (no API key required)

**AI security infrastructure auditing (MAESTRO gap coverage):**
- `rag-pipeline-security-and-data-provenance` — `agent.py audit --config rag_config.json` / `agent.py scan-documents --dir ./docs` — audits RAG pipeline security (12 controls: injection filters, vector DB encryption/access/isolation, embedding integrity, data provenance) and scans documents for 10 prompt injection patterns (no API key required)
- `ai-model-extraction-and-reprogramming-defense` — `agent.py audit --config model_api_config.json` — audits model API for 9 extraction controls (rate limiting, anomaly detection, output perturbation, differential privacy) and 5 reprogramming controls (policy layer, logit masking, fine-tuning API access); reports separate extraction/reprogramming risk scores (no API key required)
- `ai-evaluation-security-and-observability-hardening` — `agent.py audit-eval --config eval_config.json` / `agent.py audit-telemetry --config telemetry_config.json` — audits eval pipeline (10 controls: dataset signing, adversarial regression, isolation) and telemetry stack (11 controls: tamper-evident logging, PII redaction, behavioral baselines, ML-based anomaly detection) (no API key required)
- `ai-governance-and-regulatory-compliance` — `agent.py assess --system "Name" --risk-tier high|limited|minimal --framework eu-ai-act|nist-ai-rmf|iso-42001|all` then `agent.py score --checklist compliance_report.json` — generates compliance checklist (EU AI Act Articles 9-16/26/49/72, NIST AI RMF GOVERN/MAP/MEASURE/MANAGE, ISO 42001 Clauses 4-10); scores filled-in checklist as gap report (no API key required)
- `ai-workload-infrastructure-hardening` — `agent.py scan --config infra_config.json` / `agent.py scan-k8s --manifest deployment.json` — audits AI workload infra (16 controls: image signing/scanning, non-root execution, resource limits, network policy, RBAC, admission controllers, agent-to-vectorDB/secret-store isolation, vault integration) and parses raw `kubectl get deployment -o json` output for K8s-native checks (no API key required)

**SOC / SIEM:**
- `securonix-siem-operations` — `agent.py query --use-case brute-force|lateral-movement|data-exfiltration|insider-threat|cloud-abuse|ransomware` / `agent.py convert --spl "..."` / `agent.py triage --alert-type <type>` — SPOTTER query generation, SPL→SPOTTER conversion, triage checklists (no API key required)

**Vulnerability management (AWS):**
- `aws-inspector-findings-reporter` — `agent.py report --start-date 2026-03-01 --end-date 2026-03-31 --regions us-east-1,us-west-2 --kev` / `agent.py trends --current report_march.json --previous report_feb.json` — monthly Inspector v2 report with CISA KEV + EPSS enrichment, multi-region, trend comparison; exits 1 on CRITICAL (requires `pip install boto3`)
- `aws-vulnerability-remediation-prioritization` — `agent.py prioritize --findings raw_findings.json --kev` — ranks Inspector findings by composite score (severity × EPSS × KEV multiplier × affected-resource count); splits backlog by team (EC2/ECR/Lambda); identifies high-leverage "patch one, fix many" actions (no API key required)

**API security (pre-existing):**
- `conducting-api-security-testing`, `testing-api-authentication-weaknesses`, `testing-api-for-broken-object-level-authorization`, `performing-api-rate-limiting-bypass`, `exploiting-api-injection-vulnerabilities`, `detecting-api-enumeration-attacks`, `testing-api-security-with-owasp-top-10`

All scripts output structured JSON, accept `--output <file>` to save reports, and exit with code 1 on HIGH/CRITICAL findings (CI-gate compatible).

### Validate Skills (mirrors CI)
The validation logic lives in `.github/workflows/validate-skills.yml` as an inline Python script. To run it locally, extract and run the embedded Python. It checks:
- Required frontmatter fields: `name`, `description`, `domain`, `subdomain`, `tags`, `version`, `author`, `license`
- `name` must be kebab-case, max 64 characters, unique across all skills
- `domain` must be `cybersecurity`

### Regenerate index.json (mirrors CI)
The index-building logic lives in `.github/workflows/update-index.yml` as an inline Python script. Run it manually or trigger via GitHub Actions (`workflow_dispatch`).

## Architecture

### Skill Directory Structure
Each of the 796 skills lives in `skills/<skill-name>/`:
```
skills/<skill-name>/
├── SKILL.md          # Primary skill definition (required)
├── LICENSE           # Apache-2.0 copy (required)
├── references/
│   └── api-reference.md   # Severity scales, function signatures (optional)
└── scripts/
    └── agent.py           # Executable helper script (optional)
```

### SKILL.md Frontmatter Schema
```yaml
---
name: kebab-case-unique-name          # required, max 64 chars
description: >-
  Multi-line description...
domain: cybersecurity                  # always this value
subdomain: <one of 26 subdomains>     # see list below
tags:
  - keyword1
  - keyword2
version: '1.0'
author: github-username
license: Apache-2.0

# Optional framework mappings:
nist_csf: [RS.AN-01, DE.AE-02]       # NIST CSF 2.0 function/category codes
atlas_techniques: [AML.T0047]         # MITRE ATLAS technique IDs
d3fend_techniques: [Executable Denylisting]
nist_ai_rmf: [MEASURE-2.6]
---
```

MITRE ATT&CK technique IDs (e.g., `T1059.001`) are stored in the `tags` array, not a dedicated field.

### SKILL.md Body Sections (in order)
1. **When to Use** — agent trigger conditions
2. **Prerequisites** — tools, access, environment
3. **Workflow** / **Steps** — numbered steps with real commands/code
4. **Key Concepts** — markdown table of terms
5. **Tools & Systems** — reference table
6. **Common Scenarios** — real-world use cases
7. **Output Format** — example JSON/structured output

### 26 Valid Subdomains
`web-application-security`, `network-security`, `penetration-testing`, `red-teaming`, `digital-forensics`, `malware-analysis`, `threat-intelligence`, `cloud-security`, `container-security`, `identity-access-management`, `cryptography`, `vulnerability-management`, `compliance-governance`, `zero-trust-architecture`, `ot-ics-security`, `devsecops`, `soc-operations`, `incident-response`, `phishing-defense`, `ransomware-defense`, `api-security`, `mobile-security`, `endpoint-security`, `threat-hunting`, `application-security`, `data-security`

### Generated / Auto-maintained Files
- **`index.json`** — autogenerated catalog of all skills; do not edit manually, regenerate via CI
- **`mappings/attack-navigator-layer.json`** — pre-built ATT&CK Navigator heatmap (96KB)
- **`.claude-plugin/marketplace.json`** — version is bumped automatically by the `sync-marketplace-version.yml` workflow on GitHub release

### Phantom Agent (`phantom/`)
A standalone Claude API chatbot that loads skills dynamically:
- `main.py` — interactive REPL, model `claude-opus-4-6`, 7 persona modes (general, red-team, appsec, threat-hunting, cloud, forensics, soc)
- `skill_loader.py` — discovers and loads SKILL.md files matching user queries; reads `index.json` at import time
- `executor.py` — runs `scripts/agent.py` files as subprocesses; 60-second timeout per script
- `tools.py` — 4 tool definitions: `search_skills`, `load_skill`, `run_skill_agent`, `write_file`
- `sessions/` — persisted conversation history (JSON)

**Tool dispatch behaviour:**
- `run_skill_agent` is only called when the user explicitly asks to execute a script; always confirm target and args
- `write_file` writes relative to the project root; always show content to user before writing
- Scripts that exit with code 1 indicate a HIGH/CRITICAL finding — Phantom will surface this in its response

### CI Workflows
| Workflow | Trigger | Purpose |
|---|---|---|
| `validate-skills.yml` | Push/PR touching `skills/` | Validates all SKILL.md frontmatter |
| `update-index.yml` | Push to `main` or manual | Regenerates `index.json` |
| `sync-marketplace-version.yml` | GitHub release published | Bumps plugin version in marketplace.json |

All workflows use inline Python 3 on `ubuntu-latest` — no npm or Makefile.

## Adding a New Skill

1. Create `skills/<kebab-case-name>/SKILL.md` with valid frontmatter (see schema above).
2. Copy `LICENSE` from any existing skill directory into the new directory.
3. Follow the required body section order.
4. Optionally add `references/api-reference.md` and `scripts/agent.py`.
5. Push/open a PR — CI validates automatically; `index.json` is regenerated on merge to `main`.

### Adding an Executable Script (`scripts/agent.py`)

Scripts are optional but make a skill directly runnable by Phantom via `run_skill_agent`. Conventions:
- Use `argparse` for all CLI arguments; include `--output <file>` defaulting to a JSON report filename
- Print a `json.dumps(report, indent=2)` summary to stdout so Phantom can read it
- Exit with `sys.exit(1)` when overall risk is HIGH or CRITICAL (CI-gate compatible)
- Avoid hard dependencies beyond stdlib + `anthropic`; guard optional imports with try/except
- Do not hard-code API keys; read from `os.environ.get("ANTHROPIC_API_KEY")`
- Keep scripts self-contained — no imports from other skill directories

### AI Security Skill Naming Conventions

| Framework | Prefix pattern | Example |
|---|---|---|
| OWASP LLM Top 10 | `llm-<descriptor>` | `llm-system-prompt-leakage-prevention` |
| OWASP MCP Top 10 | `mcp-<descriptor>` | `mcp-tool-poisoning-detection-and-defense` |
| OWASP Agentic Top 10 | `agent-`, `agentic-`, `rogue-`, `human-agent-`, `securing-inter-` | `agent-goal-hijacking-detection` |
| MAESTRO Framework | `performing-maestro-`, `rag-pipeline-`, `ai-model-`, `ai-evaluation-`, `ai-governance-`, `ai-workload-` | `performing-maestro-threat-modeling` |

All AI security skills use `subdomain: ai-security`. Do not add `ai-security` to the official 26-subdomain list in this file — it is an accepted extension used only for these skills.
