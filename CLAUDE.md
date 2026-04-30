# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Display name: Cybersecurity Skills** (formerly Anthropic-Cybersecurity-Skills). The GitHub repo slug retains the original name; the project is independently maintained and not affiliated with Anthropic PBC.

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

## MCP Servers

Two MCP servers are registered in `.mcp.json` and load automatically in Claude Code.

### phantom-skills
Exposes the skill library to Claude Code as 4 tools: `search_skills`, `load_skill`, `run_skill_agent`, `list_subdomains`.
```json
{ "command": "python3", "args": ["mcp/phantom_mcp_server.py"] }
```
No extra dependencies — reads `index.json` at startup.

**Known limitation:** `index.json` only stores `name/description/domain/path` per skill; `list_subdomains` and `search_skills` therefore return `subdomain: "unknown"` for all skills. To fix, the MCP server needs to parse SKILL.md frontmatter directly (not yet implemented).

### cve-intel (mukul975/cve-mcp-server)
27-tool MCP server for live CVE intelligence: NVD lookup, EPSS scores, CISA KEV catalog, PoC detection, Shodan exposure, ATT&CK technique mapping, and composite risk scoring.

**Install:**
```bash
git clone https://github.com/mukul975/cve-mcp-server ~/Desktop/cve-mcp-server
cd ~/Desktop/cve-mcp-server
pip install -e .
```

**Registration in `.mcp.json`:**
```json
{ "command": "python3", "args": ["-m", "cve_mcp.server"] }
```
Run `python3 -m cve_mcp.server` from `~/Desktop/cve-mcp-server/` to verify startup. The server pre-fetches the CISA KEV catalog on boot and caches all API responses in SQLite (`~/.cache/cve_mcp/vuln_cache.db`).

**Risk scoring formula:** EPSS 35% + KEV 30% + CVSS 20% + PoC 15%; ×1.5 multiplier when both KEV and PoC are present.

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

**Vulnerability management (AWS — full autonomous pipeline):**

Phantom can run the full VM pipeline end-to-end when given AWS credentials:

1. **Collect** — `aws-inspector-findings-reporter`: `agent.py report --start-date 2026-03-01 --end-date 2026-03-31 --regions us-east-1,us-west-2 --kev` — pulls Inspector v2 findings, enriches with CISA KEV + EPSS, outputs `inspector_report.json`; exits 1 on CRITICAL (requires `pip install boto3`)
2. **Enrich** — use `cve-intel` MCP tools (`search_cve`, `get_risk_score`, `check_kev_status`) to cross-reference each CVE-ID in the Inspector report for live EPSS/PoC/ATT&CK context
3. **Prioritize** — `aws-vulnerability-remediation-prioritization`: `agent.py prioritize --findings inspector_report.json --kev` — composite score: `severity_weight × (1 + EPSS) × KEV_multiplier(3×) × log(affected_resources + 1)`; splits backlog by team (EC2/ECR/Lambda); surfaces "patch one, fix many" actions

All three steps produce structured JSON, can be chained by Phantom autonomously, and the final prioritized list can be written to file via `write_file`.

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

## Security Hardening (Applied April 2026)

A static audit of all 773 `scripts/agent.py` files and 796 `SKILL.md` files was run and saved to `skill_security_audit.json` (1,496 findings: 51 CRITICAL, 220 HIGH, 25 MEDIUM, 1,200 LOW — many LOWs are false positives from detection-rule content).

**Fixes applied to 36 scripts:**

| Issue | Pattern fixed | Scripts affected |
|---|---|---|
| Hardcoded credentials | `password = "..."` → `os.environ.get("...")` | `securing-container-registry-with-harbor`, `exploiting-active-directory-with-bloodhound`, `performing-wireless-security-assessment-with-kismet` |
| `requests` TLS bypass | `verify=False` → `verify=VERIFY_TLS` | 32 exploitation/pentest/recon scripts |
| `pickle.load` | Added `# nosec B301` + trusted-source comment | `detecting-command-and-control-over-dns` |

**VERIFY_TLS pattern** (applied to all affected scripts):
```python
VERIFY_TLS = os.environ.get("SKIP_TLS_VERIFY", "").lower() not in ("1", "true", "yes")
# Usage: requests.get(url, verify=VERIFY_TLS)
```
Set `SKIP_TLS_VERIFY=1` only when testing against self-signed certs in lab environments.

**Credential env vars per skill:**
- `HARBOR_PASSWORD` — `securing-container-registry-with-harbor`
- `NEO4J_PASSWORD` — `exploiting-active-directory-with-bloodhound` (falls back to `bloodhound`)
- `KISMET_USERNAME` / `KISMET_PASSWORD` — `performing-wireless-security-assessment-with-kismet`

## DVMCP Testing Reference

Scripts for testing skills against [DVMCP (Damn Vulnerable MCP Server)](https://github.com/halencarjunior/dvmcp) challenges live in `examples/dvmcp/`:
- `detect_challenge2.py` — implements `mcp-tool-poisoning-detection-and-defense` workflow against Challenge 2 (port 9002)
- `mcp_command_injection_audit.py` — implements `mcp-command-injection-prevention` workflow: static regex scan + 8 live injection probes

**Start DVMCP:** `docker compose up -d` from the DVMCP repo root (challenges on ports 9001–9010).

**Challenge 2 vulnerabilities confirmed:**
- Command injection via `\n` newline bypass: `split()[0]` treats newline as whitespace, so `"ls\nid"` passes the allowlist check while injecting `id` when `shell=True`
- Path traversal via `startswith('/tmp/safe/')` without `Path.resolve()`: `/tmp/safe/../../etc/passwd` passes the check

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
