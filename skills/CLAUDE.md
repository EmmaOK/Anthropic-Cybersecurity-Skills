# CLAUDE.md — `skills/`

Authoring guidance for the skill library. Loads when you work in `skills/`. Root `../CLAUDE.md`
and `../.claude/conventions.md` still apply; decision rationale is in `../docs/DECISIONS.md`.

## Skill Directory Structure
Each skill lives in `skills/<skill-name>/`:
```
skills/<skill-name>/
├── SKILL.md          # Primary skill definition (required)
├── LICENSE           # Apache-2.0 copy (required)
├── references/
│   └── api-reference.md   # Severity scales, function signatures (optional)
└── scripts/
    └── agent.py           # Executable helper script (optional)
```

## SKILL.md Frontmatter Schema
```yaml
---
name: kebab-case-unique-name          # required, max 64 chars, unique across all skills
description: >-
  Multi-line description...
domain: cybersecurity                  # always this value
subdomain: <one of 26 subdomains>     # see list below (or ai-security extension)
tags:
  - keyword1
  - keyword2
version: '1.0'
author: github-username
license: Apache-2.0

# Optional framework mappings:
nist_csf: [RS.AN-01, DE.AE-02]        # NIST CSF 2.0 function/category codes
atlas_techniques: [AML.T0047]         # MITRE ATLAS technique IDs
d3fend_techniques: [Executable Denylisting]
nist_ai_rmf: [MEASURE-2.6]
---
```
MITRE ATT&CK technique IDs (e.g., `T1059.001`) are stored in the `tags` array, not a dedicated
field (ADR-0004).

## SKILL.md Body Sections (in order)
1. **When to Use** — agent trigger conditions
2. **Prerequisites** — tools, access, environment
3. **Workflow** / **Steps** — numbered steps with real commands/code
4. **Key Concepts** — markdown table of terms
5. **Tools & Systems** — reference table
6. **Common Scenarios** — real-world use cases
7. **Output Format** — example JSON/structured output

## 26 Valid Subdomains
`web-application-security`, `network-security`, `penetration-testing`, `red-teaming`,
`digital-forensics`, `malware-analysis`, `threat-intelligence`, `cloud-security`,
`container-security`, `identity-access-management`, `cryptography`, `vulnerability-management`,
`compliance-governance`, `zero-trust-architecture`, `ot-ics-security`, `devsecops`,
`soc-operations`, `incident-response`, `phishing-defense`, `ransomware-defense`, `api-security`,
`mobile-security`, `endpoint-security`, `threat-hunting`, `application-security`, `data-security`

AI/agentic skills use `subdomain: ai-security` — an accepted extension that must **not** be
added to the official 26 above (ADR-0002).

## AI Security Coverage (~50 skills)
Full coverage of four AI/agentic security frameworks, all under `subdomain: ai-security`:
- **OWASP LLM Top 10 2025** (LLM01–LLM10) — `llm-*` prefix; LLM01 covered by
  `detecting-ai-model-prompt-injection-attacks`
- **OWASP MCP Top 10 v0.1** (MCP01–MCP10) — `mcp-*` prefix
- **OWASP Top 10 for Agentic Applications 2026** (ASI01–ASI10) — `agent-*`, `agentic-*`,
  `rogue-*`, `human-agent-*`, `securing-inter-*` prefixes
- **MAESTRO Framework** (7 layers + cross-layer) — complete layer-by-layer coverage:
  - Threat modeling: `performing-maestro-threat-modeling`
  - L1 Foundation Models: `ai-model-extraction-and-reprogramming-defense` (T02/T06),
    `adversarial-robustness-and-evasion-defense` (T01/T03/T07)
  - L2 Data Operations: `rag-pipeline-security-and-data-provenance`,
    `ai-data-operations-availability-and-integrity` (T03/T04)
  - L3 Agent Frameworks: `ai-agent-framework-security`
  - L4 Deployment & Infrastructure: `ai-workload-infrastructure-hardening`
  - L5 Evaluation & Observability: `ai-evaluation-security-and-observability-hardening`
  - L6 Security & Compliance: `ai-governance-and-regulatory-compliance` (compliance),
    `ai-security-tool-adversarial-defense` (threat)
  - L7 Agent Ecosystem: `ai-agent-ecosystem-security`
  - Cross-Layer Mitigations: `ai-explainability-and-formal-verification` (XAI, formal
    verification, reputation systems)

### AI Security Skill Naming Conventions (ADR-0003)
| Framework | Prefix pattern | Example |
|---|---|---|
| OWASP LLM Top 10 | `llm-<descriptor>` | `llm-system-prompt-leakage-prevention` |
| OWASP MCP Top 10 | `mcp-<descriptor>` | `mcp-tool-poisoning-detection-and-defense` |
| OWASP Agentic Top 10 | `agent-`, `agentic-`, `rogue-`, `human-agent-`, `securing-inter-` | `agent-goal-hijacking-detection` |
| MAESTRO Framework | `performing-maestro-`, `rag-pipeline-`, `ai-model-`, `ai-evaluation-`, `ai-governance-`, `ai-workload-` | `performing-maestro-threat-modeling` |

## Adding a New Skill
1. Create `skills/<kebab-case-name>/SKILL.md` with valid frontmatter (schema above).
2. Copy `LICENSE` from any existing skill directory into the new directory.
3. Follow the required body section order.
4. Optionally add `references/api-reference.md` and `scripts/agent.py`.
5. Push/open a PR — CI validates automatically; `index.json` is regenerated on merge to `main`.

### Adding an Executable Script (`scripts/agent.py`)
Scripts are optional but make a skill directly runnable by Phantom via `run_skill_agent`.
Conventions (and see `../.claude/conventions.md` for the security rules):
- Use `argparse` for all CLI arguments; include `--output <file>` defaulting to a JSON report filename
- Print a `json.dumps(report, indent=2)` summary to stdout so Phantom can read it
- Exit `sys.exit(1)` when overall risk is HIGH or CRITICAL (CI-gate compatible)
- Avoid hard dependencies beyond stdlib + `anthropic`; guard optional imports with try/except
- Do not hard-code API keys; read from `os.environ.get("ANTHROPIC_API_KEY")`
- Keep scripts self-contained — no imports from other skill directories
- Never hard-code credentials or disable TLS

## Validate Skills (mirrors CI)
Validation logic lives inline in `../.github/workflows/validate-skills.yml`. To run locally,
extract and run the embedded Python. It checks:
- Required frontmatter fields: `name`, `description`, `domain`, `subdomain`, `tags`, `version`,
  `author`, `license`
- `name` must be kebab-case, max 64 chars, unique across all skills
- `domain` must be `cybersecurity`
