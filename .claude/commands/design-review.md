# /design-review

Run a security design review for a new system or feature before implementation begins.

**Usage:** `/design-review $ARGUMENTS`

**Example:** `/design-review system="Customer AI Chatbot" type=agentic team=platform`

---

You are a security architect conducting a Phase 1 design review for $ARGUMENTS.

## Step 1 — Understand the system

Ask the user for the following if not already provided:
- **System name** — what are we building?
- **Architecture type** — choose one: `web-app`, `api`, `agentic` (Claude/LLM-based), `rag` (retrieval-augmented), `ml-pipeline` (training/inference), `multi-agent`, `data-pipeline`, `microservice`
- **Data classification** — does it handle PII, financial data, health data, or IP?
- **External exposure** — is it customer-facing, internal only, or B2B?
- **Team** — which team owns this? (determines which Ivanti queue findings go to)

## Step 2 — Select the right threat model

Based on architecture type, use the phantom-skills MCP tools to load the correct skill:

| Architecture type | Primary skill | Secondary skill |
|---|---|---|
| `agentic` / `multi-agent` | `performing-maestro-threat-modeling` | `threat-modeling-for-ai-ml-systems` |
| `rag` | `performing-maestro-threat-modeling` | `rag-pipeline-security-and-data-provenance` |
| `ml-pipeline` | `threat-modeling-for-ai-ml-systems` | `ai-data-operations-availability-and-integrity` |
| `web-app` / `api` | `performing-stride-threat-modeling` | `performing-asvs-compliance-assessment` |
| `microservice` | `performing-stride-threat-modeling` | `performing-pasta-threat-modeling` |
| `data-pipeline` | `performing-pasta-threat-modeling` | `ai-data-operations-availability-and-integrity` |

Use `load_skill` to read the workflow for the selected skill, then guide the user through the threat model interactively.

## Step 3 — Run the threat model

Execute `run_skill_agent` with the appropriate script and arguments. For MAESTRO:
```
skill_name: performing-maestro-threat-modeling
args: ["init", "--system", "<name>", "--arch-type", "<type>"]
```

Save the output to `security/threat-model-<system-name>.json` in the project repo.

## Step 4 — Compliance check (if data classification is PII, financial, or health)

If the system handles sensitive data, also run:
```
skill_name: ai-governance-and-regulatory-compliance  
args: ["assess", "--system", "<name>", "--risk-tier", "high", "--framework", "all"]
```

Save to `security/compliance-<system-name>.json`.

## Step 5 — Produce the design review summary

Output a structured summary in this format:

```
## Security Design Review — <System Name>
**Date:** <today>
**Team:** <team>
**Reviewer:** Claude Code + Phantom MCP (phantom-mcp.tstsecurity.[org].engineering)

### Threat Model
- Framework used: <MAESTRO / STRIDE / PASTA>
- Architecture type: <type>
- Threats identified: <count>
- CRITICAL: <count> | HIGH: <count> | MEDIUM: <count>

### Top 3 Design Risks
1. <risk> — <recommended control>
2. <risk> — <recommended control>
3. <risk> — <recommended control>

### Required Controls Before Build
- [ ] <control 1>
- [ ] <control 2>
- [ ] <control 3>

### Compliance
- Frameworks assessed: <list>
- Gaps requiring remediation: <count>

### Artifacts
- Threat model: security/threat-model-<system>.json
- Compliance report: security/compliance-<system>.json (if applicable)

### Sign-off
- [ ] Security team review (tag @security-team in PR)
- [ ] Design doc updated with threat model link
- [ ] CRITICAL/HIGH risks triaged in Ivanti
```

Write this summary to `security/design-review-<system-name>.md` and tell the user to commit it alongside their design doc.

## Escalation

If the threat model exits with code 1 (CRITICAL findings) or identifies any:
- Active exploitation (KEV CVEs in dependencies)
- Data exfiltration paths to external systems  
- Privilege escalation via AI tool misuse

→ Immediately flag to the security team before proceeding to build.
