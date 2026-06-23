# Executable Script Catalog

Skills with a `scripts/agent.py` are directly runnable by Phantom via the `run_skill_agent` tool, or standalone from the shell. All scripts output structured JSON, accept `--output <file>`, and exit with code `1` on HIGH/CRITICAL findings (CI-gate compatible). Unless noted, no API key is required.

> This catalog is reference material. Run `find skills -name agent.py | wc -l` for the current count (~820 scripts).

## AI red-teaming
- `llm-system-prompt-leakage-prevention` — `agent.py --model <model> --system-prompt "..."` — 11 extraction probes + canary token detection
- `llm-excessive-agency-prevention` — `agent.py --manifest tools.json --function "..." --required tool1,tool2` — audits tool manifest for excess permissions
- `llm-output-validation-and-sanitization` — `agent.py --model <model> --system-prompt "..."` — probes for XSS/SQLi/SSRF/cmd injection in LLM outputs
- `llm-sensitive-information-disclosure-prevention` — `agent.py --model <model> --system-prompt "..."` or `--scan-file log.jsonl` — detects PII/credential leakage
- `llm-data-and-model-poisoning-defense` — `agent.py dataset-scan --dataset data.jsonl` or `agent.py backdoor-probe --model <model>` — scans training data and probes for backdoors
- `agent-goal-hijacking-detection` — `agent.py --goal "..." --log agent.jsonl` — detects goal drift and injection patterns
- `rogue-agent-detection-and-containment` — `agent.py --log telemetry.jsonl` — detects reward hacking, self-replication, behavioural drift, collusion
- `detecting-ai-model-prompt-injection-attacks` — DeBERTa-based classifier

## Application security
- `performing-asvs-compliance-assessment` — `agent.py init --app "Name" --url "https://..." --level 2` → `agent.py report --assessment file.json` — ASVS v4.0.3 worksheet + conformance report

## Threat modeling
- `performing-stride-threat-modeling` — `init --system "Name"` → `analyze --components file.json` → `report --threats file.json` — STRIDE per component type
- `performing-pasta-threat-modeling` — `scaffold --system "Name"` → `analyze --worksheet file.json` → `report --risks file.json` — 7-stage risk-centric PASTA with business impact scoring
- `threat-modeling-for-ai-ml-systems` — `init --system "Name" --arch-type agentic|rag|llm_app|training_pipeline|multi_agent` → `analyze` → `report` — OWASP LLM/Agentic Top 10 + MITRE ATLAS taxonomy
- `performing-maestro-threat-modeling` — `init --system "Name" --arch-type single|multi|hierarchical|distributed|conversational|task_oriented|human_in_loop|self_learning` → `analyze --assessment file.json` → `report --assessment file.json` — MAESTRO 7-layer framework (54 threats per typical multi-agent system, 5 cross-layer); highlights architecture-pattern-specific risks

## AI security infrastructure auditing (MAESTRO gap coverage)
- `rag-pipeline-security-and-data-provenance` — `audit --config rag_config.json` / `scan-documents --dir ./docs` — 12 RAG controls + 10 prompt-injection patterns
- `ai-model-extraction-and-reprogramming-defense` — `audit --config model_api_config.json` — 9 extraction + 5 reprogramming controls; separate risk scores
- `ai-evaluation-security-and-observability-hardening` — `audit-eval --config eval_config.json` / `audit-telemetry --config telemetry_config.json` — 10 eval + 11 telemetry controls
- `ai-governance-and-regulatory-compliance` — `assess --system "Name" --risk-tier high|limited|minimal --framework eu-ai-act|nist-ai-rmf|iso-42001|all` → `score --checklist compliance_report.json` — EU AI Act Articles 9-16/26/49/72, NIST AI RMF GOVERN/MAP/MEASURE/MANAGE, ISO 42001 Clauses 4-10
- `ai-workload-infrastructure-hardening` — `scan --config infra_config.json` / `scan-k8s --manifest deployment.json` — 16 infra controls; parses raw `kubectl get deployment -o json`
- `ai-agent-framework-security` — `audit --config framework_config.json` — 15 MAESTRO L3 controls (dependency pinning/CVE scanning, tool allowlisting, schema validation, unsafe-pattern blocking, sandboxing, etc.)
- `ai-agent-ecosystem-security` — `audit --config ecosystem_config.json` — 18 MAESTRO L7 controls (registry signing, capability attestation, agent identity/vetting, Sybil-resistant reputation, etc.)
- `ai-security-tool-adversarial-defense` — `audit --config security_tool_config.json` — 20 MAESTRO L6 threat-side controls (training-data provenance, poisoning/evasion detection, kill switch, etc.)
- `adversarial-robustness-and-evasion-defense` — `probe --config model_robustness_config.json` (L1-T01/T07, 10 controls) / `backdoor-scan --config backdoor_config.json` (L1-T03, 6 controls)
- `ai-data-operations-availability-and-integrity` — `audit --config data_ops_config.json` — 22 MAESTRO L2 availability/integrity controls (L2-T03/T04)
- `ai-explainability-and-formal-verification` — `audit-xai --config xai_config.json` (11 controls) / `verify-goals --manifest agent_goals.json` (10 controls) / `reputation-audit --config reputation_config.json` (8 controls)

## SOC / SIEM
- `securonix-siem-operations` — `query --use-case brute-force|lateral-movement|data-exfiltration|insider-threat|cloud-abuse|ransomware` / `convert --spl "..."` / `triage --alert-type <type>` — SPOTTER query generation, SPL→SPOTTER conversion, triage checklists

## Vulnerability management (AWS — full autonomous pipeline)
Phantom can run this end-to-end given AWS credentials:

1. **Collect** — `aws-inspector-findings-reporter`: `agent.py report --start-date 2026-03-01 --end-date 2026-03-31 --regions us-east-1,us-west-2 --kev` — pulls Inspector v2 findings, enriches with CISA KEV + EPSS, outputs `inspector_report.json`; exits 1 on CRITICAL (requires `pip install boto3`). **Team-based multi-account mode:** add `--team-config teams.json` + `--role-name InspectorReadOnly` to assume a cross-account IAM role per account; report gains a `by_team` section. Add `--split-by-team` to also write `inspector_report_<team>.json` per team. Omit `--role-name` on an Inspector delegated-admin account.
2. **Enrich** — use `cve-intel` MCP tools (`search_cve`, `get_risk_score`, `check_kev_status`) to cross-reference each CVE-ID for live EPSS/PoC/ATT&CK context.
3. **Prioritize** — `aws-vulnerability-remediation-prioritization`: `agent.py prioritize --findings inspector_report.json --kev` — composite score `severity_weight × (1 + EPSS) × KEV_multiplier(3×) × log(affected_resources + 1)`; splits backlog by team (EC2/ECR/Lambda); surfaces "patch one, fix many" actions.

## API security
`conducting-api-security-testing`, `testing-api-authentication-weaknesses`, `testing-api-for-broken-object-level-authorization`, `performing-api-rate-limiting-bypass`, `exploiting-api-injection-vulnerabilities`, `detecting-api-enumeration-attacks`, `testing-api-security-with-owasp-top-10`
