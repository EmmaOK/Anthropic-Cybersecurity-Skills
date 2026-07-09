# CLAUDE.md — `phantom/`

Subsystem guidance for the **Phantom agent**. This file loads when you work in `phantom/`.
Root `../CLAUDE.md` still applies (skill schema, security conventions); decision *rationale*
lives in `../docs/DECISIONS.md`. Phantom's standing direction: evolve into an autonomous,
**task-assignable** security agent that draws on the 800+ skill library (ADR-0012).

## ⚠️ Runtime: use the dedicated venv, NOT the system `python3`

The system Homebrew Python is **broken** (`security-tools` venv → `python@3.14`/`@3.12`):
`pyexpat` fails to load (links an old `/usr/lib/libexpat.1.dylib` missing
`_XML_SetAllocTrackerActivationThreshold`) and `platform.mac_ver()` returns empty. This kills
`pip` *and* makes `uv` refuse those interpreters. Apple's `/usr/bin/python3` works but is 3.9.6
(too old; the Agent SDK needs ≥3.10).

So the Phantom Agent SDK spike runs from a **uv-managed CPython 3.12 venv** that bundles its own
expat (immune to the system breakage):

```bash
# one-time setup (already done 2026-06-20):
uv python install 3.12
uv venv phantom/.venv --python 3.12
uv pip install --python phantom/.venv/bin/python claude-agent-sdk anthropic   # claude-agent-sdk 0.2.105

# always run the SDK spike with the venv interpreter:
phantom/.venv/bin/python phantom/phantom_sdk.py --check
```

`phantom/.venv/` is gitignored. Node v25.8.1 + the `claude` CLI (the SDK's runtime) are present.
The broken pyexpat does **not** affect the SDK at runtime — it uses JSON, not XML. The broader
fix (repair Homebrew Python via CLT/`brew reinstall`) is out of scope so far.

A separate, known issue: `run_skill_agent` can be blocked by macOS TCC — grant the launching
Python "Full Disk Access" in System Settings if skill scripts won't execute.

## Two generations of the agent

| | `main.py` (current) | `phantom_sdk.py` (spike) |
|---|---|---|
| Loop | hand-rolled `run_turn()` while-loop | SDK `query()` managed loop + `max_turns` |
| Tool routing | `dispatch_tool()` router | `@tool` fns + `create_sdk_mcp_server`, SDK routes |
| Multi-agent | `orchestrator.py` threads | `AgentDefinition` subagents + `Task` tool |
| Approvals | `approvals.py` + prompt confirm | `can_use_tool` permission gate (`make_gate`) |
| Sessions | JSON save/load | SDK resume / continue |
| Status | works; interactive, walk-through | code-complete, gate verified; needs API key + executor to run |

The spike keeps Phantom's real value **unchanged** (`skill_loader`, `executor`, `kali*`); the SDK
replaces the plumbing. Prefer extending the SDK path over the hand-rolled loop for new autonomous
work.

### `phantom_sdk.py` safety gate (`make_gate`)
In-code boundary that runs **before** any tool executes. Denies non-Phantom tools, command
substitution (`$(...)`/backticks/`${...}`), and any binary not on the allowlist — across **every**
pipe/chain segment, not just the first. Enforces scope on IPs, CIDRs (whole range must be a subnet
of scope), and hostnames. Exploit-class tools need `--allow-exploit`. Residual gaps are documented
in the module docstring; **IP/CIDR scoping is the authoritative control** for unattended runs.

## Module map

| Module | Purpose |
|---|---|
| `main.py` | Interactive REPL agent; 7 persona modes; hand-rolled tool loop |
| `phantom_sdk.py` | Autonomous agent on the Claude Agent SDK (spike) |
| `skill_loader.py` | Skill discovery/loading; reads `index.json` |
| `executor.py` | Subprocess runner for a skill's `scripts/agent.py` (60s timeout) |
| `tools.py` | Claude tool definitions for `main.py` |
| `orchestrator.py` | Multi-agent coordinator (threads) |
| `kali.py` | SSH executor for the Kali VM (`192.168.64.2`) |
| `kali_docker.py` | Ephemeral Kali Docker executor |
| `approvals.py` | Approval store + Google Chat notifications (IR workflow) |
| `notifier.py` | Post-investigation email notifications |
| `investigate.py` | Autonomous SOC alert investigator |
| `phishing.py` | Autonomous phishing-email investigator (single message → verdict + IOCs) |
| `gworkspace_hunt.py` | Google Workspace campaign victim-hunt: given campaign IOCs, searches every mailbox (Gmail API + domain-wide delegation) for other recipients, flags read/reply + attacker forwarding rules, and does approval-gated purge (`--confirm-remediate`). Report-only by default. Wires into `phishing.py` via `PHANTOM_AUTO_VICTIM_HUNT` |
| `phishingbox_intake.py` | Reported-phish intake (PhishingBox webhook/API poll, or abuse-mailbox via Google delegation) + `run_pipeline()` orchestrator: investigate → correlate → case-sync → victim-hunt. Only PHISHING escalates; every stage is guarded |
| `phishing_campaigns.py` | SQLite campaign store: clusters reports into campaigns (shared URL-domain/hash, or sender+subject), dedupes by Message-ID. `reports/phishing/campaigns.db` (override `PHISH_CAMPAIGN_DB`) |
| `guardduty_intake.py` | **AWS GuardDuty finding pipeline** (cloud analog of the phishing pipeline). Normalizes an EventBridge finding → autonomous investigation on `task_agent` (enrich actor IP via the phishing fan-out, CloudTrail lookback via aws CLI) → `case_sync` → **approval-gated** containment via `approvals.create_approval` (never auto-executed). Only COMPROMISED/SUSPICIOUS escalates; dedupes by finding Id. `server.py` `/api/webhook/guardduty` (perm `guardduty:report`) |
| `case_sync.py` | Push a confirmed campaign to case management — TheHive case + observables, MISP event + attributes, optional Jira ticket. All env-keyed, optional, fail-safe |
| `http_util.py` | Shared dependency-free JSON HTTP helper (`http_json`, `ok`) used by the pipeline modules; honors `SKIP_TLS_VERIFY` |
| `store.py` | **Unified state storage** (makes Phantom stateless per-container). SQLAlchemy DB — **SQLite file by default, Postgres via `PHANTOM_DB_URL`** (same code) — holds campaigns, approvals, audit. Blob store for reports — **local FS by default, S3 via `PHANTOM_REPORTS_BUCKET`**. `session()`, `save_blob`/`read_blob`, `write_audit`, `db_kind`/`blob_kind`. `phishing_campaigns.py`, `approvals.py`, `auth.audit`, and all report writers go through it. SQLAlchemy required; `psycopg`/`boto3` optional |
| `jobs.py` | **Job queue + result store** (API/worker split). `enqueue`/`get_job`/`list_jobs`. Two backends: **local** (in-process worker threads, zero deps, default) and **redis** (separate worker processes). Selected by `PHANTOM_QUEUE_BACKEND`/`REDIS_URL`; falls back to local if Redis is unreachable |
| `worker.py` | **Execution-plane entrypoint.** `execute_job(job)` dispatches by kind (task \| phishing_pipeline \| guardduty \| echo). `run_worker()` is the Redis-mode blocking loop (`python phantom/worker.py`); no-op in local mode. `server.py` `/api/tasks*` and `/api/webhook/guardduty` enqueue instead of running in-process; `/api/queue/health` shows the backend. Deploy: `deploy/Dockerfile` + `deploy/docker-compose.yml` (api + worker + redis) |
| `task_agent.py` | Reusable autonomous-task harness + **task-type registry**. `run_agent_loop()` factors out the Claude tool-loop; every task type gets skill-library tools free. 20 registered types (2 bespoke, 18 skill-guided). `run_task(type, objective)` routes to bespoke runner or the generic skill-guided agent. `python task_agent.py` lists them |
| `detection_engineering.py` | **Bespoke task type** (purple-team loop): technique/gap → `detecting-*` skill → ATT&CK lookup → coverage assessment → validated Sigma rule (`validate_sigma`) → Atomic Red Team test. `build_detection(objective, technique=)` |
| `threat_intel.py` | **Bespoke task type** (CTI lifecycle): enrich indicators (reuses phishing fan-out) → ATT&CK map → attribution/confidence → MISP dissemination (reuses `case_sync.create_misp_event`). `produce_intel(objective, indicators=)` |
| `securonix.py` | **Securonix SIEM/UEBA connector + 4 task types**: `securonix-audit` (read-only deployment audit), `securonix-hunt` (author SPOTTER queries + detection policies — policy creation gated), `securonix-triage` (triage incidents → TP/FP verdict → apply workflow action, gated), `securonix-soar` (design SOAR playbooks). SNYPR REST client (token or user/pass); writes approval-gated unless `SECURONIX_ALLOW_WRITE=1`. Env: `SECURONIX_URL`/`SECURONIX_TOKEN`. Reuses phishing fan-out for triage enrichment |
| `defectdojo.py` | **DefectDojo connector + 4 vuln-mgmt task types**: `defectdojo-triage` (read findings → FP/duplicate/risk-accept → archive FPs (gated) + open Jira tickets), `defectdojo-sla` (SLA compliance monitoring + escalation), `defectdojo-prioritize` (exploit-aware ranking via CISA KEV + FIRST EPSS), `defectdojo-report` (posture/SLA/remediation reports). Also `ensure_product`/`ensure_engagement` (used by devsecops). API v2 client (`Authorization: Token`); finding state-changes gated unless `DEFECTDOJO_ALLOW_WRITE=1`; Jira via `case_sync.create_jira_issue`. Env: `DEFECTDOJO_URL`/`DEFECTDOJO_API_KEY` |
| `devsecops.py` | **SonarQube + Dependency-Track pipeline onboarding** → `devsecops-onboard` task type. Creates Sonar project + CI token, creates DT project (+UUID), ensures the matching DefectDojo product+engagement, generates the `bitbucket-pipelines.yml` (Sonar scan + CycloneDX→DT + DefectDojo import-scan of both into the **exact product**), and lists the Bitbucket secured variables. Writes gated by `DEVSECOPS_ALLOW_WRITE`; with writes off it still emits the full YAML + secrets + manual runbook. Env: `SONARQUBE_URL`/`SONARQUBE_TOKEN`, `DEPENDENCYTRACK_URL`/`DEPENDENCYTRACK_API_KEY` |
| `auth.py` | **Control-plane auth + RBAC.** Bearer-token identities (sha256-stored) → roles → permitted **task types** (`can_submit`) **and** non-task **permissions** (`can`/`require`: chat, phishing:report, phishing:read, approvals:read/decide). `can_read_all` + `admin`; secure-by-default (unconfigured = 503 unless `PHANTOM_AUTH_ALLOW_ANONYMOUS`); append-only audit log. Config via `PHANTOM_AUTH_FILE` / `PHANTOM_ADMIN_TOKEN`. CLI: `gen-token`, `hash`, `init-file`, `whoami`. In `server.py`, `get_principal` gates **all** `/api/tasks*`, `/api/chat`, `/api/sessions*`, `/api/investigate/*`, `/api/approvals*`, and both phishing webhooks; tokens accepted via `Authorization`, `X-Phantom-Token`, cookie, or `?token=` |
| `phantom_ci.py` | Headless CD pentest runner for staging gates |
| `garak_runner.py` | garak LLM vulnerability scanner integration |
| `server.py` | Phantom web server |
| `sessions/` | Persisted conversation history (JSON) |

## Conventions when editing here
- Model id is `claude-opus-4-8` for Phantom's own reasoning (ADR-0011). `claude-sonnet-4-6`
  appears only as an example garak *target*.
- No hard-coded credentials or API keys — read from `os.environ` (root `../CLAUDE.md`).
- Don't disable TLS unconditionally; honor `SKIP_TLS_VERIFY`.
- `run_skill_agent` runs a script only on explicit user request; `write_file` shows content first.
- A skill script exiting code 1 signals a HIGH/CRITICAL finding — preserve that contract.
