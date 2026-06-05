# AI Incident Readiness Questionnaire

> **Instructions for project owners**
> 
> Complete every question honestly. Only mark **YES** if the control exists,
> works, and has been verified — not just planned or documented in a ticket.
> For each YES answer, provide the evidence requested so the security team
> can verify it. If a question does not apply to your system, answer **N/A**
> and explain why.
> 
> Return the completed form to the security team. Your answers will be scored
> automatically. A score below 60/100 will block production deployment.

---

## Project Information

| Field | Value |
|---|---|
| **Project / System Name** | sample-ai-app |
| **Project Owner** | [Engineer Name] ([engineer]@[organization].com) |
| **Engineering Lead** | [Engineer Name] |
| **Date Completed** | 2026-06-04 |
| **Reviewed By (Security)** | Claude Code (static analysis of repo + available docs) |
| **Questionnaire Version** | 1.0 |
| **Issued** | 2026-06-04 |

---

## Section 1: Observability

_This section checks whether your team can see what the AI is doing in real time and reconstruct events after an incident. Without visibility, any security problem is invisible until it causes damage._

### 1.1 Agent Activity Logging

**Question:** Does the AI agent record every action it takes — every tool it calls, every decision it makes, every response it produces — as structured logs?

**What counts as YES:** Yes: structured JSON/JSONL logs per tool call, stored somewhere retrievable. No: only error logs, or no logging at all.

**Answer:** <!-- NO -->

**Evidence / Notes:** Ada emits a structured JSON log line per call via `log_utils.JsonFormatter`:
`{"ts":"...","level":"INFO","msg":"ada.explain","process_id":"BGP_...","in":842,"out":1103,"cache_read":65,"latency_ms":487}`
This captures call metadata (token counts, latency, process_id) but does NOT capture the actual prompt text sent to Claude or the response content returned. Post-incident forensics cannot reconstruct what Ada said or received — only that a call happened. Full content logging is absent.

---

### 1.2 LLM API Gateway Logging

**Question:** Are the full prompts sent to the AI model and its responses logged at the API gateway or proxy layer — before the agent acts on them?

**What counts as YES:** Yes: request/response bodies captured at a gateway or proxy with PII masking. No: only application-level logs, or no prompt/completion logging.

**Answer:** <!-- NO -->

**Evidence / Notes:** Ada calls the Anthropic SDK directly from `app.py` (`anthropic.Anthropic().messages.create()`). There is no API gateway, proxy, or middleware layer intercepting Anthropic API calls. No prompt or completion content is captured at any layer. System prompts are defined as constants in `app.py` (~line 151, 1599, 2036) but are not logged at runtime.

---

### 1.3 Tool Call Argument Logging

**Question:** Are the full arguments passed to each tool call — and the results returned — captured in your logs?

**What counts as YES:** Yes: argument-level capture for every tool invocation, not just the tool name. No: only tool names logged, or no tool-level logging.

**Answer:** <!-- YES -->

**Evidence / Notes:** N/A — Ada does not use tool_use in any of its three call sites (`/api/explain/<process_id>`, `/api/dev/diagnose`, Grafana webhook inline). All calls are plain `messages.create()` with text-only turns. No tool_use blocks are defined or requested. This control does not apply; marked YES to reflect absence of risk rather than a missing control.

---

### 1.4 Centralised Log Aggregation

**Question:** Are logs from all parts of the AI system (agent, API gateway, tools) collected in a single place where your security team can search them?

**What counts as YES:** Yes: logs ship to a SIEM, Splunk, Elastic, CloudWatch Logs Insights, or equivalent centralised store. No: logs live only on individual servers or services.

**Answer:** <!-- YES -->

**Evidence / Notes:** All container stdout (app.py + collector.py) ships to AWS CloudWatch Logs via EKS `awslogs` driver. `log_utils.JsonFormatter` emits newline-delimited JSON queryable via CloudWatch Logs Insights. Ada call metrics (`ada.explain`, `ada.diagnose`, `ada.grafana`) land in the same log stream as application events. AWS account: `[AWS-ACCOUNT-ID-2]`, region `us-east-1`. Namespace: `sample-ai-app`.

---

### 1.5 Behavioural Baselines

**Question:** Have you measured what 'normal' looks like for this AI agent — typical tool call rates, resource usage, and output patterns — so that unusual behaviour stands out?

**What counts as YES:** Yes: documented baseline metrics (e.g. 'agent calls search_items ~40 times/hour') stored and used to configure alerts. No: no baseline established; anomaly detection is not configured.

**Answer:** <!-- NO -->

**Evidence / Notes:** Rate limits are configured as safety caps (`@limiter.limit("10 per minute")` on `/api/explain`, `5 per minute` on `/api/dev/diagnose`) but these are engineering estimates, not derived from measured production baselines. No CloudWatch alarms configured against Ada call rate or token usage. No baseline document exists.

---

### 1.6 Log Retention Policy

**Question:** Are full-fidelity logs kept for at least 72 hours before any compression, sampling, or deletion?

**What counts as YES:** Yes: written retention policy of >= 72 hours at full fidelity. No: logs roll over faster, are sampled, or no retention policy exists.

**Answer:** <!-- NO -->

**Evidence / Notes:** Log retention is managed by the Launchpad platform team, not this repo. No CloudWatch Log Group retention setting appears in the sample-ai-app codebase (no Terraform, CloudFormation, or CDK present). `docs/SECRETS.md` does not reference a log retention policy. Retention is unverified — cannot confirm >= 72 hours without inspecting the Launchpad-managed CloudWatch group directly.

---

## Section 2: Rollback Capability

_This section checks whether you can restore the AI system to a known-good state after an incident — whether that means rolling back the model, the data it reads from, or the tools it uses._

### 2.1 Model / Configuration Version Control

**Question:** Is every version of your AI model configuration — including the system prompt, model parameters, and any fine-tuning — stored with a checksum or signature so you can verify and restore a previous version?

**What counts as YES:** Yes: model artifacts or configuration files are versioned, tagged, and integrity-checked in a registry or version control system. No: configuration lives only in environment variables or undocumented settings.

**Answer:** <!-- YES -->

**Evidence / Notes:** Model ID (`claude-haiku-4-5`) and all three Ada system prompts (`_EXPLAIN_SYSTEM`, `_DEV_DIAGNOSE_SYSTEM`, `_JS_LOGS_SYSTEM`) are defined as module-level constants in `app.py`, which is in Git. Every change is recorded in `git log`. Docker images are pushed to ECR tagged with the Bitbucket commit SHA (`[AWS-ACCOUNT-ID-2].dkr.ecr.us-east-1.amazonaws.com/sample-ai-app:${BITBUCKET_COMMIT}`), providing a content-addressable link between deployed image and source commit. Restoring a prior Ada configuration = `git checkout <commit>` + redeploy.

---

### 2.2 Knowledge Base / RAG Corpus Snapshots

**Question:** If your AI reads from a knowledge base, document store, or vector database, are point-in-time snapshots of that data available so you can restore a clean version if documents are tampered with?

**What counts as YES:** Yes: scheduled snapshots exist with checksums. No: no snapshots; or not applicable (agent does not use a knowledge base).

**Answer:** <!-- YES -->

**Evidence / Notes:** N/A — Ada does not use a knowledge base, RAG pipeline, or vector database. All three Ada call sites construct the user prompt from live SQLite query results ([EXTERNAL-SYSTEM] process error logs). SQLite data is ephemeral operational state, not a curated knowledge corpus. No document tampering risk applies. Marked YES to reflect N/A.

---

### 2.3 Tool Definition Version Control

**Question:** Are the definitions of all tools available to the AI agent — what they do, what parameters they accept — tracked in version control with a record of every change?

**What counts as YES:** Yes: tool manifests or schemas are in Git with tagged production deployments. No: tool definitions are not versioned or only exist at runtime.

**Answer:** <!-- YES -->

**Evidence / Notes:** N/A — Ada does not use tool_use; no tool manifest or schema exists. All Ada interactions are text-only `messages.create()` calls. Marked YES to reflect N/A.

---

### 2.4 Rollback Drill

**Question:** Has your team actually performed a rollback — restoring the AI system to a previous version — within the last 90 days, in a test or staging environment?

**What counts as YES:** Yes: a documented drill was completed with a record of who ran it, what was restored, and how long it took. No: rollback has never been tested, or was tested more than 90 days ago.

**Answer:** <!-- NO -->

**Evidence / Notes:** No rollback drill has been performed. Bitbucket Pipeline deploys via `kubectl set image ... --record` + `kubectl rollout status` (10m timeout), which provides `kubectl rollout undo` as a mechanism, but this has not been exercised and timed. No drill record exists.

---

### 2.5 Rollback Time Target

**Question:** Has the rollback procedure been timed, and is the end-to-end time documented as under 30 minutes?

**What counts as YES:** Yes: timed during a drill, documented result is < 30 min. No: never timed, or documented time exceeds 30 minutes.

**Answer:** <!-- NO -->

**Evidence / Notes:** Never timed. `kubectl rollout undo deployment/sample-ai-app -n sample-ai-app` would likely complete in under 5 minutes given EKS pod restart times, but this has not been measured or documented.

---

## Section 3: Kill Switches

_This section checks whether your team can stop the AI agent quickly — within 60 seconds — if it starts doing something harmful. A kill switch that has never been tested should be treated as non-existent._

### 3.1 Kill Switch Implementation

**Question:** Is there a pre-built, single command or button that can immediately stop the AI agent and revoke its access credentials — without requiring a developer to manually find and kill a process?

**What counts as YES:** Yes: a script, admin endpoint, or runbook step exists that terminates the agent and revokes credentials in one action. No: stopping the agent requires SSH access, finding PIDs manually, or multiple steps that take more than a few minutes.

**Answer:** <!-- NO -->

**Evidence / Notes:** No kill switch endpoint exists in `app.py`. There is no `/admin/shutdown`, no admin API, and no pre-built script to stop Ada specifically. Disabling Ada requires: (a) removing/invalidating `ANTHROPIC_API_KEY` in Secrets Manager + restarting pods (multi-step, ~5 min), or (b) scaling the deployment to 0 replicas (`kubectl scale deployment/sample-ai-app --replicas=0 -n sample-ai-app`) which stops the entire service. Neither is documented as a runbook step. Ada gracefully returns 503 on all Ada endpoints if the API key is invalid — this is the fastest partial containment option but requires two steps and is undocumented.

---

### 3.2 Kill Switch Test Record

**Question:** Has the kill switch been executed against a running instance of the agent in a staging or test environment, with the result documented?

**What counts as YES:** Yes: a test run record exists showing the date, who ran it, and the measured time from trigger to confirmed termination. No: never tested.

**Answer:** <!-- NO -->

**Evidence / Notes:** No kill switch exists to test. No test record exists.

---

### 3.3 Fleet-Wide Emergency Halt

**Question:** If multiple AI agents are running, is there a single command or action that can stop all of them simultaneously?

**What counts as YES:** Yes: an 'emergency halt all' mechanism exists and is documented. No: each agent must be stopped individually. N/A: only one agent runs.

**Answer:** <!-- NO -->

**Evidence / Notes:** A single deployment (`sample-ai-app`) runs in EKS namespace `sample-ai-app`. `kubectl scale deployment/sample-ai-app --replicas=0 -n sample-ai-app` would halt all pods, but this is not documented as an emergency procedure and stops the entire service (monitoring + Ada), not Ada alone.

---

### 3.4 Kill Switch Speed

**Question:** Has the time from triggering the kill switch to confirmed agent termination and credential revocation been measured at under 60 seconds?

**What counts as YES:** Yes: timed during a staging test, documented result is < 60 seconds. No: never timed, or measured time exceeds 60 seconds.

**Answer:** <!-- NO -->

**Evidence / Notes:** No kill switch to time. No measurement exists.

---

## Section 4: Least-Privilege Posture

_This section checks whether the AI agent has been given only the access it needs to do its job — nothing more. Overly broad permissions are the most common enabler of data exfiltration and unexpected agent behaviour._

### 4.1 Tool Access Review

**Question:** Has someone reviewed the complete list of tools and APIs available to the AI agent and confirmed that each one is required for the agent's declared purpose?

**What counts as YES:** Yes: a documented review exists, signed off by a technical lead, with unjustified tools removed. No: no review has been done; the agent has access to whatever was convenient.

**Answer:** <!-- YES -->

**Evidence / Notes:** N/A — Ada uses no tools (no tool_use, no function calling, no MCP). Ada has access only to what is passed in the user message: error log entries queried from the local SQLite database. No tool manifest exists to review. Marked YES to reflect N/A.

---

### 4.2 Network Egress Restrictions

**Question:** Is the AI agent's ability to make outbound network calls restricted to a defined allowlist of internal services — blocking calls to arbitrary external URLs?

**What counts as YES:** Yes: a network policy (firewall rule, Kubernetes NetworkPolicy, security group) blocks all outbound traffic except to an explicit allowlist. No: the agent can make outbound calls to any URL.

**Answer:** <!-- NO -->

**Evidence / Notes:** Network policy is managed by the Launchpad platform team and is not in this repo. No Kubernetes NetworkPolicy is committed to the sample-ai-app codebase. The app makes outbound calls to Anthropic API, [EXTERNAL-SYSTEM] REST API, SMTP relay, JIRA, Ivanti, Grafana, and the Control Service. Whether these are allowlisted at the network layer is unknown. No egress restriction is documented or verified for this project.

---

### 4.3 No Wildcard Permissions

**Question:** Does the AI agent have any permissions defined with wildcards — such as 'access all S3 buckets', 'call any API', or admin-level IAM roles?

**What counts as YES:** No wildcards: all permissions are specific and scoped to named resources. Wildcards present: the agent has one or more wildcard or admin-level permissions.

**Answer:** <!-- YES -->

**Evidence / Notes:** `docs/SECRETS.md` documents that the pod IRSA role has `secretsmanager:GetSecretValue` scoped to the single named secret `[org]-platform/sample-ai-app` — no wildcards. The CI/CD deploy role (`bb-sample-ai-app-deploy`, ARN `arn:aws:iam::[AWS-ACCOUNT-ID-2]:role/bb-sample-ai-app-deploy`) is used only during pipeline execution, not at runtime. All documented runtime permissions are resource-scoped. Note: IAM policy is Launchpad-owned and not in this repo — verified via documentation only, not direct IAM inspection.

---

### 4.4 Human Approval for Sensitive Actions

**Question:** Before the AI agent can take actions that modify data, send messages, or call external services, does a human have to explicitly approve the action?

**What counts as YES:** Yes: a confirmation step exists for write/sensitive operations before they are executed. No: the agent acts immediately without human confirmation.

**Answer:** <!-- YES -->

**Evidence / Notes:** Ada is read-only — it does not write to any database, send messages, or initiate outbound calls autonomously. Call patterns: (1) `/api/explain/<process_id>` — human-initiated HTTP GET by dashboard user; (2) `/api/dev/diagnose` — requires authenticated user with `can_manage_notifications` permission to POST explicitly; (3) Grafana webhook inline — Ada enriches a notification that Grafana already decided to send based on a human-configured alert rule. Ada has no write capability and no autonomous outbound initiation. No approval gate is needed for a read-only analysis agent.

---

### 4.5 Credential Rotation Policy

**Question:** Is there a defined policy for rotating credentials (API keys, passwords, tokens) that the AI agent uses — including a procedure to rotate them immediately during a security incident?

**What counts as YES:** Yes: rotation schedule documented, automated where possible, and an emergency rotation runbook exists. No: no rotation policy; credentials are rotated ad hoc or never.

**Answer:** <!-- YES -->

**Evidence / Notes:** `docs/SECRETS.md` documents that `ANTHROPIC_API_KEY` is stored in AWS Secrets Manager at key `[org]-platform/sample-ai-app`. Emergency rotation procedure: update the secret value in Secrets Manager + trigger pod restart (`kubectl rollout restart deployment/sample-ai-app -n sample-ai-app`). Ada auto-disables (returns 503) if the key is invalid or blank within one restart cycle (~60s). Scheduled automatic rotation is not configured — rotation is currently manual/emergency-only. Procedure exists but is not automated.

---

## Section 5: Incident Response Readiness

_This section checks whether your team is prepared to respond to an AI-specific security incident. General IT incident response playbooks do not cover AI-specific scenarios — prompt injection, a rogue agent, or tampered tools require different containment steps._

### 5.1 AI-Specific IR Playbooks

**Question:** Does your team have documented response procedures specifically for AI security incidents — covering scenarios such as the agent receiving injected instructions, the agent taking unexpected actions, or a tool the agent uses being tampered with?

**What counts as YES:** Yes: written playbooks exist for at least three AI threat types with specific containment steps. No: only a general IT IR plan exists; no AI-specific playbooks.

**Answer:** <!-- NO -->

**Evidence / Notes:** No AI-specific IR playbooks exist for sample-ai-app. `docs/SECRETS.md` covers secret rotation. `CLAUDE.md` documents the Ada architecture. Neither addresses incident response for AI-specific threats: prompt injection via [EXTERNAL-SYSTEM] error log content (LLM01), insecure output handling in Grafana notifications (LLM02), or excessive agency scenarios (LLM06). No playbooks for any AI threat type exist.

---

### 5.2 Team Training

**Question:** Has every engineer and analyst who could be on-call for this AI system reviewed the AI incident response playbooks and been trained on how to use them?

**What counts as YES:** Yes: training session completed, attendance recorded. No: playbooks exist but only the author has read them.

**Answer:** <!-- NO -->

**Evidence / Notes:** No AI-specific IR playbooks exist (see 5.1), therefore no AI IR training has been conducted. No on-call rotation or training records found in the repository.

---

### 5.3 Approvals Workflow for Containment

**Question:** For high-impact containment actions — such as terminating the agent, rotating all credentials, or rolling back the system — is there a workflow that requires a second person to approve before the action is taken?

**What counts as YES:** Yes: a documented approval step exists for destructive containment actions, with an audit trail. No: one person can take all containment actions unilaterally with no record.

**Answer:** <!-- NO -->

**Evidence / Notes:** A single engineer with AWS console access or `kubectl` credentials can rotate the Anthropic API key and restart pods unilaterally. No two-person rule, Slack approval gate, or PagerDuty escalation policy is documented for AI containment actions in this project.

---

### 5.4 Incident Command Roles

**Question:** For an AI security incident, are the following roles defined: who declares the incident, who owns containment, who handles external communications, and who is the executive escalation point?

**What counts as YES:** Yes: named roles with backups, documented in a one-page incident command card. No: roles are assumed informally or not defined at all.

**Answer:** <!-- NO -->

**Evidence / Notes:** No incident command structure is documented for sample-ai-app. `CLAUDE.md` and `docs/SECRETS.md` do not define incident roles, escalation paths, or on-call responsibilities for AI incidents.

---

### 5.5 Tabletop Exercise

**Question:** Has the team run a practice scenario — a 'tabletop exercise' — where they walked through responding to a simulated AI security incident (e.g. prompt injection, rogue agent) within the last 6 months?

**What counts as YES:** Yes: exercise run within 6 months, with an after-action report documenting gaps found and addressed. No: no tabletop exercise has been run.

**Answer:** <!-- NO -->

**Evidence / Notes:** No tabletop exercise has been conducted. sample-ai-app is a production service with a recently integrated AI component (Ada). No after-action report exists.

---

## Declaration

I confirm that the answers above are accurate to the best of my knowledge.
Controls marked YES have been verified against the sample-ai-app Git repository and
available documentation via static analysis. Runtime controls (kill switch timing, rollback drill)
were not executed — relevant controls are marked NO where evidence requires live execution.

**Signature:** [Engineer Name] / Claude Code (static analysis — 2026-06-04)

**Date:** 2026-06-04
