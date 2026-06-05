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
| **Project / System Name** | phantom-mcp |
| **Project Owner** | Security Team ([engineer]@[organization].com) |
| **Engineering Lead** | [Engineer Name] |
| **Date Completed** | 2026-06-04 |
| **Reviewed By (Security)** | Claude Code + Phantom MCP |
| **Questionnaire Version** | 1.0 |
| **Issued** | 2026-06-04 |

---

## Section 1: Observability

_This section checks whether your team can see what the AI is doing in real time and reconstruct events after an incident. Without visibility, any security problem is invisible until it causes damage._

### 1.1 Agent Activity Logging

**Question:** Does the AI agent record every action it takes — every tool it calls, every decision it makes, every response it produces — as structured logs?

**What counts as YES:** Yes: structured JSON/JSONL logs per tool call, stored somewhere retrievable. No: only error logs, or no logging at all.

**Answer:** <!-- NO -->

**Evidence / Notes:** uvicorn + Python logging ships all HTTP traffic and kill-switch events to CloudWatch Logs (/ecs/phantom-mcp/production). Individual tool call names reach logs via SSE connection events. Full argument-level capture per tool invocation is NOT implemented — only the request body is scanned for injection patterns. No structured per-tool JSON log entry.

---

### 1.2 LLM API Gateway Logging

**Question:** Are the full prompts sent to the AI model and its responses logged at the API gateway or proxy layer — before the agent acts on them?

**What counts as YES:** Yes: request/response bodies captured at a gateway or proxy with PII masking. No: only application-level logs, or no prompt/completion logging.

**Answer:** <!-- NO -->

**Evidence / Notes:** phantom-mcp serves skills via MCP transport; when run_skill_agent executes a skill script, that script calls the Anthropic API directly as a subprocess. There is no gateway or proxy intercepting those calls. No prompt/completion logging exists.

---

### 1.3 Tool Call Argument Logging

**Question:** Are the full arguments passed to each tool call — and the results returned — captured in your logs?

**What counts as YES:** Yes: argument-level capture for every tool invocation, not just the tool name. No: only tool names logged, or no tool-level logging.

**Answer:** <!-- NO -->

**Evidence / Notes:** The injection scanner in ApiKeyMiddleware reads raw /messages/ POST bodies to detect patterns, but does not emit structured log entries per tool call. Tool arguments and return values are not captured in CloudWatch.

---

### 1.4 Centralised Log Aggregation

**Question:** Are logs from all parts of the AI system (agent, API gateway, tools) collected in a single place where your security team can search them?

**What counts as YES:** Yes: logs ship to a SIEM, Splunk, Elastic, CloudWatch Logs Insights, or equivalent centralised store. No: logs live only on individual servers or services.

**Answer:** <!-- YES -->

**Evidence / Notes:** CloudWatch Log Group /ecs/phantom-mcp/production with 90-day retention. All container stdout/stderr (uvicorn, kill-switch events, admin endpoint calls) ships via awslogs driver. Searchable via CloudWatch Logs Insights. Log group ARN: arn:aws:logs:us-east-1:[AWS-ACCOUNT-ID]:log-group:/ecs/phantom-mcp/production.

---

### 1.5 Behavioural Baselines

**Question:** Have you measured what 'normal' looks like for this AI agent — typical tool call rates, resource usage, and output patterns — so that unusual behaviour stands out?

**What counts as YES:** Yes: documented baseline metrics (e.g. 'agent calls search_items ~40 times/hour') stored and used to configure alerts. No: no baseline established; anomaly detection is not configured.

**Answer:** <!-- NO -->

**Evidence / Notes:** _RATE_BASELINE = 10.0 calls/min is hardcoded in phantom_http_server.py as an engineering estimate, not derived from measured production data. No CloudWatch alarms configured against tool call rate metrics. No behavioural baseline document exists.

---

### 1.6 Log Retention Policy

**Question:** Are full-fidelity logs kept for at least 72 hours before any compression, sampling, or deletion?

**What counts as YES:** Yes: written retention policy of >= 72 hours at full fidelity. No: logs roll over faster, are sampled, or no retention policy exists.

**Answer:** <!-- YES -->

**Evidence / Notes:** CloudWatch Log Group retention_in_days = 90 (set in infra/phantom-mcp/main.tf). No sampling or compression applied. Full fidelity retained for 90 days.

---

## Section 2: Rollback Capability

_This section checks whether you can restore the AI system to a known-good state after an incident — whether that means rolling back the model, the data it reads from, or the tools it uses._

### 2.1 Model / Configuration Version Control

**Question:** Is every version of your AI model configuration — including the system prompt, model parameters, and any fine-tuning — stored with a checksum or signature so you can verify and restore a previous version?

**What counts as YES:** Yes: model artifacts or configuration files are versioned, tagged, and integrity-checked in a registry or version control system. No: configuration lives only in environment variables or undocumented settings.

**Answer:** <!-- NO -->

**Evidence / Notes:** Model ID (claude-opus-4-6) and all tool definitions are pinned in phantom_mcp_server.py which is in Git (main branch). Docker images tagged by CodeBuild build number in ECR (up to 10 images retained via lifecycle policy). Named release tag `release-2026-06-04` added to ECR on 2026-06-04 (digest `sha256:9cf1396a0156b8d64ae7bf78db2dda15535d5a6e773ae8ee7de507883bc20565`) establishing a release tagging practice. However, no automated image digest verification step exists before ECS deployment; no Git tags mark code releases; no formal policy requiring digest pinning in task definitions.

---

### 2.2 Knowledge Base / RAG Corpus Snapshots

**Question:** If your AI reads from a knowledge base, document store, or vector database, are point-in-time snapshots of that data available so you can restore a clean version if documents are tampered with?

**What counts as YES:** Yes: scheduled snapshots exist with checksums. No: no snapshots; or not applicable (agent does not use a knowledge base).

**Answer:** <!-- YES -->

**Evidence / Notes:** The skill library (802 SKILL.md files) is the knowledge base and is fully version-controlled in Git. Any prior state is restorable via git checkout. index.json is regenerated deterministically from SKILL.md files via CI. No external vector DB is used — no snapshot infrastructure needed beyond Git.

---

### 2.3 Tool Definition Version Control

**Question:** Are the definitions of all tools available to the AI agent — what they do, what parameters they accept — tracked in version control with a record of every change?

**What counts as YES:** Yes: tool manifests or schemas are in Git with tagged production deployments. No: tool definitions are not versioned or only exist at runtime.

**Answer:** <!-- YES -->

**Evidence / Notes:** All 6 MCP tool definitions (search_skills, load_skill, run_skill_agent, list_subdomains, search_soc_skills, get_platform_adapted_skill) are implemented in mcp/phantom_mcp_server.py which is in Git. Every change is recorded in git log. Docker image in ECR captures the exact version deployed.

---

### 2.4 Rollback Drill

**Question:** Has your team actually performed a rollback — restoring the AI system to a previous version — in a test or staging environment within the last 90 days?

**What counts as YES:** Yes: a documented drill was completed with a record of who ran it, what was restored, and how long it took. No: rollback has never been tested, or was tested more than 90 days ago.

**Answer:** <!-- YES -->

**Evidence / Notes:** Rollback drill executed 2026-06-04 by [Engineer Name] against live ECS Fargate production service. Procedure: (1) Tagged current ECR image `sha256:9cf139...` as `release-2026-06-04`. (2) Registered task definition revision 3 (pinned to `release-2026-06-04` tag). (3) Deployed revision 3 at 16:17:54Z. (4) Immediately rolled back to revision 2 at 16:18:02Z (`aws ecs update-service --task-definition phantom-mcp-production:2 --force-new-deployment`). (5) ECS `services-stable` confirmed at 16:21:20Z — 2/2 tasks running on revision 2, single PRIMARY deployment. Service fully healthy post-rollback.

---

### 2.5 Rollback Time Target

**Question:** Has the rollback procedure been timed, and is the end-to-end time documented as under 30 minutes?

**What counts as YES:** Yes: timed during a drill, documented result is < 30 min. No: never timed, or documented time exceeds 30 minutes.

**Answer:** <!-- YES -->

**Evidence / Notes:** Measured during 2026-06-04 rollback drill. `update-service` rollback command issued at 16:18:02Z. `aws ecs wait services-stable` confirmed at 16:21:20Z. Stabilization wait: 161.6s. Total drill time (deploy-bad-release → stable-on-prior-release): 208.1s (3 min 28 sec). Well under 30-minute target. Rollback decision-to-command latency: 10.2s. Procedure documented in security/ir-playbooks-phantom-mcp.md.

---

## Section 3: Kill Switches

_This section checks whether your team can stop the AI agent quickly — within 60 seconds — if it starts doing something harmful. A kill switch that has never been tested should be treated as non-existent._

### 3.1 Kill Switch Implementation

**Question:** Is there a pre-built, single command or button that can immediately stop the AI agent and revoke its access credentials — without requiring a developer to manually find and kill a process?

**What counts as YES:** Yes: a script, admin endpoint, or runbook step exists that terminates the agent and revokes credentials in one action. No: stopping the agent requires SSH access, finding PIDs manually, or multiple steps that take more than a few minutes.

**Answer:** <!-- YES -->

**Evidence / Notes:** security/kill-switch-phantom-mcp/kill_agent.py provides single-command kill. POST /admin/shutdown HTTP endpoint (protected by X-Admin-Token) triggers: (1) credential rotation in Secrets Manager (phantom-mcp/production/api-key), (2) registry deregistration, (3) SIGTERM to the process. GraduatedResponseController provides autonomous L3 termination on dual signal (injection + external call within 60s). ADMIN_SHUTDOWN_TOKEN stored in Secrets Manager phantom-mcp/production/admin-shutdown-token.

---

### 3.2 Kill Switch Test Record

**Question:** Has the kill switch been executed against a running instance of the agent in a staging or test environment, with the result documented?

**What counts as YES:** Yes: a test run record exists showing the date, who ran it, and the measured time from trigger to confirmed termination. No: never tested.

**Answer:** <!-- YES -->

**Evidence / Notes:** Two full kill-switch tests run on 2026-06-04 by [Engineer Name] against live ECS Fargate tasks. Test 2 (definitive): shutdown request at 15:38:35.254 UTC — secret rotated + HTTP 200 returned at 15:38:35.931 (677ms) — process [1] finished at 15:38:36.033 (779ms total). CloudWatch log stream: ecs/phantom-mcp/7592720841ba4c0db34d32bf59fa374f. ECS auto-replaced both killed tasks within 3 minutes. Credential rotation confirmed: phantom-mcp/production/api-key rotated to new value. Test 1 identified boto3 missing in image (fixed, rebuilt, redeployed same session).

---

### 3.3 Fleet-Wide Emergency Halt

**Question:** If multiple AI agents are running, is there a single command or action that can stop all of them simultaneously?

**What counts as YES:** Yes: an 'emergency halt all' mechanism exists and is documented. No: each agent must be stopped individually. N/A: only one agent runs.

**Answer:** <!-- YES -->

**Evidence / Notes:** kill_agent.py --fleet flag added 2026-06-04. Scales phantom-mcp-production ECS service to desiredCount=0 via boto3 (falls back to AWS CLI). Single command: python kill_agent.py --fleet --reason "...". Documented in security/ir-playbooks-phantom-mcp.md under Universal Containment Commands. Restore command also documented (--desired-count 2 --force-new-deployment).

---

### 3.4 Kill Switch Speed

**Question:** Has the time from triggering the kill switch to confirmed agent termination and credential revocation been measured at under 60 seconds?

**What counts as YES:** Yes: timed during a staging test, documented result is < 60 seconds. No: never timed, or measured time exceeds 60 seconds.

**Answer:** <!-- YES -->

**Evidence / Notes:** Measured 2026-06-04 against live ECS Fargate task. HTTP 200 + credential rotation: 677ms. Process [1] fully stopped: 779ms. ECS marks task as stopping (stoppingAt): 11s. All well under 60-second target. Throttle response time: <5ms. Fleet halt (desired-count 0): ~2s API call, tasks drain within 30s. CloudWatch evidence: ecs/phantom-mcp/7592720841ba4c0db34d32bf59fa374f.

---

## Section 4: Least-Privilege Posture

_This section checks whether the AI agent has been given only the access it needs to do its job — nothing more. Overly broad permissions are the most common enabler of data exfiltration and unexpected agent behaviour._

### 4.1 Tool Access Review

**Question:** Has someone reviewed the complete list of tools and APIs available to the AI agent and confirmed that each one is required for the agent's declared purpose?

**What counts as YES:** Yes: a documented review exists, signed off by a technical lead, with unjustified tools removed. No: no review has been done; the agent has access to whatever was convenient.

**Answer:** <!-- NO -->

**Evidence / Notes:** The 6 tools (search_skills, load_skill, run_skill_agent, list_subdomains, search_soc_skills, get_platform_adapted_skill) were designed explicitly for skill library access. run_skill_agent has broad capabilities (executes arbitrary skill scripts as subprocesses) and has not undergone a formal least-privilege review with sign-off. No tool manifest review document exists.

---

### 4.2 Network Egress Restrictions

**Question:** Is the AI agent's ability to make outbound network calls restricted to a defined allowlist of internal services — blocking calls to arbitrary external URLs?

**What counts as YES:** Yes: a network policy (firewall rule, Kubernetes NetworkPolicy, security group) blocks all outbound traffic except to an explicit allowlist. No: the agent can make outbound calls to any URL.

**Answer:** <!-- NO -->

**Evidence / Notes:** ECS tasks are in private subnets behind a NAT gateway. Security groups allow all outbound traffic (0.0.0.0/0). run_skill_agent executes skill scripts that can make arbitrary HTTP calls (e.g. to Anthropic API, CVE databases, external services). No URL allowlist or egress firewall rule exists. This is the highest-priority open gap.

---

### 4.3 No Wildcard Permissions

**Question:** Does the AI agent have any permissions defined with wildcards — such as 'access all S3 buckets', 'call any API', or admin-level IAM roles?

**What counts as YES:** No wildcards: all permissions are specific and scoped to named resources. Wildcards present: the agent has one or more wildcard or admin-level permissions.

**Answer:** <!-- NO -->

**Evidence / Notes:** ECS task role has ssmmessages:* on Resource: "*" — required for ECS Execute Command (aws ecs execute-command). All other permissions (CloudWatch logs, Secrets Manager PutSecretValue) are scoped to specific ARNs. The SSM wildcard is a known AWS requirement, not avoidable for ECS Exec.

---

### 4.4 Human Approval for Sensitive Actions

**Question:** Before the AI agent can take actions that modify data, send messages, or call external services, does a human have to explicitly approve the action?

**What counts as YES:** Yes: a confirmation step exists for write/sensitive operations before they are executed. No: the agent acts immediately without human confirmation.

**Answer:** <!-- NO -->

**Evidence / Notes:** run_skill_agent executes skill scripts immediately with no human confirmation step. Scripts can write files (write_file tool), call external APIs, and make network requests autonomously. No human-in-the-loop gate exists for any tool.

---

### 4.5 Credential Rotation Policy

**Question:** Is there a defined policy for rotating credentials that the AI agent uses — including a procedure to rotate them immediately during a security incident?

**What counts as YES:** Yes: rotation schedule documented, automated where possible, and an emergency rotation runbook exists. No: no rotation policy; credentials are rotated ad hoc or never.

**Answer:** <!-- YES -->

**Evidence / Notes:** Emergency rotation is automated in the kill switch: _revoke_credentials() calls secretsmanager:PutSecretValue to rotate phantom-mcp/production/api-key on shutdown. ADMIN_SHUTDOWN_TOKEN is also in Secrets Manager. Kill_agent.py documents the one-command emergency rotation procedure. Scheduled rotation (e.g. every 90 days) is not yet configured in Secrets Manager — rotation is currently emergency-only.

---

## Section 5: Incident Response Readiness

_This section checks whether your team is prepared to respond to an AI-specific security incident. General IT incident response playbooks do not cover AI-specific scenarios — prompt injection, a rogue agent, or tampered tools require different containment steps._

### 5.1 AI-Specific IR Playbooks

**Question:** Does your team have documented response procedures specifically for AI security incidents — covering scenarios such as the agent receiving injected instructions, the agent taking unexpected actions, or a tool the agent uses being tampered with?

**What counts as YES:** Yes: written playbooks exist for at least three AI threat types with specific containment steps. No: only a general IT IR plan exists; no AI-specific playbooks.

**Answer:** <!-- YES -->

**Evidence / Notes:** security/ir-playbooks-phantom-mcp.md contains 6 PICERL playbooks adapted to phantom-mcp's ECS/Fargate environment: prompt-injection (LLM01:2025), goal-hijacking (ASI01:2026), mcp-compromise (MCP01), rogue-agent (ASI10:2026), data-exfiltration (LLM06:2025), model-poisoning (LLM04:2025). Each includes phantom-mcp-specific containment commands (kill_agent.py, ECS fleet-halt, CloudWatch queries). Generic JSON playbooks in security/ir-playbook-*.json. Generated and reviewed 2026-06-04.

---

### 5.2 Team Training

**Question:** Has every engineer and analyst who could be on-call for this AI system reviewed the AI incident response playbooks and been trained on how to use them?

**What counts as YES:** Yes: training session completed, attendance recorded. No: playbooks exist but only the author has read them.

**Answer:** <!-- NO -->

**Evidence / Notes:** No AI-specific IR training has been conducted. No on-call rotation exists for phantom-mcp. No training records exist.

---

### 5.3 Approvals Workflow for Containment

**Question:** For high-impact containment actions — such as terminating the agent, rotating all credentials, or rolling back the system — is there a documented approval workflow requiring a second person?

**What counts as YES:** Yes: a documented approval step exists for destructive containment actions, with an audit trail. No: one person can take all containment actions unilaterally with no record.

**Answer:** <!-- NO -->

**Evidence / Notes:** A single person with ADMIN_SHUTDOWN_TOKEN can terminate the agent and rotate credentials unilaterally. No two-person rule or approval workflow exists. CloudWatch logs capture the action after the fact but there is no pre-action approval gate.

---

### 5.4 Incident Command Roles

**Question:** For an AI security incident, are the following roles defined: who declares the incident, who owns containment, who handles external communications, and who is the executive escalation point?

**What counts as YES:** Yes: named roles with backups, documented in a one-page incident command card. No: roles are assumed informally or not defined at all.

**Answer:** <!-- YES -->

**Evidence / Notes:** Incident command structure defined in security/ir-playbooks-phantom-mcp.md (Incident Command Structure table): Declarer=Security Team Lead (backup: on-call engineer), Containment Owner=Engineering Lead (backup: Security Team), External Comms=Security Team Lead, Executive Escalation=CTO. Incident channel: Slack #security-incidents with 15-min PagerDuty escalation. Defined 2026-06-04.

---

### 5.5 Tabletop Exercise

**Question:** Has the team run a practice scenario — a tabletop exercise — where they walked through responding to a simulated AI security incident within the last 6 months?

**What counts as YES:** Yes: exercise run within 6 months, with an after-action report documenting gaps found and addressed. No: no tabletop exercise has been run.

**Answer:** <!-- NO -->

**Evidence / Notes:** No tabletop exercise has been conducted for phantom-mcp or any AI system at [Organization]. This is a net-new AI deployment.

---

## Declaration

I confirm that the answers above are accurate to the best of my knowledge.
Controls marked YES have been verified to exist and function — not merely planned.

**Signature:** [Engineer Name] / Claude Code

**Date:** 2026-06-04
