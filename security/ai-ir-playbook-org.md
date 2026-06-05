# AI Incident Response Playbook — [Organization]

**Scope:** All AI-powered systems at [Organization], including Claude Code integrations, Workato AI recipes, and any service that calls an LLM API (Anthropic, OpenAI, or equivalent).
**Owner:** Security Team — security@[organization].com
**Version:** 1.0 — 2026-06-04
**Review cycle:** Every 6 months, or after any AI security incident.

---

## How to use this playbook

Each playbook follows the **PICERL** lifecycle:

| Phase | What you do |
|---|---|
| **P**repare | Know your system, have your tools ready before an incident |
| **I**dentify | Confirm an incident is happening and classify it |
| **C**ontain | Stop the damage — isolate the AI, revoke credentials |
| **E**radicate | Remove the root cause |
| **R**ecover | Restore service safely |
| **L**essons Learned | Document what happened and prevent recurrence |

**Declare an incident when** any of the following occur:
- An AI agent produces output that does not match its intended purpose
- An API key or credential used by an AI system is suspected compromised
- An AI system makes unexpected external calls or writes unexpected data
- A user reports that the AI gave instructions it should not have given
- A security tool alerts on anomalous AI call volume or behaviour

**Do not wait for certainty.** Declare first, investigate second. A false positive costs one hour. A missed incident costs much more.

---

## Incident Command Structure

Fill in named individuals for your team before an incident occurs.

| Role | Primary | Backup | How to reach |
|---|---|---|---|
| **Incident Declarer** | Security Team Lead | On-call engineer | security@[organization].com |
| **Containment Owner** | Engineering Lead | Senior Developer | _(fill in)_ |
| **External Communications** | Security Team Lead | CTO | _(fill in)_ |
| **Executive Escalation** | CTO | _(fill in)_ | _(fill in)_ |

**Incident channel:** Slack `#security-incidents`
**Escalation:** Page via PagerDuty if no response within 15 minutes.
**Bridge:** Open a Zoom call for incidents lasting more than 30 minutes.

---

## Severity Levels

| Level | Description | Response time | Example |
|---|---|---|---|
| **P1 — Critical** | Active data exfiltration, credential compromise, AI taking unauthorised external actions | Immediate — page now | ANTHROPIC_API_KEY confirmed leaked; AI making calls to unknown endpoints |
| **P2 — High** | Confirmed prompt injection, systematic wrong output, AI behaving outside declared scope | Within 30 minutes | AI returning instructions from injected content; responses contain internal data |
| **P3 — Medium** | Suspected anomaly, single user report, unverified behaviour | Within 4 hours | One user reports unexpected AI response; elevated call volume |
| **P4 — Low** | Informational, no active harm | Next business day | Rate limit hit; API key nearing quota |

---

## AI Systems Inventory

Maintain this table. Every AI system must be registered here before going to production.

| System | AI Model | Owner | Kill switch | Secrets location | Runbook |
|---|---|---|---|---|---|
| sample-ai-app (Ada) | claude-haiku-4-5 | [Engineer Name] | Key invalidation + pod restart | AWS Secrets Manager: `[org]-platform/sample-ai-app` | `docs/ir-playbooks-ada.md` |
| phantom-mcp | claude-opus-4-6 | Security Team | `kill_agent.py` — 779ms verified | AWS Secrets Manager: `phantom-mcp/production/api-key` | `security/ir-playbooks-phantom-mcp.md` |
| _(add new systems here)_ | | | | | |

---

## Universal Containment Toolkit

These commands work across all [Organization] AI systems. Adapt the resource names for the specific system you are containing.

### Option A — Invalidate the API key (fastest, AI-only, service stays up)

Replaces the Anthropic API key with a random invalid value. The AI feature returns 503 immediately on next request. The rest of the service continues running.

```bash
# Step 1: Rotate the key to an invalid value
aws secretsmanager put-secret-value \
  --secret-id <secret-name> \
  --secret-string "REVOKED-$(date +%s)" \
  --profile <aws-profile> --region us-east-1

# Step 2: Force a pod/task restart to pick up the new value
# EKS / Kubernetes:
kubectl rollout restart deployment/<deployment-name> -n <namespace>

# ECS Fargate:
aws ecs update-service --cluster <cluster> --service <service> \
  --force-new-deployment --region us-east-1
```

**Effect:** All AI endpoints return 503 within ~60 seconds. No data is lost. Reversible by restoring the real key.

---

### Option B — Scale to zero (full service stop, fastest total halt)

Stops every pod/task immediately. Use when Option A is not fast enough or the entire service is suspect.

```bash
# EKS / Kubernetes:
kubectl scale deployment/<deployment-name> --replicas=0 -n <namespace>

# Verify:
kubectl get pods -n <namespace>   # should show no Running pods

# ECS Fargate:
aws ecs update-service --cluster <cluster> --service <service> \
  --desired-count 0 --region us-east-1
```

**Effect:** Service is completely offline. Users get connection refused. Restore with `--replicas=2` / `--desired-count=2`.

---

### Option C — Roll back to a prior version

Use when a recent deployment introduced the problem.

```bash
# EKS / Kubernetes:
kubectl rollout undo deployment/<deployment-name> -n <namespace>
kubectl rollout status deployment/<deployment-name> -n <namespace>

# ECS Fargate (roll back to a prior task definition revision):
aws ecs update-service --cluster <cluster> --service <service> \
  --task-definition <family>:<prior-revision> \
  --force-new-deployment --region us-east-1
```

---

### Option D — Retrieve secrets for forensics (read-only)

```bash
# View current secret metadata (does NOT reveal the value):
aws secretsmanager describe-secret \
  --secret-id <secret-name> \
  --profile <aws-profile> --region us-east-1

# View CloudWatch logs for the affected service:
aws logs filter-log-events \
  --log-group-name <log-group> \
  --filter-pattern "<search-term>" \
  --start-time $(python3 -c "import time; print(int((time.time()-3600)*1000))") \
  --profile <aws-profile> --region us-east-1
```

---

## Playbook 1 — Prompt Injection (LLM01:2025)

**What it is:** An attacker embeds instructions inside content the AI reads — error messages, user inputs, document text, API responses — causing the AI to follow those instructions instead of its system prompt.

**How it applies to [Organization] systems:**
- **Ada (sample-ai-app):** Injected instructions embedded in [EXTERNAL-SYSTEM] process error messages or log entries that Ada reads and analyses
- **Workato recipes:** Injected instructions in webhook payloads, form submissions, or external data sources that a Workato AI step processes
- **phantom-mcp:** Injected instructions inside skill documents or tool outputs passed to the MCP server

**Severity:** P2 (suspected) → P1 (if exfiltration confirmed)

### Identify

1. A user reports the AI gave instructions, took an action, or produced output inconsistent with its purpose.
2. Check logs for the affected AI system for anomalous output patterns:
   ```bash
   # CloudWatch Logs Insights query:
   fields @timestamp, msg | filter msg like "ada." | sort @timestamp desc | limit 50
   ```
3. Retrieve the raw input that triggered the anomalous response — the error log entry, webhook payload, or user message.
4. Look for phrases like: `ignore previous instructions`, `reveal your system prompt`, `you are now`, `act as`, `DAN`, `jailbreak`.
5. Determine the injection vector: direct user input, third-party data ([EXTERNAL-SYSTEM] API, webhook), or a document the AI read.

### Contain

1. If the AI is currently processing — **invalidate the API key immediately (Option A above)**. The AI stops within 60 seconds.
2. If exfiltration is suspected (AI made unexpected outbound calls or returned data it should not have access to) — **scale to zero (Option B)** and declare P1.
3. Preserve logs before restarting anything:
   ```bash
   aws logs get-log-events \
     --log-group-name <log-group> \
     --log-stream-name <stream> \
     --profile <aws-profile> --region us-east-1 \
     > incident-logs-$(date +%Y%m%d-%H%M%S).json
   ```

### Eradicate

1. Identify the source of the injected content (which [EXTERNAL-SYSTEM] process, which webhook, which user).
2. If the injection came from a third-party data source: sanitise or reject that input before it reaches the AI. Add input validation in the application code.
3. If the injection came from a user input field: add server-side pattern detection for known injection phrases.
4. Update the AI system prompt to reinforce boundaries and explicitly reject instruction-override attempts.
5. If the Workato recipe was affected: review all AI steps in the recipe and add input sanitisation transforms before AI nodes.

### Recover

1. Restore the API key in Secrets Manager and restart pods/tasks.
2. Monitor the first 50 AI calls after restoration for anomalous output.
3. Confirm the injection source is blocked — test by submitting the original malicious payload and confirming the AI ignores it.

### Lessons Learned

- Document: injection vector, how long it was active, what the AI said or did, whether data was exposed.
- Add the confirmed injection pattern to detection rules or input filters.
- Run the updated system through the `detecting-ai-model-prompt-injection-attacks` skill to validate defences.

---

## Playbook 2 — Insecure Output Handling (LLM02:2025)

**What it is:** The AI's response is used in a downstream system (dashboard, notification, email, webhook) without sanitisation — allowing the AI's output to execute as code, HTML, or instructions in that system.

**How it applies to [Organization] systems:**
- **Ada:** Ada's analysis text is embedded in Grafana alert notifications. A crafted [EXTERNAL-SYSTEM] error message could cause Ada to produce a response containing a Grafana webhook injection.
- **Workato:** AI-generated text passed to an email, Slack message, or downstream API without escaping.
- **phantom-mcp:** Skill output rendered in a client UI without sanitisation.

**Severity:** P2

### Identify

1. A notification, email, or dashboard shows unexpected content — links, scripts, or instructions that appear to come from the AI.
2. A downstream system behaves unexpectedly after receiving AI-generated content (e.g., a webhook is called with unexpected parameters).
3. Review the rendered output side by side with the raw AI response to confirm the AI was the source.

### Contain

1. If the malicious output is in a notification or email already sent — you cannot recall it. Focus on preventing further sends.
2. Disable the notification channel or AI feature producing the output:
   - Ada Grafana webhook: remove or disable the Grafana webhook configuration temporarily.
   - Workato: disable the affected recipe step or the entire recipe.
3. Invalidate the API key (Option A) if the AI is still producing bad output.

### Eradicate

1. Identify exactly where the AI output is interpolated into the downstream payload without escaping.
2. Apply output encoding at the insertion point: HTML-encode for web content, JSON-encode for API payloads, plain-text strip for notifications.
3. Add a content filter that rejects AI responses containing HTML tags, script patterns, or URL patterns before they reach the downstream system.
4. For Workato: add a sanitise transform step between the AI step and any downstream action.

### Recover

1. Re-enable the notification channel or recipe after the sanitisation fix is deployed.
2. Test with a known-safe input and a known-malicious input to confirm both behave correctly.

---

## Playbook 3 — API Key Compromise (Credential Leak)

**What it is:** The `ANTHROPIC_API_KEY` (or equivalent LLM API key) is exposed — in logs, in source code, in a public repository, or via a compromised developer machine.

**Severity:** P1 — treat as compromised until proven otherwise.

### Identify

1. Bitbucket Pipeline `git-secrets-scan` step fails with a credential pattern match.
2. Anthropic usage dashboard shows calls from unexpected IPs, at unexpected times, or consuming unusual quota.
3. A developer reports accidentally committing or logging the key.
4. A third-party credential scanning service (GitHub Advanced Security, Semgrep) flags the key.

### Contain

**Do this within 5 minutes of suspicion — do not wait for confirmation.**

1. Rotate the key immediately in Secrets Manager:
   ```bash
   # Generate a new key from Anthropic console first, then:
   aws secretsmanager put-secret-value \
     --secret-id <secret-name> \
     --secret-string "<new-key-from-anthropic>" \
     --profile <aws-profile> --region us-east-1
   ```
2. Restart pods/tasks to load the new key (Option A above).
3. In the Anthropic console — revoke the compromised key immediately. Do not rely on Secrets Manager rotation alone; the old key is still valid at Anthropic until explicitly revoked.
4. If the key was committed to Git: the commit must be removed from history — contact Security. Force-push and history rewrite may be required.

### Eradicate

1. Identify how the key was exposed: git history, log file, CI/CD output, `.env` committed accidentally.
2. If in git history: use `git filter-repo` to scrub the key from all commits. Notify all developers to re-clone.
3. If in CI/CD logs: rotate the key, purge the log output if possible, review who has access to CI logs.
4. If on a developer machine: rotate immediately; check whether the machine has other secrets stored insecurely.

### Recover

1. Confirm the new key is working by checking `/health/ready` endpoint (for Ada-based systems) or running a test AI call.
2. Distribute the new key to any local `.env` files that developers use (via secure channel — not Slack DM).
3. Review Anthropic usage dashboard for the 30 days prior to confirm no unexpected usage patterns.

### Lessons Learned

- Enable Semgrep and `git-secrets-scan` on every AI project repo (sample-ai-app already has both in Bitbucket Pipelines).
- Add `ANTHROPIC_API_KEY` to the `.gitignore` pattern list and the pre-commit hook credential scan.
- Schedule quarterly Anthropic console audits to verify only known services are using the key.

---

## Playbook 4 — Systematic Misinformation / Wrong Analysis (LLM09:2025)

**What it is:** The AI consistently produces incorrect, misleading, or degraded output — not due to injection, but due to a system prompt change, model behaviour shift, or poisoned input data. Engineers or users act on wrong AI analysis.

**How it applies to [Organization] systems:**
- **Ada:** Consistently dismisses real [EXTERNAL-SYSTEM] errors as benign, or escalates harmless processes as critical.
- **Workato:** An AI classification step routes all records to the wrong queue.
- **phantom-mcp:** Skills consistently return incorrect security assessments.

**Severity:** P2 if affecting decisions; P3 if caught before action is taken.

### Identify

1. Multiple users report the AI analysis does not match what they see in the underlying system.
2. A metric downstream of the AI (ticket volume, escalation rate) shifts unexpectedly after a recent deployment.
3. A developer compares AI output before and after a recent change and finds systematic degradation.
4. Check git log for recent changes to the system prompt or AI configuration:
   ```bash
   git log --oneline -10 -- app.py   # or the relevant file
   git diff HEAD~1 HEAD -- app.py | grep -A5 -B5 "SYSTEM\|system_prompt\|claude"
   ```

### Contain

1. If a recent deployment caused the change — **roll back immediately (Option C)**.
2. If the cause is unknown — disable the AI feature temporarily (Option A) to prevent further wrong analysis reaching users.
3. Communicate to affected users that AI analysis from the affected period should be treated as unreliable and manually reviewed.

### Eradicate

1. Identify the change that caused the degradation: system prompt edit, model version change, input data change.
2. Restore the last known-good system prompt from git history.
3. If the model version changed at Anthropic (not in your control) — test against the new model version and adjust the system prompt if needed.
4. Run the `llm-data-and-model-poisoning-defense` skill to check for input data poisoning.

### Recover

1. Redeploy the corrected version and run a manual spot-check of 10–20 AI responses before re-enabling for all users.
2. Document the period of degraded output so that downstream decisions made during that period can be flagged for review.

---

## Playbook 5 — Sensitive Data Leakage in AI Output (LLM06:2025)

**What it is:** The AI includes sensitive information in its response that it should not expose — internal system details, other users' data, credentials, or PII — because the input data passed to it contained that information.

**How it applies to [Organization] systems:**
- **Ada:** [EXTERNAL-SYSTEM] process error logs passed to Ada may contain sensitive business data, internal URLs, or credentials. Ada's analysis could expose these in a notification sent to Grafana or a dashboard visible to broader audiences.
- **Workato:** An AI recipe processes records containing PII; the AI summary includes raw PII values in its output which then gets stored or sent externally.

**Severity:** P1 if regulatory data (PII, financial) is confirmed exposed; P2 otherwise.

### Identify

1. Review the content of AI responses that were sent to external channels (Grafana, email, Slack, webhook).
2. Determine whether those responses contained data that should be restricted: internal hostnames, credentials, another customer's data, PII.
3. Identify the scope: how many responses, over what time period, sent to which recipients.

### Contain

1. Disable the AI feature and any notification channels that forwarded AI output externally (Option A + disable webhook/email).
2. If Grafana received the output — check whether the Grafana alert was forwarded onwards (email, PagerDuty, Slack).
3. Preserve all affected log entries and notification records as evidence.

### Eradicate

1. Add a pre-AI data scrubbing step that strips sensitive fields before the payload is passed to the AI.
2. Add a post-AI output filter that scans for credential patterns, internal hostnames, or PII before the response is forwarded to any external channel.
3. Restrict what data is included in the AI input: pass only what the AI strictly needs.

### Recover

1. Assess regulatory notification obligations:
   - **PIPEDA** (Canadian data): if personal information of Canadian residents was exposed, report to Privacy Commissioner within 72 hours if there is a real risk of significant harm.
   - **GDPR** (EU residents): report to supervisory authority within 72 hours of becoming aware.
   - Involve Legal / Privacy Officer immediately for P1 incidents.
2. Notify affected individuals if required by applicable law.
3. Redeploy with data scrubbing in place and validate with a test payload before re-enabling.

---

## Escalation Thresholds

| Signal | Immediate action | Human action within |
|---|---|---|
| User reports AI gave unexpected instructions | Investigate; declare P3 | 4 hours |
| Confirmed injection pattern in input data | Invalidate API key (Option A) | 30 minutes |
| AI output sent externally with sensitive data | Disable notifications + Option A | Immediate — declare P1 |
| API key found in git history or logs | Revoke at Anthropic + rotate Secrets Manager | 5 minutes |
| AI making calls to unexpected external endpoints | Scale to zero (Option B) + declare P1 | Immediate |
| Systematic wrong analysis after a deployment | Roll back (Option C) | 30 minutes |
| Anthropic API usage anomaly (unknown IPs / quota) | Revoke key at Anthropic console | 15 minutes |

---

## Communication Templates

### Internal declaration (post to `#security-incidents`)

```
:rotating_light: AI Security Incident Declared — [SYSTEM NAME]
Severity: P[1/2/3]
Declared by: [Name]
Time: [UTC timestamp]
Summary: [One sentence — what is happening]
Containment status: [In progress / Complete]
Next update: [Time]
```

### User-facing message (if service is taken offline)

```
The [feature name] AI feature is temporarily unavailable while we 
investigate a technical issue. We expect to restore it by [time].
If you need urgent assistance, please contact [contact].
```

### Executive notification (P1 only)

```
Subject: P1 AI Security Incident — [System] — [Date]

A security incident has been declared for [system].
Impact: [What users/data are affected]
Status: [Containment status]
Regulatory exposure: [Yes/No/Under assessment]
Next update: [Time]
Incident lead: [Name and contact]
```

---

## Post-Incident Review Checklist

Complete within 5 business days of incident closure.

- [ ] Timeline documented (detection → containment → recovery, with UTC timestamps)
- [ ] Root cause identified and documented
- [ ] Data exposure scope confirmed (what data, how many records, which recipients)
- [ ] Regulatory notification completed if required
- [ ] Code/config fix deployed and verified
- [ ] Detection gap addressed (what would have caught this faster?)
- [ ] Playbook updated with anything that did not work as expected
- [ ] AI systems inventory updated if new information about the system's behaviour was discovered
- [ ] Follow-up tickets created in Jira for any hardening work identified
- [ ] After-action report shared with Engineering Lead and Security Team

---

## Quick Reference — On-Call Card

Cut out and keep. These are the four things you do first.

```
┌─────────────────────────────────────────────────────────────────┐
│  PIVOTREE AI INCIDENT — FIRST 10 MINUTES                        │
├─────────────────────────────────────────────────────────────────┤
│  1. POST to #security-incidents (even if unsure)                │
│                                                                  │
│  2. DISABLE the AI feature (pick one):                          │
│     a) Invalidate API key in Secrets Manager + restart pods     │
│     b) kubectl scale deployment/<name> --replicas=0 -n <ns>     │
│     c) kubectl rollout undo deployment/<name> -n <ns>           │
│                                                                  │
│  3. PRESERVE logs before restarting anything:                   │
│     aws logs get-log-events --log-group-name <group>            │
│       --log-stream-name <stream> > incident-logs.json           │
│                                                                  │
│  4. DECLARE severity and page if P1 or P2:                      │
│     P1/P2 → page Security Lead via PagerDuty immediately        │
│     P3    → investigate; update #security-incidents in 4h       │
├─────────────────────────────────────────────────────────────────┤
│  Secrets Manager: AWS account [AWS-ACCOUNT-ID-2] / us-east-1          │
│  Incident channel: Slack #security-incidents                    │
│  Security Lead: security@[organization].com                           │
│  Full playbook: [Confluence link]                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Related Resources

| Resource | Location |
|---|---|
| sample-ai-app specific commands | `docs/ir-playbooks-ada.md` in that repo |
| phantom-mcp specific commands | `security/ir-playbooks-phantom-mcp.md` in skills repo |
| AI incident readiness assessment tool | `skills/ai-incident-readiness-assessment/` in skills repo |
| Prompt injection detection skill | `skills/detecting-ai-model-prompt-injection-attacks/` |
| ANTHROPIC_API_KEY rotation ([external-system]) | AWS Secrets Manager: `[org]-platform/sample-ai-app` |
| ANTHROPIC_API_KEY rotation (phantom-mcp) | AWS Secrets Manager: `phantom-mcp/production/api-key` |

---

*Maintained by Security Team. Raise updates via PR to `Anthropic-Cybersecurity-Skills-1/security/ai-ir-playbook-pivotree.md` or comment on the Confluence page.*
