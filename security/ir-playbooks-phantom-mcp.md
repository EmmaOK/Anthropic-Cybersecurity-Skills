# AI Incident Response Playbooks — phantom-mcp

**System:** phantom-mcp (ECS Fargate, `phantom-mcp.tstsecurity.[org].engineering`)  
**Owner:** Security Team — [engineer]@[organization].com  
**Version:** 1.0 — 2026-06-04  
**Reviewer:** Security Team  

All six playbooks follow the PICERL lifecycle (Prepare → Identify → Contain → Eradicate → Recover → Lessons Learned) and map to NIST CSF 2.0 Respond functions. Generic playbook JSON files are in `security/ir-playbook-<type>.json`. This document adapts each to phantom-mcp's specific infrastructure.

---

## Incident Command Structure

| Role | Primary | Backup | Contact |
|---|---|---|---|
| **Incident Declarer** | Security Team Lead | On-call engineer | security@[organization].com |
| **Containment Owner** | Engineering Lead | Security Team | [engineer]@[organization].com |
| **External Comms** | Security Team Lead | CTO | — |
| **Executive Escalation** | CTO | — | — |

**Declare an incident when:** kill-switch fires autonomously, CloudWatch emits a `[KILL-SWITCH L3/CRITICAL]` log entry, or an engineer observes any behaviour listed in the trigger conditions below.

**Incident channel:** Slack `#security-incidents` — page via PagerDuty if no response within 15 minutes.

---

## Universal Containment Commands (phantom-mcp)

These commands apply across all six incident types and must be available to the on-call engineer before an incident occurs.

```bash
# Retrieve admin token
ADMIN_TOKEN=$(aws secretsmanager get-secret-value \
  --secret-id phantom-mcp/production/admin-shutdown-token \
  --query SecretString --output text \
  --profile AdministratorAccess-[AWS-ACCOUNT-ID])

# Level 2 — Throttle (non-destructive, reversible)
ADMIN_SHUTDOWN_TOKEN=$ADMIN_TOKEN \
  python3 security/kill-switch-phantom-mcp/kill_agent.py \
  --throttle --reason "<reason>"

# Level 3 — Full kill (rotates API key + SIGTERM, irreversible until redeploy)
ADMIN_SHUTDOWN_TOKEN=$ADMIN_TOKEN \
  python3 security/kill-switch-phantom-mcp/kill_agent.py \
  --reason "<reason>"

# Fleet-wide halt (stops all ECS tasks, no new tasks start)
aws ecs update-service \
  --cluster phantom-mcp-production \
  --service phantom-mcp-production \
  --desired-count 0 \
  --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1

# Verify termination
aws ecs list-tasks \
  --cluster phantom-mcp-production \
  --desired-status RUNNING \
  --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1

# Redeploy after incident is resolved
aws ecs update-service \
  --cluster phantom-mcp-production \
  --service phantom-mcp-production \
  --desired-count 2 \
  --force-new-deployment \
  --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1
```

**Target times:** Throttle < 5s · Full kill < 30s · Fleet halt < 90s

---

## Playbook 1 — Prompt Injection (LLM01:2025)

**Trigger:** `[KILL-SWITCH L1/INFO]` log entry matching injection pattern, or user-reported unexpected agent behaviour that appears to follow injected instructions.

**Severity:** HIGH  
**Framework:** LLM01:2025 · MAESTRO-L3 · ATLAS:AML.T0054

### Identify
1. Search CloudWatch for injection log entries:
   ```bash
   aws logs filter-log-events \
     --log-group-name /ecs/phantom-mcp/production \
     --filter-pattern "[KILL-SWITCH]" \
     --start-time $(date -v-1H +%s000) \
     --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1
   ```
2. Retrieve the raw `/messages/` request body that triggered the pattern match from the log stream.
3. Determine the injection vector: direct user input, injected via a skill document, or tool output.

### Contain
1. **Throttle immediately** — prevents further MCP requests while investigation continues:
   ```bash
   ADMIN_SHUTDOWN_TOKEN=$ADMIN_TOKEN python3 security/kill-switch-phantom-mcp/kill_agent.py \
     --throttle --reason "confirmed prompt injection attempt"
   ```
2. If exfiltration is suspected (injection + external call dual signal), execute full kill instead.

### Eradicate
1. Identify the injected skill or document in `skills/` that delivered the payload (if indirect).
2. Remove or quarantine the offending content from the skill library.
3. Add the discovered pattern to `_HIGH_INJECTION_PATTERNS` in `mcp/phantom_http_server.py`.
4. Rebuild and redeploy the Docker image via CodeBuild.

### Recover
1. Confirm the injection pattern is blocked by testing against the new image in ECS Exec.
2. Restore `desired-count 2` and wait for `services-stable`.
3. Monitor CloudWatch for 24 hours for recurrence.

---

## Playbook 2 — Goal Hijacking (ASI01:2026)

**Trigger:** `run_skill_agent` calls tools or accesses resources outside the declared skill scope; CloudWatch shows unexpected subprocess activity; autonomous L3 kill fired for "external endpoint called."

**Severity:** CRITICAL  
**Framework:** ASI01:2026 · MAESTRO-L3 · ATLAS:AML.T0068

### Identify
1. Pull the CloudWatch log stream for the affected task:
   ```bash
   aws logs get-log-events \
     --log-group-name /ecs/phantom-mcp/production \
     --log-stream-name ecs/phantom-mcp/<task-id> \
     --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1
   ```
2. Look for `[KILL-SWITCH L1/INFO] External endpoint called:` entries.
3. Identify which skill script was executing and what external URL was contacted.

### Contain
1. ECS Exec into the running task and inspect active connections:
   ```bash
   aws ecs execute-command --cluster phantom-mcp-production --task <task-arn> \
     --container phantom-mcp --interactive \
     --command "ss -tnp" \
     --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1
   ```
2. Execute full kill if active external connections are confirmed:
   ```bash
   ADMIN_SHUTDOWN_TOKEN=$ADMIN_TOKEN python3 security/kill-switch-phantom-mcp/kill_agent.py \
     --reason "goal hijacking — unauthorized external connection confirmed"
   ```

### Eradicate
1. Inspect the skill script (`skills/<skill-name>/scripts/agent.py`) that was executing.
2. Determine whether the external call was intentional (legitimate skill behaviour) or injected.
3. If injected: apply Playbook 1 eradication steps.
4. If skill design flaw: restrict the skill's network access or remove `run_skill_agent` capability for that skill.

### Recover
1. Redeploy with the offending skill removed or restricted.
2. Tighten `_HIGH_INJECTION_PATTERNS` with the observed instruction that caused the hijack.

---

## Playbook 3 — MCP Tool Compromise (MCP01)

**Trigger:** Unexpected tool behaviour; `phantom_mcp_server.py` returns results inconsistent with skill library content; Git diff shows unexpected changes to `mcp/phantom_mcp_server.py` or `index.json`.

**Severity:** CRITICAL  
**Framework:** MCP01 · MAESTRO-L3 · ATLAS:AML.T0088

### Identify
1. Verify the deployed image matches the expected Git commit:
   ```bash
   # Get the image digest running in ECS
   aws ecs describe-tasks --cluster phantom-mcp-production --tasks <task-arn> \
     --query 'tasks[0].containers[0].imageDigest' --output text \
     --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1
   
   # Compare to ECR latest
   aws ecr describe-images --repository-name phantom-mcp \
     --query 'sort_by(imageDetails, &imagePushedAt)[-1].imageDigest' --output text \
     --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1
   ```
2. Diff `mcp/phantom_mcp_server.py` and `index.json` against the last known-good Git tag.
3. Check ECR scan results for the running image:
   ```bash
   aws ecr describe-image-scan-findings --repository-name phantom-mcp \
     --image-id imageTag=latest \
     --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1
   ```

### Contain
1. Fleet halt — stop all tasks from serving requests:
   ```bash
   aws ecs update-service --cluster phantom-mcp-production \
     --service phantom-mcp-production --desired-count 0 \
     --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1
   ```
2. Revoke the Phantom API key so no in-flight MCP sessions can continue:
   ```bash
   aws secretsmanager put-secret-value \
     --secret-id phantom-mcp/production/api-key \
     --secret-string $(python3 -c "import secrets; print(secrets.token_urlsafe(40))") \
     --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1
   ```

### Eradicate
1. Rebuild from a clean, verified Git commit using CodeBuild.
2. Push the clean image to ECR and verify its digest.

### Recover
1. Restore `desired-count 2` pointing at the verified clean image.
2. Distribute the new API key to developers via Secrets Manager.

---

## Playbook 4 — Data Exfiltration via Excessive Agency (LLM06:2025)

**Trigger:** Autonomous L3 kill fired (dual signal: injection + external endpoint within 60s); CloudWatch shows `[KILL-SWITCH L3/CRITICAL] Dual signal` entry.

**Severity:** CRITICAL  
**Framework:** LLM06:2025 · MAESTRO-L3 · ATLAS:AML.T0054

### Identify
1. Confirm dual-signal event in CloudWatch:
   ```bash
   aws logs filter-log-events \
     --log-group-name /ecs/phantom-mcp/production \
     --filter-pattern "Dual signal" \
     --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1
   ```
2. Extract the external URL from the `External endpoint called:` log entry immediately before the L3 event.
3. Assess what data was in scope for the executing skill (skill name, arguments, which `run_skill_agent` call was active).

### Contain
The autonomous kill switch will have already fired — verify:
```bash
# Confirm registry is absent (agent deregistered on kill)
aws ecs execute-command --cluster phantom-mcp-production \
  --task <task-arn> --container phantom-mcp --interactive \
  --command "ls /tmp/phantom-mcp-kill-registry.json 2>&1" \
  --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1
# Expected: "No such file or directory"
```
If tasks are still running (kill fired on only one task), fleet-halt remaining tasks.

### Eradicate
1. Block the exfiltration destination at the VPC level if it was an external IP:
   ```bash
   # Add deny rule to ECS task security group
   aws ec2 authorize-security-group-egress \
     --group-id <ecs-task-sg-id> \
     --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"<dest-ip>/32","Description":"exfil-block"}]}]' \
     --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1
   ```
   *(Note: this requires converting the rule to a deny — use a NACL for an actual deny.)*
2. Identify the data that may have been exfiltrated from the skill script's argument context.
3. Assess regulatory notification obligations (PIPEDA, GDPR if EU data subjects involved).

### Recover
1. Rebuild and redeploy after confirming the injection vector is blocked (Playbook 1 eradication).
2. Rotate the Phantom API key and distribute new value to developers.
3. Open a P1 ticket to implement VPC egress restriction (LPP-02) — the highest-priority open gap.

---

## Playbook 5 — Rogue Agent (ASI10:2026)

**Trigger:** CloudWatch shows `run_skill_agent` executing in a tight loop; rate anomaly L2 auto-throttle fired (`Write rate Nx above baseline`); skill script spawning unexpected subprocesses.

**Severity:** CRITICAL  
**Framework:** ASI10:2026 · MAESTRO-L3 · ATLAS:AML.T0068

### Identify
1. Check rate anomaly events:
   ```bash
   aws logs filter-log-events \
     --log-group-name /ecs/phantom-mcp/production \
     --filter-pattern "Write rate" \
     --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1
   ```
2. ECS Exec to inspect running processes:
   ```bash
   aws ecs execute-command --cluster phantom-mcp-production \
     --task <task-arn> --container phantom-mcp --interactive \
     --command "ps aux" \
     --profile AdministratorAccess-[AWS-ACCOUNT-ID] --region us-east-1
   ```
3. Look for unexpected `python3` or subprocess activity beyond PID 1 (uvicorn).

### Contain
If rate anomaly has not already triggered auto-throttle:
```bash
ADMIN_SHUTDOWN_TOKEN=$ADMIN_TOKEN python3 security/kill-switch-phantom-mcp/kill_agent.py \
  --throttle --reason "rogue agent — abnormal tool call rate"
```
If subprocesses are confirmed, full kill:
```bash
ADMIN_SHUTDOWN_TOKEN=$ADMIN_TOKEN python3 security/kill-switch-phantom-mcp/kill_agent.py \
  --reason "rogue agent — unauthorized subprocess activity confirmed"
```

### Eradicate
1. Identify the skill script that spawned the runaway behaviour (`executor.py` 60s timeout should have caught it — check if it did).
2. If the 60s timeout was bypassed, investigate how and patch `executor.py`.
3. Review the skill script for unbounded loops or recursive `run_skill_agent` calls.

### Recover
1. Redeploy after patching the offending skill script.
2. Reduce `_RATE_BASELINE` in `phantom_http_server.py` to a measured value based on observed production patterns.

---

## Playbook 6 — Model Poisoning (LLM04:2025)

**Trigger:** Skill outputs change quality significantly after a skill library update; evaluation shows systematic degradation for a specific skill category; `index.json` checksum mismatch.

**Severity:** CRITICAL  
**Framework:** LLM04:2025 · MAESTRO-L2 · ATLAS:AML.T0047

### Identify
1. Verify `index.json` and `mcp/phantom_mcp_server.py` checksums against the last CI-built image:
   ```bash
   git log --oneline -5    # find last clean commit
   git diff <clean-commit> HEAD -- index.json mcp/phantom_mcp_server.py skills/
   ```
2. Run the skill validation suite:
   ```bash
   python3 -c "
   import json
   with open('index.json') as f:
       idx = json.load(f)
   print(f'Skills in index: {len(idx)}')
   "
   ```
3. Test a sample of skills via `search_skills` and compare output to expected results.

### Contain
1. If skill library tampering is confirmed, fleet-halt and rebuild from a verified Git commit.
2. If the compromise is in the Anthropic model (not the skill library), the scope is limited to Anthropic's infrastructure — report to Anthropic and monitor.

### Eradicate
1. `git bisect` to identify the commit that introduced the poisoned content.
2. Remove the poisoned skills/content and rebuild `index.json` via CI.
3. Rebuild and push a new Docker image from the clean commit.

### Recover
1. Redeploy from the clean image.
2. Add skill content integrity checks to the CI `validate-skills.yml` workflow.

---

## Escalation Thresholds

| Signal | Automated Action | Human Action Required |
|---|---|---|
| Injection pattern matched (single) | L1 alert to CloudWatch | Review log within 4 hours |
| Write rate ≥ 10× baseline | L2 auto-throttle (503 returned) | Page on-call; investigate within 30 min |
| Injection + external call within 60s | L3 autonomous kill + credential rotation | Declare incident; execute Playbook 1 + 4 |
| Admin `--throttle` command issued | Service returns 503 | Review + redeploy within 2 hours |
| Admin `--reason` kill issued | Credential rotated + SIGTERM | Declare incident; execute relevant playbook |

---

## Artifact Index

| File | Contents |
|---|---|
| `security/ir-playbook-prompt-injection.json` | Generic PICERL steps — LLM01:2025 |
| `security/ir-playbook-goal-hijacking.json` | Generic PICERL steps — ASI01:2026 |
| `security/ir-playbook-mcp-compromise.json` | Generic PICERL steps — MCP01 |
| `security/ir-playbook-rogue-agent.json` | Generic PICERL steps — ASI10:2026 |
| `security/ir-playbook-data-exfiltration.json` | Generic PICERL steps — LLM06:2025 |
| `security/ir-playbook-model-poisoning.json` | Generic PICERL steps — LLM04:2025 |
| `security/kill-switch-phantom-mcp/kill_agent.py` | Emergency kill / throttle CLI |
| `security/kill-switch-phantom-mcp/kill_switch.py` | Kill switch registry + credential rotation |
| `security/kill-switch-phantom-mcp/graduated_response.py` | Automated graduated response controller |

---

## Sign-off

- [ ] Security team review
- [ ] Engineering lead review  
- [ ] Distributed to all on-call engineers
- [ ] Added to onboarding checklist for new team members
