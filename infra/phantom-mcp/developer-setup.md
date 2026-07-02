# Phantom MCP — Developer Setup

## One-time setup (5 minutes)

**Prerequisite:** VPN connected to reach the internal ALB (10.0.0.0/16 network).

### 1. Get your API key (requires AWS SSO access)

```bash
aws sso login --sso-session kiro-cli

aws secretsmanager get-secret-value \
  --secret-id phantom-mcp/production/api-key \
  --query SecretString --output text \
  --profile AdministratorAccess-[AWS-ACCOUNT-ID]
```

Add the key to your shell profile:
```bash
echo 'export PHANTOM_MCP_KEY="<paste-key-here>"' >> ~/.zshrc
source ~/.zshrc
```

### 2. Install mcp-remote (requires Node.js 18+)

```bash
npm install -g mcp-remote
```

Verify:
```bash
npx mcp-remote --version
```

### 3. Add to your project's .mcp.json

```json
{
  "mcpServers": {
    "phantom-skills": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://phantom-mcp.tstsecurity.[org].engineering/sse"
      ],
      "env": {
        "MCP_REMOTE_HEADER_AUTHORIZATION": "Bearer ${PHANTOM_MCP_KEY}"
      }
    }
  }
}
```

Or add it to the **shared commands repo** submodule so the config is automatic across all projects.

### 4. Verify in Claude Code

Start Claude Code from your project directory and run:
```
/mcp
```

You should see `phantom-skills connected 6 tools`.

Test it:
```
search_skills("prompt injection")
```

---

## Available tools (Claude Code / MCP)

| Tool | What it does |
|---|---|
| `search_skills` | Search 841+ skills by keyword, subdomain, or tag |
| `load_skill` | Get the full SKILL.md for a specific skill |
| `run_skill_agent` | Execute a skill's agent.py (audits, threat models, etc.) |
| `list_subdomains` | See all skill domains with counts |
| `search_soc_skills` | SOC-filtered search (threat intel, IR, hunting) |
| `get_platform_adapted_skill` | Load skill with Wazuh/OpenSearch/TheHive context injected |

---

## Assigning tasks to Phantom (autonomous mode)

Phantom can now run security tasks autonomously via the `/tasks` HTTP API.
You send a plain-language task and Phantom plans, finds relevant skills, and executes
API-based skill scripts end-to-end without you staying in the loop.

**Base URL:** `https://phantom-mcp.tstsecurity.[org].engineering`
**Auth:** `Authorization: Bearer $PHANTOM_MCP_KEY` (same key as above)

### Submit a task

```bash
curl -s -X POST \
  -H "Authorization: Bearer $PHANTOM_MCP_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "task": "Audit the AWS account for public S3 buckets and report findings",
    "scope": ["<AWS_ACCOUNT_ID>"]
  }' \
  https://phantom-mcp.tstsecurity.[org].engineering/tasks
```

Response (202 Accepted):
```json
{
  "job_id":     "a1b2c3d4-...",
  "status":     "pending",
  "poll_url":   "/tasks/a1b2c3d4-...",
  "stream_url": "/tasks/a1b2c3d4-.../stream"
}
```

### Poll for status

```bash
curl -s \
  -H "Authorization: Bearer $PHANTOM_MCP_KEY" \
  https://phantom-mcp.tstsecurity.[org].engineering/tasks/a1b2c3d4-...
```

Returns `status` (`pending` → `running` → `completed` / `failed`), `result`, `turns`, `elapsed_s`, and `event_count`.

### Stream live events (SSE)

```bash
curl -s \
  -H "Authorization: Bearer $PHANTOM_MCP_KEY" \
  -H "Accept: text/event-stream" \
  https://phantom-mcp.tstsecurity.[org].engineering/tasks/a1b2c3d4-.../stream
```

Each `data:` line is a JSON event:

| Event type | Meaning |
|---|---|
| `start` | Task accepted and agent starting |
| `turn` | Agent starting turn N of max 20 |
| `message` | Text the agent emitted this turn |
| `tool_call` | Agent is about to call a skill tool |
| `tool_result` | Tool returned (preview of first 400 chars) |
| `done` | Task complete — `result` field has the final report |
| `error` | Agent failed — `error` field has the reason |
| `stream_end` | Stream closing (task reached terminal state) |

### List all tasks (your team's queue)

```bash
curl -s \
  -H "Authorization: Bearer $PHANTOM_MCP_KEY" \
  https://phantom-mcp.tstsecurity.[org].engineering/tasks
```

### What Phantom can do autonomously

Phantom uses API-based skills (~564 of 841). Good task types:

- AWS security audits (Inspector findings, CloudTrail forensics, IAM analysis, public S3/EBS)
- Threat intelligence lookups (CVE research, IOC enrichment, MISP queries)
- Certificate transparency monitoring and phishing domain detection
- Vulnerability management reporting (Inspector deltas, KEV checks)
- Cloud misconfiguration checks (Security Hub, GuardDuty findings)

Skills requiring `nmap`, `kali`, or system tools are not yet available in autonomous mode
(Kali execution backend is the next phase).

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `phantom-skills failed` in `/mcp` | Check `PHANTOM_MCP_KEY` is exported in the shell that launched Claude Code |
| 401 Unauthorized | API key expired or wrong — re-retrieve from Secrets Manager |
| `mcp-remote: command not found` | Run `npm install -g mcp-remote` |
| Connection timeout | Confirm VPN is connected (ALB is internal-only) |
| `/tasks` returns 503 | `ANTHROPIC_API_KEY` not set in the container — check Secrets Manager and redeploy |
| Task stuck in `running` | Check CloudWatch logs (`/ecs/phantom-mcp/production`) for the job_id |
