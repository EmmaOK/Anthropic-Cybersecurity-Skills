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

## Available tools

| Tool | What it does |
|---|---|
| `search_skills` | Search 800+ skills by keyword, subdomain, or tag |
| `load_skill` | Get the full SKILL.md for a specific skill |
| `run_skill_agent` | Execute a skill's agent.py (audits, threat models, etc.) |
| `list_subdomains` | See all skill domains with counts |
| `search_soc_skills` | SOC-filtered search (threat intel, IR, hunting) |
| `get_platform_adapted_skill` | Load skill with Wazuh/OpenSearch/TheHive context injected |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `phantom-skills failed` in `/mcp` | Check `PHANTOM_MCP_KEY` is exported in the shell that launched Claude Code |
| 401 Unauthorized | API key expired or wrong — re-retrieve from Secrets Manager |
| `mcp-remote: command not found` | Run `npm install -g mcp-remote` |
| Connection timeout | Confirm VPN is connected (ALB is internal-only) |
