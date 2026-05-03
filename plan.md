# Phantom Org-Wide Distribution Plan

## Context

Developers across the organization work in their own separate repos (React, Python, Java, etc.).
Phantom is a shared cybersecurity capability — not a tool developers need to clone or manage.
The goal is to make `/audit`, `/threat`, and `/remediate` available in every developer's Claude Code
session regardless of which project they are working in, with zero setup on their part.

---

## Architecture

### What this repo becomes

A **backend service repo** maintained by the security team:
- `mcp/phantom_mcp_server.py` is deployed as a central HTTP service
- `.claude/commands/` is the source of truth for org-level slash commands
- Developers never clone this repo or know it exists

### What developers get automatically

| Capability | How it reaches them |
|---|---|
| `/audit` slash command | Org-level command via Claude Code Enterprise admin console |
| `/threat` slash command | Org-level command via Claude Code Enterprise admin console |
| `/remediate` slash command | Org-level command via Claude Code Enterprise admin console |
| `mcp__phantom-skills__*` tools | Centrally-hosted Phantom MCP server registered at org level |
| `mcp__cve-intel__*` tools | Centrally-hosted cve-intel MCP server registered at org level |
| Billing / API key | Managed by org enterprise account — no personal API key needed |

---

## Infrastructure steps (security team actions)

### 1. Deploy Phantom MCP server as a central HTTP service
- Host `mcp/phantom_mcp_server.py` on internal infrastructure (EC2, Cloud Run, internal Kubernetes, etc.)
- Expose via HTTPS on an internal hostname (e.g., `https://phantom-mcp.internal`)
- The server reads `index.json` at startup — keep this repo's `index.json` accessible to it (mount as volume or bake into image)
- No extra Python dependencies beyond stdlib

### 2. Deploy cve-intel MCP server centrally
- Clone `https://github.com/mukul975/cve-mcp-server`
- `pip install -e .` and run `python3 -m cve_mcp.server` as a service
- Expose on internal hostname (e.g., `https://cve-intel-mcp.internal`)
- SQLite cache (`~/.cache/cve_mcp/vuln_cache.db`) should persist across restarts (mount a volume)

### 3. Register both MCP servers at org level in Claude Code Enterprise admin console
- Type: `http`
- URLs: internal hostnames from steps 1 and 2
- Scope: organization-wide (all users, all projects)

### 4. Register slash commands at org level
- Upload `audit.md`, `threat.md`, `remediate.md` as org-level Claude Code commands
- These become available to every developer in every project automatically

### 5. Update `.mcp.json` in this repo
Change from local process to remote HTTP for both servers:
```json
{
  "mcpServers": {
    "phantom-skills": {
      "type": "http",
      "url": "https://phantom-mcp.internal"
    },
    "cve-intel": {
      "type": "http",
      "url": "https://cve-intel-mcp.internal"
    }
  }
}
```
This keeps local development working for the security team using this repo directly.

---

## Developer experience (zero setup)

1. Developer opens any project in Claude Code
2. Types `/threat` — Claude analyzes their code for STRIDE + MAESTRO + OWASP threats
3. Behind the scenes, Claude calls the centrally-hosted Phantom MCP server to load relevant skills
4. Types `/remediate` — Claude guides them through fixing findings using Phantom skill knowledge
5. Types `/audit` — Claude audits their dependencies across all detected ecosystems

No cloning. No API key. No configuration.

---

## Maintenance (security team)

| Task | Frequency |
|---|---|
| Add new skills to the library | As needed — redeploy MCP server image or restart service |
| Update slash commands | Push changes to `.claude/commands/` and re-upload to Enterprise admin |
| Update `index.json` | Automatic via CI on merge to main |
| Rotate cve-intel API keys | Per cve-mcp-server documentation |
