# MCP Servers — setup & troubleshooting reference

On-demand detail for the 7 MCP servers in `.mcp.json`. The root `CLAUDE.md` carries the
server table + verifying-load note; this file has the per-server setup. For the server
*code* internals, see `mcp/CLAUDE.md`. Servers fail closed when their backend is
unreachable, so the full set is safe to leave registered (ADR-0007).

**Verifying load:** run `/mcp` in any session started from the repo root. Each server should
show `connected` with its tool count; `failed` entries link to the server's stderr log.

## phantom-skills
Exposes the skill library as 6 tools: `search_skills`, `load_skill`, `run_skill_agent`,
`list_subdomains`, `search_soc_skills`, `get_platform_adapted_skill`.
Registration: `{ "command": "python3", "args": ["mcp/phantom_mcp_server.py"] }`.

**Dependency: the `mcp` Python SDK.** `mcp/phantom_mcp_server.py` imports `mcp.server`. On a
fresh checkout the import succeeds as a namespace package but `mcp.server.Server` is missing,
so the server fails to start with a silent stderr log. Install into **whichever Python
`.mcp.json`'s `python3` resolves to** (`which python3` from the launching shell):
```bash
# Homebrew / PEP 668-managed Python:
python3 -m pip install --break-system-packages mcp
# Other environments (asdf, pyenv, plain pip):
python3 -m pip install mcp
# Verify:
python3 -c "from mcp.server import Server; print('OK')"
```
Using a venv requires editing `.mcp.json` to point at `.venv/bin/python` — a committed file,
so changes affect all teammates. Once installed, `/mcp` shows `phantom-skills connected 6 tools`.

**subdomain/tags:** the server builds a *rich index* by parsing each `SKILL.md`'s frontmatter
at startup (`_build_rich_index`), so `search_skills`/`list_subdomains` report real subdomains and
tags. `index.json` also carries `subdomain` + `tags` (see `mcp/CLAUDE.md`), used as a fast
description fallback.

**Troubleshooting:**
| Symptom | Cause | Fix |
|---|---|---|
| `phantom-skills failed` in `/mcp` | `mcp.server` not importable in launching Python | Re-run install in the right Python (`which python3` first) |
| Tools return errors | `ANTHROPIC_API_KEY` not exported in launching shell | `export ANTHROPIC_API_KEY=sk-ant-...`, relaunch |
| Tools list empty / wrong cwd | `claude` launched outside project root | `cd` to repo root first |
| `pip install` blocked (PEP 668) | System-managed Python | Add `--break-system-packages` |

## cve-intel (mukul975/cve-mcp-server)
27-tool server for live CVE intelligence: NVD lookup, EPSS, CISA KEV, PoC detection, Shodan
exposure, ATT&CK mapping, composite risk scoring.
```bash
git clone https://github.com/mukul975/cve-mcp-server ~/Desktop/cve-mcp-server
cd ~/Desktop/cve-mcp-server && pip install -e .
```
Registration: `{ "command": "python3", "args": ["-m", "cve_mcp.server"] }`. Pre-fetches the CISA
KEV catalog on boot; caches API responses in SQLite (`~/.cache/cve_mcp/vuln_cache.db`).
**Risk formula:** EPSS 35% + KEV 30% + CVSS 20% + PoC 15%; ×1.5 when both KEV and PoC present.

## defectdojo
Triages/updates DefectDojo findings — 8 tools: `dd_list_findings`, `dd_get_finding`,
`dd_update_finding` (PATCH any field), `dd_add_note`, `dd_list_products`, `dd_list_engagements`,
`dd_weekly_activity`, `dd_get_metrics`.
```bash
export DEFECTDOJO_URL=https://defectdojo.example.com
export DEFECTDOJO_API_KEY=<token>     # production credential — rotate routinely
```
`.mcp.json` defaults point at `localhost:8080` / empty key — override via shell env, **never
embed the token** (it's committed).

## jira
Creates/tracks security tickets — 6 tools: `jira_create_issue`, `jira_search`, `jira_get_issue`,
`jira_add_comment`, `jira_transition_issue`, `jira_weekly_activity`.
```bash
export JIRA_URL=https://[org].atlassian.net
export JIRA_USER=<email>
export JIRA_TOKEN=<api-token>
export JIRA_PROJECT_KEY=SEC     # default project key; override per call
```

## infra · dast · burp-pentest
| Server | Tool prefix | Notes |
|---|---|---|
| `infra` | `kubectl_*`, `aws_*`, `terraform_*`, `helm_*`, `write_manifest` | Executes against local AWS/k8s credentials. **Production-capable** — every `aws_run` / `kubectl_apply` is a real action. |
| `dast` | `dast_*`, `zap_*`, `burp_*` | Requires ZAP at `localhost:8080` and/or Burp at `localhost:1337` (`ZAP_API_KEY` / `BURP_API_KEY`). |
| `burp-pentest` | `burp_*` | Requires the custom Burp extension at `127.0.0.1:9877`. See `burp-extension/` if present. |
