# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.
It is a **hub**: always-on engineering rules are imported below; subsystem and reference detail live
in the files linked under [Where things live](#where-things-live) and [Reference Docs](#reference-docs).

> **Counts in this file are approximate.** The library grows continuously, so exact numbers drift. For current figures run: `find skills -name SKILL.md | wc -l` (skills), `find skills -name agent.py | wc -l` (scripts), `grep -rl "subdomain: ai-security" skills | wc -l` (AI skills).

## Project Overview

**Display name: Cybersecurity Skills** (formerly Anthropic-Cybersecurity-Skills). The GitHub repo slug retains the original name. This is a community project, independently maintained, **not affiliated with Anthropic PBC**. Apache 2.0 licensed (ADR-0009).

A library of **800+ cybersecurity skills** for AI agents, mapped to 5 industry frameworks:
- **MITRE ATT&CK Enterprise** — offensive techniques (218 unique techniques, 100% of 14 tactics)
- **NIST Cybersecurity Framework 2.0** — risk management functions/categories
- **MITRE ATLAS v5.5** — AI-specific threats
- **MITRE D3FEND v1.3** — defensive countermeasures
- **NIST AI RMF 1.0** — AI risk management

Skills follow the `agentskills.io` open standard and are compatible with Claude Code, Cursor, GitHub Copilot, and 23+ other AI agent platforms (ADR-0001). ~50 skills cover four AI/agentic frameworks (OWASP LLM/MCP/Agentic Top 10s + MAESTRO) under `subdomain: ai-security` — full layer map and naming conventions are in [`skills/CLAUDE.md`](skills/CLAUDE.md).

## Where things live

| Area | Guide (loads when relevant) | What's there |
|---|---|---|
| Authoring skills | [`skills/CLAUDE.md`](skills/CLAUDE.md) | Directory structure, frontmatter schema, body sections, 26 subdomains, AI coverage + naming, how to add a skill/script, validation |
| Phantom agent | [`phantom/CLAUDE.md`](phantom/CLAUDE.md) | Module map, the two agent generations, the Agent SDK spike, venv/runtime situation |
| MCP server code | [`mcp/CLAUDE.md`](mcp/CLAUDE.md) | Server file map, `phantom_mcp_server` internals, the `mcp` SDK dependency, rich index |
| Engineering rules | [`.claude/conventions.md`](.claude/conventions.md) | Security conventions, generated files, CI workflows (imported below — always on) |
| Decisions (the *why*) | [`docs/DECISIONS.md`](docs/DECISIONS.md) | Architecture Decision Record |

Generated files (never hand-edit): `index.json`, `mappings/attack-navigator-layer.json`, `.claude-plugin/marketplace.json`. Details in [`.claude/conventions.md`](.claude/conventions.md).

## Key Commands

**Validate skills** (mirrors CI): logic is inline in `.github/workflows/validate-skills.yml`; extract and run the embedded Python. See [`skills/CLAUDE.md`](skills/CLAUDE.md).

**Regenerate `index.json`** (mirrors CI): logic is inline in `.github/workflows/update-index.yml`. Run manually or trigger via GitHub Actions (`workflow_dispatch`).

**Run the Phantom Agent:**
```bash
cd phantom
pip install anthropic
export ANTHROPIC_API_KEY=sk-...
python main.py
```
In-REPL slash commands: `/mode <name>`, `/modes`, `/save`, `/load`, `/sessions`, `exit`. (The Agent SDK spike `phantom_sdk.py` runs differently — see [`phantom/CLAUDE.md`](phantom/CLAUDE.md).)

## MCP Servers

Seven MCP servers are registered in `.mcp.json` and load automatically when Claude Code is launched from this directory. They **fail closed** when their backend is unreachable — safe to leave registered (ADR-0007). Per-server setup & troubleshooting: [`.claude/mcp-servers.md`](.claude/mcp-servers.md). Server code internals: [`mcp/CLAUDE.md`](mcp/CLAUDE.md).

| Server | Tools | Backend required |
|---|---|---|
| `phantom-skills` | 6 | Skill library only (this repo) |
| `cve-intel` | 27 | External clone at `~/Desktop/cve-mcp-server` |
| `defectdojo` | 8 | A reachable DefectDojo instance (env vars) |
| `jira` | 6 | A reachable Jira (env vars) |
| `infra` | 13 | `kubectl`, `aws`, `terraform`, `helm` on PATH — **production-capable** |
| `dast` | 11 | OWASP ZAP and/or Burp running locally |
| `burp-pentest` | 10 | Burp Suite Pro extension at `127.0.0.1:9877` |

**Verifying load:** run `/mcp` in any session started from this dir; each server should show `connected` with its tool count. Secrets come from shell env vars — never embed tokens (`.mcp.json` is committed).

@.claude/conventions.md

## Reference Docs
- **[docs/DECISIONS.md](docs/DECISIONS.md)** — Architecture Decision Record: the *why* behind the taxonomy, naming, CI, security, and Phantom choices. Read before reversing a convention; add an ADR when making a non-obvious decision.
- **[docs/SCRIPTS.md](docs/SCRIPTS.md)** — full catalog of runnable `agent.py` scripts by category, with invocation examples (AI red-teaming, threat modeling, MAESTRO auditing, SOC/SIEM, AWS VM pipeline, API security).
- **[docs/DVMCP.md](docs/DVMCP.md)** — testing skills against the Damn Vulnerable MCP Server (`examples/dvmcp/`).
- **[.claude/mcp-servers.md](.claude/mcp-servers.md)** — per-server MCP setup & troubleshooting.
- Subsystem guides: [`skills/CLAUDE.md`](skills/CLAUDE.md), [`phantom/CLAUDE.md`](phantom/CLAUDE.md), [`mcp/CLAUDE.md`](mcp/CLAUDE.md) — auto-load when you work in those directories.
