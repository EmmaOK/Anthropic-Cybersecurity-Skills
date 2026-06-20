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
| `phishing.py` | Autonomous phishing-email investigator |
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
