#!/usr/bin/env python3
"""
phantom_sdk.py — Phantom as an autonomous agent on the Claude Agent SDK (SPIKE)

This is a proof-of-concept port of Phantom onto the Claude Agent SDK. Where the
current main.py hand-rolls the agent loop (run_turn), tool router (dispatch_tool),
threaded orchestrator, sessions, and approvals, this spike lets the SDK own all of
that and keeps only Phantom's unique value:

    KEPT  (domain logic, imported unchanged):
        skill_loader.search_skills / load_skill   — the 800+ skill library
        executor.run_agent                         — runs a skill's agent.py
        kali.run_on_kali / kali_docker.run_in_container — real tool execution

    REPLACED BY THE SDK (deleted plumbing):
        run_turn() while-loop      -> query() managed loop + max_turns
        dispatch_tool() router     -> @tool functions, SDK routes calls
        orchestrator.py threads    -> agents={...} AgentDefinition subagents
        approvals.py + confirm     -> can_use_tool() permission callback
        session save/load JSON     -> SDK resume / continue_conversation

Assign it a task (run with the dedicated venv interpreter — see Requirements):
    export ANTHROPIC_API_KEY=sk-...
    phantom/.venv/bin/python phantom/phantom_sdk.py "pentest" --scope 10.10.10.0/24
    phantom/.venv/bin/python phantom/phantom_sdk.py "enum web surface" --scope 10.10.10.5 --executor docker

Safety (the can_use_tool gate is the in-code boundary; see make_gate):
    - Any tool that is not an explicit Phantom tool (e.g. raw Bash) is DENIED.
    - Command substitution ($(...), backticks, ${...}) is DENIED — it can hide
      binaries/targets from the static check.
    - EVERY binary across pipe/chain segments (;, &&, ||, |, &) must be on the
      allowlist (or a pure text filter), not just the first one.
    - Exploit-class tools (msfconsole, sqlmap, hydra, ...) are DENIED unless --allow-exploit.
    - Scope is enforced on IPs, CIDRs (the whole range must be a subnet of the scope),
      and hostnames (URL/scheme/user@ positions and bare FQDNs).

    Known residual gaps (still spike-grade — tighten before real use): output
    redirection targets (`> /etc/x`) are not checked; a host whose final label is a
    real ccTLD that overlaps a file extension (e.g. .sh) is treated as a file; and an
    obfuscated/unparseable target can fail open. IP/CIDR scoping is the authoritative
    control — keep targets IP-based for unattended runs.

Requirements:
    The system Homebrew Python is broken (pyexpat/platform), so the SDK lives in a
    dedicated uv-managed venv. Set up / verify with:
        uv venv phantom/.venv --python 3.12
        uv pip install --python phantom/.venv/bin/python claude-agent-sdk anthropic
    The Claude Code CLI runtime (Node.js) is also required and is already present.
    export ANTHROPIC_API_KEY=sk-...
Run `phantom/.venv/bin/python phantom/phantom_sdk.py --check` to verify first.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# --- make sibling phantom modules importable regardless of cwd ---------------
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# --- Phantom domain logic: imported UNCHANGED --------------------------------
from skill_loader import search_skills as _search_skills, load_skill as _load_skill
from executor import run_agent as _run_agent
import kali
import kali_docker

# --- Claude Agent SDK (the only new dependency) ------------------------------
try:
    from claude_agent_sdk import (
        query,
        ClaudeAgentOptions,
        AgentDefinition,
        tool,
        create_sdk_mcp_server,
        AssistantMessage,
        ResultMessage,
        TextBlock,
        ToolUseBlock,
    )
    from claude_agent_sdk.types import PermissionResultAllow, PermissionResultDeny
    _SDK_AVAILABLE = True
    _SDK_IMPORT_ERROR = ""
except Exception as e:  # noqa: BLE001 — surface any import problem as a friendly message
    _SDK_AVAILABLE = False
    _SDK_IMPORT_ERROR = str(e)

    # Fallback stubs so this module still imports (and --check works) without the SDK.
    # The real run path is guarded by _SDK_AVAILABLE and never reaches the SDK calls.
    def tool(name, description, input_schema, annotations=None):  # noqa: ANN001
        def _wrap(fn):
            fn._phantom_tool = (name, description, input_schema)
            return fn
        return _wrap

    def create_sdk_mcp_server(*a, **k):  # noqa: ANN002, ANN003
        raise RuntimeError("claude-agent-sdk not installed")

    def AgentDefinition(*a, **k):  # noqa: ANN002, ANN003, N802
        return None

    def query(*a, **k):  # noqa: ANN002, ANN003
        raise RuntimeError("claude-agent-sdk not installed")

    ClaudeAgentOptions = None
    AssistantMessage = ResultMessage = TextBlock = ToolUseBlock = tuple
    PermissionResultAllow = PermissionResultDeny = None

MODEL = "claude-opus-4-8"

# ---------------------------------------------------------------------------
# Scope & safety policy  (replaces approvals.py + the prompt-only confirmation)
# ---------------------------------------------------------------------------

# Pragmatic allowlist — recon/enumeration tools that are safe to run unattended.
RECON_BINARIES = {
    "nmap", "masscan", "amass", "subfinder", "dnsx", "httpx", "whatweb",
    "wafw00f", "nikto", "gobuster", "feroxbuster", "ffuf", "dig", "host",
    "whois", "curl", "ping", "arp-scan", "netdiscover", "nuclei", "ldapsearch",
    "netexec", "nbtscan", "enum4linux", "smbclient", "ssl-cert-check", "sslscan",
}
# Exploit-class — only permitted when --allow-exploit is set.
EXPLOIT_BINARIES = {
    "msfconsole", "msfvenom", "sqlmap", "hydra", "medusa", "commix", "wfuzz",
    "evil-winrm", "impacket-psexec", "impacket-secretsdump", "responder",
    "certipy-ad", "hashcat", "john", "bully", "reaver",
}
# Wrappers we strip to find the real binary.
_WRAPPERS = {"sudo", "doas", "env", "timeout", "stdbuf", "nice", "proxychains", "proxychains4"}

# Pure text-processing filters: they may appear in a pipeline without being treated
# as a "target" binary because they cannot reach the network or exec on their own.
# (xargs/exec/eval are deliberately excluded — they can launch arbitrary binaries.)
_SAFE_FILTERS = {
    "grep", "egrep", "fgrep", "awk", "gawk", "sed", "cut", "sort", "uniq",
    "head", "tail", "wc", "tr", "tee", "cat", "jq", "column", "rev", "nl",
}

# Octet-validated IPv4, optional CIDR suffix — avoids matching version-like 999.x tokens.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
_IPV4_RE = re.compile(rf"\b{_OCTET}(?:\.{_OCTET}){{3}}(?:/\d{{1,2}})?\b")
# Loose IPv6 candidate (validated by ipaddress before it counts as a target).
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?")
# FQDN token (labels + an alphabetic TLD).
_HOST_RE = re.compile(r"(?<![\w.@-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b")
# Host taken from a URL / scheme:// / user@ position (also catches bracketed IPv6).
_URL_HOST_RE = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*://|//|@)\[?([0-9A-Za-z._:-]+?)\]?(?:[:/?#]|$)")
# Command substitution can smuggle binaries/targets past static inspection.
_CMD_SUBST_RE = re.compile(r"\$\(|`|\$\{")
# Shell operators that start a new command (so each segment's binary is vetted).
_SEGMENT_SPLIT_RE = re.compile(r"&&|\|\||[|;&\n]")
# FQDN-looking tokens ending in these labels are treated as filenames, not targets.
_FILE_SUFFIXES = {
    "txt", "json", "xml", "html", "htm", "csv", "tsv", "md", "log", "conf", "cfg",
    "ini", "yaml", "yml", "pem", "key", "crt", "cer", "pcap", "cap", "gnmap", "nmap",
    "out", "tmp", "bak", "db", "sqlite", "sqlite3", "zip", "tar", "gz", "tgz", "lst",
}


@dataclass
class Scope:
    """Authorized engagement scope. Out-of-scope targets are denied at the gate."""
    networks: list = field(default_factory=list)   # list[ipaddress network]
    hostnames: list = field(default_factory=list)  # list[str] in-scope hostnames/domains
    allow_exploit: bool = False
    executor: str = "auto"   # auto | ssh | docker

    @classmethod
    def parse(cls, scope_args: list[str], allow_exploit: bool, executor: str) -> "Scope":
        nets, hosts = [], []
        for tok in scope_args:
            tok = tok.strip()
            if not tok:
                continue
            try:
                nets.append(ipaddress.ip_network(tok, strict=False))
            except ValueError:
                hosts.append(tok.lower())
        return cls(networks=nets, hostnames=hosts, allow_exploit=allow_exploit, executor=executor)

    def ip_in_scope(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(ip in net for net in self.networks)

    def target_in_scope(self, token: str) -> bool:
        """True only if an IP or CIDR token falls *entirely* within an authorized
        network. A single IP is treated as a /32 (or /128); a CIDR must be a subnet
        of an in-scope network, so a broad range can't slip past a narrow scope."""
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            return False
        return any(net.version == s.version and net.subnet_of(s) for s in self.networks)

    def host_in_scope(self, host: str) -> bool:
        host = host.lower()
        return any(host == h or host.endswith("." + h) for h in self.hostnames)

    def describe(self) -> str:
        parts = [str(n) for n in self.networks] + self.hostnames
        return ", ".join(parts) if parts else "(none — all kali commands will be denied)"


def _extract_binary(segment: str) -> str:
    """Return the real binary in a single command segment, skipping known wrappers."""
    for token in segment.strip().split():
        if "=" in token and not token.startswith("-"):
            continue  # VAR=value env assignment
        base = token.split("/")[-1]
        if base in _WRAPPERS or token.startswith("-"):
            continue
        return base
    return ""


def _binaries(command: str) -> list[str]:
    """Every binary invoked across pipe/chain segments — so a command like
    `nmap ... ; curl evil` or `nmap ... & wget evil` has *each* binary vetted,
    not just the first one."""
    out = []
    for seg in _SEGMENT_SPLIT_RE.split(command):
        b = _extract_binary(seg)
        if b:
            out.append(b)
    return out


def _is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def _candidate_hosts(command: str) -> list[str]:
    """Hostnames referenced as targets (URL/scheme/user@ positions and bare FQDNs).
    IP literals are excluded here — they are scope-checked separately."""
    hosts = set()
    for m in _URL_HOST_RE.findall(command):
        hosts.add(m.lower())
    for m in _HOST_RE.findall(command):
        hosts.add(m.lower())
    return [h for h in hosts if not _is_ip(h)]


def _scope_violation(command: str, scope: Scope) -> str | None:
    """Return a denial reason if any IP, CIDR, or hostname target in the command is
    out of scope, else None. Fails closed for IPs/CIDRs and for real-looking hosts;
    tokens that merely *look* like files (report.json) are not treated as targets."""
    for tok in _IPV4_RE.findall(command):
        if not scope.target_in_scope(tok):
            return f"{tok} is out of the authorized scope"

    for tok in _IPV6_RE.findall(command):
        base = tok.split("/")[0]
        try:                                  # only count tokens that truly parse as IPv6 —
            ipaddress.ip_address(base)        # avoids denying MACs / timestamps that share the shape
        except ValueError:
            try:
                ipaddress.ip_network(tok, strict=False)
            except ValueError:
                continue
        if not scope.target_in_scope(tok):
            return f"{tok} is out of the authorized scope"

    for host in _candidate_hosts(command):
        if scope.host_in_scope(host):
            continue
        if host.rsplit(".", 1)[-1] in _FILE_SUFFIXES:
            continue  # looks like a filename, not a network target
        return f"host '{host}' is out of the authorized scope"

    return None


def make_gate(scope: Scope, log):
    """
    Build the can_use_tool callback. This is the real, in-code safety boundary —
    it runs BEFORE any tool executes and can allow, rewrite, or deny.
    """
    phantom_tool_prefix = "mcp__phantom__"
    kali_tools = {phantom_tool_prefix + "kali_exec", phantom_tool_prefix + "kali_docker_exec"}

    async def gate(tool_name: str, input_data: dict, context):  # noqa: ANN001
        # 1. Lock the surface to Phantom tools + the Task tool (for subagent dispatch).
        if tool_name != "Task" and not tool_name.startswith(phantom_tool_prefix):
            log(f"DENY  {tool_name}  (not a Phantom tool — raw built-ins are off-limits in the spike)")
            return PermissionResultDeny(message=f"{tool_name} is not permitted; use Phantom tools only.")

        # 2. Kali command tools get substitution + per-segment allowlist + scope checks.
        if tool_name in kali_tools:
            command = (input_data or {}).get("command", "")

            # 2a. No command substitution — it can hide binaries/targets from static checks.
            if _CMD_SUBST_RE.search(command):
                log(f"DENY  (command substitution): {command[:80]}")
                return PermissionResultDeny(
                    message="Command substitution ($(...), backticks, ${...}) is not permitted."
                )

            # 2b. Every binary across pipes/chains must be on the allowlist (or a safe filter).
            binaries = _binaries(command)
            if not binaries:
                return PermissionResultDeny(message="Empty or unparseable command.")

            for binary in binaries:
                if binary in _SAFE_FILTERS:
                    continue
                if binary in EXPLOIT_BINARIES and not scope.allow_exploit:
                    log(f"DENY  {binary}  (exploit-class; run with --allow-exploit to permit)")
                    return PermissionResultDeny(
                        message=f"'{binary}' is an exploit-class tool, denied unless --allow-exploit is set."
                    )
                if binary not in RECON_BINARIES and binary not in EXPLOIT_BINARIES:
                    log(f"DENY  {binary}  (not on the allowlist)")
                    return PermissionResultDeny(
                        message=f"'{binary}' is not on the approved tool allowlist."
                    )

            # 2c. Every IP, CIDR, and hostname target must be within the authorized scope.
            violation = _scope_violation(command, scope)
            if violation:
                log(f"DENY  {violation}  (scope: {scope.describe()})")
                return PermissionResultDeny(
                    message=f"{violation} (authorized scope: {scope.describe()})."
                )

            log(f"ALLOW {' | '.join(binaries)}  | {command[:80]}")
            return PermissionResultAllow(updated_input=input_data)

        # 3. Everything else Phantom-namespaced (search/load/run/write) is allowed.
        return PermissionResultAllow(updated_input=input_data)

    return gate


# ---------------------------------------------------------------------------
# Tools  (tools.py dicts -> @tool functions; the bodies call UNCHANGED modules)
# ---------------------------------------------------------------------------

@tool("search_skills", "Search the 800+ cybersecurity skill library by keyword, tool, or ATT&CK ID.", {"query": str})
async def search_skills(args):  # noqa: ANN001
    hits = _search_skills(args["query"])
    lines = [f"- {h['name']}: {h.get('description', '')[:140]}" for h in hits] or ["(no matches)"]
    return {"content": [{"type": "text", "text": "\n".join(lines)}]}


@tool("load_skill", "Load the full workflow/commands for a skill by its exact kebab-case name.", {"skill_name": str})
async def load_skill(args):  # noqa: ANN001
    content = _load_skill(args["skill_name"])
    if len(content) > 8000:
        content = content[:8000] + "\n\n[... truncated for context efficiency ...]"
    return {"content": [{"type": "text", "text": content}]}


@tool("run_skill_agent", "Execute a skill's agent.py script. Args is a list of CLI arguments.",
      {"skill_name": str, "args": list})
async def run_skill_agent(args):  # noqa: ANN001
    out = _run_agent(args["skill_name"], args.get("args", []))
    return {"content": [{"type": "text", "text": out}]}


@tool("kali_exec", "Run a security tool on the Kali VM via SSH. Gated by the scope/allowlist policy.",
      {"command": str, "timeout": int})
async def kali_exec(args):  # noqa: ANN001
    if not kali.kali_reachable():
        return {"content": [{"type": "text", "text": "[Error] Kali VM unreachable."}], "is_error": True}
    r = kali.run_on_kali(args["command"], timeout=int(args.get("timeout", 120)))
    return _exec_result(r)


@tool("kali_docker_exec", "Run a security tool in an ephemeral Kali container. Gated by the scope/allowlist policy.",
      {"command": str, "timeout": int})
async def kali_docker_exec(args):  # noqa: ANN001
    if not kali_docker.docker_available():
        return {"content": [{"type": "text", "text": "[Error] Docker not available."}], "is_error": True}
    r = kali_docker.run_in_container(args["command"], timeout=int(args.get("timeout", 120)))
    return _exec_result(r)


@tool("write_report", "Write a report/artifact under reports/. Path is relative to reports/.",
      {"path": str, "content": str})
async def write_report(args):  # noqa: ANN001
    reports = ROOT / "reports"
    target = (reports / args["path"]).resolve()
    if not str(target).startswith(str(reports.resolve())):
        return {"content": [{"type": "text", "text": "[Error] Path escapes reports/."}], "is_error": True}
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(args["content"], encoding="utf-8")
    return {"content": [{"type": "text", "text": f"Wrote {target}"}]}


def _exec_result(r: dict) -> dict:
    """Map a kali/docker result dict to an SDK tool result, flagging failures with is_error."""
    if r.get("error"):
        return {"content": [{"type": "text", "text": f"[Error] {r['error']}"}], "is_error": True}
    out = r.get("stdout", "")
    if r.get("stderr"):
        out += f"\n[stderr]\n{r['stderr']}"
    if r.get("exit_code"):
        out += f"\n[exit {r['exit_code']}]"
    return {"content": [{"type": "text", "text": out.strip() or "[no output]"}]}


PHANTOM_TOOL_NAMES = [
    "search_skills", "load_skill", "run_skill_agent",
    "kali_exec", "kali_docker_exec", "write_report",
]
ALL_TOOLS = [search_skills, load_skill, run_skill_agent, kali_exec, kali_docker_exec, write_report]


def _qualified(names: list[str]) -> list[str]:
    return [f"mcp__phantom__{n}" for n in names]


# ---------------------------------------------------------------------------
# Specialist subagents  (orchestrator.py's 6 threads -> AgentDefinitions)
# ---------------------------------------------------------------------------

RECON_TOOLS = _qualified(["search_skills", "load_skill", "kali_exec", "kali_docker_exec"])
ASSESS_TOOLS = _qualified(["search_skills", "load_skill", "run_skill_agent", "kali_exec", "kali_docker_exec"])
REPORT_TOOLS = _qualified(["search_skills", "load_skill", "write_report"])


def build_specialists() -> dict:
    return {
        "recon": AgentDefinition(
            description="Reconnaissance & discovery: hosts, ports, services, subdomains, web fingerprints.",
            prompt=(
                "You are a recon specialist. Discover hosts, open ports, services, subdomains, and web "
                "surfaces using nmap/httpx/subfinder/whatweb via kali_exec. Search the skill library for the "
                "right procedure first. Stay strictly within the authorized scope. "
                "Report findings as concise JSON: {hosts, services, open_ports, web_endpoints, notes}."
            ),
            tools=RECON_TOOLS, model=MODEL, maxTurns=12,
        ),
        "webapp": AgentDefinition(
            description="Web application security testing of discovered HTTP services.",
            prompt=(
                "You are a web app testing specialist. For each in-scope web endpoint, load the relevant "
                "skill (e.g. OWASP testing skills) and run nuclei/nikto/gobuster via kali_exec. "
                "Report findings JSON: [{title, severity, url, evidence, cve, remediation}]."
            ),
            tools=ASSESS_TOOLS, model=MODEL, maxTurns=12,
        ),
        "ad": AgentDefinition(
            description="Active Directory / Windows network enumeration and attack-path analysis.",
            prompt=(
                "You are an Active Directory specialist. For in-scope SMB/LDAP/WinRM hosts, enumerate with "
                "netexec/ldapsearch via kali_exec and consult the skill library. Map findings to ATT&CK IDs. "
                "Report JSON: {findings, attack_paths, credentials_obtained}."
            ),
            tools=ASSESS_TOOLS, model=MODEL, maxTurns=12,
        ),
        "reporting": AgentDefinition(
            description="Aggregate all specialist findings into a final assessment report.",
            prompt=(
                "You are the reporting specialist. Aggregate every finding into a structured report: "
                "executive summary, scope, methodology, findings by severity, ATT&CK coverage, prioritized "
                "remediation, and per-finding reproduction steps. Save both JSON and Markdown via write_report."
            ),
            tools=REPORT_TOOLS, model=MODEL, maxTurns=10,
        ),
    }


COORDINATOR_PROMPT = (
    "You are Phantom Coordinator, an autonomous security engagement lead. You are given a high-level task "
    "and an authorized scope. Plan the engagement, then delegate to your specialist subagents (recon, webapp, "
    "ad, reporting) using the Task tool — recon first, then assessment specialists based on what recon finds, "
    "and finally the reporting specialist to aggregate everything. Use search_skills/load_skill to ground each "
    "step in the library's procedures. NEVER act outside the authorized scope. Every finding in the final "
    "report must include reproduction steps. This is for authorized lab/test environments only."
)


# ---------------------------------------------------------------------------
# Options + run
# ---------------------------------------------------------------------------

def build_options(scope: Scope, log):
    phantom_server = create_sdk_mcp_server(name="phantom", version="1.0", tools=ALL_TOOLS)
    return ClaudeAgentOptions(
        system_prompt=COORDINATOR_PROMPT,
        model=MODEL,
        mcp_servers={"phantom": phantom_server},
        allowed_tools=["Task", *_qualified(PHANTOM_TOOL_NAMES)],
        can_use_tool=make_gate(scope, log),
        agents=build_specialists(),
        max_turns=40,            # hard cap — fixes the unbounded run_turn() loop
        permission_mode="default",
        setting_sources=[],      # ignore repo CLAUDE.md/settings for a clean spike surface
        cwd=str(ROOT),
    )


async def run_task(task: str, scope: Scope) -> int:
    def log(msg: str) -> None:
        print(f"  [gate] {msg}")

    prompt = (
        f"TASK: {task}\n"
        f"AUTHORIZED SCOPE: {scope.describe()}\n"
        f"Exploit tools permitted: {scope.allow_exploit}\n"
        f"Carry out the task end-to-end, delegating to specialists, then produce the final report."
    )
    options = build_options(scope, log)

    print(f"\n=== Phantom (Agent SDK spike) ===\nTask : {task}\nScope: {scope.describe()}\n")
    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock) and block.text.strip():
                    print(f"\nPhantom: {block.text.strip()}")
                elif isinstance(block, ToolUseBlock):
                    print(f"  [tool] {block.name}")
        elif isinstance(message, ResultMessage):
            cost = f"${message.total_cost_usd:.4f}" if message.total_cost_usd else "n/a"
            print(f"\n=== done in {message.num_turns} turns | cost {cost} | error={message.is_error} ===")
            return 1 if message.is_error else 0
    return 0


# ---------------------------------------------------------------------------
# Environment check + CLI
# ---------------------------------------------------------------------------

def check_env() -> int:
    print("Phantom Agent SDK spike — environment check\n")
    ok = True
    if _SDK_AVAILABLE:
        print("  [ok]   claude-agent-sdk importable")
    else:
        ok = False
        print(f"  [FAIL] claude-agent-sdk not importable: {_SDK_IMPORT_ERROR}")
        print("         -> pip install claude-agent-sdk  (and install the Claude Code CLI / Node.js)")
    import os
    print(f"  [{'ok' if os.environ.get('ANTHROPIC_API_KEY') else 'FAIL'}]   ANTHROPIC_API_KEY set")
    print(f"  [info] Kali VM reachable : {kali.kali_reachable() if _safe(kali.kali_reachable) else 'n/a'}")
    print(f"  [info] Docker available  : {kali_docker.docker_available()}")
    print(f"  [info] skill library     : {len(_search_skills('a') ) >= 0 and 'loaded'}")
    return 0 if ok else 1


def _safe(fn):
    try:
        return fn()
    except Exception:
        return False


def main() -> int:
    p = argparse.ArgumentParser(description="Phantom autonomous security agent (Claude Agent SDK spike)")
    p.add_argument("task", nargs="?", help='High-level task, e.g. "pentest" or "enumerate web surface"')
    p.add_argument("--scope", nargs="+", default=[], help="Authorized targets: CIDRs, IPs, or hostnames")
    p.add_argument("--allow-exploit", action="store_true", help="Permit exploit-class tools (off by default)")
    p.add_argument("--executor", choices=["auto", "ssh", "docker"], default="auto")
    p.add_argument("--check", action="store_true", help="Verify environment and exit")
    args = p.parse_args()

    if args.check:
        return check_env()

    if not _SDK_AVAILABLE:
        print(f"[Error] claude-agent-sdk not installed: {_SDK_IMPORT_ERROR}")
        print("Run: pip install claude-agent-sdk   (then: python phantom/phantom_sdk.py --check)")
        return 1
    if not args.task:
        p.error("a task is required (or use --check)")
    if not args.scope:
        print("[Error] --scope is required: without it every kali command is denied. "
              'Example: --scope 10.10.10.0/24')
        return 1

    scope = Scope.parse(args.scope, allow_exploit=args.allow_exploit, executor=args.executor)
    return asyncio.run(run_task(args.task, scope))


if __name__ == "__main__":
    sys.exit(main())
