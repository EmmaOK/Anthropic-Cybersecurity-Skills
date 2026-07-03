#!/usr/bin/env python3
"""
phantom_task_runner.py — Autonomous task agent for the /tasks HTTP endpoint.

Accepts a natural-language security task and runs a multi-turn Claude Opus agent
loop that searches the 841-skill library, loads workflows, and executes API-based
skill scripts to complete the task end-to-end.

The agent stores task state in memory (per-process) and emits structured events
that are replayed to SSE stream subscribers.

Usage (internal — called from phantom_http_server.py):
    task = create_task("audit all public S3 buckets", scope=["550262670357"])
    asyncio.create_task(run_task_agent(task))
    # poll: get_task(task.job_id)
    # stream: iterate task.events[cursor:]
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Skill library functions — re-used from the MCP server module
sys.path.insert(0, str(Path(__file__).parent))
from phantom_mcp_server import (
    _search_skills,
    _load_skill,
    _run_skill_agent,
    _list_subdomains,
)

log = logging.getLogger("phantom-tasks")

try:
    import anthropic
    _SDK_OK = True
except ImportError:
    _SDK_OK = False

try:
    import asyncssh
    _SSH_OK = True
except ImportError:
    _SSH_OK = False

# Bedrock cross-region inference profile — override via BEDROCK_MODEL_ID env var.
# Verify the exact ID against: aws bedrock list-inference-profiles --region us-east-1
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.anthropic.claude-opus-4-8")
BEDROCK_REGION   = os.environ.get("BEDROCK_REGION", "us-east-1")
MAX_TURNS        = 20

# Kali pentest backend — SSH connection parameters injected by ECS task definition
KALI_HOST    = os.environ.get("KALI_HOST", "")
KALI_USER    = os.environ.get("KALI_USER", "kali")
KALI_SSH_KEY = os.environ.get("KALI_SSH_KEY", "")  # PEM string from Secrets Manager

_SYSTEM_PROMPT = """\
You are Phantom, an autonomous cybersecurity AI agent with access to an 841-skill library
and a Kali Linux execution backend for system-level tools.

Tools:
  search_skills     — find skills by keyword, subdomain, or tag
  list_subdomains   — see every skill domain and its count
  load_skill        — read the full SKILL.md workflow for a skill
  run_skill_agent   — execute a skill's agent.py script (API-based skills only)
  kali_exec         — run any command on the Kali Linux backend (nmap, nikto, sqlmap, nuclei, etc.)

Tool selection:
  - For skills that use boto3 / requests / Python APIs: use run_skill_agent
  - For skills that require nmap, nikto, masscan, gobuster, sqlmap, hydra, nuclei,
    metasploit, or any system binary: use kali_exec directly
  - Always load_skill first to check the skill's prerequisites before calling run_skill_agent
  - kali_exec is available only when KALI_HOST is configured — check availability by
    running: kali_exec("echo kali-ready")

Kali tools available: nmap, nikto, masscan, gobuster, sqlmap, hydra, john, hashcat,
  nuclei, wfuzz, whatweb, sslscan, testssl.sh, curl, wget, python3

Workflow:
  1. search_skills (and list_subdomains if unsure of domain) to find candidates
  2. load_skill to read prerequisites
  3. run_skill_agent for API-based skills, kali_exec for system-tool skills
  4. Synthesise all findings into a clear, structured final report

Authorized scope: {scope}
"""

_TOOLS: list[dict] = [
    {
        "name": "search_skills",
        "description": (
            "Search the 841-skill cybersecurity library by keyword, subdomain, or tag. "
            "Returns name, description, subdomain, tags, and whether an agent.py script exists."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query":     {"type": "string", "description": "Keyword to search"},
                "subdomain": {"type": "string", "description": "Filter by subdomain"},
                "tag":       {"type": "string", "description": "Filter by tag"},
                "limit":     {"type": "integer", "default": 10, "description": "Max results (max 30)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "list_subdomains",
        "description": "List all skill subdomains with their skill counts.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "load_skill",
        "description": (
            "Load the full SKILL.md for a specific skill — workflow, prerequisites, "
            "steps, and whether an agent.py script exists."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "skill_name": {"type": "string", "description": "Kebab-case skill name"},
            },
            "required": ["skill_name"],
        },
    },
    {
        "name": "run_skill_agent",
        "description": (
            "Execute a skill's agent.py script. "
            "API-based skills only (boto3, requests, urllib) — not for nmap/kali/system tools. "
            "Exit code 1 signals HIGH/CRITICAL finding."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "skill_name": {"type": "string"},
                "args":       {"type": "array", "items": {"type": "string"},
                               "description": "CLI args for the script"},
            },
            "required": ["skill_name", "args"],
        },
    },
    {
        "name": "kali_exec",
        "description": (
            "Run a shell command on the Kali Linux pentest backend over SSH. "
            "Use for any skill requiring system tools: nmap, nikto, masscan, gobuster, "
            "sqlmap, hydra, nuclei, wfuzz, whatweb, sslscan, testssl.sh, metasploit, etc. "
            "Returns stdout, stderr, and exit_code. "
            "Test availability first: kali_exec('echo kali-ready'). "
            "Returns an error dict if the Kali backend is unreachable."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "command":   {"type": "string", "description": "Shell command to execute on Kali"},
                "timeout_s": {"type": "integer", "default": 120,
                              "description": "Max seconds to wait for command completion (default 120, max 600)"},
            },
            "required": ["command"],
        },
    },
]


# ── Task lifecycle ─────────────────────────────────────────────────────────────

class TaskStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"


_TERMINAL = {TaskStatus.COMPLETED, TaskStatus.FAILED}


@dataclass
class TaskEvent:
    type: str
    data: dict
    ts: float = field(default_factory=time.time)

    def to_sse(self) -> str:
        payload = json.dumps({"type": self.type, "ts": self.ts, **self.data})
        return f"data: {payload}\n\n"


@dataclass
class PhantomTask:
    job_id:      str
    task:        str
    scope:       list
    status:      TaskStatus = TaskStatus.PENDING
    events:      list       = field(default_factory=list)
    result:      str | None = None
    error:       str | None = None
    turns:       int        = 0
    created_at:  float      = field(default_factory=time.time)
    started_at:  float | None = None
    finished_at: float | None = None

    def elapsed_s(self) -> float | None:
        if self.started_at is None:
            return None
        return round((self.finished_at or time.time()) - self.started_at, 1)

    def emit(self, etype: str, **data) -> None:
        self.events.append(TaskEvent(type=etype, data=data))

    def to_dict(self) -> dict:
        return {
            "job_id":      self.job_id,
            "status":      self.status,
            "task":        self.task,
            "scope":       self.scope,
            "turns":       self.turns,
            "elapsed_s":   self.elapsed_s(),
            "result":      self.result,
            "error":       self.error,
            "created_at":  self.created_at,
            "started_at":  self.started_at,
            "finished_at": self.finished_at,
            "event_count": len(self.events),
        }


# ── In-memory task store ───────────────────────────────────────────────────────

_TASKS:     dict[str, PhantomTask] = {}
_MAX_TASKS: int                    = 100


def create_task(task: str, scope: list) -> PhantomTask:
    if not _SDK_OK:
        raise RuntimeError("anthropic[bedrock] SDK not installed — cannot run tasks")

    job_id = str(uuid.uuid4())
    pt = PhantomTask(job_id=job_id, task=task, scope=scope)

    # Evict oldest finished tasks when at capacity
    if len(_TASKS) >= _MAX_TASKS:
        done_keys = [k for k, v in _TASKS.items() if v.status in _TERMINAL]
        for k in done_keys[:10]:
            del _TASKS[k]

    _TASKS[job_id] = pt
    return pt


def get_task(job_id: str) -> PhantomTask | None:
    return _TASKS.get(job_id)


def list_all_tasks() -> list[dict]:
    return [t.to_dict() for t in _TASKS.values()]


# ── Kali SSH execution ─────────────────────────────────────────────────────────

async def _kali_exec(args: dict) -> str:
    if not _SSH_OK:
        return json.dumps({"error": "asyncssh not installed — rebuild Docker image"})
    if not KALI_HOST:
        return json.dumps({"error": "KALI_HOST not set — Kali backend not configured"})
    if not KALI_SSH_KEY:
        return json.dumps({"error": "KALI_SSH_KEY not set — SSH key not injected"})

    command   = args.get("command", "")
    timeout_s = min(int(args.get("timeout_s", 120)), 600)

    try:
        key = asyncssh.import_private_key(KALI_SSH_KEY)
        async with asyncssh.connect(
            KALI_HOST,
            username=KALI_USER,
            client_keys=[key],
            known_hosts=None,   # lab VPC — host key pinning not required
            connect_timeout=15,
        ) as conn:
            result = await asyncio.wait_for(
                conn.run(command, check=False),
                timeout=timeout_s,
            )
            return json.dumps({
                "stdout":    result.stdout,
                "stderr":    result.stderr,
                "exit_code": result.exit_status,
            })
    except asyncio.TimeoutError:
        return json.dumps({"error": f"command timed out after {timeout_s}s"})
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ── Tool dispatch (runs sync skill functions in a thread pool) ─────────────────

async def _dispatch(name: str, args: dict) -> str:
    if name == "search_skills":
        return await asyncio.to_thread(_search_skills, args)
    if name == "list_subdomains":
        return await asyncio.to_thread(_list_subdomains)
    if name == "load_skill":
        return await asyncio.to_thread(_load_skill, args)
    if name == "run_skill_agent":
        return await asyncio.to_thread(_run_skill_agent, args)
    if name == "kali_exec":
        return await _kali_exec(args)
    return json.dumps({"error": f"unknown tool: {name}"})


def _redact_args(tool_name: str, args: dict) -> dict:
    if tool_name == "run_skill_agent" and "args" in args:
        return {**args, "args": f"[{len(args['args'])} args]"}
    if tool_name == "kali_exec":
        cmd = args.get("command", "")
        return {**args, "command": cmd[:120] + ("..." if len(cmd) > 120 else "")}
    return args


# ── Agent loop ─────────────────────────────────────────────────────────────────

async def run_task_agent(task: PhantomTask) -> None:
    """
    Multi-turn Claude Opus agent loop. Runs in the background as an asyncio task.
    Emits structured events to task.events throughout execution.
    """
    task.status     = TaskStatus.RUNNING
    task.started_at = time.time()
    scope_str       = ", ".join(task.scope) if task.scope else "none (API-only skills)"
    task.emit("start", message="Task started", scope=task.scope)
    log.info("[task:%s] started — %s", task.job_id[:8], task.task[:80])

    system   = _SYSTEM_PROMPT.format(scope=scope_str)
    messages = [{"role": "user", "content": task.task}]
    client   = anthropic.AsyncAnthropicBedrock(aws_region=BEDROCK_REGION)

    try:
        while task.turns < MAX_TURNS:
            task.turns += 1
            task.emit("turn", n=task.turns, max=MAX_TURNS)

            resp = await client.messages.create(
                model=BEDROCK_MODEL_ID,
                max_tokens=4096,
                system=system,
                tools=_TOOLS,
                messages=messages,
            )

            # Collect any text blocks the model emitted this turn
            text_parts = [
                b.text for b in resp.content
                if hasattr(b, "text") and b.text.strip()
            ]
            for text in text_parts:
                task.emit("message", text=text)

            # Model finished — no more tool calls
            if resp.stop_reason == "end_turn":
                task.result      = "\n\n".join(text_parts) or "(task complete)"
                task.status      = TaskStatus.COMPLETED
                task.finished_at = time.time()
                task.emit("done", result=task.result, turns=task.turns)
                log.info("[task:%s] completed in %d turns (%.1fs)",
                         task.job_id[:8], task.turns, task.elapsed_s())
                return

            tool_uses = [b for b in resp.content if b.type == "tool_use"]
            if not tool_uses:
                # stop_reason wasn't end_turn but no tool calls — treat as done
                task.result      = "\n\n".join(text_parts) or "(no output)"
                task.status      = TaskStatus.COMPLETED
                task.finished_at = time.time()
                task.emit("done", result=task.result, turns=task.turns)
                return

            # Append the full assistant turn (text + tool_use blocks) to history
            messages.append({"role": "assistant", "content": resp.content})

            # Execute each tool call and collect results
            tool_results: list[dict] = []
            for tu in tool_uses:
                task.emit("tool_call",
                          tool=tu.name,
                          args=_redact_args(tu.name, tu.input))
                try:
                    output   = await _dispatch(tu.name, tu.input)
                    is_error = False
                except Exception as exc:
                    output   = json.dumps({"error": str(exc)})
                    is_error = True

                task.emit("tool_result",
                          tool=tu.name,
                          is_error=is_error,
                          preview=output[:400])
                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": tu.id,
                    "content":     output,
                    "is_error":    is_error,
                })

            messages.append({"role": "user", "content": tool_results})

        # MAX_TURNS reached without end_turn
        task.result      = "(reached max turns — see events for partial findings)"
        task.status      = TaskStatus.COMPLETED
        task.finished_at = time.time()
        task.emit("done", result=task.result, turns=task.turns, max_turns_reached=True)
        log.warning("[task:%s] hit max_turns=%d", task.job_id[:8], MAX_TURNS)

    except Exception as exc:
        task.error       = str(exc)
        task.status      = TaskStatus.FAILED
        task.finished_at = time.time()
        task.emit("error", error=str(exc))
        log.exception("[task:%s] failed", task.job_id[:8])
