#!/usr/bin/env python3
"""
Phantom — Adaptive Cybersecurity AI Agent
Powered by Claude API + 796-skill cybersecurity library

Usage:
    python phantom/main.py

Requirements:
    pip install anthropic
    export ANTHROPIC_API_KEY=sk-...

Slash commands:
    /mode <name>     Switch persona (red-team, appsec, threat-hunting, cloud, forensics, soc, ai-security, general)
    /modes           List all available modes
    /save [name]     Save current session
    /load <name>     Load a saved session
    /sessions        List saved sessions
    exit / quit      Auto-save and exit
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import anthropic
except ImportError:
    print("Missing dependency. Run: pip install anthropic")
    sys.exit(1)

from skill_loader import search_skills, load_skill
from executor import run_agent
from tools import TOOLS

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ROOT = Path(__file__).parent.parent
SESSIONS_DIR = Path(__file__).parent / "sessions"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MODEL = "claude-opus-4-6"
MAX_TOKENS = 4096

_BASE = (
    "You have access to a curated library of 796 cybersecurity skills mapped to "
    "MITRE ATT&CK, NIST CSF 2.0, MITRE ATLAS, D3FEND, and NIST AI RMF. "
    "When a user asks about a security task: "
    "(1) use search_skills to find relevant procedures, "
    "(2) use load_skill to retrieve the full workflow, "
    "(3) walk the user through each step clearly. "
    "Only call run_skill_agent when the user explicitly asks to execute a script. "
    "Only call write_file when the user asks to save or write output to a file. "
    "You are concise, technically precise, and treat the user as a capable security professional. "
    "This assistant is for authorized lab environments and personal learning only."
)

PERSONAS: dict[str, str] = {
    "general": (
        f"You are Phantom, a full-spectrum cybersecurity expert. "
        f"You are equally comfortable with offensive techniques, defensive operations, "
        f"threat hunting, cloud security, forensics, and AppSec. "
        f"Adapt your focus to whatever the user needs. {_BASE}"
    ),
    "red-team": (
        f"You are Phantom in Red Team mode. "
        f"Focus on offensive security: reconnaissance, initial access, exploitation, "
        f"lateral movement, privilege escalation, persistence, C2, and exfiltration. "
        f"Frame all guidance through the MITRE ATT&CK kill chain. {_BASE}"
    ),
    "appsec": (
        f"You are Phantom in AppSec mode. "
        f"Focus on web application security, API security, mobile app security, "
        f"SAST/DAST integration, secure SDLC, and OWASP Top 10. "
        f"Prioritize practical testing workflows and pipeline integration. {_BASE}"
    ),
    "threat-hunting": (
        f"You are Phantom in Threat Hunting mode. "
        f"Focus on proactive threat detection, hypothesis-driven hunting, "
        f"log analysis, behavioral analytics, and SIEM/EDR queries. "
        f"Frame guidance around detection engineering and ATT&CK technique coverage. {_BASE}"
    ),
    "cloud": (
        f"You are Phantom in Cloud Security mode. "
        f"Focus on AWS, GCP, and Azure security — IAM misconfigurations, "
        f"cloud-native attack paths, container/Kubernetes security, "
        f"serverless security, and cloud compliance. {_BASE}"
    ),
    "forensics": (
        f"You are Phantom in Forensics mode. "
        f"Focus on digital forensics and incident response (DFIR): "
        f"memory forensics, disk imaging, log analysis, artifact collection, "
        f"malware triage, and chain of custody. {_BASE}"
    ),
    "soc": (
        f"You are Phantom in SOC mode. "
        f"Focus on security operations: alert triage, incident response playbooks, "
        f"SIEM rule tuning, escalation workflows, and threat intelligence enrichment. "
        f"Prioritize speed and clarity for analysts under pressure. {_BASE}"
    ),
    "ai-security": (
        f"You are Phantom in AI Security mode. "
        f"You are an expert in securing AI systems, LLMs, agentic pipelines, and MCP infrastructure. "
        f"Your knowledge covers all four AI security frameworks in the library: "
        f"OWASP LLM Top 10 2025 (LLM01–LLM10), OWASP MCP Top 10 v0.1 (MCP01–MCP10), "
        f"OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10), and the MAESTRO 7-layer framework. "
        f"When a user describes an AI system, proactively identify which threat categories apply "
        f"and which skills are most relevant. "
        f"For audit and remediation tasks, always suggest running the appropriate executable script "
        f"(RAG pipeline audit, model extraction defense, infra hardening, eval/telemetry audit, "
        f"governance compliance, MAESTRO threat model). "
        f"Frame risks in terms of concrete attacker scenarios: prompt injection, goal hijacking, "
        f"model extraction, supply chain compromise, rogue agents, cascading failures. "
        f"Reference MITRE ATLAS techniques and NIST AI RMF functions when explaining controls. "
        f"This mode is for AI/ML engineers, AI red teamers, and security architects building or "
        f"auditing AI-powered systems. {_BASE}"
    ),
}

BANNER = """
 ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
 ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
 ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
 ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
 ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝

 Adaptive Cybersecurity AI  |  796 Skills  |  8 Modes  |  Claude-Opus-4-6
 Type /modes to list modes, /help for all commands, exit to quit.
"""

HELP_TEXT = """
Commands:
  /mode <name>     Switch persona — e.g. /mode ai-security
  /modes           List all available modes
  /save [name]     Save session — e.g. /save lab-recon
  /load <name>     Load a session — e.g. /load lab-recon
  /sessions        List all saved sessions
  exit / quit      Auto-save and exit
"""


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def _serialize_messages(messages: list) -> list:
    """Convert messages (may contain SDK objects) to JSON-serializable dicts."""
    serialized = []
    for msg in messages:
        if isinstance(msg, dict):
            content = msg.get("content")
            if isinstance(content, list):
                # Content blocks — convert each to dict
                blocks = []
                for block in content:
                    if isinstance(block, dict):
                        blocks.append(block)
                    elif hasattr(block, "model_dump"):
                        blocks.append(block.model_dump())
                    elif hasattr(block, "__dict__"):
                        blocks.append(vars(block))
                    else:
                        blocks.append(str(block))
                serialized.append({"role": msg["role"], "content": blocks})
            else:
                serialized.append(msg)
        else:
            serialized.append(str(msg))
    return serialized


def save_session(messages: list, mode: str, name: str | None = None) -> str:
    """Save the current session to phantom/sessions/{name}.json."""
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    if not name:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        name = f"session_{ts}"

    path = SESSIONS_DIR / f"{name}.json"
    data = {
        "name": name,
        "mode": mode,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "messages": _serialize_messages(messages),
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return str(path)


def load_session(name: str) -> tuple[list, str] | None:
    """
    Load a session by name. Returns (messages, mode) or None if not found.
    Tries exact name first, then with .json extension.
    """
    for candidate in [SESSIONS_DIR / name, SESSIONS_DIR / f"{name}.json"]:
        if candidate.exists():
            with open(candidate) as f:
                data = json.load(f)
            return data.get("messages", []), data.get("mode", "general")
    return None


def list_sessions() -> list[dict]:
    """Return metadata for all saved sessions."""
    if not SESSIONS_DIR.exists():
        return []
    sessions = []
    for path in sorted(SESSIONS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            with open(path) as f:
                data = json.load(f)
            sessions.append({
                "name": data.get("name", path.stem),
                "mode": data.get("mode", "general"),
                "created_at": data.get("created_at", ""),
                "messages": len(data.get("messages", [])),
            })
        except (json.JSONDecodeError, KeyError):
            continue
    return sessions


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------

def dispatch_tool(tool_name: str, tool_input: dict) -> str:
    """Route Claude's tool call to the correct function."""
    if tool_name == "search_skills":
        query = tool_input.get("query", "")
        results = search_skills(query)
        if not results:
            return json.dumps({"results": [], "message": f"No skills found matching '{query}'"})
        formatted = [
            {"name": r["name"], "description": r.get("description", ""), "path": r["path"]}
            for r in results
        ]
        return json.dumps({"results": formatted, "count": len(formatted)})

    elif tool_name == "load_skill":
        skill_name = tool_input.get("skill_name", "")
        content = load_skill(skill_name)
        if len(content) > 8000:
            content = content[:8000] + "\n\n[... content truncated for context efficiency ...]"
        return content

    elif tool_name == "run_skill_agent":
        skill_name = tool_input.get("skill_name", "")
        args = tool_input.get("args", [])
        print(f"\n[Phantom] Running: skills/{skill_name}/scripts/agent.py {' '.join(args)}")
        return run_agent(skill_name, args)

    elif tool_name == "write_file":
        path_str = tool_input.get("path", "")
        content = tool_input.get("content", "")
        target = ROOT / path_str
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        print(f"\n[Phantom] File written: {target}")
        return f"File successfully written to: {target}"

    return f"[Error] Unknown tool: {tool_name}"


# ---------------------------------------------------------------------------
# Agentic loop
# ---------------------------------------------------------------------------

def run_turn(client: anthropic.Anthropic, messages: list, system_prompt: str) -> str:
    """
    Run one full turn: call Claude, handle tool use in a loop,
    and return the final text response.
    """
    while True:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=system_prompt,
            tools=TOOLS,
            messages=messages,
        )

        text_parts = [b.text for b in response.content if b.type == "text"]

        if response.stop_reason == "end_turn":
            return "\n".join(text_parts)

        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    print(f"  [tool] {block.name}({json.dumps(block.input, separators=(',', ':'))})")
                    result = dispatch_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })

            messages.append({"role": "user", "content": tool_results})
            continue

        return "\n".join(text_parts) if text_parts else "[No response]"


# ---------------------------------------------------------------------------
# Slash command handlers
# ---------------------------------------------------------------------------

def handle_slash_command(
    cmd: str, messages: list, current_mode: str
) -> tuple[list, str, bool]:
    """
    Process a slash command. Returns (messages, current_mode, handled).
    `handled=True` means the input was a command and should not be sent to Claude.
    """
    parts = cmd.strip().split(maxsplit=1)
    command = parts[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""

    if command == "/modes":
        print("\nAvailable modes:")
        for name in PERSONAS:
            marker = " *" if name == current_mode else ""
            print(f"  {name}{marker}")
        return messages, current_mode, True

    if command == "/mode":
        if not arg:
            print(f"[Phantom] Current mode: {current_mode}. Usage: /mode <name>")
        elif arg not in PERSONAS:
            print(f"[Phantom] Unknown mode '{arg}'. Run /modes to see options.")
        else:
            current_mode = arg
            print(f"[Phantom] Switched to {current_mode} mode.")
        return messages, current_mode, True

    if command == "/save":
        name = arg or None
        path = save_session(messages, current_mode, name)
        print(f"[Phantom] Session saved: {path}")
        return messages, current_mode, True

    if command == "/load":
        if not arg:
            print("[Phantom] Usage: /load <session-name>")
        else:
            result = load_session(arg)
            if result is None:
                print(f"[Phantom] Session '{arg}' not found. Run /sessions to list saved sessions.")
            else:
                messages, current_mode = result
                print(f"[Phantom] Session '{arg}' loaded. Mode: {current_mode}. Messages: {len(messages)}")
        return messages, current_mode, True

    if command == "/sessions":
        sessions = list_sessions()
        if not sessions:
            print("[Phantom] No saved sessions found.")
        else:
            print(f"\nSaved sessions ({len(sessions)}):")
            for s in sessions:
                print(f"  {s['name']:30s}  mode={s['mode']:15s}  msgs={s['messages']:3d}  {s['created_at'][:19]}")
        return messages, current_mode, True

    if command == "/help":
        print(HELP_TEXT)
        return messages, current_mode, True

    # Unknown slash command
    print(f"[Phantom] Unknown command '{command}'. Type /help for options.")
    return messages, current_mode, True


# ---------------------------------------------------------------------------
# Main interactive loop
# ---------------------------------------------------------------------------

def main():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[Error] ANTHROPIC_API_KEY environment variable not set.")
        print("Run: export ANTHROPIC_API_KEY=sk-...")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    messages: list = []
    current_mode = "general"

    print(BANNER)

    while True:
        try:
            user_input = input(f"\nYou [{current_mode}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n[Phantom] Auto-saving session...")
            path = save_session(messages, current_mode)
            print(f"[Phantom] Saved to {path}. Session ended.")
            break

        if not user_input:
            continue

        # Exit commands — auto-save first
        if user_input.lower() in ("exit", "quit", "q"):
            if messages:
                print("[Phantom] Auto-saving session...")
                path = save_session(messages, current_mode)
                print(f"[Phantom] Saved to {path}.")
            print("[Phantom] Session ended.")
            break

        # Slash commands
        if user_input.startswith("/"):
            messages, current_mode, _ = handle_slash_command(user_input, messages, current_mode)
            continue

        messages.append({"role": "user", "content": user_input})

        try:
            system_prompt = PERSONAS[current_mode]
            response_text = run_turn(client, messages, system_prompt)
            print(f"\nPhantom: {response_text}")
            messages.append({"role": "assistant", "content": response_text})
        except anthropic.APIError as e:
            print(f"\n[Error] API call failed: {e}")
        except Exception as e:
            print(f"\n[Error] Unexpected error: {e}")


if __name__ == "__main__":
    main()
