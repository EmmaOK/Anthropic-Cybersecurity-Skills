#!/usr/bin/env python3
"""
Kali Linux MCP Server
Exposes the Kali VM (default: 192.168.64.2) to Claude Code via MCP.

Tools:
  kali_status       — Check VM reachability and basic system info
  kali_exec         — Run any shell command on the Kali VM
  kali_upload       — Upload a local file to the VM via SCP
  kali_download     — Download a file from the VM via SCP

Config via env vars (override defaults in .mcp.json):
  KALI_HOST         — VM IP or hostname (default: 192.168.64.2)
  KALI_USER         — SSH username (default: emmanuel)
  KALI_SSH_KEY      — Path to private key (default: ~/.ssh/id_ed25519)
  KALI_TIMEOUT      — Default command timeout in seconds (default: 120)
"""

import json
import os
import subprocess
import sys
from pathlib import Path

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError:
    print("MCP SDK not installed. Run: pip install mcp", file=sys.stderr)
    sys.exit(1)

# ── Config ─────────────────────────────────────────────────────────────────────

KALI_HOST    = os.environ.get("KALI_HOST", "192.168.64.2")
KALI_USER    = os.environ.get("KALI_USER", "emmanuel")
SSH_KEY      = os.path.expanduser(os.environ.get("KALI_SSH_KEY", "~/.ssh/id_ed25519"))
DEFAULT_TIMEOUT = int(os.environ.get("KALI_TIMEOUT", "120"))
MAX_TIMEOUT  = 600

_SSH_OPTS = [
    "-i", SSH_KEY,
    "-o", "StrictHostKeyChecking=no",
    "-o", "ConnectTimeout=10",
    "-o", "BatchMode=yes",
]

# ── SSH helpers ────────────────────────────────────────────────────────────────

def _ssh_run(command: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    timeout = min(timeout, MAX_TIMEOUT)
    ssh_cmd = ["ssh"] + _SSH_OPTS + [f"{KALI_USER}@{KALI_HOST}", command]
    try:
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "stdout":    result.stdout.strip(),
            "stderr":    result.stderr.strip(),
            "exit_code": result.returncode,
            "error":     None,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "", "exit_code": -1,
                "error": f"Command timed out after {timeout}s"}
    except Exception as e:
        return {"stdout": "", "stderr": "", "exit_code": -1, "error": str(e)}


def _scp_to(local_path: str, remote_path: str, timeout: int = 60) -> dict:
    cmd = ["scp"] + _SSH_OPTS + [local_path, f"{KALI_USER}@{KALI_HOST}:{remote_path}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "success":   result.returncode == 0,
            "exit_code": result.returncode,
            "stderr":    result.stderr.strip(),
            "error":     None,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "exit_code": -1, "stderr": "", "error": f"SCP timed out after {timeout}s"}
    except Exception as e:
        return {"success": False, "exit_code": -1, "stderr": "", "error": str(e)}


def _scp_from(remote_path: str, local_path: str, timeout: int = 60) -> dict:
    cmd = ["scp"] + _SSH_OPTS + [f"{KALI_USER}@{KALI_HOST}:{remote_path}", local_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "success":   result.returncode == 0,
            "exit_code": result.returncode,
            "stderr":    result.stderr.strip(),
            "error":     None,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "exit_code": -1, "stderr": "", "error": f"SCP timed out after {timeout}s"}
    except Exception as e:
        return {"success": False, "exit_code": -1, "stderr": "", "error": str(e)}

# ── Server ─────────────────────────────────────────────────────────────────────

server = Server("kali")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="kali_status",
            description=(
                f"Check whether the Kali VM at {KALI_HOST} is reachable via SSH. "
                "Returns OS info, uptime, disk usage, and current user if reachable."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="kali_exec",
            description=(
                f"Execute a shell command on the Kali Linux VM at {KALI_HOST} via SSH. "
                "Returns stdout, stderr, and exit code. "
                "Timeout defaults to 120s, max 600s. "
                "Use for recon tools (nmap, nikto, gobuster), exploitation, or any shell task."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to run on the Kali VM, e.g. 'nmap -sV 10.0.0.1'",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default 120, max 600)",
                        "default": 120,
                    },
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="kali_upload",
            description=(
                "Upload a local file to the Kali VM via SCP. "
                "Useful for transferring scripts, wordlists, or payloads to the VM."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "local_path": {
                        "type": "string",
                        "description": "Absolute path to the local file to upload",
                    },
                    "remote_path": {
                        "type": "string",
                        "description": "Destination path on the Kali VM, e.g. '/home/emmanuel/scripts/payload.py'",
                    },
                },
                "required": ["local_path", "remote_path"],
            },
        ),
        Tool(
            name="kali_download",
            description=(
                "Download a file from the Kali VM to the local machine via SCP. "
                "Useful for retrieving scan reports, captured files, or tool output."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "remote_path": {
                        "type": "string",
                        "description": "Path to the file on the Kali VM, e.g. '/home/emmanuel/scan_results.xml'",
                    },
                    "local_path": {
                        "type": "string",
                        "description": "Local destination path, e.g. '/tmp/scan_results.xml'",
                    },
                },
                "required": ["remote_path", "local_path"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "kali_status":
        return [TextContent(type="text", text=_tool_status())]
    if name == "kali_exec":
        return [TextContent(type="text", text=_tool_exec(arguments))]
    if name == "kali_upload":
        return [TextContent(type="text", text=_tool_upload(arguments))]
    if name == "kali_download":
        return [TextContent(type="text", text=_tool_download(arguments))]
    return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]

# ── Tool implementations ───────────────────────────────────────────────────────

def _tool_status() -> str:
    probe = _ssh_run("uname -a && uptime && df -h / && id", timeout=15)
    if probe["error"] or probe["exit_code"] != 0:
        return json.dumps({
            "reachable": False,
            "host": KALI_HOST,
            "user": KALI_USER,
            "error": probe["error"] or probe["stderr"] or "SSH probe failed",
            "hint": "Ensure the Kali VM is powered on and SSH is running.",
        }, indent=2)

    lines = probe["stdout"].splitlines()
    return json.dumps({
        "reachable": True,
        "host": KALI_HOST,
        "user": KALI_USER,
        "ssh_key": SSH_KEY,
        "system_info": lines[0] if lines else "",
        "uptime": lines[1] if len(lines) > 1 else "",
        "disk": lines[2] if len(lines) > 2 else "",
        "current_user": lines[3] if len(lines) > 3 else "",
    }, indent=2)


def _tool_exec(args: dict) -> str:
    command = args.get("command", "").strip()
    if not command:
        return json.dumps({"error": "command is required"})
    timeout = min(int(args.get("timeout", DEFAULT_TIMEOUT)), MAX_TIMEOUT)
    result = _ssh_run(command, timeout=timeout)
    return json.dumps({
        "host":      KALI_HOST,
        "command":   command,
        "stdout":    result["stdout"],
        "stderr":    result["stderr"],
        "exit_code": result["exit_code"],
        "error":     result["error"],
    }, indent=2)


def _tool_upload(args: dict) -> str:
    local_path  = args.get("local_path", "").strip()
    remote_path = args.get("remote_path", "").strip()
    if not local_path or not remote_path:
        return json.dumps({"error": "local_path and remote_path are required"})
    if not Path(local_path).exists():
        return json.dumps({"error": f"Local file not found: {local_path}"})
    result = _scp_to(local_path, remote_path)
    return json.dumps({
        "host":        KALI_HOST,
        "local_path":  local_path,
        "remote_path": remote_path,
        "success":     result["success"],
        "exit_code":   result["exit_code"],
        "stderr":      result["stderr"],
        "error":       result["error"],
    }, indent=2)


def _tool_download(args: dict) -> str:
    remote_path = args.get("remote_path", "").strip()
    local_path  = args.get("local_path", "").strip()
    if not remote_path or not local_path:
        return json.dumps({"error": "remote_path and local_path are required"})
    result = _scp_from(remote_path, local_path)
    return json.dumps({
        "host":        KALI_HOST,
        "remote_path": remote_path,
        "local_path":  local_path,
        "success":     result["success"],
        "exit_code":   result["exit_code"],
        "stderr":      result["stderr"],
        "error":       result["error"],
    }, indent=2)

# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    print(f"[kali-mcp] Started — targeting {KALI_USER}@{KALI_HOST} (key: {SSH_KEY})", file=sys.stderr)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
