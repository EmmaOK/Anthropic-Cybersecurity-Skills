#!/usr/bin/env python3
"""
Phantom MCP Server
Exposes the 796-skill cybersecurity library to Claude Code via MCP.

Tools:
  search_skills    — Search skills by keyword, subdomain, or framework tag
  load_skill       — Load a full SKILL.md and its agent.py synopsis
  run_skill_agent  — Execute a skill's scripts/agent.py with given arguments
  list_subdomains  — List all available subdomains for filtering
"""

import json
import subprocess
import sys
import os
from pathlib import Path

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError:
    print("MCP SDK not installed. Run: pip install mcp", file=sys.stderr)
    sys.exit(1)

# ── Paths ──────────────────────────────────────────────────────────────────

ROOT       = Path(__file__).parent.parent
SKILLS_DIR = ROOT / "skills"
INDEX_PATH = ROOT / "index.json"

# ── Index cache ────────────────────────────────────────────────────────────

_INDEX: list[dict] | None = None

def _load_index() -> list[dict]:
    global _INDEX
    if _INDEX is None:
        if not INDEX_PATH.exists():
            _INDEX = []
        else:
            with open(INDEX_PATH) as f:
                data = json.load(f)
            _INDEX = data if isinstance(data, list) else data.get("skills", [])
    return _INDEX

# ── Server ─────────────────────────────────────────────────────────────────

server = Server("phantom-skills")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="search_skills",
            description=(
                "Search the Phantom cybersecurity skill library (796 skills). "
                "Returns matching skills with name, description, subdomain, tags, and script availability. "
                "Use this to find the right skill before loading or running it."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Keyword to search in skill names and descriptions (e.g. 'prompt injection', 'rag', 'k8s')",
                    },
                    "subdomain": {
                        "type": "string",
                        "description": "Filter by subdomain (e.g. 'ai-security', 'cloud-security', 'api-security'). Optional.",
                    },
                    "tag": {
                        "type": "string",
                        "description": "Filter by tag (e.g. 'OWASP-MCP-Top10', 'mcp-security', 'T1059'). Optional.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results to return (default 10, max 25).",
                        "default": 10,
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="load_skill",
            description=(
                "Load the full SKILL.md for a specific skill. "
                "Returns the complete workflow, prerequisites, key concepts, and output format. "
                "Also indicates whether an executable agent.py script is available."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "skill_name": {
                        "type": "string",
                        "description": "Exact kebab-case skill name (e.g. 'rag-pipeline-security-and-data-provenance')",
                    }
                },
                "required": ["skill_name"],
            },
        ),
        Tool(
            name="run_skill_agent",
            description=(
                "Execute a skill's scripts/agent.py with the given arguments. "
                "Only call this when the user explicitly asks to run an audit or scan. "
                "Always confirm the skill name and args with the user before calling. "
                "Returns the script's JSON output and exit code (exit 1 = HIGH/CRITICAL finding)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "skill_name": {
                        "type": "string",
                        "description": "Skill whose agent.py to execute",
                    },
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "CLI arguments for the script (e.g. ['scan-k8s', '--manifest', 'deployment.json'])",
                    },
                },
                "required": ["skill_name", "args"],
            },
        ),
        Tool(
            name="list_subdomains",
            description="List all available subdomains in the skill library with skill counts.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "search_skills":
        return [TextContent(type="text", text=_search_skills(arguments))]
    if name == "load_skill":
        return [TextContent(type="text", text=_load_skill(arguments))]
    if name == "run_skill_agent":
        return [TextContent(type="text", text=_run_skill_agent(arguments))]
    if name == "list_subdomains":
        return [TextContent(type="text", text=_list_subdomains())]
    return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]


# ── Tool implementations ───────────────────────────────────────────────────

def _search_skills(args: dict) -> str:
    query     = args.get("query", "").lower()
    subdomain = args.get("subdomain", "").lower()
    tag       = args.get("tag", "").lower()
    limit     = min(int(args.get("limit", 10)), 25)

    skills = _load_index()
    results = []

    for skill in skills:
        name_match  = query in skill.get("name", "").lower()
        desc_match  = query in skill.get("description", "").lower()
        tag_match   = any(query in t.lower() for t in skill.get("tags", []))
        if not (name_match or desc_match or tag_match):
            continue
        if subdomain and subdomain not in skill.get("subdomain", "").lower():
            continue
        if tag and not any(tag in t.lower() for t in skill.get("tags", [])):
            continue

        skill_dir = SKILLS_DIR / skill.get("name", "")
        has_script = (skill_dir / "scripts" / "agent.py").exists()

        results.append({
            "name":        skill.get("name"),
            "description": skill.get("description", "")[:120] + "..." if len(skill.get("description", "")) > 120 else skill.get("description", ""),
            "subdomain":   skill.get("subdomain"),
            "tags":        skill.get("tags", [])[:5],
            "has_script":  has_script,
        })

        if len(results) >= limit:
            break

    return json.dumps({
        "query":   args.get("query"),
        "count":   len(results),
        "results": results,
    }, indent=2)


def _load_skill(args: dict) -> str:
    skill_name = args.get("skill_name", "")
    skill_dir  = SKILLS_DIR / skill_name

    if not skill_dir.exists():
        # Try fuzzy match
        candidates = [d.name for d in SKILLS_DIR.iterdir()
                      if d.is_dir() and skill_name.lower() in d.name.lower()]
        return json.dumps({
            "error": f"Skill '{skill_name}' not found.",
            "suggestions": candidates[:5],
        })

    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return json.dumps({"error": f"SKILL.md missing for '{skill_name}'"})

    content = skill_md.read_text(encoding="utf-8")

    script_path = skill_dir / "scripts" / "agent.py"
    script_info = None
    if script_path.exists():
        # Extract first docstring from agent.py as usage hint
        lines = script_path.read_text(encoding="utf-8").splitlines()
        docstring_lines = []
        in_doc = False
        for line in lines[1:30]:
            if '"""' in line and not in_doc:
                in_doc = True
                docstring_lines.append(line.replace('"""', '').strip())
                continue
            if '"""' in line and in_doc:
                break
            if in_doc:
                docstring_lines.append(line.strip())
        script_info = "\n".join(l for l in docstring_lines if l)

    return json.dumps({
        "name":       skill_name,
        "has_script": script_path.exists(),
        "script_usage": script_info,
        "content":    content,
    }, indent=2)


def _run_skill_agent(args: dict) -> str:
    skill_name = args.get("skill_name", "")
    cli_args   = args.get("args", [])

    script_path = SKILLS_DIR / skill_name / "scripts" / "agent.py"
    if not script_path.exists():
        return json.dumps({
            "error": f"No executable script found for skill '{skill_name}'.",
            "tip":   "Use search_skills to find skills with has_script=true.",
        })

    cmd = [sys.executable, str(script_path)] + [str(a) for a in cli_args]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(ROOT),
        )
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Script timed out after 120s for skill '{skill_name}'"})
    except Exception as e:
        return json.dumps({"error": str(e)})

    # Try to parse stdout as JSON; fall back to raw string
    stdout = result.stdout.strip()
    try:
        parsed = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        parsed = stdout

    return json.dumps({
        "skill":     skill_name,
        "args":      cli_args,
        "exit_code": result.returncode,
        "risk_flag": result.returncode != 0,
        "output":    parsed,
        "stderr":    result.stderr.strip() or None,
    }, indent=2)


def _list_subdomains() -> str:
    skills = _load_index()
    counts: dict[str, int] = {}
    for skill in skills:
        sd = skill.get("subdomain", "unknown")
        counts[sd] = counts.get(sd, 0) + 1
    sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return json.dumps({
        "total_skills": len(skills),
        "subdomains": [{"subdomain": sd, "skill_count": n} for sd, n in sorted_counts],
    }, indent=2)


# ── Entry point ────────────────────────────────────────────────────────────

async def main():
    if not SKILLS_DIR.exists():
        print(f"[phantom-mcp] ERROR: Skills directory not found at {SKILLS_DIR}", file=sys.stderr)
        sys.exit(1)
    skills = _load_index()
    print(f"[phantom-mcp] Started — {len(skills)} skills loaded from {ROOT}", file=sys.stderr)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
