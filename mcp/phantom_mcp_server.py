#!/usr/bin/env python3
"""
Phantom MCP Server
Exposes the cybersecurity skill library to Claude Code via MCP.

Tools:
  search_skills             — Search all skills by keyword, subdomain, or tag
  load_skill                — Load a full SKILL.md and its agent.py synopsis
  run_skill_agent           — Execute a skill's scripts/agent.py with given arguments
  list_subdomains           — List all subdomains with skill counts
  search_soc_skills         — Search SOC-relevant skills only (pre-filtered)
  get_platform_adapted_skill — Load a skill with SOC platform adaptation notes injected
"""

import json
import subprocess
import sys
import re
import time
from pathlib import Path

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError:
    print("MCP SDK not installed. Run: pip install mcp", file=sys.stderr)
    sys.exit(1)

# ── Paths ──────────────────────────────────────────────────────────────────────

ROOT       = Path(__file__).parent.parent
SKILLS_DIR = ROOT / "skills"
INDEX_PATH = ROOT / "index.json"

# ── SOC platform context injected into adapted skills ─────────────────────────

_SOC_PLATFORM = {
    "opensearch_url":    "https://192.168.6.213:9200",
    "dashboards_url":    "http://192.168.6.213:5601",
    "wazuh_url":         "https://192.168.6.213:55000",
    "thehive_url":       "http://192.168.6.213:9000",
    "cortex_url":        "http://192.168.6.213:9001",
    "misp_url":          "http://192.168.6.213:8080",
    "shuffle_url":       "http://192.168.6.213:3001",
    "shuffle_api_url":   "http://192.168.6.213:5001",
}

# SIEM/SOAR term substitutions for platform adaptation
_ADAPTATIONS = [
    (r"\bSplunk\b",              "OpenSearch"),
    (r"\bElastic Security\b",    "OpenSearch Dashboards"),
    (r"\bElastic SIEM\b",        "OpenSearch + Wazuh"),
    (r"\bElasticsearch\b",       "OpenSearch"),
    (r"\bKQL\b",                 "OpenSearch Lucene/DQL"),
    (r"\bEQL\b",                 "OpenSearch PPL"),
    (r"\bSPL\b",                 "OpenSearch Lucene query syntax"),
    (r"\bSplunk Phantom\b",      "Shuffle SOAR"),
    (r"\bPhantom SOAR\b",        "Shuffle SOAR"),
    (r"\bXSOAR\b",               "Shuffle SOAR"),
    (r"\bServiceNow\b",          "TheHive"),
    (r"\bJira\b",                "TheHive"),
    (r"\bQRadar\b",              "OpenSearch + Wazuh"),
    (r"\bSentinel\b",            "OpenSearch Dashboards"),
    (r"\bDatadog\b",             "OpenSearch Dashboards"),
    (r"\bSecuronix\b",           "Wazuh"),
]

# SOC-relevant subdomains
_SOC_SUBDOMAINS = {
    "soc-operations", "security-operations",
    "threat-intelligence", "incident-response",
    "threat-hunting", "malware-analysis",
    "digital-forensics", "network-security",
    "endpoint-security", "phishing-defense",
    "ransomware-defense",
}

# ── Rich index (parses SKILL.md frontmatter to get subdomain + tags) ───────────

_RICH_INDEX: list[dict] | None = None


def _parse_frontmatter(text: str) -> dict:
    """Extract key:value pairs from YAML frontmatter between --- delimiters."""
    if not text.startswith("---"):
        return {}
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}
    fm_text = parts[1]
    result: dict = {}
    current_key = None
    current_list: list | None = None
    for line in fm_text.splitlines():
        if not line.strip():
            continue
        if line.startswith("  ") and current_list is not None:
            val = line.strip().lstrip("- ").strip()
            if val:
                current_list.append(val)
            continue
        if ":" in line and not line.startswith(" "):
            current_list = None
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip().strip("'\"")
            if not val or val == ">-":
                current_list = []
                result[key] = current_list
                current_key = key
            else:
                result[key] = val
                current_key = key
        elif line.startswith("- ") and current_key:
            if not isinstance(result.get(current_key), list):
                result[current_key] = []
                current_list = result[current_key]
            if current_list is not None:
                current_list.append(line.strip().lstrip("- ").strip())
    # Flatten list descriptions
    for k, v in result.items():
        if isinstance(v, list) and k == "description":
            result[k] = " ".join(v)
    return result


def _build_rich_index() -> list[dict]:
    """Build index by parsing SKILL.md frontmatter — fixes the subdomain/tag limitation."""
    global _RICH_INDEX
    if _RICH_INDEX is not None:
        return _RICH_INDEX

    # Load base index for description fallback
    base: dict[str, dict] = {}
    if INDEX_PATH.exists():
        with open(INDEX_PATH) as f:
            raw = json.load(f)
        entries = raw if isinstance(raw, list) else raw.get("skills", [])
        for e in entries:
            base[e.get("name", "")] = e

    skills = []
    if not SKILLS_DIR.exists():
        _RICH_INDEX = skills
        return skills

    for skill_dir in sorted(SKILLS_DIR.iterdir()):
        if not skill_dir.is_dir():
            continue
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            continue
        try:
            text = skill_md.read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            name = fm.get("name") or skill_dir.name
            desc = fm.get("description", "")
            if not desc:
                desc = base.get(name, {}).get("description", "")
            skills.append({
                "name":       name,
                "description": desc,
                "subdomain":  fm.get("subdomain", "unknown"),
                "tags":       fm.get("tags", []) if isinstance(fm.get("tags"), list) else [],
                "has_script": (skill_dir / "scripts" / "agent.py").exists(),
            })
        except Exception:
            continue

    _RICH_INDEX = skills
    return skills


# ── Structured audit logging (OBS-01) ─────────────────────────────────────────

def _audit_log(name: str, args: dict, elapsed_ms: float, error: bool = False) -> None:
    # Redact raw script args to avoid leaking paths/tokens in logs
    safe_args: dict = {}
    for k, v in args.items():
        if k == "args":
            safe_args["args_count"] = len(v) if isinstance(v, list) else 1
        else:
            safe_args[k] = v
    print(json.dumps({
        "event": "tool_call",
        "tool": name,
        "ts": time.time(),
        "elapsed_ms": round(elapsed_ms, 1),
        "args": safe_args,
        "error": error,
    }), flush=True)


# ── Server ─────────────────────────────────────────────────────────────────────

server = Server("phantom-skills")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="search_skills",
            description=(
                "Search the cybersecurity skill library (800+ skills). "
                "Returns matching skills with name, description, subdomain, tags, and script availability."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Keyword to search in skill names, descriptions, and tags",
                    },
                    "subdomain": {
                        "type": "string",
                        "description": "Filter by subdomain e.g. 'threat-intelligence', 'soc-operations', 'malware-analysis'",
                    },
                    "tag": {
                        "type": "string",
                        "description": "Filter by tag e.g. 'wazuh', 'misp', 'T1059', 'OWASP-MCP-Top10'",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results (default 10, max 30)",
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
                "Returns the complete workflow, prerequisites, steps, and whether an agent.py script exists."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "skill_name": {
                        "type": "string",
                        "description": "Kebab-case skill name e.g. 'collecting-threat-intelligence-with-misp'",
                    }
                },
                "required": ["skill_name"],
            },
        ),
        Tool(
            name="run_skill_agent",
            description=(
                "Execute a skill's scripts/agent.py. "
                "Only call when the user explicitly asks to run an audit or scan. "
                "Exit code 1 means HIGH/CRITICAL finding."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "skill_name": {"type": "string", "description": "Skill whose agent.py to execute"},
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "CLI arguments for the script",
                    },
                },
                "required": ["skill_name", "args"],
            },
        ),
        Tool(
            name="list_subdomains",
            description="List all skill subdomains with counts.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="search_soc_skills",
            description=(
                "Search skills relevant to SOC operations only. "
                "Pre-filtered to: soc-operations, threat-intelligence, incident-response, "
                "threat-hunting, malware-analysis, digital-forensics, network-security, "
                "endpoint-security, phishing-defense, ransomware-defense. "
                "Use this instead of search_skills when working in a SOC context."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Keyword e.g. 'wazuh', 'alert triage', 'misp', 'ransomware playbook', 'threat hunt'",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results (default 15, max 30)",
                        "default": 15,
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="get_platform_adapted_skill",
            description=(
                "Load a skill's SKILL.md with SOC platform adaptation notes injected. "
                "Replaces generic SIEM/SOAR references (Splunk, Elastic, Phantom, ServiceNow) "
                "with the deployed stack: Wazuh, OpenSearch, Shuffle, TheHive, MISP, Cortex. "
                "Also appends concrete connection details (URLs, API endpoints) for immediate use."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "skill_name": {
                        "type": "string",
                        "description": "Kebab-case skill name to load and adapt",
                    }
                },
                "required": ["skill_name"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    t0 = time.monotonic()
    error = False
    try:
        if name == "search_skills":
            result = [TextContent(type="text", text=_search_skills(arguments))]
        elif name == "load_skill":
            result = [TextContent(type="text", text=_load_skill(arguments))]
        elif name == "run_skill_agent":
            result = [TextContent(type="text", text=_run_skill_agent(arguments))]
        elif name == "list_subdomains":
            result = [TextContent(type="text", text=_list_subdomains())]
        elif name == "search_soc_skills":
            result = [TextContent(type="text", text=_search_soc_skills(arguments))]
        elif name == "get_platform_adapted_skill":
            result = [TextContent(type="text", text=_get_platform_adapted_skill(arguments))]
        else:
            error = True
            result = [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]
    except Exception:
        error = True
        raise
    finally:
        _audit_log(name, arguments, (time.monotonic() - t0) * 1000, error=error)
    return result


# ── Implementations ────────────────────────────────────────────────────────────

def _search_skills(args: dict) -> str:
    query     = args.get("query", "").lower()
    subdomain = args.get("subdomain", "").lower()
    tag       = args.get("tag", "").lower()
    limit     = min(int(args.get("limit", 10)), 30)

    results = []
    for skill in _build_rich_index():
        name_hit = query in skill["name"].lower()
        desc_hit = query in skill["description"].lower()
        tag_hit  = any(query in t.lower() for t in skill["tags"])
        if not (name_hit or desc_hit or tag_hit):
            continue
        if subdomain and subdomain not in skill["subdomain"].lower():
            continue
        if tag and not any(tag in t.lower() for t in skill["tags"]):
            continue
        results.append({
            "name":        skill["name"],
            "description": skill["description"][:120],
            "subdomain":   skill["subdomain"],
            "tags":        skill["tags"][:6],
            "has_script":  skill["has_script"],
        })
        if len(results) >= limit:
            break

    return json.dumps({"query": args.get("query"), "count": len(results), "results": results}, indent=2)


def _load_skill(args: dict) -> str:
    skill_name = args.get("skill_name", "")
    skill_dir  = SKILLS_DIR / skill_name

    if not skill_dir.exists():
        candidates = [d.name for d in SKILLS_DIR.iterdir()
                      if d.is_dir() and skill_name.lower() in d.name.lower()]
        return json.dumps({"error": f"Skill '{skill_name}' not found.", "suggestions": candidates[:5]})

    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return json.dumps({"error": f"SKILL.md missing for '{skill_name}'"})

    content = skill_md.read_text(encoding="utf-8")
    script_path = skill_dir / "scripts" / "agent.py"
    script_info = None
    if script_path.exists():
        lines = script_path.read_text(encoding="utf-8").splitlines()
        doc_lines, in_doc = [], False
        for line in lines[1:30]:
            if '"""' in line and not in_doc:
                in_doc = True
                doc_lines.append(line.replace('"""', '').strip())
            elif '"""' in line and in_doc:
                break
            elif in_doc:
                doc_lines.append(line.strip())
        script_info = "\n".join(l for l in doc_lines if l)

    return json.dumps({
        "name": skill_name,
        "has_script": script_path.exists(),
        "script_usage": script_info,
        "content": content,
    }, indent=2)


def _run_skill_agent(args: dict) -> str:
    skill_name = args.get("skill_name", "")
    cli_args   = args.get("args", [])
    script_path = SKILLS_DIR / skill_name / "scripts" / "agent.py"

    if not script_path.exists():
        return json.dumps({"error": f"No agent.py for '{skill_name}'."})

    try:
        result = subprocess.run(
            [sys.executable, str(script_path)] + [str(a) for a in cli_args],
            capture_output=True, text=True, timeout=120, cwd=str(ROOT),
        )
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Timed out after 120s"})
    except Exception as e:
        return json.dumps({"error": str(e)})

    stdout = result.stdout.strip()
    try:
        output = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        output = stdout

    return json.dumps({
        "skill": skill_name, "args": cli_args,
        "exit_code": result.returncode,
        "risk_flag": result.returncode != 0,
        "output": output,
        "stderr": result.stderr.strip() or None,
    }, indent=2)


def _list_subdomains() -> str:
    counts: dict[str, int] = {}
    for skill in _build_rich_index():
        sd = skill["subdomain"]
        counts[sd] = counts.get(sd, 0) + 1
    sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return json.dumps({
        "total_skills": sum(counts.values()),
        "subdomains": [{"subdomain": sd, "count": n} for sd, n in sorted_counts],
    }, indent=2)


def _search_soc_skills(args: dict) -> str:
    query = args.get("query", "").lower()
    limit = min(int(args.get("limit", 15)), 30)

    results = []
    for skill in _build_rich_index():
        if skill["subdomain"] not in _SOC_SUBDOMAINS:
            continue
        name_hit = query in skill["name"].lower()
        desc_hit = query in skill["description"].lower()
        tag_hit  = any(query in t.lower() for t in skill["tags"])
        if not (name_hit or desc_hit or tag_hit):
            continue
        results.append({
            "name":       skill["name"],
            "description": skill["description"][:120],
            "subdomain":  skill["subdomain"],
            "tags":       skill["tags"][:6],
            "has_script": skill["has_script"],
        })
        if len(results) >= limit:
            break

    return json.dumps({
        "query": args.get("query"),
        "soc_subdomains_searched": sorted(_SOC_SUBDOMAINS),
        "count": len(results),
        "results": results,
    }, indent=2)


def _get_platform_adapted_skill(args: dict) -> str:
    skill_name = args.get("skill_name", "")
    skill_dir  = SKILLS_DIR / skill_name

    if not skill_dir.exists():
        candidates = [d.name for d in SKILLS_DIR.iterdir()
                      if d.is_dir() and skill_name.lower() in d.name.lower()]
        return json.dumps({"error": f"Skill '{skill_name}' not found.", "suggestions": candidates[:5]})

    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return json.dumps({"error": f"SKILL.md missing for '{skill_name}'"})

    content = skill_md.read_text(encoding="utf-8")

    # Apply term substitutions
    adapted = content
    for pattern, replacement in _ADAPTATIONS:
        adapted = re.sub(pattern, replacement, adapted, flags=re.IGNORECASE)

    # Build platform context block
    platform_note = f"""
---
## SOC Platform Adaptation Notes

This skill has been adapted for the deployed SOC stack. Term substitutions applied:
- Splunk / Elastic SIEM → **Wazuh + OpenSearch**
- Phantom / XSOAR → **Shuffle SOAR**
- ServiceNow / Jira → **TheHive**

### Live Platform Endpoints

| Service | URL |
|---|---|
| OpenSearch (SIEM store) | `{_SOC_PLATFORM['opensearch_url']}` |
| OpenSearch Dashboards | `{_SOC_PLATFORM['dashboards_url']}` |
| Wazuh Manager API | `{_SOC_PLATFORM['wazuh_url']}` |
| TheHive (Case Management) | `{_SOC_PLATFORM['thehive_url']}` |
| Cortex (Analyzers) | `{_SOC_PLATFORM['cortex_url']}` |
| MISP (Threat Intel) | `{_SOC_PLATFORM['misp_url']}` |
| Shuffle SOAR | `{_SOC_PLATFORM['shuffle_url']}` |

### MCP Tools Available
Use `soc-platform` MCP tools to execute actions from this skill:
- **Alert queries** → `search_security_events(query=..., index="wazuh-alerts-*")`
- **IOC lookup** → `lookup_ioc(value=...)`
- **Case creation** → `create_thehive_alert(title=..., description=..., severity=...)`
- **IP block** → `run_active_response(command="firewall-drop", agent_ids=[...], arguments=[...])`
- **Cortex analysis** → `run_cortex_analyzer(analyzer_id="AbuseIPDB_1_0", data=..., data_type="ip")`
- **SOAR trigger** → `trigger_shuffle_workflow(workflow_name=...)`
---
"""

    return json.dumps({
        "name": skill_name,
        "has_script": (skill_dir / "scripts" / "agent.py").exists(),
        "adapted_content": adapted + platform_note,
        "platform": _SOC_PLATFORM,
    }, indent=2)


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    if not SKILLS_DIR.exists():
        print(f"[phantom-mcp] ERROR: Skills directory not found at {SKILLS_DIR}", file=sys.stderr)
        sys.exit(1)
    index = _build_rich_index()
    soc_count = sum(1 for s in index if s["subdomain"] in _SOC_SUBDOMAINS)
    print(f"[phantom-mcp] Started — {len(index)} skills ({soc_count} SOC-relevant) from {ROOT}", file=sys.stderr)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
