#!/usr/bin/env python3
"""
phantom/investigate.py — Autonomous SOC Alert Investigator

Accepts a Wazuh alert (JSON file, raw JSON string, or alert ID) and runs
a fully autonomous multi-step investigation using Claude claude-opus-4-8 in SOC mode.
Queries live SOC platform data (OpenSearch, Wazuh, MISP, Cortex, TheHive), maps
findings to MITRE ATT&CK, and writes a timestamped Markdown investigation report.

Usage:
    python phantom/investigate.py --alert-file alert.json
    python phantom/investigate.py --alert-json '{"rule":{"level":12},...}'
    python phantom/investigate.py --alert-id  <wazuh-alert-id>
    python phantom/investigate.py --demo                         # uses built-in demo alert

Options:
    --alert-file <path>     Path to a Wazuh alert JSON file
    --alert-json <string>   Raw Wazuh alert JSON string
    --alert-id   <id>       Fetch alert from OpenSearch by _id
    --demo                  Run with a built-in brute-force demo alert
    --no-thehive            Skip TheHive case creation
    --no-cortex             Skip Cortex enrichment
    --output <path>         Write report to this path (default: reports/investigation_<ts>.md)
    --env-file <path>       Path to SOC .env file (default: ~/soc-platform/.env)

Exit codes:
    0  — investigation complete (LOW / MEDIUM finding)
    1  — HIGH or CRITICAL finding
    2  — error (missing creds, unreachable platform, etc.)

Requirements:
    pip install anthropic httpx python-dotenv   (or use security-tools venv)
    ANTHROPIC_API_KEY must be set in environment or .env
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Dependency check ──────────────────────────────────────────────────────────
try:
    import anthropic
except ImportError:
    print("[investigate] ERROR: anthropic not installed. Run: pip install anthropic", file=sys.stderr)
    sys.exit(2)

try:
    import httpx
except ImportError:
    print("[investigate] ERROR: httpx not installed. Run: pip install httpx", file=sys.stderr)
    sys.exit(2)

# ── Paths ─────────────────────────────────────────────────────────────────────

ROOT        = Path(__file__).parent.parent
REPORTS_DIR = ROOT / "reports"
SESSIONS_DIR = Path(__file__).parent / "sessions"

# ── SOC Platform defaults ─────────────────────────────────────────────────────

_SOC_DEFAULTS = {
    "OPENSEARCH_URL":           "https://192.168.6.213:9200",
    "OPENSEARCH_USER":          "admin",
    "OPENSEARCH_ADMIN_PASSWORD": "",
    "WAZUH_URL":                "https://192.168.6.213:55000",
    "WAZUH_API_USERNAME":       "wazuh-api-admin",
    "WAZUH_API_PASSWORD":       "",
    "THEHIVE_URL":              "http://192.168.6.213:9000",
    "THEHIVE_API_KEY":          "",
    "MISP_URL":                 "http://192.168.6.213:8080",
    "MISP_API_KEY":             "",
    "CORTEX_URL":               "http://192.168.6.213:9001",
    "CORTEX_API_KEY":           "",
}

# ── Demo alert (used with --demo) ─────────────────────────────────────────────

DEMO_ALERT = {
    "id": "demo-alert-001",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "rule": {
        "id": "5712",
        "level": 10,
        "description": "SSHD brute force trying to get access to the system.",
        "groups": ["authentication_failed", "sshd", "brute_force"],
        "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
    },
    "agent": {"id": "003", "name": "webserver-01", "ip": "192.168.1.50"},
    "data": {
        "srcip":  "185.220.101.45",
        "dstip":  "192.168.1.50",
        "srcuser": "root",
        "dstuser": "root",
    },
    "full_log": "sshd[1234]: Failed password for root from 185.220.101.45 port 54321 ssh2",
}

# ── Model ─────────────────────────────────────────────────────────────────────

MODEL      = "claude-opus-4-8"
MAX_TOKENS = 8096

# ── Load .env ─────────────────────────────────────────────────────────────────

def _load_env(env_file: Path) -> None:
    if not env_file.exists():
        return
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val


def _cfg(key: str) -> str:
    return os.environ.get(key, _SOC_DEFAULTS.get(key, ""))


# ── SOC platform helpers ──────────────────────────────────────────────────────

def _os_client() -> httpx.Client:
    return httpx.Client(
        base_url=_cfg("OPENSEARCH_URL"),
        auth=(_cfg("OPENSEARCH_USER"), _cfg("OPENSEARCH_ADMIN_PASSWORD")),
        verify=False, timeout=15,
    )


def _wazuh_token() -> str:
    r = httpx.get(
        f"{_cfg('WAZUH_URL')}/security/user/authenticate",
        auth=(_cfg("WAZUH_API_USERNAME"), _cfg("WAZUH_API_PASSWORD")),
        verify=False, timeout=10,
    )
    r.raise_for_status()
    return r.json()["data"]["token"]


def _thehive_client() -> httpx.Client:
    return httpx.Client(
        base_url=_cfg("THEHIVE_URL"),
        headers={"Authorization": f"Bearer {_cfg('THEHIVE_API_KEY')}"},
        timeout=15,
    )


def _misp_client() -> httpx.Client:
    return httpx.Client(
        base_url=_cfg("MISP_URL"),
        headers={"Authorization": _cfg("MISP_API_KEY"), "Accept": "application/json",
                 "Content-Type": "application/json"},
        verify=False, timeout=15,
    )


# ── Tool implementations ──────────────────────────────────────────────────────

def _tool_search_related_events(alert: dict, time_range: str = "24h", size: int = 20) -> dict:
    """Query OpenSearch for events related to the alert's source IP and agent."""
    src_ip  = alert.get("data", {}).get("srcip", "")
    agent   = alert.get("agent", {}).get("name", "")
    clauses = []
    if src_ip:
        clauses.append({"match": {"data.srcip": src_ip}})
    if agent:
        clauses.append({"match": {"agent.name": agent}})
    if not clauses:
        return {"error": "No IP or agent to search"}

    body = {
        "query": {"bool": {"should": clauses, "minimum_should_match": 1,
                           "filter": [{"range": {"@timestamp": {"gte": f"now-{time_range}"}}}]}},
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": size,
    }
    try:
        with _os_client() as c:
            r = c.post("/wazuh-alerts-*/_search", json=body)
            r.raise_for_status()
        hits = r.json().get("hits", {})
        return {
            "total": hits.get("total", {}).get("value", 0),
            "events": [h["_source"] for h in hits.get("hits", [])],
        }
    except Exception as e:
        return {"error": str(e)}


def _tool_get_agent_info(agent_id: str) -> dict:
    """Get Wazuh agent details."""
    try:
        token = _wazuh_token()
        r = httpx.get(
            f"{_cfg('WAZUH_URL')}/agents/{agent_id}",
            headers={"Authorization": f"Bearer {token}"},
            verify=False, timeout=10,
        )
        r.raise_for_status()
        return r.json().get("data", {})
    except Exception as e:
        return {"error": str(e)}


def _tool_lookup_ioc(value: str) -> dict:
    """Search MISP for an IOC (IP, domain, hash)."""
    key = _cfg("MISP_API_KEY")
    if not key:
        return {"skipped": "MISP_API_KEY not configured"}
    try:
        with _misp_client() as c:
            r = c.post("/attributes/restSearch",
                       json={"returnFormat": "json", "value": value, "limit": 10})
            r.raise_for_status()
        attrs = r.json().get("response", {}).get("Attribute", [])
        return {
            "query": value,
            "hits": len(attrs),
            "attributes": [
                {"type": a.get("type"), "value": a.get("value"),
                 "comment": a.get("comment", ""), "to_ids": a.get("to_ids")}
                for a in attrs[:5]
            ],
        }
    except Exception as e:
        return {"error": str(e)}


def _tool_run_cortex_analyzer(observable: str, data_type: str, analyzer: str = "AbuseIPDB_1_0") -> dict:
    """Run a Cortex analyzer on an observable."""
    key = _cfg("CORTEX_API_KEY")
    if not key:
        return {"skipped": "CORTEX_API_KEY not configured"}
    try:
        headers = {"Authorization": f"Bearer {key}"}
        with httpx.Client(base_url=_cfg("CORTEX_URL"), headers=headers, timeout=60) as c:
            r = c.post("/api/analyzer/run", json={
                "analyzerId": analyzer,
                "parameters": {"data": observable, "dataType": data_type, "tlp": 2},
            })
            r.raise_for_status()
            job = r.json()
            job_id = job.get("id")
            # Poll for result (max 30s)
            for _ in range(10):
                time.sleep(3)
                poll = c.get(f"/api/job/{job_id}")
                if poll.json().get("status") in ("Success", "Failure"):
                    return poll.json()
            return {"status": "timeout", "job_id": job_id}
    except Exception as e:
        return {"error": str(e)}


def _tool_create_thehive_case(title: str, description: str, severity: int,
                               tags: list, alert_id: str) -> dict:
    """Create a TheHive alert and promote to case."""
    key = _cfg("THEHIVE_API_KEY")
    if not key:
        return {"skipped": "THEHIVE_API_KEY not configured"}
    try:
        with _thehive_client() as c:
            r = c.post("/api/v1/alert", json={
                "title": title,
                "description": description,
                "severity": severity,
                "source": "Phantom Investigator",
                "sourceRef": f"phantom-{alert_id}-{int(time.time())}",
                "tags": tags,
                "type": "alert",
            })
            r.raise_for_status()
            alert_data = r.json()
            alert_hive_id = alert_data.get("_id") or alert_data.get("id")
            return {"thehive_alert_id": alert_hive_id, "status": "created", "url": f"{_cfg('THEHIVE_URL')}/alerts"}
    except Exception as e:
        return {"error": str(e)}


def _tool_fetch_alert_by_id(alert_id: str) -> dict:
    """Fetch a Wazuh alert from OpenSearch by _id."""
    try:
        with _os_client() as c:
            r = c.get(f"/wazuh-alerts-*/_doc/{alert_id}")
            if r.status_code == 200:
                return r.json().get("_source", {})
            return {"error": f"Alert {alert_id} not found", "status": r.status_code}
    except Exception as e:
        return {"error": str(e)}


# ── Tool definitions for Claude ───────────────────────────────────────────────

from skill_loader import search_skills as _search_skills_lib, load_skill as _load_skill_lib

INVESTIGATION_TOOLS = [
    {
        "name": "search_related_events",
        "description": (
            "Query the live OpenSearch SIEM for events related to the alert being investigated. "
            "Searches by source IP and/or agent name across the last 24 hours. "
            "Use this to establish a timeline and identify if this is an isolated event or part of a campaign."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "time_range": {"type": "string", "description": "Time range e.g. '1h', '24h', '7d'", "default": "24h"},
                "size": {"type": "integer", "description": "Number of events to return (default 20)", "default": 20},
            },
        },
    },
    {
        "name": "get_agent_info",
        "description": "Get details about the Wazuh agent that generated the alert: OS, version, groups, last seen.",
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string", "description": "Wazuh agent ID e.g. '003'"},
            },
            "required": ["agent_id"],
        },
    },
    {
        "name": "lookup_ioc",
        "description": "Check an IP address, domain, or file hash against MISP threat intelligence. Returns any known threat intel hits.",
        "input_schema": {
            "type": "object",
            "properties": {
                "value": {"type": "string", "description": "IP, domain, or hash to look up"},
            },
            "required": ["value"],
        },
    },
    {
        "name": "run_cortex_analyzer",
        "description": "Run a Cortex analyzer to enrich an observable. Use AbuseIPDB_1_0 for IP reputation, Shodan_1_0 for IP intel, MISP_2_1 for threat lookup.",
        "input_schema": {
            "type": "object",
            "properties": {
                "observable": {"type": "string", "description": "Value to analyze e.g. an IP address"},
                "data_type": {"type": "string", "description": "Type: 'ip', 'domain', 'hash', 'url'"},
                "analyzer": {"type": "string", "description": "Analyzer ID e.g. 'AbuseIPDB_1_0', 'Shodan_1_0'", "default": "AbuseIPDB_1_0"},
            },
            "required": ["observable", "data_type"],
        },
    },
    {
        "name": "create_thehive_case",
        "description": "Create a TheHive alert and log the investigation. Call this when the investigation concludes with a confirmed or suspected threat.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title":       {"type": "string", "description": "Case title"},
                "description": {"type": "string", "description": "Investigation summary with findings"},
                "severity":    {"type": "integer", "description": "1=Low, 2=Medium, 3=High, 4=Critical"},
                "tags":        {"type": "array", "items": {"type": "string"}, "description": "Tags e.g. ['brute-force', 'T1110']"},
            },
            "required": ["title", "description", "severity", "tags"],
        },
    },
    {
        "name": "search_skills",
        "description": "Search the cybersecurity skill library for investigation procedures, triage workflows, or threat hunting queries relevant to this alert.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search term e.g. 'brute force triage', 'credential stuffing', 'C2 hunting'"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "load_skill",
        "description": "Load the full SKILL.md workflow for a specific skill. Use the name returned by search_skills.",
        "input_schema": {
            "type": "object",
            "properties": {
                "skill_name": {"type": "string", "description": "Kebab-case skill name"},
            },
            "required": ["skill_name"],
        },
    },
    {
        "name": "write_report",
        "description": "Write the final investigation report to disk as Markdown. Call this as the LAST action after all investigation steps are complete.",
        "input_schema": {
            "type": "object",
            "properties": {
                "report_content": {"type": "string", "description": "Full Markdown investigation report"},
                "severity":       {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"], "description": "Overall verdict"},
            },
            "required": ["report_content", "severity"],
        },
    },
]


# ── Tool dispatcher ───────────────────────────────────────────────────────────

def dispatch(tool_name: str, tool_input: dict, alert: dict, output_path: Path,
             no_thehive: bool, no_cortex: bool) -> tuple[str, str | None]:
    """
    Execute a tool call. Returns (result_json, severity_if_report_written).
    """
    print(f"  [tool] {tool_name}({json.dumps({k: v for k, v in tool_input.items() if k != 'report_content'}, separators=(',', ':'))})")

    if tool_name == "search_related_events":
        result = _tool_search_related_events(
            alert,
            tool_input.get("time_range", "24h"),
            int(tool_input.get("size", 20)),
        )
        return json.dumps(result), None

    elif tool_name == "get_agent_info":
        result = _tool_get_agent_info(tool_input.get("agent_id", ""))
        return json.dumps(result), None

    elif tool_name == "lookup_ioc":
        result = _tool_lookup_ioc(tool_input.get("value", ""))
        return json.dumps(result), None

    elif tool_name == "run_cortex_analyzer":
        if no_cortex:
            return json.dumps({"skipped": "--no-cortex flag set"}), None
        result = _tool_run_cortex_analyzer(
            tool_input.get("observable", ""),
            tool_input.get("data_type", "ip"),
            tool_input.get("analyzer", "AbuseIPDB_1_0"),
        )
        return json.dumps(result), None

    elif tool_name == "create_thehive_case":
        if no_thehive:
            return json.dumps({"skipped": "--no-thehive flag set"}), None
        result = _tool_create_thehive_case(
            title=tool_input.get("title", ""),
            description=tool_input.get("description", ""),
            severity=int(tool_input.get("severity", 2)),
            tags=tool_input.get("tags", []),
            alert_id=str(alert.get("id", "unknown")),
        )
        return json.dumps(result), None

    elif tool_name == "search_skills":
        results = _search_skills_lib(tool_input.get("query", ""))
        formatted = [{"name": r["name"], "description": r.get("description", "")} for r in results]
        return json.dumps({"results": formatted}), None

    elif tool_name == "load_skill":
        content = _load_skill_lib(tool_input.get("skill_name", ""))
        if len(content) > 6000:
            content = content[:6000] + "\n\n[... truncated ...]"
        return content, None

    elif tool_name == "write_report":
        content = tool_input.get("report_content", "")
        severity = tool_input.get("severity", "MEDIUM")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        print(f"\n[investigate] Report written: {output_path}")
        return json.dumps({"written": str(output_path), "severity": severity}), severity

    return json.dumps({"error": f"Unknown tool: {tool_name}"}), None


# ── Autonomous investigation loop ─────────────────────────────────────────────

SYSTEM_PROMPT = """You are Phantom, an autonomous SOC investigator running in headless mode.
You have been given a Wazuh security alert. Your job is to investigate it completely without
human interaction and produce a thorough investigation report.

Follow this investigation sequence:
1. Analyse the alert — rule level, groups, MITRE technique, affected agent, source IP
2. search_skills to find the most relevant triage/investigation procedure for this alert type
3. load_skill to read the workflow steps
4. get_agent_info for the affected agent
5. search_related_events to build a timeline (check last 24h for this source IP and agent)
6. lookup_ioc for any external IPs or suspicious indicators
7. run_cortex_analyzer for external IPs (use AbuseIPDB_1_0 for IP reputation)
8. Determine verdict: FALSE POSITIVE / LOW / MEDIUM / HIGH / CRITICAL
9. If severity >= MEDIUM: create_thehive_case
10. write_report — write a complete Markdown investigation report as the FINAL action

The report must contain:
- Executive Summary (2-3 sentences, verdict, severity)
- Alert Details table
- Timeline of Events (from related events)
- Indicator Analysis (IOC lookup + Cortex results)
- MITRE ATT&CK Mapping
- Affected Assets
- Verdict & Confidence level
- Recommended Actions (prioritised)
- TheHive case link (if created)
- Analyst Notes

Be thorough but efficient. Do not ask the user anything — make your own judgement calls.
When evidence is absent or a tool returns an error, note it and continue.
You MUST call write_report as your final action."""


def investigate(alert: dict, output_path: Path, no_thehive: bool, no_cortex: bool) -> int:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[investigate] ERROR: ANTHROPIC_API_KEY not set", file=sys.stderr)
        return 2

    client = anthropic.Anthropic(api_key=api_key)

    alert_summary = json.dumps(alert, indent=2)
    initial_message = f"""Investigate this Wazuh security alert autonomously and write a full investigation report.

ALERT:
```json
{alert_summary}
```

Begin the investigation now. Do not wait for user input."""

    messages = [{"role": "user", "content": initial_message}]
    final_severity: str | None = None
    step = 0
    max_steps = 25  # safety limit

    print(f"\n[investigate] Starting autonomous investigation (max {max_steps} tool steps)...")
    print(f"[investigate] Alert: {alert.get('rule', {}).get('description', 'Unknown')} "
          f"(level {alert.get('rule', {}).get('level', '?')})")
    print(f"[investigate] Agent: {alert.get('agent', {}).get('name', 'unknown')} | "
          f"Source IP: {alert.get('data', {}).get('srcip', 'n/a')}")
    print()

    while step < max_steps:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            tools=INVESTIGATION_TOOLS,
            messages=messages,
        )

        # Collect text parts
        text_parts = [b.text for b in response.content if b.type == "text"]
        if text_parts:
            print(f"\nPhantom: {' '.join(text_parts)[:300]}{'...' if sum(len(t) for t in text_parts) > 300 else ''}")

        if response.stop_reason == "end_turn":
            # Claude finished without calling write_report
            if not final_severity:
                print("\n[investigate] WARNING: investigation ended without write_report. Saving conversation as report.")
                fallback = "\n".join(text_parts) or "No report generated."
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(fallback, encoding="utf-8")
                final_severity = "UNKNOWN"
            break

        if response.stop_reason != "tool_use":
            break

        # Build assistant message with all content blocks
        assistant_blocks = []
        for b in response.content:
            if b.type == "tool_use":
                assistant_blocks.append({"type": "tool_use", "id": b.id, "name": b.name, "input": b.input})
            else:
                assistant_blocks.append({"type": "text", "text": getattr(b, "text", "")})
        messages.append({"role": "assistant", "content": assistant_blocks})

        # Execute all tool calls
        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            result_str, sev = dispatch(
                block.name, block.input, alert, output_path, no_thehive, no_cortex
            )
            if sev:
                final_severity = sev
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result_str,
            })
            step += 1

            # Stop after write_report
            if block.name == "write_report":
                messages.append({"role": "user", "content": tool_results})
                break
        else:
            messages.append({"role": "user", "content": tool_results})

        # Exit if report was written
        if final_severity is not None:
            break

    print(f"\n[investigate] Investigation complete — verdict: {final_severity or 'UNKNOWN'}")
    print(f"[investigate] Report: {output_path}")

    # Save session for replay
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    session_path = SESSIONS_DIR / f"investigation_{ts}.json"
    with open(session_path, "w") as f:
        json.dump({"mode": "soc", "alert": alert, "severity": final_severity,
                   "report": str(output_path), "messages": messages}, f, indent=2, default=str)
    print(f"[investigate] Session: {session_path}")

    sev = final_severity or "UNKNOWN"
    return 1 if sev in ("HIGH", "CRITICAL") else 0


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Phantom — Autonomous SOC Alert Investigator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--alert-file", metavar="PATH", help="Path to Wazuh alert JSON file")
    src.add_argument("--alert-json", metavar="JSON", help="Raw Wazuh alert JSON string")
    src.add_argument("--alert-id",   metavar="ID",   help="Fetch alert from OpenSearch by _id")
    src.add_argument("--demo",       action="store_true", help="Use built-in brute-force demo alert")

    parser.add_argument("--no-thehive", action="store_true", help="Skip TheHive case creation")
    parser.add_argument("--no-cortex",  action="store_true", help="Skip Cortex enrichment")
    parser.add_argument("--output", metavar="PATH", help="Report output path")
    parser.add_argument("--env-file", metavar="PATH",
                        default=str(Path.home() / "soc-platform" / ".env"),
                        help="SOC platform .env file (default: ~/soc-platform/.env)")

    args = parser.parse_args()

    # Load environment
    _load_env(Path(args.env_file).expanduser())

    # Resolve alert
    alert: dict = {}
    if args.demo:
        alert = DEMO_ALERT
        print("[investigate] Using demo alert (SSH brute force)")
    elif args.alert_file:
        p = Path(args.alert_file).expanduser()
        if not p.exists():
            print(f"[investigate] ERROR: file not found: {p}", file=sys.stderr)
            return 2
        alert = json.loads(p.read_text())
    elif args.alert_json:
        try:
            alert = json.loads(args.alert_json)
        except json.JSONDecodeError as e:
            print(f"[investigate] ERROR: invalid JSON: {e}", file=sys.stderr)
            return 2
    elif args.alert_id:
        print(f"[investigate] Fetching alert {args.alert_id} from OpenSearch...")
        alert = _tool_fetch_alert_by_id(args.alert_id)
        if "error" in alert:
            print(f"[investigate] ERROR: {alert['error']}", file=sys.stderr)
            return 2
    else:
        parser.print_help()
        print("\n[investigate] ERROR: provide --alert-file, --alert-json, --alert-id, or --demo", file=sys.stderr)
        return 2

    # Resolve output path
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    rule_desc = alert.get("rule", {}).get("description", "alert")
    safe_desc = "".join(c if c.isalnum() else "_" for c in rule_desc[:40]).strip("_").lower()
    default_out = REPORTS_DIR / f"investigation_{safe_desc}_{ts}.md"
    output_path = Path(args.output).expanduser() if args.output else default_out

    return investigate(alert, output_path, args.no_thehive, args.no_cortex)


if __name__ == "__main__":
    sys.exit(main())
