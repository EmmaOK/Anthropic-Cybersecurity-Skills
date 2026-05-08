#!/usr/bin/env python3
"""
Phantom Jira MCP Server
Exposes Jira REST API v2 to Claude/Phantom for AI-assisted vulnerability ticket management.

Replaces the manual "push to Jira" step in the DefectDojo → Jira workflow:
Phantom triages a DefectDojo finding, confirms it is a true positive, then calls
jira_create_issue to create the ticket — no human click required.

Tools:
  jira_create_issue      — Create a security ticket (maps DD severity → Jira priority)
  jira_search            — JQL search (find by title, CVE, label, or custom query)
  jira_get_issue         — Full detail for an issue by key (e.g. SEC-123)
  jira_add_comment       — Add a comment (records triage reasoning, links back to DD finding)
  jira_transition_issue  — Move issue through workflow (fetches transitions then applies)
  jira_weekly_activity   — Issues created/updated in last N days (for weekly report)
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError:
    print("MCP SDK not installed. Run: pip install mcp", file=sys.stderr)
    sys.exit(1)

JIRA_URL         = os.environ.get("JIRA_URL", "").rstrip("/")
JIRA_USER        = os.environ.get("JIRA_USER", "")
JIRA_TOKEN       = os.environ.get("JIRA_TOKEN", "")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "SEC")

server = Server("jira")

# DefectDojo severity → Jira priority name
SEVERITY_TO_PRIORITY = {
    "Critical": "Highest",
    "High":     "High",
    "Medium":   "Medium",
    "Low":      "Low",
    "Info":     "Lowest",
}


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _auth_header() -> str:
    token = base64.b64encode(f"{JIRA_USER}:{JIRA_TOKEN}".encode()).decode()
    return f"Basic {token}"


def _headers() -> dict:
    return {
        "Authorization": _auth_header(),
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }


def _get(path: str, params: dict | None = None) -> dict:
    url = f"{JIRA_URL}/rest/api/2/{path.lstrip('/')}"
    if params:
        url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    req = urllib.request.Request(url, headers=_headers())
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "detail": e.read().decode(errors="replace")}
    except Exception as e:
        return {"error": str(e)}


def _post(path: str, data: dict) -> dict:
    url = f"{JIRA_URL}/rest/api/2/{path.lstrip('/')}"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=_headers(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return json.loads(raw) if raw.strip() else {"success": True}
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "detail": e.read().decode(errors="replace")}
    except Exception as e:
        return {"error": str(e)}


def _text(content) -> list[TextContent]:
    if not isinstance(content, str):
        content = json.dumps(content, indent=2, default=str)
    return [TextContent(type="text", text=content)]


# ── Tool definitions ───────────────────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="jira_create_issue",
            description=(
                "Create a Jira security ticket for a verified DefectDojo finding. "
                "Automatically maps DefectDojo severity (Critical/High/Medium/Low/Info) to "
                "Jira priority (Highest/High/Medium/Low/Lowest). "
                "Adds a 'security' label and optionally a defectdojo_id label for traceability. "
                "Returns the created issue key (e.g. SEC-123) and URL."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "summary":        {"type": "string",  "description": "Issue title / finding title"},
                    "description":    {"type": "string",  "description": "Full issue description including finding details, evidence, and remediation steps"},
                    "severity":       {"type": "string",  "description": "DefectDojo severity: Critical, High, Medium, Low, Info"},
                    "issue_type":     {"type": "string",  "description": "Jira issue type (default: Bug)", "default": "Bug"},
                    "project_key":    {"type": "string",  "description": "Jira project key (overrides JIRA_PROJECT_KEY env var)"},
                    "defectdojo_id":  {"type": "integer", "description": "DefectDojo finding ID — added as label dd-<id> for traceability"},
                    "cve":            {"type": "string",  "description": "CVE identifier — added as label if provided"},
                    "assignee":       {"type": "string",  "description": "Assignee account ID or username"},
                    "labels":         {"type": "array",   "items": {"type": "string"}, "description": "Additional labels"},
                },
                "required": ["summary", "severity"],
            },
        ),
        Tool(
            name="jira_search",
            description=(
                "Search Jira issues using JQL. "
                "Use to check if a ticket already exists for a DefectDojo finding before creating a duplicate. "
                "Common patterns: search by summary text, CVE label, or defectdojo label (dd-<id>)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "jql":        {"type": "string",  "description": "JQL query string, e.g. 'project=SEC AND labels=dd-42 AND statusCategory != Done'"},
                    "max_results":{"type": "integer", "description": "Max results to return (default 20)", "default": 20},
                    "fields":     {"type": "string",  "description": "Comma-separated field names to return (default: summary,status,priority,labels,assignee,created)"},
                },
                "required": ["jql"],
            },
        ),
        Tool(
            name="jira_get_issue",
            description=(
                "Get full detail for a Jira issue by key (e.g. SEC-123). "
                "Returns summary, description, status, priority, assignee, reporter, "
                "labels, comments, and linked issues."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "issue_key": {"type": "string", "description": "Jira issue key, e.g. SEC-123"},
                },
                "required": ["issue_key"],
            },
        ),
        Tool(
            name="jira_add_comment",
            description=(
                "Add a comment to a Jira issue. "
                "Use to record AI triage reasoning, link back to the DefectDojo finding, "
                "or add remediation notes after a ticket is created."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "issue_key": {"type": "string", "description": "Jira issue key, e.g. SEC-123"},
                    "comment":   {"type": "string", "description": "Comment text to add"},
                },
                "required": ["issue_key", "comment"],
            },
        ),
        Tool(
            name="jira_transition_issue",
            description=(
                "Move a Jira issue through its workflow (e.g. In Progress → Done). "
                "First fetches available transitions for the issue, then applies the matching one. "
                "Transition name matching is case-insensitive and partial (e.g. 'done' matches 'Done')."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "issue_key":       {"type": "string", "description": "Jira issue key, e.g. SEC-123"},
                    "transition_name": {"type": "string", "description": "Target workflow state name, e.g. 'In Progress', 'Done', 'Resolved'"},
                },
                "required": ["issue_key", "transition_name"],
            },
        ),
        Tool(
            name="jira_weekly_activity",
            description=(
                "Get Jira issues created or updated in the last N days. "
                "Used to build the 'Jira Ticket Activity' section of the weekly vulnerability report. "
                "Returns counts and lists of created, in-progress, and closed issues."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "days":        {"type": "integer", "description": "Number of days to look back (default 7)", "default": 7},
                    "project_key": {"type": "string",  "description": "Jira project key to filter (overrides env var)"},
                    "max_results": {"type": "integer", "description": "Max issues per category (default 50)", "default": 50},
                },
            },
        ),
    ]


# ── Tool handlers ──────────────────────────────────────────────────────────────

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "jira_create_issue":
            return _jira_create_issue(arguments)
        elif name == "jira_search":
            return _jira_search(arguments)
        elif name == "jira_get_issue":
            return _jira_get_issue(arguments)
        elif name == "jira_add_comment":
            return _jira_add_comment(arguments)
        elif name == "jira_transition_issue":
            return _jira_transition_issue(arguments)
        elif name == "jira_weekly_activity":
            return _jira_weekly_activity(arguments)
        else:
            return _text({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return _text({"error": str(e), "tool": name})


def _jira_create_issue(args: dict) -> list[TextContent]:
    project_key = args.get("project_key") or JIRA_PROJECT_KEY
    severity    = args.get("severity", "Medium")
    priority    = SEVERITY_TO_PRIORITY.get(severity, "Medium")

    labels = ["security"]
    if args.get("defectdojo_id"):
        labels.append(f"dd-{args['defectdojo_id']}")
    if args.get("cve"):
        labels.append(args["cve"].upper().replace(" ", "-"))
    labels.extend(args.get("labels") or [])

    payload = {
        "fields": {
            "project":   {"key": project_key},
            "summary":   args["summary"],
            "issuetype": {"name": args.get("issue_type", "Bug")},
            "priority":  {"name": priority},
            "labels":    labels,
        }
    }

    if args.get("description"):
        payload["fields"]["description"] = args["description"]
    if args.get("assignee"):
        payload["fields"]["assignee"] = {"name": args["assignee"]}

    result = _post("issue", payload)

    if "key" in result:
        issue_url = f"{JIRA_URL}/browse/{result['key']}"
        return _text({
            "success":    True,
            "issue_key":  result["key"],
            "issue_id":   result.get("id"),
            "issue_url":  issue_url,
            "priority":   priority,
            "labels":     labels,
        })
    return _text(result)


def _jira_search(args: dict) -> list[TextContent]:
    fields_default = "summary,status,priority,labels,assignee,created,updated"
    params = {
        "jql":        args["jql"],
        "maxResults": args.get("max_results", 20),
        "fields":     args.get("fields", fields_default),
    }
    data = _get("search", params)

    if "issues" in data:
        slim = []
        for issue in data["issues"]:
            f = issue.get("fields", {})
            slim.append({
                "key":      issue["key"],
                "summary":  f.get("summary"),
                "status":   f.get("status", {}).get("name"),
                "priority": f.get("priority", {}).get("name"),
                "labels":   f.get("labels", []),
                "assignee": (f.get("assignee") or {}).get("displayName"),
                "created":  f.get("created"),
            })
        return _text({"total": data.get("total", 0), "issues": slim})
    return _text(data)


def _jira_get_issue(args: dict) -> list[TextContent]:
    issue_key = args["issue_key"]
    data = _get(f"issue/{issue_key}")

    if "error" in data:
        return _text(data)

    f = data.get("fields", {})
    comments = f.get("comment", {}).get("comments", [])
    slim_comments = [
        {
            "author":  (c.get("author") or {}).get("displayName"),
            "body":    c.get("body", "")[:500],
            "created": c.get("created"),
        }
        for c in comments[-5:]
    ]

    return _text({
        "key":           data["key"],
        "summary":       f.get("summary"),
        "status":        f.get("status", {}).get("name"),
        "priority":      f.get("priority", {}).get("name"),
        "assignee":      (f.get("assignee") or {}).get("displayName"),
        "reporter":      (f.get("reporter") or {}).get("displayName"),
        "labels":        f.get("labels", []),
        "created":       f.get("created"),
        "updated":       f.get("updated"),
        "description":   (f.get("description") or "")[:1000],
        "recent_comments": slim_comments,
    })


def _jira_add_comment(args: dict) -> list[TextContent]:
    issue_key = args["issue_key"]
    result = _post(f"issue/{issue_key}/comment", {"body": args["comment"]})
    return _text({
        "issue_key": issue_key,
        "comment_id": result.get("id"),
        "success":    "id" in result,
        "error":      result.get("error"),
    })


def _jira_transition_issue(args: dict) -> list[TextContent]:
    issue_key       = args["issue_key"]
    transition_name = args["transition_name"].lower()

    transitions_data = _get(f"issue/{issue_key}/transitions")
    if "error" in transitions_data:
        return _text(transitions_data)

    transitions = transitions_data.get("transitions", [])
    match = next(
        (t for t in transitions if transition_name in t.get("name", "").lower()),
        None
    )
    if not match:
        available = [t.get("name") for t in transitions]
        return _text({
            "error": f"No transition matching '{args['transition_name']}'",
            "available_transitions": available,
        })

    result = _post(f"issue/{issue_key}/transitions", {"transition": {"id": match["id"]}})
    return _text({
        "issue_key":        issue_key,
        "transition_applied": match["name"],
        "transition_id":    match["id"],
        "success":          "error" not in result,
        "error":            result.get("error"),
    })


def _jira_weekly_activity(args: dict) -> list[TextContent]:
    days        = args.get("days", 7)
    project_key = args.get("project_key") or JIRA_PROJECT_KEY
    max_results = args.get("max_results", 50)
    cutoff      = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")

    base_jql = f"project = {project_key} AND "

    created = _get("search", {
        "jql":        base_jql + f"created >= '{cutoff}' ORDER BY created DESC",
        "maxResults": max_results,
        "fields":     "summary,status,priority,labels,created",
    })
    in_progress = _get("search", {
        "jql":        base_jql + f"statusCategory = 'In Progress' AND updated >= '{cutoff}' ORDER BY updated DESC",
        "maxResults": max_results,
        "fields":     "summary,status,priority,labels,updated",
    })
    closed = _get("search", {
        "jql":        base_jql + f"statusCategory = Done AND updated >= '{cutoff}' ORDER BY updated DESC",
        "maxResults": max_results,
        "fields":     "summary,status,priority,labels,updated",
    })

    def slim_issues(data):
        return [
            {
                "key":      i["key"],
                "summary":  i["fields"].get("summary"),
                "status":   i["fields"].get("status", {}).get("name"),
                "priority": i["fields"].get("priority", {}).get("name"),
                "labels":   i["fields"].get("labels", []),
            }
            for i in data.get("issues", [])
        ]

    return _text({
        "period_days":  days,
        "cutoff_date":  cutoff,
        "project_key":  project_key,
        "created": {
            "count":  created.get("total", 0),
            "issues": slim_issues(created),
        },
        "in_progress": {
            "count":  in_progress.get("total", 0),
            "issues": slim_issues(in_progress),
        },
        "closed": {
            "count":  closed.get("total", 0),
            "issues": slim_issues(closed),
        },
    })


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    url_display = JIRA_URL if JIRA_TOKEN else f"{JIRA_URL or '(no JIRA_URL set)'} (no credentials)"
    print(f"[jira] Started — {url_display}", file=sys.stderr)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream,
                         server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
