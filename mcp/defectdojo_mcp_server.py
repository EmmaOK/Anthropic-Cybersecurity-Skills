#!/usr/bin/env python3
"""
Phantom DefectDojo MCP Server
Exposes DefectDojo REST API v2 to Claude/Phantom for AI-assisted vulnerability triage.

The existing pipeline pushes findings into DefectDojo automatically.
This server lets Phantom:
  - List and inspect unverified findings
  - Mark findings as verified, false positive, or risk accepted
  - Add triage notes recording AI reasoning
  - Pull weekly activity for reporting

Tools:
  dd_list_findings     — List findings with filters (severity, status, date)
  dd_get_finding       — Full detail for a single finding by ID
  dd_update_finding    — PATCH finding status (verified, false_p, risk_accepted, etc.)
  dd_add_note          — Add a note to a finding (records triage reasoning)
  dd_list_products     — List all products
  dd_list_engagements  — List engagements for a product
  dd_weekly_activity   — Findings created/updated in the last N days (for weekly report)
  dd_get_metrics       — Severity breakdown counts by product
"""

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

DD_URL     = os.environ.get("DEFECTDOJO_URL", "http://localhost:8080").rstrip("/")
DD_API_KEY = os.environ.get("DEFECTDOJO_API_KEY", "")

server = Server("defectdojo")


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _headers() -> dict:
    return {
        "Authorization": f"Token {DD_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _get(endpoint: str, params: dict | None = None) -> dict:
    url = f"{DD_URL}/api/v2/{endpoint.lstrip('/')}/"
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


def _patch(endpoint: str, data: dict) -> dict:
    url = f"{DD_URL}/api/v2/{endpoint.lstrip('/')}/"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=_headers(), method="PATCH")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "detail": e.read().decode(errors="replace")}
    except Exception as e:
        return {"error": str(e)}


def _post(endpoint: str, data: dict) -> dict:
    url = f"{DD_URL}/api/v2/{endpoint.lstrip('/')}/"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=_headers(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
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
            name="dd_list_findings",
            description=(
                "List DefectDojo findings with optional filters. "
                "Use to fetch unverified, active findings for triage. "
                "Returns id, title, severity, active, verified, false_p, risk_accepted, "
                "cve, endpoint, tool name, and date for each finding."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "product_id":   {"type": "integer", "description": "Filter by product ID"},
                    "severity":     {"type": "string",  "description": "Comma-separated severities: Critical,High,Medium,Low,Info"},
                    "active":       {"type": "boolean", "description": "Filter by active status"},
                    "verified":     {"type": "boolean", "description": "Filter by verified status — use false to get unreviewed findings"},
                    "false_p":      {"type": "boolean", "description": "Filter by false positive status"},
                    "date_after":   {"type": "string",  "description": "Filter findings created after this date (YYYY-MM-DD)"},
                    "limit":        {"type": "integer", "description": "Max results to return (default 50)", "default": 50},
                    "offset":       {"type": "integer", "description": "Pagination offset", "default": 0},
                },
            },
        ),
        Tool(
            name="dd_get_finding",
            description=(
                "Get full detail for a single DefectDojo finding by ID. "
                "Returns title, description, severity, CVE, endpoints, tool/scanner name, "
                "existing notes, mitigation, references, and current status fields."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "integer", "description": "DefectDojo finding ID"},
                },
                "required": ["finding_id"],
            },
        ),
        Tool(
            name="dd_update_finding",
            description=(
                "Update the status of a DefectDojo finding. Use after AI triage to record "
                "the decision: mark as verified (true positive), false positive, risk accepted, "
                "or out of scope. Always add a note via dd_add_note with the reasoning."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id":    {"type": "integer", "description": "DefectDojo finding ID"},
                    "verified":      {"type": "boolean", "description": "Mark as verified true positive"},
                    "false_p":       {"type": "boolean", "description": "Mark as false positive"},
                    "risk_accepted": {"type": "boolean", "description": "Mark as risk accepted"},
                    "out_of_scope":  {"type": "boolean", "description": "Mark as out of scope"},
                    "active":        {"type": "boolean", "description": "Set active status"},
                    "severity":      {"type": "string",  "description": "Override severity: Critical, High, Medium, Low, Info"},
                },
                "required": ["finding_id"],
            },
        ),
        Tool(
            name="dd_add_note",
            description=(
                "Add a note/comment to a DefectDojo finding. "
                "Use this to record AI triage reasoning, false positive justification, "
                "or risk acceptance rationale so the decision is auditable."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "integer", "description": "DefectDojo finding ID"},
                    "note":       {"type": "string",  "description": "Note text to add (triage reasoning, FP justification, etc.)"},
                },
                "required": ["finding_id", "note"],
            },
        ),
        Tool(
            name="dd_list_products",
            description="List all DefectDojo products. Returns id, name, description, and finding counts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max results (default 100)", "default": 100},
                },
            },
        ),
        Tool(
            name="dd_list_engagements",
            description="List DefectDojo engagements, optionally filtered by product.",
            inputSchema={
                "type": "object",
                "properties": {
                    "product_id": {"type": "integer", "description": "Filter by product ID (optional)"},
                    "limit":      {"type": "integer", "description": "Max results (default 50)", "default": 50},
                },
            },
        ),
        Tool(
            name="dd_weekly_activity",
            description=(
                "Get findings created, verified, or closed in the last N days. "
                "Used to build the weekly vulnerability management report. "
                "Returns new_findings, verified_findings, closed_findings, and false_positives."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "days":       {"type": "integer", "description": "Number of days to look back (default 7)", "default": 7},
                    "product_id": {"type": "integer", "description": "Filter to a specific product (optional)"},
                },
            },
        ),
        Tool(
            name="dd_get_metrics",
            description="Get finding severity breakdown counts, optionally filtered by product.",
            inputSchema={
                "type": "object",
                "properties": {
                    "product_id": {"type": "integer", "description": "Filter by product ID (optional)"},
                },
            },
        ),
    ]


# ── Tool handlers ──────────────────────────────────────────────────────────────

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "dd_list_findings":
            return _dd_list_findings(arguments)
        elif name == "dd_get_finding":
            return _dd_get_finding(arguments)
        elif name == "dd_update_finding":
            return _dd_update_finding(arguments)
        elif name == "dd_add_note":
            return _dd_add_note(arguments)
        elif name == "dd_list_products":
            return _dd_list_products(arguments)
        elif name == "dd_list_engagements":
            return _dd_list_engagements(arguments)
        elif name == "dd_weekly_activity":
            return _dd_weekly_activity(arguments)
        elif name == "dd_get_metrics":
            return _dd_get_metrics(arguments)
        else:
            return _text({"error": f"Unknown tool: {name}"})
    except Exception as e:
        return _text({"error": str(e), "tool": name})


def _dd_list_findings(args: dict) -> list[TextContent]:
    params = {
        "limit":      args.get("limit", 50),
        "offset":     args.get("offset", 0),
        "active":     str(args["active"]).lower() if "active" in args else None,
        "verified":   str(args["verified"]).lower() if "verified" in args else None,
        "false_p":    str(args["false_p"]).lower() if "false_p" in args else None,
        "product":    args.get("product_id"),
        "date":       args.get("date_after"),
    }
    if args.get("severity"):
        params["severity"] = args["severity"]

    data = _get("findings", {k: v for k, v in params.items() if v is not None})

    # Slim down the response for context efficiency
    if "results" in data:
        slim = []
        for f in data["results"]:
            slim.append({
                "id":           f.get("id"),
                "title":        f.get("title"),
                "severity":     f.get("severity"),
                "active":       f.get("active"),
                "verified":     f.get("verified"),
                "false_p":      f.get("false_p"),
                "risk_accepted":f.get("risk_accepted"),
                "cve":          f.get("cve"),
                "cwe":          f.get("cwe"),
                "date":         f.get("date"),
                "found_by":     [t.get("name") for t in f.get("found_by", [])],
                "endpoints":    [e.get("host") for e in f.get("endpoints", [])[:3]],
            })
        return _text({"count": data.get("count", 0), "findings": slim})
    return _text(data)


def _dd_get_finding(args: dict) -> list[TextContent]:
    finding_id = args["finding_id"]
    data = _get(f"findings/{finding_id}")
    return _text(data)


def _dd_update_finding(args: dict) -> list[TextContent]:
    finding_id = args.pop("finding_id")
    # Only pass fields that were explicitly provided
    patch_data = {k: v for k, v in args.items()
                  if k in ("verified", "false_p", "risk_accepted", "out_of_scope", "active", "severity")}
    if not patch_data:
        return _text({"error": "No fields to update — provide at least one of: verified, false_p, risk_accepted, out_of_scope, active, severity"})
    result = _patch(f"findings/{finding_id}", patch_data)
    return _text({
        "finding_id":   finding_id,
        "updated":      patch_data,
        "result":       result.get("id") and "success" or result,
    })


def _dd_add_note(args: dict) -> list[TextContent]:
    finding_id = args["finding_id"]
    note_text  = args["note"]
    # DefectDojo notes API: POST /api/v2/notes/ with {entry, finding}
    result = _post("notes", {"entry": note_text, "finding": finding_id})
    return _text({
        "finding_id": finding_id,
        "note_id":    result.get("id"),
        "success":    "id" in result,
        "error":      result.get("error"),
    })


def _dd_list_products(args: dict) -> list[TextContent]:
    data = _get("products", {"limit": args.get("limit", 100)})
    if "results" in data:
        slim = [{"id": p["id"], "name": p["name"],
                 "findings_count": p.get("findings_count", 0)} for p in data["results"]]
        return _text({"count": data.get("count", 0), "products": slim})
    return _text(data)


def _dd_list_engagements(args: dict) -> list[TextContent]:
    params = {"limit": args.get("limit", 50)}
    if args.get("product_id"):
        params["product"] = args["product_id"]
    data = _get("engagements", params)
    if "results" in data:
        slim = [{"id": e["id"], "name": e.get("name", ""), "status": e.get("status"),
                 "target_start": e.get("target_start"), "target_end": e.get("target_end")}
                for e in data["results"]]
        return _text({"count": data.get("count", 0), "engagements": slim})
    return _text(data)


def _dd_weekly_activity(args: dict) -> list[TextContent]:
    days = args.get("days", 7)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    product_id = args.get("product_id")

    base_params = {"limit": 500}
    if product_id:
        base_params["product"] = product_id

    # New findings (created this week)
    new = _get("findings", {**base_params, "date": cutoff})
    new_count = new.get("count", 0)

    # Verified this week
    verified = _get("findings", {**base_params, "verified": "true", "date": cutoff})
    verified_count = verified.get("count", 0)

    # False positives marked this week
    fp = _get("findings", {**base_params, "false_p": "true", "date": cutoff})
    fp_count = fp.get("count", 0)

    # Closed (inactive) this week
    closed = _get("findings", {**base_params, "active": "false", "date": cutoff})
    closed_count = closed.get("count", 0)

    # Severity breakdown of new findings
    severity_breakdown = {}
    for f in new.get("results", []):
        sev = f.get("severity", "Unknown")
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    return _text({
        "period_days":       days,
        "cutoff_date":       cutoff,
        "new_findings":      new_count,
        "verified":          verified_count,
        "false_positives":   fp_count,
        "closed":            closed_count,
        "severity_breakdown": severity_breakdown,
        "new_findings_list": [
            {"id": f["id"], "title": f["title"], "severity": f["severity"],
             "verified": f["verified"], "false_p": f["false_p"]}
            for f in new.get("results", [])[:50]
        ],
    })


def _dd_get_metrics(args: dict) -> list[TextContent]:
    params = {"limit": 1000, "active": "true"}
    if args.get("product_id"):
        params["product"] = args["product_id"]

    data = _get("findings", params)
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in data.get("results", []):
        sev = f.get("severity", "")
        if sev in counts:
            counts[sev] += 1

    return _text({
        "active_findings_total": data.get("count", 0),
        "severity_counts": counts,
        "product_id": args.get("product_id", "all"),
    })


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    url_display = DD_URL if DD_API_KEY else f"{DD_URL} (no API key set)"
    print(f"[defectdojo] Started — {url_display}", file=sys.stderr)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream,
                         server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
