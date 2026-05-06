#!/usr/bin/env python3
"""
Phantom DAST MCP Server
Exposes ZAP and Burp Suite Pro REST APIs to Claude/Phantom as MCP tools.

Auto-detects which DAST tool is running:
  ZAP daemon  → http://localhost:8080  (or ZAP_URL env var)
  Burp Pro    → http://localhost:1337  (or BURP_URL env var)

Tools:
  dast_detect         — Check which DAST tools are running
  dast_start_scan     — Start a scan (auto-routes to ZAP or Burp)
  dast_scan_status    — Poll scan progress by scan ID
  dast_get_findings   — Get all findings for a target URL
  dast_stop_scan      — Stop a running scan
  zap_spider          — Spider a target with ZAP (discover URLs/endpoints)
  zap_ajax_spider     — Ajax spider for JavaScript-heavy SPAs
  zap_get_alerts      — Get ZAP alerts with optional severity filter
  zap_active_scan     — Start ZAP active scan on a specific URL
  burp_get_issues     — Get Burp scanner issues with full detail
  burp_start_scan     — Start a Burp scan on a specific URL
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError:
    print("MCP SDK not installed. Run: pip install mcp", file=sys.stderr)
    sys.exit(1)

ZAP_URL  = os.environ.get("ZAP_URL",  "http://localhost:8080")
ZAP_KEY  = os.environ.get("ZAP_API_KEY", "")
BURP_URL = os.environ.get("BURP_URL", "http://localhost:1337")
BURP_KEY = os.environ.get("BURP_API_KEY", "")

ZAP_RISK  = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
ZAP_CONF  = {"4": "CONFIRMED", "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "FALSE_POSITIVE"}
BURP_SEV  = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "information": "INFO"}
BURP_CONF = {"certain": "CONFIRMED", "firm": "HIGH", "tentative": "MEDIUM"}

CWE_MAP = {
    "89":  ("A03:2021 Injection",        "V5"),  "79":  ("A03:2021 Injection",        "V5"),
    "78":  ("A03:2021 Injection",        "V5"),  "918": ("A10:2021 SSRF",             "V5"),
    "22":  ("A01:2021 Broken Access",    "V12"), "352": ("A01:2021 Broken Access",    "V4"),
    "287": ("A07:2021 Auth Failures",    "V2"),  "384": ("A07:2021 Auth Failures",    "V3"),
    "319": ("A02:2021 Crypto Failures",  "V9"),  "311": ("A02:2021 Crypto Failures",  "V6"),
    "200": ("A05:2021 Misconfiguration", "V7"),  "16":  ("A05:2021 Misconfiguration", "V14"),
    "1021":("A05:2021 Misconfiguration", "V14"), "601": ("A01:2021 Broken Access",    "V14"),
}

server = Server("dast-mcp")


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _get(base, path, params=None, api_key=None, key_header=None):
    qs = {}
    if api_key and not key_header:
        qs["apikey"] = api_key
    if params:
        qs.update(params)
    url = base.rstrip("/") + path + ("?" + urllib.parse.urlencode(qs) if qs else "")
    headers = {}
    if api_key and key_header:
        headers[key_header] = api_key
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception as ex:
        return 0, {"_error": str(ex)}


def _post(base, path, data, api_key=None, key_header=None):
    url = base.rstrip("/") + path
    headers = {"Content-Type": "application/json"}
    if api_key and key_header:
        headers[key_header] = api_key
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}
    except Exception as ex:
        return 0, {"_error": str(ex)}


# ── ZAP helpers ────────────────────────────────────────────────────────────────

def zap_get(path, params=None):
    return _get(ZAP_URL, path, params=params, api_key=ZAP_KEY)


def zap_post(path, params=None):
    qs = {"apikey": ZAP_KEY} if ZAP_KEY else {}
    if params:
        qs.update(params)
    url = ZAP_URL.rstrip("/") + path + ("?" + urllib.parse.urlencode(qs) if qs else "")
    req = urllib.request.Request(url, data=b"", method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception as ex:
        return 0, {"_error": str(ex)}


def zap_alive():
    s, b = zap_get("/JSON/core/view/version/")
    return s == 200 and "version" in b, b.get("version", "")


# ── Burp helpers ───────────────────────────────────────────────────────────────

def burp_get(path, params=None):
    return _get(BURP_URL, path, params=params, api_key=BURP_KEY, key_header="X-Api-Key")


def burp_post(path, data):
    return _post(BURP_URL, path, data, api_key=BURP_KEY, key_header="X-Api-Key")


def burp_alive():
    s, b = burp_get("/v0.1/scan")
    return s in (200, 404), ""


# ── Normalise findings ─────────────────────────────────────────────────────────

def _norm_zap_alert(a):
    cwe = str(a.get("cweid", ""))
    owasp, asvs = CWE_MAP.get(cwe, ("A05:2021 Misconfiguration", "V14"))
    return {
        "tool": "ZAP",
        "alert": a.get("alert", a.get("name", "")),
        "severity": ZAP_RISK.get(str(a.get("riskcode", "0")), "INFO"),
        "confidence": ZAP_CONF.get(str(a.get("confidence", "2")), "MEDIUM"),
        "owasp": owasp, "asvs": asvs, "cwe": cwe or "N/A",
        "url": a.get("url", a.get("uri", "")),
        "param": a.get("param", ""),
        "evidence": str(a.get("evidence", ""))[:200],
        "solution": str(a.get("solution", ""))[:300],
    }


def _norm_burp_issue(i):
    cwe = str(i.get("vulnerability_classifications", [{}])[0].get("link", "").split("CWE-")[-1].split('"')[0]) if i.get("vulnerability_classifications") else ""
    owasp, asvs = CWE_MAP.get(cwe, ("A05:2021 Misconfiguration", "V14"))
    return {
        "tool": "Burp",
        "alert": i.get("name", i.get("issue_type", {}).get("name", "")),
        "severity": BURP_SEV.get(i.get("severity", "").lower(), "INFO"),
        "confidence": BURP_CONF.get(i.get("confidence", "").lower(), "MEDIUM"),
        "owasp": owasp, "asvs": asvs, "cwe": cwe or "N/A",
        "url": i.get("origin", "") + i.get("path", ""),
        "param": "",
        "evidence": str(i.get("evidence", {}).get("request_response", {}).get("request", ""))[:200],
        "solution": str(i.get("remediation_detail", i.get("issue_background", "")))[:300],
    }


# ── Tool implementations ───────────────────────────────────────────────────────

def _dast_detect(_args):
    zap_ok, zap_ver = zap_alive()
    burp_ok, _      = burp_alive()
    tools = []
    if zap_ok:
        tools.append({"tool": "ZAP", "url": ZAP_URL, "version": zap_ver, "status": "running"})
    if burp_ok:
        tools.append({"tool": "Burp Suite Pro", "url": BURP_URL, "status": "running"})
    if not tools:
        return json.dumps({
            "status": "none_detected",
            "message": (
                "No DAST tool detected. "
                f"ZAP daemon: zap.sh -daemon -port 8080 -config api.key={ZAP_KEY or 'phantom'}  |  "
                "Burp Pro: Proxy > Options > Enable REST API on port 1337"
            ),
            "checked": [ZAP_URL, BURP_URL],
        }, indent=2)
    return json.dumps({"detected": tools, "preferred": tools[0]["tool"]}, indent=2)


def _dast_start_scan(args):
    target = args.get("target_url", "")
    scan_type = args.get("scan_type", "active")

    zap_ok, _ = zap_alive()
    burp_ok, _ = burp_alive()

    if zap_ok:
        # New ZAP session
        zap_post("/JSON/core/action/newSession/", {"name": "phantom", "overwrite": "true"})
        _, resp = zap_post("/JSON/spider/action/scan/",
                           {"url": target, "maxChildren": "10", "recurse": "true"})
        spider_id = resp.get("scan", "0")
        scan_id = None
        if scan_type in ("active", "full"):
            _, aresp = zap_post("/JSON/ascan/action/scan/",
                                {"url": target, "recurse": "true", "inScopeOnly": "false"})
            scan_id = aresp.get("scan", "0")
        return json.dumps({
            "tool": "ZAP", "target": target, "scan_type": scan_type,
            "spider_id": spider_id, "active_scan_id": scan_id,
            "status": "started",
            "next": "Call dast_scan_status with scan_id to monitor progress",
        }, indent=2)

    if burp_ok:
        scope = {"include": [{"rule": target + ".*", "type": "PrefixMatch"}]}
        _, resp = burp_post("/v0.1/scan", {
            "urls": [target], "scope": scope,
            "scan_configurations": [{"name": "Crawl strategy - fastest"}],
        })
        scan_id = str(resp.get("id", "1"))
        return json.dumps({
            "tool": "Burp", "target": target, "scan_id": scan_id,
            "status": "started",
            "next": "Call dast_scan_status with scan_id to monitor progress",
        }, indent=2)

    return json.dumps({"error": "No DAST tool running. Call dast_detect for setup instructions."}, indent=2)


def _dast_scan_status(args):
    scan_id = str(args.get("scan_id", "0"))
    tool = args.get("tool", "auto")

    zap_ok, _ = zap_alive()
    burp_ok, _ = burp_alive()

    results = {}
    if tool in ("auto", "ZAP") and zap_ok:
        _, spider = zap_get("/JSON/spider/view/status/", {"scanId": scan_id})
        _, ascan  = zap_get("/JSON/ascan/view/status/",  {"scanId": scan_id})
        results["ZAP"] = {
            "spider_progress": spider.get("status", "N/A"),
            "active_scan_progress": ascan.get("status", "N/A"),
        }
    if tool in ("auto", "Burp") and burp_ok:
        _, resp = burp_get(f"/v0.1/scan/{scan_id}")
        results["Burp"] = {
            "status": resp.get("scan_status", "unknown"),
            "crawl_requests_completed": resp.get("scan_metrics", {}).get("crawl_requests_completed", 0),
            "audit_queue_items_completed": resp.get("scan_metrics", {}).get("audit_queue_items_completed", 0),
        }
    return json.dumps({"scan_id": scan_id, "status": results}, indent=2)


def _dast_get_findings(args):
    target = args.get("target_url", "")
    min_severity = args.get("min_severity", "LOW")
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    min_w = sev_order.get(min_severity.upper(), 1)

    findings = []
    zap_ok, _ = zap_alive()
    burp_ok, _ = burp_alive()

    if zap_ok:
        _, resp = zap_get("/JSON/core/view/alerts/",
                          {"baseurl": target, "start": "0", "count": "2000"})
        for a in resp.get("alerts", []):
            f = _norm_zap_alert(a)
            if sev_order.get(f["severity"], 0) >= min_w and a.get("confidence") != "0":
                findings.append(f)

    if burp_ok:
        _, resp = burp_get("/v0.1/scan")
        for scan in resp if isinstance(resp, list) else []:
            scan_id = scan.get("id", "")
            _, iresp = burp_get(f"/v0.1/scan/{scan_id}")
            for issue in iresp.get("issue_events", []):
                i = issue.get("issue", issue)
                f = _norm_burp_issue(i)
                if target in f["url"] and sev_order.get(f["severity"], 0) >= min_w:
                    findings.append(f)

    findings.sort(key=lambda x: sev_order.get(x["severity"], 0), reverse=True)
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return json.dumps({
        "target": target, "total": len(findings),
        "by_severity": counts, "findings": findings,
    }, indent=2)


def _dast_stop_scan(args):
    scan_id = str(args.get("scan_id", "0"))
    stopped = []
    zap_ok, _ = zap_alive()
    burp_ok, _ = burp_alive()
    if zap_ok:
        zap_post("/JSON/spider/action/stop/",   {"scanId": scan_id})
        zap_post("/JSON/ascan/action/stop/",    {"scanId": scan_id})
        stopped.append("ZAP")
    if burp_ok:
        burp_post(f"/v0.1/scan/{scan_id}/cancel", {})
        stopped.append("Burp")
    return json.dumps({"scan_id": scan_id, "stopped": stopped}, indent=2)


def _zap_spider(args):
    target = args.get("target_url", "")
    max_children = args.get("max_children", 20)
    if not zap_alive()[0]:
        return json.dumps({"error": "ZAP not running"}, indent=2)
    zap_post("/JSON/core/action/newSession/", {"name": "spider", "overwrite": "true"})
    _, resp = zap_post("/JSON/spider/action/scan/",
                       {"url": target, "maxChildren": str(max_children), "recurse": "true"})
    scan_id = resp.get("scan", "0")
    return json.dumps({
        "spider_id": scan_id, "target": target,
        "next": f"Call dast_scan_status with scan_id={scan_id} to monitor, then zap_get_alerts to see discovered endpoints",
    }, indent=2)


def _zap_ajax_spider(args):
    target = args.get("target_url", "")
    if not zap_alive()[0]:
        return json.dumps({"error": "ZAP not running"}, indent=2)
    _, resp = zap_post("/JSON/ajaxSpider/action/scan/",
                       {"url": target, "inScope": "false"})
    return json.dumps({
        "status": resp.get("Result", "started"),
        "target": target,
        "note": "Ajax spider uses a real browser — requires ZAP with browser configured",
        "next": "Poll GET /JSON/ajaxSpider/view/status/ until 'stopped'",
    }, indent=2)


def _zap_get_alerts(args):
    target = args.get("target_url", "")
    severity = args.get("severity", "")
    sev_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    min_w = sev_order.get(severity.upper(), 0)

    if not zap_alive()[0]:
        return json.dumps({"error": "ZAP not running"}, indent=2)

    _, resp = zap_get("/JSON/core/view/alerts/",
                      {"baseurl": target, "start": "0", "count": "2000"})
    alerts = []
    for a in resp.get("alerts", []):
        if a.get("confidence") == "0":
            continue
        f = _norm_zap_alert(a)
        if sev_order.get(f["severity"], 0) >= min_w:
            alerts.append(f)
    alerts.sort(key=lambda x: sev_order.get(x["severity"], 0), reverse=True)
    return json.dumps({"target": target, "count": len(alerts), "alerts": alerts}, indent=2)


def _zap_active_scan(args):
    target = args.get("target_url", "")
    policy = args.get("policy", "")
    if not zap_alive()[0]:
        return json.dumps({"error": "ZAP not running"}, indent=2)
    params = {"url": target, "recurse": "true", "inScopeOnly": "false"}
    if policy:
        params["scanPolicyName"] = policy
    _, resp = zap_post("/JSON/ascan/action/scan/", params)
    scan_id = resp.get("scan", "0")
    return json.dumps({
        "scan_id": scan_id, "target": target,
        "next": f"Call dast_scan_status with scan_id={scan_id} to monitor progress",
    }, indent=2)


def _burp_get_issues(args):
    target = args.get("target_url", "")
    min_sev = args.get("min_severity", "LOW")
    sev_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    min_w = sev_order.get(min_sev.upper(), 1)

    if not burp_alive()[0]:
        return json.dumps({"error": "Burp Suite Pro REST API not running. Enable it in Proxy > Options > REST API."}, indent=2)

    _, scans = burp_get("/v0.1/scan")
    issues = []
    if isinstance(scans, list):
        for scan in scans:
            sid = scan.get("id", "")
            if target and target not in scan.get("urls", [""])[0]:
                continue
            _, detail = burp_get(f"/v0.1/scan/{sid}")
            for ev in detail.get("issue_events", []):
                i = ev.get("issue", ev)
                f = _norm_burp_issue(i)
                if sev_order.get(f["severity"], 0) >= min_w:
                    issues.append(f)

    issues.sort(key=lambda x: sev_order.get(x["severity"], 0), reverse=True)
    return json.dumps({"target": target, "count": len(issues), "issues": issues}, indent=2)


def _burp_start_scan(args):
    target = args.get("target_url", "")
    if not burp_alive()[0]:
        return json.dumps({"error": "Burp Suite Pro REST API not running"}, indent=2)
    scope = {"include": [{"rule": target, "type": "PrefixMatch"}]}
    _, resp = burp_post("/v0.1/scan", {"urls": [target], "scope": scope})
    scan_id = str(resp.get("id", ""))
    return json.dumps({
        "tool": "Burp", "target": target, "scan_id": scan_id, "status": "started",
        "next": f"Call dast_scan_status with scan_id={scan_id} and tool=Burp",
    }, indent=2)


# ── Tool registry ──────────────────────────────────────────────────────────────

@server.list_tools()
async def list_tools():
    return [
        Tool(name="dast_detect",
             description="Detect which DAST tools are running (ZAP daemon, Burp Suite Pro REST API). Always call this first before scanning.",
             inputSchema={"type": "object", "properties": {}}),
        Tool(name="dast_start_scan",
             description="Start a DAST scan against a target URL. Auto-routes to ZAP or Burp based on what is running. Returns a scan_id for status polling.",
             inputSchema={"type": "object", "properties": {
                 "target_url": {"type": "string", "description": "Base URL to scan e.g. https://app.example.com"},
                 "scan_type":  {"type": "string", "enum": ["passive", "active", "full"], "default": "active"},
             }, "required": ["target_url"]}),
        Tool(name="dast_scan_status",
             description="Poll the progress of a running DAST scan. Returns percentage complete for spider and active scan phases.",
             inputSchema={"type": "object", "properties": {
                 "scan_id": {"type": "string", "description": "Scan ID returned by dast_start_scan"},
                 "tool":    {"type": "string", "enum": ["auto", "ZAP", "Burp"], "default": "auto"},
             }, "required": ["scan_id"]}),
        Tool(name="dast_get_findings",
             description="Get all findings (alerts/issues) discovered by DAST tools for a target URL. Normalized across ZAP and Burp with OWASP Top 10 and ASVS chapter mapping.",
             inputSchema={"type": "object", "properties": {
                 "target_url":   {"type": "string", "description": "Target URL to get findings for"},
                 "min_severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], "default": "LOW"},
             }, "required": ["target_url"]}),
        Tool(name="dast_stop_scan",
             description="Stop a running DAST scan.",
             inputSchema={"type": "object", "properties": {
                 "scan_id": {"type": "string", "description": "Scan ID to stop"},
             }, "required": ["scan_id"]}),
        Tool(name="zap_spider",
             description="Spider a target URL with ZAP to discover all pages and endpoints before scanning. Returns a spider_id to track progress.",
             inputSchema={"type": "object", "properties": {
                 "target_url":   {"type": "string"},
                 "max_children": {"type": "integer", "default": 20, "description": "Max child links to follow per page"},
             }, "required": ["target_url"]}),
        Tool(name="zap_ajax_spider",
             description="Run ZAP Ajax Spider for JavaScript-heavy SPAs (React, Angular, Vue). Uses a real browser to discover dynamically rendered content.",
             inputSchema={"type": "object", "properties": {
                 "target_url": {"type": "string"},
             }, "required": ["target_url"]}),
        Tool(name="zap_get_alerts",
             description="Get ZAP alerts for a target. Call after a scan or spider completes. Filter by minimum severity.",
             inputSchema={"type": "object", "properties": {
                 "target_url": {"type": "string"},
                 "severity":   {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW", "INFO"], "default": "LOW"},
             }, "required": ["target_url"]}),
        Tool(name="zap_active_scan",
             description="Start a ZAP active scan on a specific URL (sends attack payloads — SQLi, XSS, SSRF, etc). Must spider first for best coverage.",
             inputSchema={"type": "object", "properties": {
                 "target_url": {"type": "string"},
                 "policy":     {"type": "string", "description": "ZAP scan policy name (optional, uses default if empty)"},
             }, "required": ["target_url"]}),
        Tool(name="burp_get_issues",
             description="Get Burp Suite scanner issues for a target. Returns full detail including evidence, remediation, and OWASP mapping.",
             inputSchema={"type": "object", "properties": {
                 "target_url":   {"type": "string"},
                 "min_severity": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW", "INFO"], "default": "LOW"},
             }, "required": ["target_url"]}),
        Tool(name="burp_start_scan",
             description="Start a Burp Suite Pro scan on a specific URL. Burp REST API must be enabled in Proxy > Options.",
             inputSchema={"type": "object", "properties": {
                 "target_url": {"type": "string"},
             }, "required": ["target_url"]}),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    dispatch = {
        "dast_detect":      _dast_detect,
        "dast_start_scan":  _dast_start_scan,
        "dast_scan_status": _dast_scan_status,
        "dast_get_findings": _dast_get_findings,
        "dast_stop_scan":   _dast_stop_scan,
        "zap_spider":       _zap_spider,
        "zap_ajax_spider":  _zap_ajax_spider,
        "zap_get_alerts":   _zap_get_alerts,
        "zap_active_scan":  _zap_active_scan,
        "burp_get_issues":  _burp_get_issues,
        "burp_start_scan":  _burp_start_scan,
    }
    fn = dispatch.get(name)
    if not fn:
        return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]
    return [TextContent(type="text", text=fn(arguments))]


async def main():
    zap_ok, zver = zap_alive()
    burp_ok, _   = burp_alive()
    active = []
    if zap_ok:  active.append(f"ZAP {zver} at {ZAP_URL}")
    if burp_ok: active.append(f"Burp Pro at {BURP_URL}")
    status = ", ".join(active) if active else "none detected (tools will be checked at call time)"
    print(f"[dast-mcp] Started — DAST tools: {status}", file=sys.stderr)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
