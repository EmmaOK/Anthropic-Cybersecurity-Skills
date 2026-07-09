#!/usr/bin/env python3
"""
phantom/securonix.py — Securonix SIEM/UEBA connector + task types.

Gives Phantom hands-on Securonix capability, built on the task_agent harness and
the `securonix-siem-operations` skill:

  securonix-audit   — read-only audit of the deployment (policies, data sources,
                      incident hygiene, detection/ATT&CK coverage) → report.
  securonix-hunt    — author SPOTTER queries + detection POLICIES to improve threat
                      hunting; can create policies (approval-gated).
  securonix-triage  — triage incidents/violations, enrich indicators, decide
                      true-positive / false-positive, and apply the workflow action
                      (mark FP / close / comment) — approval-gated.
  securonix-soar    — design SOAR response playbooks (triage automation, enrichment,
                      FP auto-close, containment hand-off) and the steps to wire them.

Connector (SNYPR REST API). Auth: either a pre-provisioned token or username/password
(token is generated + cached). Endpoint paths follow SNYPR conventions but are
tenant/version dependent — treat as best-effort and adjust per your instance.

  Environment:
    SECURONIX_URL        — base, e.g. https://<tenant>.securonix.net/Snypr
    SECURONIX_TOKEN      — pre-provisioned API token, OR
    SECURONIX_USERNAME + SECURONIX_PASSWORD  — generate a token
    SECURONIX_AUTH_HEADER — header name for the token (default: Authorization)
    SECURONIX_ALLOW_WRITE=1 — execute writes (create policy / incident action)
                              directly; OFF by default → writes are filed as
                              pending human approvals instead.
    SKIP_TLS_VERIFY=1    — self-signed lab only.

Safety: reads are always allowed. Writes (create_policy, apply_incident_action)
are gated — by default Phantom PROPOSES the change and files an approval
(approvals.create_approval); it only calls the Securonix API when SECURONIX_ALLOW_WRITE
is set. Marking a false positive or closing an incident is a write.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode

from http_util import http_json, ok
from task_agent import (SKILL_TOOLS, run_agent_loop, save_report, register_task,
                        generic_report_tool, _BASE_RULES)

VERIFY_TLS = os.environ.get("SKIP_TLS_VERIFY", "").lower() not in ("1", "true", "yes")
_TOKEN_CACHE: dict[str, str] = {}


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").lower() in ("1", "true", "yes", "on")


# ── Connector ────────────────────────────────────────────────────────────────

def _base() -> str:
    return os.environ.get("SECURONIX_URL", "").rstrip("/")


def _token() -> str:
    tok = os.environ.get("SECURONIX_TOKEN", "")
    if tok:
        return tok
    if _TOKEN_CACHE.get("t"):
        return _TOKEN_CACHE["t"]
    user = os.environ.get("SECURONIX_USERNAME", "")
    pwd = os.environ.get("SECURONIX_PASSWORD", "")
    if _base() and user and pwd:
        # SNYPR token generation: GET /ws/token/generate with username/password headers
        r = http_json(f"{_base()}/ws/token/generate", method="GET",
                      headers={"username": user, "password": pwd}, verify=VERIFY_TLS)
        tok = r if isinstance(r, str) else (r.get("token") or r.get("access_token") or "")
        if tok:
            _TOKEN_CACHE["t"] = tok
        return tok
    return ""


def _api(path: str, method: str = "GET", params: dict | None = None,
         data: dict | None = None) -> dict:
    """One SNYPR API call. Returns the JSON body or {'error': ...}."""
    base = _base()
    if not base:
        return {"error": "SECURONIX_URL not set"}
    tok = _token()
    if not tok:
        return {"error": "no Securonix token (set SECURONIX_TOKEN or USERNAME/PASSWORD)"}
    url = base + path
    if params:
        url += "?" + urlencode(params)
    hdr = {os.environ.get("SECURONIX_AUTH_HEADER", "Authorization"): tok}
    r = http_json(url, headers=hdr, method=method, data=data, verify=VERIFY_TLS)
    if not ok(r):
        return {"error": r.get("_http_error") or r.get("_error") or "api error", "detail": r}
    return r


def _window(hours: int) -> dict:
    now = datetime.now(timezone.utc)
    to_ms = int(now.timestamp() * 1000)
    from_ms = int((now - timedelta(hours=hours)).timestamp() * 1000)
    return {"eventtime_from": from_ms, "eventtime_to": to_ms}


def spotter_search(query: str, hours: int = 24, maximum: int = 50) -> dict:
    r = _api("/ws/spotter/index/search", params={"query": query, "max": maximum, **_window(hours)})
    if r.get("error"):
        return {"available": False, **r}
    events = r.get("events") or r.get("hits") or r.get("data") or []
    return {"available": True, "query": query, "count": len(events),
            "sample": events[:10]}


def list_policies() -> dict:
    r = _api("/ws/policy/getAllPolicies")
    if r.get("error"):
        return {"available": False, **r}
    pols = r.get("policies") or r.get("data") or (r if isinstance(r, list) else [])
    return {"available": True, "count": len(pols),
            "policies": [{"id": p.get("id"), "name": p.get("name") or p.get("policyName"),
                          "criticality": p.get("criticality"), "enabled": p.get("enabled")}
                         for p in pols][:200]}


def list_datasources() -> dict:
    r = _api("/ws/sccWidget/getDatasources")
    if r.get("error"):
        return {"available": False, **r}
    return {"available": True, "datasources": r.get("datasources") or r.get("data") or r}


def list_incidents(status: str = "", hours: int = 168, maximum: int = 50) -> dict:
    params = {"type": "list", "rangeType": "updated", "max": maximum, **_window(hours)}
    if status:
        params["status"] = status
    r = _api("/ws/incident/get", params=params)
    if r.get("error"):
        return {"available": False, **r}
    items = (r.get("result", {}) or {}).get("data", {}).get("incidentItems") \
        or r.get("incidentItems") or r.get("data") or []
    return {"available": True, "count": len(items),
            "incidents": [{"id": i.get("incidentId") or i.get("id"),
                           "entity": i.get("entity"), "policy": i.get("policyName"),
                           "risk": i.get("riskscore") or i.get("priority"),
                           "status": i.get("status")} for i in items][:100]}


def get_incident(incident_id: str) -> dict:
    r = _api("/ws/incident/get", params={"type": "metaInfo", "incidentId": incident_id})
    if r.get("error"):
        return {"available": False, **r}
    return {"available": True, "incident": r.get("result") or r.get("data") or r}


def _do_incident_action(incident_id: str, action: str, comment: str) -> dict:
    r = _api("/ws/incident/actions", method="POST",
             params={"incidentId": incident_id, "actionName": action},
             data={"comment": comment} if comment else None)
    return {"api_result": r}


def _do_create_policy(policy: dict) -> dict:
    r = _api("/ws/policy/createPolicy", method="POST", data=policy)
    return {"api_result": r}


def _gated_write(action_type: str, resources: list, justification: str,
                 impact_level: str, do_write) -> dict:
    """Execute a Securonix write if SECURONIX_ALLOW_WRITE, else file an approval."""
    if _truthy("SECURONIX_ALLOW_WRITE"):
        try:
            return {"executed": True, **do_write()}
        except Exception as e:  # noqa: BLE001
            return {"executed": False, "error": str(e)}
    try:
        from approvals import create_approval
        a = create_approval(session_id="securonix", action_type=action_type, resources=resources,
                            justification=justification, impact="Securonix change",
                            impact_level=impact_level, requested_by="phantom-securonix")
        return {"executed": False, "status": "pending_approval", "approval_id": a.get("id")}
    except Exception as e:  # noqa: BLE001
        return {"executed": False, "error": str(e)}


# ── Tool implementations ─────────────────────────────────────────────────────

def _tool_enrich(indicator: str, indicator_type: str) -> dict:
    try:
        from phishing import _tool_threat_intel
        return _tool_threat_intel(indicator, indicator_type)
    except Exception as e:  # noqa: BLE001
        return {"error": f"enrichment unavailable: {e}"}


def _tool_create_policy(name: str, criteria: str, criticality: str, spotter_query: str,
                        rationale: str) -> dict:
    policy = {"name": name, "criticality": criticality or "Medium",
              "criteria": criteria, "query": spotter_query, "source": "phantom"}
    return _gated_write("securonix-create-policy", [name],
                        f"New detection policy: {rationale}", "medium",
                        lambda: _do_create_policy(policy))


def _tool_apply_incident_action(incident_id: str, action: str, comment: str) -> dict:
    return _gated_write("securonix-incident-action", [f"incident:{incident_id}:{action}"],
                        comment or f"{action} on incident {incident_id}", "low",
                        lambda: _do_incident_action(incident_id, action, comment))


# ── Tool schemas ─────────────────────────────────────────────────────────────

T_SPOTTER = {"name": "spotter_search",
             "description": "Run a Securonix SPOTTER query (read). Use to hunt, validate a "
                            "detection idea, or gather incident evidence.",
             "input_schema": {"type": "object", "properties": {
                 "query": {"type": "string"}, "hours": {"type": "integer"}},
                 "required": ["query"]}}
T_LIST_POL = {"name": "list_policies", "description": "List Securonix detection policies.",
              "input_schema": {"type": "object", "properties": {}}}
T_DATASRC = {"name": "list_datasources", "description": "List Securonix data-source connections (for audit).",
             "input_schema": {"type": "object", "properties": {}}}
T_LIST_INC = {"name": "list_incidents",
              "description": "List Securonix incidents/violations. Optional status filter.",
              "input_schema": {"type": "object", "properties": {
                  "status": {"type": "string"}, "hours": {"type": "integer"}}}}
T_GET_INC = {"name": "get_incident", "description": "Get full detail for one incident.",
             "input_schema": {"type": "object", "properties": {"incident_id": {"type": "string"}},
                              "required": ["incident_id"]}}
T_ENRICH = {"name": "enrich_indicator",
            "description": "Enrich an IP/domain/hash across external threat intel (for triage).",
            "input_schema": {"type": "object", "properties": {
                "indicator": {"type": "string"},
                "indicator_type": {"type": "string", "enum": ["ip", "domain", "url", "hash"]}},
                "required": ["indicator", "indicator_type"]}}
T_CREATE_POL = {"name": "create_policy",
                "description": "Create a Securonix detection policy from a SPOTTER query. WRITE — "
                               "gated: files a human approval unless writes are enabled. Validate the "
                               "query with spotter_search first.",
                "input_schema": {"type": "object", "properties": {
                    "name": {"type": "string"}, "criteria": {"type": "string"},
                    "criticality": {"type": "string", "enum": ["Low", "Medium", "High", "Critical"]},
                    "spotter_query": {"type": "string"}, "rationale": {"type": "string"}},
                    "required": ["name", "spotter_query", "rationale"]}}
T_INC_ACTION = {"name": "apply_incident_action",
                "description": "Apply a workflow action to an incident — e.g. mark false positive, "
                               "close/conclude, claim, or add a comment. WRITE — gated (files approval "
                               "unless writes enabled). Only after you've reached a verdict.",
                "input_schema": {"type": "object", "properties": {
                    "incident_id": {"type": "string"},
                    "action": {"type": "string",
                               "description": "e.g. 'Mark as false positive', 'Close', 'Claim', 'Comment'"},
                    "comment": {"type": "string"}},
                    "required": ["incident_id", "action"]}}


def _dispatch(name: str, inp: dict) -> tuple[str, dict | None]:
    if name == "spotter_search":
        return json.dumps(spotter_search(inp.get("query", ""), inp.get("hours", 24))), None
    if name == "list_policies":
        return json.dumps(list_policies()), None
    if name == "list_datasources":
        return json.dumps(list_datasources()), None
    if name == "list_incidents":
        return json.dumps(list_incidents(inp.get("status", ""), inp.get("hours", 168))), None
    if name == "get_incident":
        return json.dumps(get_incident(inp.get("incident_id", ""))), None
    if name == "enrich_indicator":
        return json.dumps(_tool_enrich(inp.get("indicator", ""), inp.get("indicator_type", ""))), None
    if name == "create_policy":
        return json.dumps(_tool_create_policy(inp.get("name", ""), inp.get("criteria", ""),
                          inp.get("criticality", ""), inp.get("spotter_query", ""),
                          inp.get("rationale", ""))), None
    if name == "apply_incident_action":
        return json.dumps(_tool_apply_incident_action(inp.get("incident_id", ""),
                          inp.get("action", ""), inp.get("comment", ""))), None
    if name == "write_report":
        return json.dumps({"written": True}), dict(inp)
    return json.dumps({"error": f"unknown tool {name}"}), None


# ── Task definitions ─────────────────────────────────────────────────────────

_READ = [T_SPOTTER, T_LIST_POL, T_DATASRC, T_LIST_INC, T_GET_INC]
_REPORT = generic_report_tool()

_TASKS = {
    "securonix-audit": {
        "tools": SKILL_TOOLS + _READ + [_REPORT],
        "subdir": "securonix-audit",
        "system": ("You are Phantom auditing a Securonix SIEM/UEBA deployment (read-only). Pull the "
                   "securonix-siem-operations skill. Enumerate policies (list_policies), data sources "
                   "(list_datasources), and recent incident hygiene (list_incidents), and probe coverage "
                   "with spotter_search. Assess: detection/ATT&CK coverage gaps, disabled/noisy/stale "
                   "policies, data-source/ingestion gaps, and incident backlog. write_report with "
                   "findings + prioritized recommendations. Read-only — never write. " + _BASE_RULES)},
    "securonix-hunt": {
        "tools": SKILL_TOOLS + _READ + [T_CREATE_POL, _REPORT],
        "subdir": "securonix-hunt",
        "system": ("You are Phantom improving threat-hunting in Securonix. Use the securonix-siem-"
                   "operations skill (SPOTTER reference). Author high-fidelity SPOTTER queries for the "
                   "hunt objective, VALIDATE each with spotter_search (check hit volume / false-positive "
                   "risk), then propose detection policies. Use create_policy to add a policy — it is "
                   "gated (files an approval unless writes are enabled). Map each detection to ATT&CK. "
                   "write_report with the SPOTTER queries, the policies proposed/created, and tuning "
                   "notes. " + _BASE_RULES)},
    "securonix-triage": {
        "tools": [T_LIST_INC, T_GET_INC, T_SPOTTER, T_ENRICH, T_INC_ACTION, _REPORT],
        "subdir": "securonix-triage",
        "system": ("You are Phantom triaging Securonix incidents/violations. For each incident: "
                   "get_incident for detail, spotter_search for supporting activity, enrich_indicator "
                   "on IPs/domains/hashes. Decide TRUE-POSITIVE / FALSE-POSITIVE / BENIGN with evidence "
                   "and confidence. For clear false positives, apply_incident_action('Mark as false "
                   "positive', comment=<why>); for confirmed true positives, comment + claim and hand "
                   "off. Write actions are gated (approval unless writes enabled). Never close a "
                   "true-positive as FP. write_report with per-incident verdicts + actions. " + _BASE_RULES)},
    "securonix-soar": {
        "tools": SKILL_TOOLS + _READ + [_REPORT],
        "subdir": "securonix-soar",
        "system": ("You are Phantom designing SOAR response automation for Securonix. Use the "
                   "securonix-siem-operations skill + inspect current policies/incidents for context. "
                   "Design playbooks for: alert triage & enrichment, false-positive auto-close, "
                   "risk-based escalation, and containment hand-off (to the approval-gated actions in "
                   "Phantom's IR pipelines). For each playbook give the trigger, steps, enrichment "
                   "sources, decision logic, and which steps are API-automatable vs UI-configured. "
                   "write_report with the playbook designs + a rollout plan. " + _BASE_RULES)},
}


def _run(task_type: str, objective: str, context: str = "") -> dict:
    entry = _TASKS[task_type]
    task_id = f"{task_type}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    initial = (f"SECURONIX TASK ({task_type}): {objective}\n"
               f"{('CONTEXT: ' + context + chr(10)) if context else ''}\n"
               f"Securonix configured: {bool(_base())}. Begin now.")
    report, _ = run_agent_loop(entry["system"], initial, entry["tools"], _dispatch, label=task_type)
    if not report:
        return {"error": "no report produced", "task_type": task_type}
    report["task_id"] = task_id
    report["task_type"] = task_type
    report["report_path"] = save_report(entry["subdir"], task_id, report)
    return report


for _tt in _TASKS:
    _summary = {
        "securonix-audit": "Read-only audit of a Securonix deployment (policies, data sources, coverage, hygiene)",
        "securonix-hunt": "Author SPOTTER queries + detection policies to improve Securonix threat hunting (policy creation gated)",
        "securonix-triage": "Triage Securonix incidents, enrich, decide TP/FP, and apply the workflow action (gated)",
        "securonix-soar": "Design SOAR response playbooks for Securonix (triage/enrich/FP-auto-close/containment hand-off)",
    }[_tt]
    register_task(_tt, _summary,
                  runner=(lambda tt: lambda objective, **kw: _run(tt, objective, kw.get("context", "")))(_tt))


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python securonix.py <securonix-audit|securonix-hunt|securonix-triage|securonix-soar> '<objective>'")
        raise SystemExit(0)
    out = _run(sys.argv[1], " ".join(sys.argv[2:]))
    print("\n" + out.get("report_markdown", json.dumps(out, indent=2, default=str)))
