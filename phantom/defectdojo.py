#!/usr/bin/env python3
"""
phantom/defectdojo.py — DefectDojo connector + vulnerability-management task types.

Gives Phantom hands-on DefectDojo capability on the task_agent harness, using the
`triaging-defectdojo-findings` skill. Beyond the basics, a vuln-management platform
enables exploit-aware prioritization, risk-acceptance workflow, dedup, and posture
reporting — so this covers the full lifecycle:

  defectdojo-triage      — read findings, decide false-positive / duplicate / risk-
                           accept / real, archive FPs (gated), add notes, and open
                           Jira remediation tickets for the real ones.
  defectdojo-sla         — monitor SLA: surface overdue / near-due findings by
                           severity and escalate (Jira tickets) the breaches.
  defectdojo-prioritize  — exploit-aware ranking: enrich finding CVEs with CISA KEV
                           + FIRST EPSS, flag what to fix first, annotate findings.
  defectdojo-report      — generate posture / SLA / remediation / executive reports
                           from DefectDojo metrics + findings.

Connector: DefectDojo REST API v2. Auth header `Authorization: Token <key>`.
  Environment:
    DEFECTDOJO_URL  (or DD_URL)          — e.g. https://defectdojo.corp/
    DEFECTDOJO_API_KEY (or DD_API_KEY)   — API v2 token
    DEFECTDOJO_ALLOW_WRITE=1             — apply finding mutations (archive FP,
                                           risk-accept, mitigate) directly; OFF by
                                           default → they're filed as human approvals.
    SKIP_TLS_VERIFY=1                    — self-signed lab only.
    Jira tickets reuse case_sync (JIRA_URL / JIRA_USER / JIRA_API_TOKEN / JIRA_PROJECT_KEY).

Safety: reads + note-adds + Jira ticket creation are allowed. Finding STATE changes
(false_p, risk_accepted, is_mitigated) are gated — proposed as approvals unless
DEFECTDOJO_ALLOW_WRITE is set.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from http_util import http_json, ok
from task_agent import (SKILL_TOOLS, run_agent_loop, save_report, register_task,
                        generic_report_tool, _BASE_RULES)

VERIFY_TLS = os.environ.get("SKIP_TLS_VERIFY", "").lower() not in ("1", "true", "yes")
_KEV_CACHE: dict[str, set] = {}


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").lower() in ("1", "true", "yes", "on")


# ── Connector (DefectDojo API v2) ────────────────────────────────────────────

def _base() -> str:
    return (os.environ.get("DEFECTDOJO_URL") or os.environ.get("DD_URL", "")).rstrip("/")


def _key() -> str:
    return os.environ.get("DEFECTDOJO_API_KEY") or os.environ.get("DD_API_KEY", "")


def _api(path: str, method: str = "GET", params: dict | None = None,
         data: dict | None = None) -> dict:
    base, key = _base(), _key()
    if not base:
        return {"error": "DEFECTDOJO_URL not set"}
    if not key:
        return {"error": "DEFECTDOJO_API_KEY not set"}
    url = f"{base}/api/v2{path}"
    if params:
        from urllib.parse import urlencode
        url += "?" + urlencode({k: v for k, v in params.items() if v not in (None, "")})
    r = http_json(url, headers={"Authorization": f"Token {key}"},
                  method=method, data=data, verify=VERIFY_TLS)
    if not ok(r):
        return {"error": r.get("_http_error") or r.get("_error") or "api error", "detail": r}
    return r


def _slim_finding(f: dict) -> dict:
    cves = f.get("vulnerability_ids") or ([{"vulnerability_id": f["cve"]}] if f.get("cve") else [])
    cve = ""
    if cves:
        c0 = cves[0]
        cve = c0.get("vulnerability_id") if isinstance(c0, dict) else c0
    return {"id": f.get("id"), "title": f.get("title", "")[:120], "severity": f.get("severity"),
            "active": f.get("active"), "false_p": f.get("false_p"),
            "duplicate": f.get("duplicate"), "risk_accepted": f.get("risk_accepted"),
            "mitigated": f.get("is_mitigated"), "cve": cve,
            "sla_expiration_date": f.get("sla_expiration_date"),
            "found_by": f.get("found_by")}


def list_findings(severity: str = "", active: bool | None = True, false_p: bool | None = None,
                  duplicate: bool | None = None, product: str = "", limit: int = 50) -> dict:
    params = {"limit": limit, "severity": severity, "product_name": product}
    if active is not None:
        params["active"] = str(active).lower()
    if false_p is not None:
        params["false_p"] = str(false_p).lower()
    if duplicate is not None:
        params["duplicate"] = str(duplicate).lower()
    r = _api("/findings/", params=params)
    if r.get("error"):
        return {"available": False, **r}
    return {"available": True, "count": r.get("count", 0),
            "findings": [_slim_finding(f) for f in r.get("results", [])]}


def get_finding(finding_id: str) -> dict:
    r = _api(f"/findings/{finding_id}/")
    if r.get("error"):
        return {"available": False, **r}
    return {"available": True, "finding": {**_slim_finding(r),
            "description": (r.get("description") or "")[:2000],
            "mitigation": (r.get("mitigation") or "")[:1000]}}


def update_finding(finding_id: str, fields: dict) -> dict:
    return {"api_result": _api(f"/findings/{finding_id}/", method="PATCH", data=fields)}


def add_note(finding_id: str, note: str) -> dict:
    r = _api(f"/findings/{finding_id}/notes/", method="POST", data={"entry": note})
    return {"added": ok(r) and not r.get("error"), "detail": r}


def sla_findings(severity: str = "", limit: int = 100) -> dict:
    """Active findings with an SLA date, tagged overdue / days remaining."""
    r = list_findings(severity=severity, active=True, limit=limit)
    if not r.get("available"):
        return r
    today = datetime.now(timezone.utc).date()
    out = []
    for f in r["findings"]:
        exp = f.get("sla_expiration_date")
        if not exp:
            continue
        try:
            due = datetime.fromisoformat(exp[:10]).date()
            days = (due - today).days
            out.append({**f, "sla_days_remaining": days,
                        "sla_state": "OVERDUE" if days < 0 else "due-soon" if days <= 7 else "ok"})
        except ValueError:
            continue
    out.sort(key=lambda x: x["sla_days_remaining"])
    return {"available": True, "count": len(out),
            "overdue": [f for f in out if f["sla_state"] == "OVERDUE"],
            "due_soon": [f for f in out if f["sla_state"] == "due-soon"]}


def list_products() -> dict:
    r = _api("/products/", params={"limit": 100})
    if r.get("error"):
        return {"available": False, **r}
    return {"available": True, "products": [{"id": p.get("id"), "name": p.get("name")}
                                            for p in r.get("results", [])]}


def metrics() -> dict:
    """Severity/status counts from finding queries (DefectDojo posture snapshot)."""
    out = {"available": True}
    for sev in ("Critical", "High", "Medium", "Low"):
        r = _api("/findings/", params={"severity": sev, "active": "true", "limit": 1})
        out[f"active_{sev.lower()}"] = r.get("count", 0) if not r.get("error") else "?"
    fp = _api("/findings/", params={"false_p": "true", "limit": 1})
    out["false_positives"] = fp.get("count", 0) if not fp.get("error") else "?"
    return out


def _default_prod_type() -> int:
    r = _api("/product_types/", params={"limit": 1})
    results = r.get("results", []) if not r.get("error") else []
    return results[0]["id"] if results else 1


def ensure_product(name: str) -> dict:
    """Find a DefectDojo product by name, or create it (create gated by DEFECTDOJO_ALLOW_WRITE)."""
    r = _api("/products/", params={"name": name})
    if r.get("error"):
        return {"available": False, **r}
    for p in r.get("results", []):
        if p.get("name") == name:
            return {"available": True, "created": False, "id": p["id"], "name": name}
    if not _truthy("DEFECTDOJO_ALLOW_WRITE"):
        return {"available": True, "created": False, "proposed": True, "id": None, "name": name,
                "note": "product missing — set DEFECTDOJO_ALLOW_WRITE to auto-create, or create it in DefectDojo"}
    c = _api("/products/", method="POST",
             data={"name": name, "description": f"Phantom-managed: {name}", "prod_type": _default_prod_type()})
    return {"available": True, "created": not c.get("error"), "id": c.get("id"), "name": name, "detail": c}


def ensure_engagement(product_id, name: str) -> dict:
    """Find/create a CI/CD engagement under a product (create gated)."""
    if not product_id:
        return {"available": False, "note": "no product id (ensure the product first)"}
    r = _api("/engagements/", params={"product": product_id, "name": name})
    if r.get("error"):
        return {"available": False, **r}
    for e in r.get("results", []):
        if e.get("name") == name:
            return {"available": True, "created": False, "id": e["id"], "name": name}
    if not _truthy("DEFECTDOJO_ALLOW_WRITE"):
        return {"available": True, "created": False, "proposed": True, "id": None, "name": name,
                "note": "engagement missing — set DEFECTDOJO_ALLOW_WRITE to auto-create"}
    today = datetime.now(timezone.utc).date().isoformat()
    c = _api("/engagements/", method="POST",
             data={"name": name, "product": product_id, "target_start": today, "target_end": today,
                   "engagement_type": "CI/CD", "status": "In Progress"})
    return {"available": True, "created": not c.get("error"), "id": c.get("id"), "name": name, "detail": c}


def enrich_cve(cve: str) -> dict:
    """Exploit intel for a CVE: CISA KEV (actively exploited) + FIRST EPSS (probability)."""
    cve = (cve or "").upper().strip()
    if not cve.startswith("CVE-"):
        return {"cve": cve, "note": "no CVE id"}
    # KEV catalog — fetch once, cache the id set
    if "set" not in _KEV_CACHE:
        kev = http_json("https://www.cisa.gov/sites/default/files/feeds/"
                        "known_exploited_vulnerabilities.json", timeout=20)
        _KEV_CACHE["set"] = {v.get("cveID") for v in kev.get("vulnerabilities", [])} \
            if isinstance(kev, dict) else set()
    in_kev = cve in _KEV_CACHE["set"]
    epss = http_json(f"https://api.first.org/data/v1/epss?cve={cve}")
    data = (epss.get("data") or [{}])[0] if isinstance(epss, dict) else {}
    score = float(data.get("epss", 0) or 0)
    return {"cve": cve, "in_kev": in_kev, "epss": score,
            "epss_percentile": float(data.get("percentile", 0) or 0),
            "priority": "CRITICAL" if in_kev else "HIGH" if score >= 0.5
            else "MEDIUM" if score >= 0.1 else "LOW"}


def _gated_write(action_type: str, resources: list, justification: str, do_write):
    if _truthy("DEFECTDOJO_ALLOW_WRITE"):
        try:
            return {"executed": True, **do_write()}
        except Exception as e:  # noqa: BLE001
            return {"executed": False, "error": str(e)}
    try:
        from approvals import create_approval
        a = create_approval(session_id="defectdojo", action_type=action_type, resources=resources,
                            justification=justification, impact="DefectDojo finding change",
                            impact_level="low", requested_by="phantom-defectdojo")
        return {"executed": False, "status": "pending_approval", "approval_id": a.get("id")}
    except Exception as e:  # noqa: BLE001
        return {"executed": False, "error": str(e)}


# ── Tool implementations ─────────────────────────────────────────────────────

def _tool_archive_fp(finding_id: str, reason: str) -> dict:
    def _w():
        update_finding(finding_id, {"false_p": True, "active": False})
        add_note(finding_id, f"[Phantom] False positive: {reason}")
        return {"finding": finding_id, "action": "archived-false-positive"}
    return _gated_write("dd-archive-fp", [f"finding:{finding_id}"],
                        f"Archive FP: {reason}", _w)


def _tool_set_status(finding_id: str, status: str, justification: str) -> dict:
    field_map = {"risk_accept": {"risk_accepted": True, "active": False},
                 "mitigate": {"is_mitigated": True, "active": False},
                 "reactivate": {"active": True, "false_p": False}}
    fields = field_map.get(status)
    if not fields:
        return {"error": f"unknown status '{status}' (risk_accept|mitigate|reactivate)"}

    def _w():
        update_finding(finding_id, fields)
        add_note(finding_id, f"[Phantom] {status}: {justification}")
        return {"finding": finding_id, "action": status}
    return _gated_write(f"dd-{status}", [f"finding:{finding_id}"], justification, _w)


def _tool_jira(finding_id: str, summary: str, description: str) -> dict:
    try:
        from case_sync import create_jira_issue
        r = create_jira_issue(summary or f"[DefectDojo] Finding {finding_id}",
                              description or f"Remediate DefectDojo finding {finding_id}", "Bug")
        return r
    except Exception as e:  # noqa: BLE001
        return {"enabled": False, "error": str(e)}


def _cwe_int(cwe) -> int | None:
    import re
    m = re.search(r"(\d+)", str(cwe or ""))
    return int(m.group(1)) if m else None


def _tool_add_context(finding_id: str, summary: str, impact: str, cwe: str, owasp: str,
                      remediation: str, references: list | None) -> dict:
    """Enrich an under-documented TRUE-POSITIVE with an explanatory note + standards
    references (CWE / OWASP). The note is added directly; setting the finding's
    structured cwe/references fields is a gated write."""
    refs = references or []
    lines = ["[Phantom] Context & standards enrichment"]
    if summary:
        lines.append(f"Summary: {summary}")
    if impact:
        lines.append(f"Impact: {impact}")
    if cwe:
        lines.append(f"Weakness: {cwe}")
    if owasp:
        lines.append(f"OWASP: {owasp}")
    if remediation:
        lines.append(f"Remediation: {remediation}")
    if refs:
        lines.append("References:\n" + "\n".join(f"- {r}" for r in refs))
    note_res = add_note(finding_id, "\n".join(lines))

    structured = None
    cwe_num = _cwe_int(cwe)
    if cwe_num or refs:
        fields = {}
        if cwe_num:
            fields["cwe"] = cwe_num
        if refs:
            fields["references"] = "\n".join(refs)

        def _w():
            update_finding(finding_id, fields)
            return {"fields_set": list(fields)}
        structured = _gated_write("dd-set-context", [f"finding:{finding_id}"],
                                  f"Set CWE/references metadata: {cwe} {owasp}", _w)
    return {"note_added": note_res.get("added"), "cwe": cwe, "owasp": owasp,
            "structured_update": structured}


# ── Tool schemas ─────────────────────────────────────────────────────────────

T_LIST = {"name": "list_findings",
          "description": "List DefectDojo findings. Filter by severity (Critical/High/Medium/Low), "
                         "active, false_p, duplicate, product.",
          "input_schema": {"type": "object", "properties": {
              "severity": {"type": "string"}, "product": {"type": "string"},
              "active": {"type": "boolean"}, "false_p": {"type": "boolean"},
              "duplicate": {"type": "boolean"}, "limit": {"type": "integer"}}}}
T_GET = {"name": "get_finding", "description": "Get full detail for one finding.",
         "input_schema": {"type": "object", "properties": {"finding_id": {"type": "string"}},
                          "required": ["finding_id"]}}
T_NOTE = {"name": "add_note", "description": "Add a note/comment to a finding (allowed directly).",
          "input_schema": {"type": "object", "properties": {
              "finding_id": {"type": "string"}, "note": {"type": "string"}},
              "required": ["finding_id", "note"]}}
T_CONTEXT = {"name": "add_finding_context",
             "description": "For a TRUE-POSITIVE that lacks proper context, add an explanatory note "
                            "(what the vuln is, impact/exploitability, remediation) AND reference the "
                            "applicable security standard: a CWE id (e.g. 'CWE-89'), an OWASP Top 10 "
                            "category (e.g. 'A03:2021 - Injection'), and OWASP ASVS control where "
                            "relevant. The note is added directly; setting the finding's structured "
                            "cwe/references fields is gated. Use whenever a real finding is under-documented.",
             "input_schema": {"type": "object", "properties": {
                 "finding_id": {"type": "string"},
                 "summary": {"type": "string", "description": "what the vulnerability is"},
                 "impact": {"type": "string", "description": "exploitability / business impact"},
                 "cwe": {"type": "string", "description": "e.g. 'CWE-79'"},
                 "owasp": {"type": "string", "description": "e.g. 'A03:2021 - Injection'"},
                 "remediation": {"type": "string"},
                 "references": {"type": "array", "items": {"type": "string"},
                                "description": "standard/URL references (CWE, OWASP cheat sheet, ...)"}},
                 "required": ["finding_id", "summary", "cwe"]}}
T_ARCHIVE = {"name": "archive_false_positive",
             "description": "Mark a finding as false-positive and archive it (sets false_p, deactivates, "
                            "adds a note). WRITE — gated (files approval unless writes enabled). Only for "
                            "findings you've assessed as clear false positives.",
             "input_schema": {"type": "object", "properties": {
                 "finding_id": {"type": "string"}, "reason": {"type": "string"}},
                 "required": ["finding_id", "reason"]}}
T_STATUS = {"name": "set_finding_status",
            "description": "Change a finding's disposition: risk_accept (accept + deactivate), mitigate "
                           "(mark fixed), or reactivate. WRITE — gated. Always give a justification.",
            "input_schema": {"type": "object", "properties": {
                "finding_id": {"type": "string"},
                "status": {"type": "string", "enum": ["risk_accept", "mitigate", "reactivate"]},
                "justification": {"type": "string"}},
                "required": ["finding_id", "status", "justification"]}}
T_ENRICH_CVE = {"name": "enrich_cve",
                "description": "Exploit intel for a finding's CVE — CISA KEV (actively exploited) + FIRST "
                               "EPSS (exploitation probability). Use to prioritize what to fix first.",
                "input_schema": {"type": "object", "properties": {"cve": {"type": "string"}},
                                 "required": ["cve"]}}
T_SLA = {"name": "sla_status", "description": "List active findings that are OVERDUE or due within 7 days "
                                              "against their DefectDojo SLA, sorted most-overdue first.",
         "input_schema": {"type": "object", "properties": {"severity": {"type": "string"}}}}
T_METRICS = {"name": "get_metrics", "description": "DefectDojo posture snapshot: active counts by severity "
                                                   "+ false-positive count.",
             "input_schema": {"type": "object", "properties": {}}}
T_PRODUCTS = {"name": "list_products", "description": "List DefectDojo products.",
              "input_schema": {"type": "object", "properties": {}}}
T_JIRA = {"name": "create_jira_ticket",
          "description": "Open a Jira remediation ticket for a finding (allowed directly). Use for real "
                         "findings that need owner action.",
          "input_schema": {"type": "object", "properties": {
              "finding_id": {"type": "string"}, "summary": {"type": "string"},
              "description": {"type": "string"}},
              "required": ["finding_id"]}}


def _dispatch(name: str, inp: dict) -> tuple[str, dict | None]:
    if name == "list_findings":
        return json.dumps(list_findings(inp.get("severity", ""), inp.get("active", True),
                          inp.get("false_p"), inp.get("duplicate"), inp.get("product", ""),
                          inp.get("limit", 50))), None
    if name == "get_finding":
        return json.dumps(get_finding(inp.get("finding_id", ""))), None
    if name == "add_note":
        return json.dumps(add_note(inp.get("finding_id", ""), inp.get("note", ""))), None
    if name == "add_finding_context":
        return json.dumps(_tool_add_context(inp.get("finding_id", ""), inp.get("summary", ""),
                          inp.get("impact", ""), inp.get("cwe", ""), inp.get("owasp", ""),
                          inp.get("remediation", ""), inp.get("references"))), None
    if name == "archive_false_positive":
        return json.dumps(_tool_archive_fp(inp.get("finding_id", ""), inp.get("reason", ""))), None
    if name == "set_finding_status":
        return json.dumps(_tool_set_status(inp.get("finding_id", ""), inp.get("status", ""),
                          inp.get("justification", ""))), None
    if name == "enrich_cve":
        return json.dumps(enrich_cve(inp.get("cve", ""))), None
    if name == "sla_status":
        return json.dumps(sla_findings(inp.get("severity", ""))), None
    if name == "get_metrics":
        return json.dumps(metrics()), None
    if name == "list_products":
        return json.dumps(list_products()), None
    if name == "create_jira_ticket":
        return json.dumps(_tool_jira(inp.get("finding_id", ""), inp.get("summary", ""),
                          inp.get("description", ""))), None
    if name == "write_report":
        return json.dumps({"written": True}), dict(inp)
    return json.dumps({"error": f"unknown tool {name}"}), None


# ── Task definitions ─────────────────────────────────────────────────────────

_REPORT = generic_report_tool()
_TASKS = {
    "defectdojo-triage": {
        "tools": SKILL_TOOLS + [T_LIST, T_GET, T_ENRICH_CVE, T_NOTE, T_CONTEXT, T_ARCHIVE, T_STATUS,
                                T_JIRA, _REPORT],
        "subdir": "defectdojo-triage",
        "system": ("You are Phantom triaging DefectDojo findings. Pull the triaging-defectdojo-findings "
                   "skill (and the relevant OWASP/CWE skill when mapping standards). For each finding: "
                   "get_finding, enrich_cve on its CVE (KEV/EPSS). Decide FALSE-POSITIVE / DUPLICATE / "
                   "RISK-ACCEPT / REAL with evidence.\n"
                   "- Clear false positives → archive_false_positive.\n"
                   "- TRUE POSITIVES: assess whether the finding has proper context (clear description, "
                   "impact/exploitability, a CWE + OWASP mapping, and remediation). If it is "
                   "under-documented, call add_finding_context to add the explanation AND reference the "
                   "applicable standard — the CWE id, the OWASP Top 10 category, and an OWASP ASVS "
                   "control / cheat-sheet URL. Map accurately from the finding type (e.g. SQLi → CWE-89, "
                   "A03:2021 Injection; XSS → CWE-79, A03:2021; SSRF → CWE-918, A10:2021).\n"
                   "- Then set_finding_status for risk-accept/mitigate and create_jira_ticket for real "
                   "findings that need owner action.\n"
                   "State changes (archive/status/CWE-metadata) are gated (approval unless writes "
                   "enabled); notes and Jira tickets are direct. write_report with dispositions and the "
                   "standards references added. " + _BASE_RULES)},
    "defectdojo-sla": {
        "tools": [T_SLA, T_LIST, T_GET, T_JIRA, _REPORT],
        "subdir": "defectdojo-sla",
        "system": ("You are Phantom monitoring DefectDojo SLA compliance. sla_status to find OVERDUE and "
                   "due-soon findings by severity. For overdue high/critical findings, create_jira_ticket "
                   "to escalate to the owning team. write_report: an SLA breach summary (counts by "
                   "severity + age), the escalations opened, and at-risk items. " + _BASE_RULES)},
    "defectdojo-prioritize": {
        "tools": SKILL_TOOLS + [T_LIST, T_GET, T_ENRICH_CVE, T_NOTE, _REPORT],
        "subdir": "defectdojo-prioritize",
        "system": ("You are Phantom doing exploit-aware vulnerability prioritization in DefectDojo. Pull "
                   "active findings (list_findings), enrich_cve each CVE (CISA KEV + FIRST EPSS), and rank "
                   "them: KEV-listed and high-EPSS first, regardless of base CVSS. Annotate the top items "
                   "with add_note explaining the priority. write_report: a ranked fix-first list with the "
                   "exploit rationale (KEV status, EPSS score) for each. " + _BASE_RULES)},
    "defectdojo-report": {
        "tools": [T_METRICS, T_LIST, T_SLA, T_PRODUCTS, _REPORT],
        "subdir": "defectdojo-report",
        "system": ("You are Phantom generating a DefectDojo vulnerability-management report. Use "
                   "get_metrics (posture), sla_status (compliance), and list_findings (top open items) "
                   "across products. write_report: an executive summary (posture, trend, top risks), SLA "
                   "compliance, remediation status, and recommended focus areas. " + _BASE_RULES)},
}


def _run(task_type: str, objective: str, context: str = "") -> dict:
    entry = _TASKS[task_type]
    task_id = f"{task_type}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    initial = (f"DEFECTDOJO TASK ({task_type}): {objective}\n"
               f"{('CONTEXT: ' + context + chr(10)) if context else ''}\n"
               f"DefectDojo configured: {bool(_base())}. Begin now.")
    report, _ = run_agent_loop(entry["system"], initial, entry["tools"], _dispatch, label=task_type)
    if not report:
        return {"error": "no report produced", "task_type": task_type}
    report["task_id"] = task_id
    report["task_type"] = task_type
    report["report_path"] = save_report(entry["subdir"], task_id, report)
    return report


_SUMMARIES = {
    "defectdojo-triage": "Triage DefectDojo findings: FP/duplicate/risk-accept, archive FPs (gated), open Jira tickets",
    "defectdojo-sla": "Monitor DefectDojo SLA compliance and escalate overdue findings to Jira",
    "defectdojo-prioritize": "Exploit-aware vuln prioritization (CISA KEV + FIRST EPSS) over DefectDojo findings",
    "defectdojo-report": "Generate a DefectDojo vulnerability-management report (posture, SLA, remediation)",
}
for _tt in _TASKS:
    register_task(_tt, _SUMMARIES[_tt],
                  runner=(lambda tt: lambda objective, **kw: _run(tt, objective, kw.get("context", "")))(_tt))


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python defectdojo.py <defectdojo-triage|-sla|-prioritize|-report> '<objective>'")
        raise SystemExit(0)
    out = _run(sys.argv[1], " ".join(sys.argv[2:]))
    print("\n" + out.get("report_markdown", json.dumps(out, indent=2, default=str)))
