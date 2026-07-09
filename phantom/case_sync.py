#!/usr/bin/env python3
"""
phantom/case_sync.py — push a confirmed phishing campaign to case management.

Turns a phishing.py verdict + its campaign into durable records in the SOC stack:
  - TheHive  : create a case with the campaign's IOCs as observables
  - MISP     : create an event and add the IOCs as attributes (write, not just
               the read-only correlation phishing.py already does)
  - Jira     : (optional) open a tracking ticket

Every integration is OPTIONAL and fails safe: if its env vars aren't set the
stage is skipped and reported as such; a transport error never raises. Nothing
here is destructive on the mail side — it only records intelligence.

Environment variables:
  TheHive : THEHIVE_URL, THEHIVE_API_KEY   (targets the TheHive v4 REST API)
  MISP    : MISP_URL, MISP_API_KEY         (MISP_KEY also accepted)
  Jira    : JIRA_URL, JIRA_USER, JIRA_API_TOKEN, JIRA_PROJECT_KEY
  SKIP_TLS_VERIFY=1  — only for self-signed lab endpoints (repo convention)

Public API:
    refs = sync_campaign(phishing_result, campaign)   # -> {thehive, misp, jira}
"""
from __future__ import annotations

import os

from http_util import http_json, ok

VERIFY_TLS = os.environ.get("SKIP_TLS_VERIFY", "").lower() not in ("1", "true", "yes")


# ── IOC mapping helpers ──────────────────────────────────────────────────────

def _hash_type(h: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h.strip()), "sha256")


def _iter_iocs(iocs: dict):
    """Yield (kind, value) for every indicator. kind ∈ ip|domain|url|hash|mail."""
    for v in iocs.get("ips", []) or []:
        yield "ip", v
    for v in iocs.get("domains", []) or []:
        yield "domain", v
    for v in iocs.get("urls", []) or []:
        yield "url", v
    for v in iocs.get("hashes", []) or []:
        yield "hash", v
    for v in iocs.get("emails", []) or []:
        yield "mail", v


# ── TheHive (v4) ─────────────────────────────────────────────────────────────

_SEV = {"PHISHING": 3, "COMPROMISED": 3, "SUSPICIOUS": 2, "LEGITIMATE": 1,
        "BENIGN": 1, "UNKNOWN": 2}
_TH_OBS = {"ip": "ip", "domain": "domain", "url": "url", "hash": "hash", "mail": "mail"}


def push_thehive(result: dict, campaign: dict) -> dict:
    url = os.environ.get("THEHIVE_URL", "").rstrip("/")
    key = os.environ.get("THEHIVE_API_KEY", "")
    if not (url and key):
        return {"enabled": False, "reason": "THEHIVE_URL / THEHIVE_API_KEY not set"}
    hdr = {"Authorization": f"Bearer {key}"}
    cid = campaign.get("campaign_id", "")
    title = f"[Phishing] {result.get('subject', '')[:80]} ({cid})"
    desc = (f"Campaign **{cid}** — {campaign.get('report_count', 1)} report(s).\n\n"
            f"Verdict: {result.get('verdict')} ({result.get('confidence')}%)\n"
            f"Sender: {result.get('from_email', '')}\n\n{result.get('summary', '')}")
    case = http_json(f"{url}/api/case", headers=hdr, method="POST", verify=VERIFY_TLS,
                     data={"title": title, "description": desc,
                           "severity": _SEV.get(result.get("verdict"), 2),
                           "tags": ["phishing", "phantom", cid],
                           "flag": result.get("verdict") == "PHISHING"})
    if not ok(case) or not case.get("id"):
        return {"enabled": True, "created": False, "error": case}
    case_id = case["id"]
    added = 0
    for kind, value in _iter_iocs(result.get("iocs", {})):
        obs = http_json(f"{url}/api/case/{case_id}/artifact", headers=hdr, method="POST",
                        verify=VERIFY_TLS,
                        data={"dataType": _TH_OBS.get(kind, "other"), "data": value,
                              "message": f"phish IOC ({kind})", "tags": [cid], "ioc": True})
        if ok(obs):
            added += 1
    return {"enabled": True, "created": True, "case_id": case_id,
            "url": f"{url}/index.html#!/case/{case_id}/details", "observables": added}


# ── MISP ─────────────────────────────────────────────────────────────────────

def _misp_attr(kind: str, value: str) -> dict:
    if kind == "ip":
        t = "ip-dst"
    elif kind == "domain":
        t = "domain"
    elif kind == "url":
        t = "url"
    elif kind == "mail":
        t = "email-src"
    else:
        t = _hash_type(value)
    return {"type": t, "value": value, "category": "Network activity"
            if kind in ("ip", "domain", "url") else "Payload delivery",
            "to_ids": kind in ("url", "hash", "domain")}


def create_misp_event(info: str, iocs: dict, tags: list[str] | None = None,
                      threat_level_id: int = 2, analysis: int = 1) -> dict:
    """Generic MISP event creator — reusable by any Phantom task type that needs
    to disseminate IOCs (phishing case-sync, threat-intel production, etc.)."""
    url = os.environ.get("MISP_URL", "").rstrip("/")
    key = os.environ.get("MISP_API_KEY", os.environ.get("MISP_KEY", ""))
    if not (url and key):
        return {"enabled": False, "reason": "MISP_URL / MISP_API_KEY not set"}
    attrs = [_misp_attr(k, v) for k, v in _iter_iocs(iocs)]
    event = {"Event": {
        "info": info[:255], "distribution": 0,
        "threat_level_id": threat_level_id, "analysis": analysis,
        "Attribute": attrs,
        "Tag": [{"name": t} for t in (tags or ["phantom"])],
    }}
    resp = http_json(f"{url}/events/add", headers={"Authorization": key},
                     method="POST", data=event, verify=VERIFY_TLS)
    if not ok(resp):
        return {"enabled": True, "created": False, "error": resp}
    ev_id = resp.get("Event", {}).get("id", "")
    return {"enabled": True, "created": bool(ev_id), "event_id": ev_id,
            "url": f"{url}/events/view/{ev_id}" if ev_id else "",
            "attributes": len(attrs)}


def push_misp(result: dict, campaign: dict) -> dict:
    cid = campaign.get("campaign_id", "")
    return create_misp_event(
        info=f"Phishing campaign {cid}: {result.get('subject', '')[:80]}",
        iocs=result.get("iocs", {}),
        tags=["phantom:phishing", f"campaign:{cid}"])


# ── Jira (optional) ──────────────────────────────────────────────────────────

def create_jira_issue(summary: str, description: str, issue_type: str = "") -> dict:
    """Generic Jira issue creator — reusable by any Phantom task type (phishing
    case-sync, DefectDojo remediation tickets, ...)."""
    url = os.environ.get("JIRA_URL", "").rstrip("/")
    user = os.environ.get("JIRA_USER", "")
    token = os.environ.get("JIRA_API_TOKEN", "")
    project = os.environ.get("JIRA_PROJECT_KEY", "")
    if not (url and user and token and project):
        return {"enabled": False, "reason": "JIRA_URL / JIRA_USER / JIRA_API_TOKEN / JIRA_PROJECT_KEY not set"}
    fields = {"fields": {
        "project": {"key": project},
        "summary": summary[:250],
        "description": description,
        "issuetype": {"name": issue_type or os.environ.get("JIRA_ISSUE_TYPE", "Task")},
    }}
    resp = http_json(f"{url}/rest/api/2/issue", method="POST", data=fields,
                     verify=VERIFY_TLS, auth=(user, token))
    if not ok(resp) or not resp.get("key"):
        return {"enabled": True, "created": False, "error": resp}
    return {"enabled": True, "created": True, "key": resp["key"],
            "url": f"{url}/browse/{resp['key']}"}


def push_jira(result: dict, campaign: dict) -> dict:
    cid = campaign.get("campaign_id", "")
    ioc_lines = "\n".join(f"- {k}: {v}" for k, v in _iter_iocs(result.get("iocs", {}))) or "- (none)"
    return create_jira_issue(
        summary=f"[Phishing] {result.get('subject', '')[:100]} ({cid})",
        description=(f"Phantom-investigated phishing campaign {cid}.\n"
                     f"Verdict: {result.get('verdict')} ({result.get('confidence')}%)\n"
                     f"Reports in campaign: {campaign.get('report_count', 1)}\n\nIOCs:\n{ioc_lines}"))


# ── Orchestrator ─────────────────────────────────────────────────────────────

def sync_campaign(result: dict, campaign: dict) -> dict:
    """Push a campaign to every configured case-management target. Never raises."""
    refs = {}
    for name, fn in (("thehive", push_thehive), ("misp", push_misp), ("jira", push_jira)):
        try:
            refs[name] = fn(result, campaign)
        except Exception as e:  # noqa: BLE001 — a broken integration must not sink the pipeline
            refs[name] = {"enabled": True, "created": False, "error": str(e)}
    return refs
