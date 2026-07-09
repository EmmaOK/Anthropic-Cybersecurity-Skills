#!/usr/bin/env python3
"""
phantom/threat_intel.py — Threat Intelligence / CTI as a first-class task.

Runs the intelligence lifecycle as a Phantom task type: take indicators or a raw
CTI report, enrich against external sources, map to ATT&CK, assess attribution,
and produce a finished intelligence product — optionally disseminated to MISP.

Reuses infrastructure already built:
  - enrichment  : phishing.py's threat-intel fan-out (Shodan/AbuseIPDB/GreyNoise/
                  urlscan/ThreatFox/MISP) via _tool_threat_intel
  - dissemination: case_sync.create_misp_event (write IOCs to a MISP event)
  - knowledge    : the ~69 CTI skills via search_skills/load_skill

Flow:
  indicators / report text
    -> search/load CTI skills (attribution, intel lifecycle, ATT&CK mapping)
    -> enrich_indicator  (fan-out per IOC)
    -> [model maps to ATT&CK + assesses attribution/confidence]
    -> disseminate_misp  (optional, if MISP configured)
    -> write_intel_report (finished product: assessment, IOCs, ATT&CK, actions)

Public API:
    result = produce_intel("assess this IOC set", indicators=[("ip","5.6.7.8"), ("domain","evil.com")])
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from task_agent import (SKILL_TOOLS, run_agent_loop, save_report, register_task, _BASE_RULES)


def _tool_enrich(indicator: str, indicator_type: str) -> dict:
    """Fan an indicator out across external TI sources (reuses phishing.py)."""
    try:
        from phishing import _tool_threat_intel  # lazy: shares the fan-out impl
        return _tool_threat_intel(indicator, indicator_type)
    except Exception as e:  # noqa: BLE001
        return {"error": f"enrichment unavailable: {e}", "indicator": indicator}


def _tool_disseminate_misp(title: str, iocs: dict, tags=None) -> dict:
    try:
        from case_sync import create_misp_event
        return create_misp_event(title, iocs, tags=tags or ["phantom:cti"])
    except Exception as e:  # noqa: BLE001
        return {"enabled": False, "error": str(e)}


TI_TOOLS = SKILL_TOOLS + [
    {"name": "enrich_indicator",
     "description": "Enrich one indicator across external threat-intel sources (Shodan, AbuseIPDB, "
                    "GreyNoise, urlscan, ThreatFox, MISP). Returns correlated reputation + a "
                    "'malicious_signals' rollup. Unconfigured sources are skipped, not 'clean'.",
     "input_schema": {"type": "object", "properties": {
         "indicator": {"type": "string"},
         "indicator_type": {"type": "string", "enum": ["ip", "domain", "url", "hash"]}},
         "required": ["indicator", "indicator_type"]}},
    {"name": "disseminate_misp",
     "description": "Publish the finished IOC set to a MISP event (only if MISP is configured). "
                    "iocs is an object with ips/domains/urls/hashes/emails arrays.",
     "input_schema": {"type": "object", "properties": {
         "title": {"type": "string"},
         "iocs": {"type": "object", "properties": {
             "ips": {"type": "array", "items": {"type": "string"}},
             "domains": {"type": "array", "items": {"type": "string"}},
             "urls": {"type": "array", "items": {"type": "string"}},
             "hashes": {"type": "array", "items": {"type": "string"}},
             "emails": {"type": "array", "items": {"type": "string"}}}},
         "tags": {"type": "array", "items": {"type": "string"}}},
         "required": ["title", "iocs"]}},
    {"name": "write_intel_report",
     "description": "Write the finished intelligence product. Call LAST.",
     "input_schema": {"type": "object", "properties": {
         "title": {"type": "string"},
         "summary": {"type": "string", "description": "BLUF — bottom line up front"},
         "indicators": {"type": "array", "items": {"type": "object"},
                        "description": "each IOC with its enrichment verdict"},
         "attack_techniques": {"type": "array", "items": {"type": "string"},
                               "description": "mapped ATT&CK techniques (id + name)"},
         "attribution": {"type": "string", "description": "actor/campaign assessment + basis"},
         "confidence": {"type": "string", "enum": ["low", "moderate", "high"]},
         "recommended_actions": {"type": "array", "items": {"type": "string"}},
         "misp_event": {"type": "string", "description": "MISP event id if disseminated"},
         "skills_used": {"type": "array", "items": {"type": "string"}},
         "report_markdown": {"type": "string"},
     }, "required": ["title", "summary", "confidence", "report_markdown"]}},
]

TI_SYSTEM = (
    "You are Phantom in Threat Intelligence mode — a CTI analyst running the intelligence "
    "lifecycle. You turn raw indicators or reports into a finished, actionable intelligence "
    "product with explicit confidence and ATT&CK mapping.\n\n"
    "Method:\n"
    "1. search_skills for CTI procedures (attribution, intel lifecycle, ATT&CK mapping) and load them.\n"
    "2. enrich_indicator for EVERY indicator; treat 'malicious_signals' as evidence and note which "
    "sources were unconfigured (do not call a skipped source 'clean').\n"
    "3. Map observed behavior to ATT&CK techniques with ids.\n"
    "4. Assess attribution and set a confidence level (low/moderate/high) with your reasoning — "
    "use estimative language, never overclaim.\n"
    "5. If MISP is configured, disseminate_misp the consolidated IOC set.\n"
    "6. write_intel_report (BLUF first, then indicators, ATT&CK, attribution, actions).\n\n"
    + _BASE_RULES)


def _dispatch(name: str, inp: dict) -> tuple[str, dict | None]:
    if name == "enrich_indicator":
        return json.dumps(_tool_enrich(inp.get("indicator", ""), inp.get("indicator_type", ""))), None
    if name == "disseminate_misp":
        return json.dumps(_tool_disseminate_misp(inp.get("title", ""), inp.get("iocs", {}),
                                                 inp.get("tags"))), None
    if name == "write_intel_report":
        return json.dumps({"written": True}), dict(inp)
    return json.dumps({"error": f"unknown tool {name}"}), None


def produce_intel(objective: str, indicators: list | None = None, context: str = "") -> dict:
    task_id = f"threat-intelligence-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    ind_lines = ""
    if indicators:
        ind_lines = "INDICATORS:\n" + "\n".join(
            f"  - {t}: {v}" for t, v in
            (i if isinstance(i, (list, tuple)) else (i.get("type"), i.get("value"))
             for i in indicators)) + "\n"
    initial = (f"INTELLIGENCE TASK: {objective}\n{ind_lines}"
               f"{('CONTEXT: ' + context + chr(10)) if context else ''}\n"
               "Run the intelligence lifecycle now.")
    report, _ = run_agent_loop(TI_SYSTEM, initial, TI_TOOLS, _dispatch, label="cti")
    if not report:
        return {"error": "no intel product produced", "task_type": "threat-intelligence"}
    report["task_id"] = task_id
    report["task_type"] = "threat-intelligence"
    report["report_path"] = save_report("threat-intelligence", task_id, report)
    return report


register_task("threat-intelligence",
              "Run the CTI lifecycle: enrich indicators, map to ATT&CK, assess attribution, disseminate to MISP",
              runner=lambda objective, **kw: produce_intel(
                  objective, indicators=kw.get("indicators"), context=kw.get("context", "")))


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python threat_intel.py '<objective>' [type:value ...]")
        raise SystemExit(0)
    inds = []
    for a in sys.argv[2:]:
        if ":" in a:
            t, v = a.split(":", 1)
            inds.append((t, v))
    out = produce_intel(sys.argv[1], indicators=inds or None)
    print("\n" + out.get("report_markdown", json.dumps(out, indent=2, default=str)))
    raise SystemExit(1 if out.get("summary") else 0)
