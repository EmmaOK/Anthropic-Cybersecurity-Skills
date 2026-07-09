#!/usr/bin/env python3
"""
phantom/detection_engineering.py — Detection Engineering as a first-class task.

The purple-team loop, as a Phantom task type: take an ATT&CK technique (or a
described gap), pull the relevant `detecting-*` skills, assess what your SIEM/EDR
would catch, and author a validated Sigma detection with a test procedure. This
is the largest domain in the library (~120 skills) and now a first-class type,
not a sub-bullet of IR.

Flow:
  technique/gap
    -> search/load the detecting-* skill(s)
    -> lookup_attack_technique   (tactic, data sources, log sources)
    -> assess_detection_coverage (what's instrumented; what a query would check)
    -> [model authors a Sigma rule]
    -> validate_sigma            (structural + logsource/condition checks)
    -> write_detection_report    (rule + gap analysis + Atomic Red Team test + ATT&CK map)

Actual execution of the Atomic Red Team test stays behind Phantom's existing
executor/kali + approval gate — this task produces the *tested-ready* detection
and the exact test to run, it does not fire the technique itself.

Public API:
    result = build_detection("write a detection for LSASS credential dumping", technique="T1003.001")
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import yaml

from task_agent import (SKILL_TOOLS, run_agent_loop, save_report, register_task, _BASE_RULES)

# A small local ATT&CK reference for the techniques most asked about. Not a full
# STIX mirror — enough to seed the agent; it can search skills for the rest.
_ATTACK = {
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access",
              "data_sources": ["Process", "Command", "Windows Registry", "File"],
              "log_sources": ["Sysmon EID 10 (ProcessAccess)", "Security 4688", "EDR"]},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access",
                  "data_sources": ["Process Access", "Process Creation"],
                  "log_sources": ["Sysmon EID 10 target lsass.exe", "EDR memory access telemetry"]},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion / Privilege Escalation",
              "data_sources": ["Process", "API monitoring"],
              "log_sources": ["Sysmon EID 8 (CreateRemoteThread)", "Sysmon EID 10", "EDR"]},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation",
              "data_sources": ["Process Creation", "Command"],
              "log_sources": ["Security 4688", "Sysmon EID 1"]},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "Lateral Movement",
              "data_sources": ["Logon Session", "Authentication logs"],
              "log_sources": ["Security 4624/4768/4769", "EDR"]},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement",
              "data_sources": ["Logon Session", "Network Traffic"],
              "log_sources": ["Security 4624 type 3/10", "Zeek", "EDR"]},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence / Execution",
              "data_sources": ["Scheduled Job", "Process Creation"],
              "log_sources": ["Security 4698", "Sysmon EID 1"]},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence",
              "data_sources": ["Windows Registry", "Process Creation"],
              "log_sources": ["Sysmon EID 12/13 (Registry)", "Autoruns"]},
}


def _tool_lookup_attack(technique_id: str) -> dict:
    tid = (technique_id or "").upper().strip()
    if tid in _ATTACK:
        return {"technique_id": tid, **_ATTACK[tid], "source": "local-reference"}
    base = tid.split(".")[0]
    if base in _ATTACK:
        return {"technique_id": tid, "parent": base, **_ATTACK[base],
                "note": "sub-technique; parent reference shown", "source": "local-reference"}
    return {"technique_id": tid, "note": "not in local reference — search the skill library "
            "(e.g. 'detecting <technique>') and cite the skill's data sources.",
            "source": "unknown"}


def _tool_assess_coverage(technique_id: str, log_source: str = "") -> dict:
    """Report what telemetry is configured for Phantom to check against, honestly.
    A live SIEM/EDR query is integration-specific; this returns the instrumentation
    picture + the concrete check to run, rather than pretending to have queried."""
    import os
    configured = {
        "wazuh": bool(os.environ.get("WAZUH_URL")),
        "securonix": bool(os.environ.get("SECURONIX_URL")),
        "sentinelone": bool(os.environ.get("SENTINELONE_URL")),
        "splunk": bool(os.environ.get("SPLUNK_URL")),
    }
    any_configured = any(configured.values())
    return {
        "technique_id": technique_id,
        "telemetry_configured": configured,
        "coverage_check": (
            f"Query the configured SIEM/EDR for existing rules matching {technique_id}"
            f"{(' via ' + log_source) if log_source else ''}."
            if any_configured else
            "No SIEM/EDR endpoint configured (set WAZUH_URL / SECURONIX_URL / SENTINELONE_URL). "
            "Treat coverage as UNVERIFIED and author the detection assuming the gap is real."),
        "recommended_data_sources": _ATTACK.get(technique_id.upper().split(".")[0], {}).get("log_sources", []),
    }


def _tool_validate_sigma(rule_yaml: str) -> dict:
    """Structural validation of a Sigma rule (no external sigma toolchain needed)."""
    result = {"valid": False, "errors": [], "warnings": []}
    try:
        doc = yaml.safe_load(rule_yaml)
    except yaml.YAMLError as e:
        result["errors"].append(f"YAML parse error: {e}")
        return result
    if not isinstance(doc, dict):
        result["errors"].append("Sigma rule must be a YAML mapping")
        return result
    for req in ("title", "logsource", "detection"):
        if req not in doc:
            result["errors"].append(f"missing required field: {req}")
    det = doc.get("detection", {})
    if isinstance(det, dict):
        if "condition" not in det:
            result["errors"].append("detection.condition is required")
        if not any(k for k in det if k != "condition"):
            result["errors"].append("detection needs at least one search identifier (e.g. 'selection')")
    else:
        result["errors"].append("detection must be a mapping")
    if isinstance(doc.get("logsource"), dict) and not doc["logsource"]:
        result["warnings"].append("logsource is empty — specify product/category/service")
    if "level" not in doc:
        result["warnings"].append("no 'level' set (informational/low/medium/high/critical)")
    if "tags" not in doc:
        result["warnings"].append("no ATT&CK 'tags' (e.g. attack.t1003.001)")
    result["valid"] = not result["errors"]
    return result


DE_TOOLS = SKILL_TOOLS + [
    {"name": "lookup_attack_technique",
     "description": "Get tactic, data sources, and log sources for an ATT&CK technique id (e.g. T1003.001).",
     "input_schema": {"type": "object", "properties": {"technique_id": {"type": "string"}},
                      "required": ["technique_id"]}},
    {"name": "assess_detection_coverage",
     "description": "Report which SIEM/EDR telemetry is instrumented and the coverage check to run "
                    "for a technique. Be honest: if nothing is configured, coverage is UNVERIFIED.",
     "input_schema": {"type": "object",
                      "properties": {"technique_id": {"type": "string"},
                                     "log_source": {"type": "string"}},
                      "required": ["technique_id"]}},
    {"name": "validate_sigma",
     "description": "Structurally validate a Sigma detection rule (YAML). Fix any errors it returns "
                    "before writing the report.",
     "input_schema": {"type": "object", "properties": {"rule_yaml": {"type": "string"}},
                      "required": ["rule_yaml"]}},
    {"name": "write_detection_report",
     "description": "Write the final detection-engineering deliverable. Call LAST.",
     "input_schema": {"type": "object", "properties": {
         "technique_id": {"type": "string"}, "technique_name": {"type": "string"},
         "tactic": {"type": "string"},
         "gap_summary": {"type": "string", "description": "the detection gap this closes"},
         "sigma_rule": {"type": "string", "description": "the validated Sigma rule YAML"},
         "data_sources": {"type": "array", "items": {"type": "string"}},
         "atomic_test": {"type": "string",
                         "description": "the Atomic Red Team test / command that validates this detection"},
         "false_positive_notes": {"type": "string"},
         "attack_mapping": {"type": "array", "items": {"type": "string"},
                            "description": "ATT&CK technique tags, e.g. attack.t1003.001"},
         "skills_used": {"type": "array", "items": {"type": "string"}},
         "report_markdown": {"type": "string"},
     }, "required": ["technique_id", "sigma_rule", "gap_summary", "report_markdown"]}},
]

DE_SYSTEM = (
    "You are Phantom in Detection Engineering mode — a purple-team detection author. "
    "Given a technique or a described detection gap, you produce a validated, deployable "
    "Sigma detection plus the Atomic Red Team test that proves it fires.\n\n"
    "Method:\n"
    "1. search_skills for the relevant 'detecting-*' skill and load it — follow its logic.\n"
    "2. lookup_attack_technique for tactic, data sources, and log sources.\n"
    "3. assess_detection_coverage — establish what telemetry exists; if none, say coverage is UNVERIFIED.\n"
    "4. Author a Sigma rule with precise selection logic, a condition, level, and attack.* tags.\n"
    "5. validate_sigma and fix every error before proceeding.\n"
    "6. Provide the exact Atomic Red Team test/command a purple team runs to validate the rule.\n"
    "7. write_detection_report.\n\n"
    "Favor high-fidelity logic over broad matches; always note likely false positives and tuning. "
    + _BASE_RULES)


def _dispatch(name: str, inp: dict) -> tuple[str, dict | None]:
    if name == "lookup_attack_technique":
        return json.dumps(_tool_lookup_attack(inp.get("technique_id", ""))), None
    if name == "assess_detection_coverage":
        return json.dumps(_tool_assess_coverage(inp.get("technique_id", ""), inp.get("log_source", ""))), None
    if name == "validate_sigma":
        return json.dumps(_tool_validate_sigma(inp.get("rule_yaml", ""))), None
    if name == "write_detection_report":
        return json.dumps({"written": True}), dict(inp)
    return json.dumps({"error": f"unknown tool {name}"}), None


def build_detection(objective: str, technique: str = "", context: str = "") -> dict:
    task_id = f"detection-engineering-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    initial = (f"DETECTION TASK: {objective}\n"
               f"{('ATT&CK technique: ' + technique + chr(10)) if technique else ''}"
               f"{('CONTEXT: ' + context + chr(10)) if context else ''}\n"
               "Build and validate the detection now.")
    report, _ = run_agent_loop(DE_SYSTEM, initial, DE_TOOLS, _dispatch, label="detection")
    if not report:
        return {"error": "no detection produced", "task_type": "detection-engineering"}
    report["task_id"] = task_id
    report["task_type"] = "detection-engineering"
    report["report_path"] = save_report("detection-engineering", task_id, report)
    return report


register_task("detection-engineering",
              "Author validated Sigma detections + Atomic Red Team tests for ATT&CK techniques (purple-team loop)",
              runner=lambda objective, **kw: build_detection(
                  objective, technique=kw.get("technique", ""), context=kw.get("context", "")))


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python detection_engineering.py '<objective>' [technique]")
        raise SystemExit(0)
    tech = sys.argv[2] if len(sys.argv) > 2 else ""
    out = build_detection(sys.argv[1], technique=tech)
    print("\n" + out.get("report_markdown", json.dumps(out, indent=2, default=str)))
    raise SystemExit(1 if out.get("sigma_rule") else 0)
