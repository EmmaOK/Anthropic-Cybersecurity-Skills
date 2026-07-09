#!/usr/bin/env python3
"""
phantom/task_agent.py — reusable autonomous task harness + task-type registry.

phishing.py and investigate.py each hand-roll the same Claude tool-loop. This
module factors that loop out so a new Phantom *task type* is just: a system
prompt, a set of domain tools, a dispatch function, and a final write_report
schema. Every task type gets skill-library access (search_skills / load_skill)
for free, so it always reasons from the 800+ skill corpus.

Two ways to define a task type:
  1. Bespoke  — its own module with real domain tools (see detection_engineering.py,
     threat_intel.py). Register it with register_task(..., runner=fn).
  2. Skill-guided — no bespoke tooling; the generic agent searches the library
     using `skill_hints` and produces a structured deliverable. Register it with
     just a system_prompt + skill_hints; run_generic_task() drives it.

Public API:
    run_agent_loop(system_prompt, initial_message, tools, dispatch) -> (report, messages)
    run_generic_task(task_type, objective, context="") -> report dict
    run_task(task_type, objective, **kw) -> dispatches to bespoke runner or generic
    list_task_types() -> [{name, summary, bespoke}]
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

try:
    import anthropic
except ImportError:
    raise ImportError("pip install anthropic")

from skill_loader import search_skills as _search_skills, load_skill as _load_skill

ROOT = Path(__file__).resolve().parent.parent
MODEL = "claude-opus-4-8"          # Phantom's own reasoning model (ADR-0011)
MAX_TOKENS = 8096

# ── Skill-library tools (available to every task type) ──────────────────────

SKILL_TOOLS = [
    {
        "name": "search_skills",
        "description": "Search Phantom's 800+ cybersecurity skill library for relevant procedures. "
                       "Call this early and often — the skills are your source of truth.",
        "input_schema": {"type": "object",
                         "properties": {"query": {"type": "string"}},
                         "required": ["query"]},
    },
    {
        "name": "load_skill",
        "description": "Load a skill's full workflow by its kebab-case name (from search_skills results).",
        "input_schema": {"type": "object",
                         "properties": {"skill_name": {"type": "string"}},
                         "required": ["skill_name"]},
    },
]


def handle_skill_tool(name: str, inp: dict) -> str | None:
    """Dispatch the shared skill tools. Returns a JSON/text string, or None if
    `name` is not a skill tool (so the caller handles its own tools)."""
    if name == "search_skills":
        results = _search_skills(inp.get("query", ""))
        return json.dumps({"results": [{"name": r["name"], "description": r.get("description", "")}
                                       for r in results]})
    if name == "load_skill":
        content = _load_skill(inp.get("skill_name", ""))
        return content[:6000] + ("\n\n[... truncated ...]" if len(content) > 6000 else "")
    return None


def generic_report_tool(fields_desc: str = "") -> dict:
    return {
        "name": "write_report",
        "description": "Write the final deliverable. Call this LAST, after all analysis. " + fields_desc,
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "summary": {"type": "string", "description": "2-4 sentence executive summary"},
                "findings": {"type": "array", "items": {"type": "string"}},
                "recommended_actions": {"type": "array", "items": {"type": "string"}},
                "report_markdown": {"type": "string", "description": "the full report in Markdown"},
            },
            "required": ["title", "summary", "report_markdown"],
        },
    }


# ── The agent loop ───────────────────────────────────────────────────────────

def run_agent_loop(system_prompt: str, initial_message: str, tools: list[dict],
                   dispatch: Callable[[str, dict], tuple[str, dict | None]],
                   *, model: str = MODEL, max_tokens: int = MAX_TOKENS,
                   max_steps: int = 28, label: str = "task") -> tuple[dict | None, list]:
    """Run an autonomous Claude tool-loop until write_report is called or steps run out.

    `dispatch(name, input)` must return (result_string, final_report_or_None).
    Skill tools are handled here automatically; dispatch only sees domain tools.
    Returns (final_report_dict_or_None, messages).
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return {"error": "ANTHROPIC_API_KEY not set"}, []
    client = anthropic.Anthropic(api_key=api_key)
    messages = [{"role": "user", "content": initial_message}]
    final: dict | None = None
    step = 0

    while step < max_steps:
        resp = client.messages.create(model=model, max_tokens=max_tokens,
                                      system=system_prompt, tools=tools, messages=messages)
        texts = [b.text for b in resp.content if b.type == "text"]
        if texts:
            print(f"  [{label}] {' '.join(texts)[:200]}", flush=True)
        if resp.stop_reason != "tool_use":
            break

        assistant_blocks = []
        for b in resp.content:
            if b.type == "tool_use":
                assistant_blocks.append({"type": "tool_use", "id": b.id, "name": b.name, "input": b.input})
            elif b.type == "text":
                assistant_blocks.append({"type": "text", "text": b.text})
        messages.append({"role": "assistant", "content": assistant_blocks})

        tool_results = []
        for b in resp.content:
            if b.type != "tool_use":
                continue
            print(f"  [{label}:{b.name}]", flush=True)
            skill_out = handle_skill_tool(b.name, b.input)
            if skill_out is not None:
                tool_results.append({"type": "tool_result", "tool_use_id": b.id, "content": skill_out})
            else:
                result_str, final_data = dispatch(b.name, b.input)
                tool_results.append({"type": "tool_result", "tool_use_id": b.id, "content": result_str})
                if final_data is not None:
                    final = final_data
            step += 1
        messages.append({"role": "user", "content": tool_results})
        if final is not None:
            break
    return final, messages


def save_report(subdir: str, task_id: str, report: dict) -> str:
    """Persist a report via the shared blob store (local FS by default, S3 when
    PHANTOM_REPORTS_BUCKET is set). Returns the report URI."""
    import store
    md = report.get("report_markdown", "")
    uri = store.save_blob(subdir, f"{task_id}.md", md) if md else ""
    store.save_blob(subdir, f"{task_id}.json",
                    json.dumps({k: v for k, v in report.items() if k != "report_markdown"},
                               indent=2, default=str))
    return uri or f"{subdir}/{task_id}.md"


# ── Task-type registry ───────────────────────────────────────────────────────
# Bespoke types (detection-engineering, threat-intelligence) register a runner.
# Skill-guided types register a system_prompt + skill_hints and use the generic
# runner. This makes every Part-1 domain an assignable Phantom task type.

_REGISTRY: dict[str, dict] = {}


def register_task(name: str, summary: str, *, system_prompt: str = "",
                  skill_hints: list[str] | None = None,
                  runner: Callable | None = None) -> None:
    _REGISTRY[name] = {"name": name, "summary": summary, "system_prompt": system_prompt,
                       "skill_hints": skill_hints or [], "runner": runner}


def list_task_types() -> list[dict]:
    return [{"name": v["name"], "summary": v["summary"], "bespoke": v["runner"] is not None}
            for v in sorted(_REGISTRY.values(), key=lambda x: x["name"])]


def run_generic_task(task_type: str, objective: str, context: str = "") -> dict:
    """Drive a skill-guided task type: the agent researches the library via its
    skill_hints and produces a structured deliverable."""
    entry = _REGISTRY.get(task_type)
    if not entry:
        return {"error": f"unknown task type '{task_type}'", "available": list(_REGISTRY)}
    task_id = f"{task_type}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    hints = ", ".join(entry["skill_hints"]) or task_type
    system = entry["system_prompt"] or (
        f"You are Phantom performing a {task_type} task. Work from the skill library. {_BASE_RULES}")
    initial = (f"TASK: {objective}\n\n"
               f"{('CONTEXT:\n' + context + chr(10) + chr(10)) if context else ''}"
               f"Begin by searching the skill library (suggested topics: {hints}). "
               f"Load the most relevant skills, follow their procedures, then call write_report.")

    def dispatch(name: str, inp: dict) -> tuple[str, dict | None]:
        if name == "write_report":
            return json.dumps({"written": True}), inp
        return json.dumps({"error": f"unknown tool {name}"}), None

    report, _ = run_agent_loop(system, initial, SKILL_TOOLS + [generic_report_tool()],
                               dispatch, label=task_type)
    if report:
        report["task_id"] = task_id
        report["task_type"] = task_type
        report["report_path"] = save_report(task_type, task_id, report)
    return report or {"error": "no report produced", "task_type": task_type}


def run_task(task_type: str, objective: str, **kwargs) -> dict:
    """Entry point: route to a bespoke runner if present, else the generic runner."""
    entry = _REGISTRY.get(task_type)
    if entry and entry["runner"]:
        return entry["runner"](objective, **kwargs)
    return run_generic_task(task_type, objective, context=kwargs.get("context", ""))


_BASE_RULES = ("Be thorough and evidence-driven. Cite the specific skills you used. "
               "Do not ask the user questions — investigate autonomously. "
               "Call write_report as your final action.")


# ── Register the Part-1 domains as skill-guided task types ───────────────────
# (detection_engineering.py and threat_intel.py register their own bespoke
#  runners on import; the rest are skill-guided until they grow bespoke tools.)

_SKILL_GUIDED = [
    ("dfir-forensics", "Digital forensics & IR: memory/disk/cloud forensics, timelines, evidence",
     ["memory forensics volatility", "disk image analysis", "cloud forensics cloudtrail", "incident timeline"]),
    ("red-team", "Offensive engagement planning & adversary emulation",
     ["red team engagement", "adversary emulation", "atomic red team", "privilege escalation"]),
    ("purple-team", "Purple-team exercises: emulate + measure detection coverage",
     ["purple team exercise", "atomic testing", "mitre attack coverage", "breach and attack simulation"]),
    ("ot-ics-security", "OT/ICS/SCADA assessment & monitoring",
     ["modbus anomaly", "plc firmware", "iec 62443", "ics asset discovery", "historian security"]),
    ("identity-pam", "Identity governance, PAM, access reviews",
     ["privileged access management", "access recertification", "service account audit", "zero standing privilege"]),
    ("api-security", "API security testing (REST/GraphQL/SOAP, JWT/OAuth, BOLA)",
     ["api security assessment", "graphql security", "broken object level authorization", "jwt vulnerabilities"]),
    ("data-protection-dlp", "DLP & privacy: Purview, cloud/endpoint DLP, GDPR, DSAR",
     ["data loss prevention", "cloud dlp", "gdpr data protection", "privacy impact assessment"]),
    ("email-security", "Email security controls & BEC defense",
     ["dmarc dkim spf", "proofpoint email security", "business email compromise", "email sandboxing"]),
    ("crypto-pki", "Cryptography, PKI & secrets: certs, signing, HSM",
     ["certificate lifecycle", "code signing sigstore", "hsm integration", "jwt signing"]),
    ("supply-chain-devsecops", "Software supply-chain & pipeline security",
     ["image provenance cosign", "typosquatting packages", "github actions security", "devsecops pipeline"]),
    ("cloud-posture", "Multi-cloud posture: CSPM/CWPP across AWS/Azure/GCP",
     ["cloud security posture management", "cloud workload protection", "azure security", "gcp security", "cartography"]),
    ("zero-trust-network", "Zero Trust / network / SASE controls & network attack sims",
     ["zero trust", "software defined perimeter", "secure web gateway", "vlan hopping"]),
    ("insider-threat", "Insider-threat investigation & UEBA",
     ["insider threat investigation", "user behavior analytics", "dlp exfiltration"]),
    ("iot-firmware", "IoT/firmware/physical assessment",
     ["iot security assessment", "firmware extraction binwalk", "physical intrusion"]),
    ("mcp-security", "MCP security (OWASP MCP Top-10)",
     ["mcp command injection", "mcp privilege scope", "mcp shadow server", "mcp audit logging"]),
    ("resilience-backup", "Resilience: immutable backup, recovery validation, chaos",
     ["immutable backup restic", "backup integrity", "security chaos engineering"]),
    ("deception", "Deception & honeypots",
     ["honeypot deployment", "deception technology"]),
    ("blockchain-security", "Smart-contract / blockchain security",
     ["ethereum smart contract vulnerabilities", "blockchain security"]),
]

for _name, _summary, _hints in _SKILL_GUIDED:
    register_task(_name, _summary, skill_hints=_hints,
                  system_prompt=(f"You are Phantom performing a {_summary.split(':')[0].lower()} task. "
                                 f"{_BASE_RULES}"))

# Auto-register bespoke task types (they import task_agent, so import them last,
# once this module's registry API is fully defined). Failures are non-fatal.
for _mod in ("detection_engineering", "threat_intel"):
    try:
        __import__(_mod)
    except Exception as _e:  # noqa: BLE001
        print(f"[task_agent] {_mod} not registered: {_e}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3:
        print(json.dumps(run_task(sys.argv[1], " ".join(sys.argv[2:])), indent=2, default=str))
    else:
        print("Registered Phantom task types:\n")
        for t in list_task_types():
            print(f"  {'★' if t['bespoke'] else ' '} {t['name']:24} {t['summary']}")
        print("\n  ★ = bespoke tooling | others are skill-guided")
        print("\nUsage: python task_agent.py <task-type> <objective...>")
