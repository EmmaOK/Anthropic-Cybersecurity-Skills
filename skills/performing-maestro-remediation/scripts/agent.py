#!/usr/bin/env python3
"""
MAESTRO Remediation Orchestrator
Consolidates audit outputs from any combination of MAESTRO layer auditors
into a prioritized, phased remediation plan.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

LAYER_LABELS = {
    "L1": "Foundation Models",
    "L2": "Data Operations",
    "L3": "Agent Frameworks",
    "L4": "Deployment & Infrastructure",
    "L5": "Evaluation & Observability",
    "L6": "Security & Compliance",
    "L7": "Agent Ecosystem",
    "Cross-Layer": "Cross-Layer Mitigations",
}

# Map audit file report keys to canonical skill names
SKILL_HINTS = {
    "ecosystem_name": "ai-agent-ecosystem-security",
    "framework_name": "ai-agent-framework-security",
    "tool_name": "ai-security-tool-adversarial-defense",
    "system": "ai-data-operations-availability-and-integrity",
}

METHODOLOGY_HINTS = {
    "L1": ["adversarial-robustness-and-evasion-defense", "ai-model-extraction-and-reprogramming-defense"],
    "L2": ["ai-data-operations-availability-and-integrity", "rag-pipeline-security-and-data-provenance"],
    "L3": ["ai-agent-framework-security"],
    "L4": ["ai-workload-infrastructure-hardening"],
    "L5": ["ai-evaluation-security-and-observability-hardening"],
    "L6": ["ai-governance-and-regulatory-compliance", "ai-security-tool-adversarial-defense"],
    "L7": ["ai-agent-ecosystem-security"],
    "Cross-Layer": ["ai-explainability-and-formal-verification", "performing-maestro-threat-modeling"],
}

PHASE_DEFS = [
    {"phase": 1, "label": "Immediate (0–2 weeks)", "severities": ["CRITICAL"]},
    {"phase": 2, "label": "Short-term (2–6 weeks)", "severities": ["HIGH"]},
    {"phase": 3, "label": "Medium-term (6–12 weeks)", "severities": ["MEDIUM"]},
    {"phase": 4, "label": "Long-term (12+ weeks)", "severities": ["LOW"]},
]


def normalize_finding(raw: dict, source_file: str, skill_name: str) -> dict:
    return {
        "id": raw.get("id", "UNKNOWN"),
        "severity": raw.get("severity", "MEDIUM"),
        "layer": raw.get("layer", "UNKNOWN"),
        "category": raw.get("category", ""),
        "threat": raw.get("threat", ""),
        "control": raw.get("control", ""),
        "finding": raw.get("finding", ""),
        "remediation": raw.get("remediation", ""),
        "resource": raw.get("resource", ""),
        "source_skill": skill_name,
        "source_file": source_file,
    }


def infer_skill(report: dict, source_file: str) -> str:
    methodology = report.get("methodology", "")
    for fragment, skill in [
        ("ai-agent-ecosystem-security", "ai-agent-ecosystem-security"),
        ("ai-agent-framework-security", "ai-agent-framework-security"),
        ("ai-security-tool-adversarial-defense", "ai-security-tool-adversarial-defense"),
        ("ai-data-operations", "ai-data-operations-availability-and-integrity"),
        ("adversarial-robustness", "adversarial-robustness-and-evasion-defense"),
        ("ai-model-extraction", "ai-model-extraction-and-reprogramming-defense"),
        ("ai-workload-infrastructure", "ai-workload-infrastructure-hardening"),
        ("ai-evaluation-security", "ai-evaluation-security-and-observability-hardening"),
        ("ai-governance", "ai-governance-and-regulatory-compliance"),
        ("rag-pipeline", "rag-pipeline-security-and-data-provenance"),
        ("ai-explainability", "ai-explainability-and-formal-verification"),
        ("MAESTRO Layer 7", "ai-agent-ecosystem-security"),
        ("MAESTRO Layer 3", "ai-agent-framework-security"),
        ("MAESTRO Layer 6", "ai-security-tool-adversarial-defense"),
        ("MAESTRO Layer 2", "ai-data-operations-availability-and-integrity"),
        ("MAESTRO Layer 1", "adversarial-robustness-and-evasion-defense"),
    ]:
        if fragment in methodology:
            return skill
    stem = Path(source_file).stem.replace("_audit", "").replace("_report", "").replace("_", "-")
    return stem


def load_audit(path: str) -> tuple:
    with open(path) as f:
        report = json.load(f)
    skill_name = infer_skill(report, path)
    raw_findings = report.get("findings", [])
    normalized = [normalize_finding(r, path, skill_name) for r in raw_findings]
    return report, normalized, skill_name


def deduplicate(findings: list) -> list:
    seen = set()
    unique = []
    for f in findings:
        key = (f["id"], f.get("resource", ""))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def build_phases(findings: list) -> list:
    phases = []
    for phase_def in PHASE_DEFS:
        items = [f for f in findings if f["severity"] in phase_def["severities"]]
        if not items:
            continue
        by_layer = {}
        for f in items:
            layer = f.get("layer", "UNKNOWN")
            by_layer.setdefault(layer, []).append({
                "id": f["id"],
                "severity": f["severity"],
                "layer": layer,
                "category": f["category"],
                "control": f["control"],
                "finding": f["finding"],
                "remediation": f["remediation"],
                "resource": f.get("resource", ""),
                "source_skill": f["source_skill"],
            })
        phases.append({
            "phase": phase_def["phase"],
            "label": phase_def["label"],
            "total_items": len(items),
            "layers_affected": sorted(by_layer.keys()),
            "by_layer": by_layer,
        })
    return phases


def compute_risk(findings: list) -> str:
    severities = {f["severity"] for f in findings}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in severities:
            return sev
    return "PASS"


def main():
    parser = argparse.ArgumentParser(
        description="MAESTRO Remediation Orchestrator — consolidates MAESTRO layer audit outputs into a phased remediation plan"
    )
    sub = parser.add_subparsers(dest="command")

    plan_p = sub.add_parser("plan", help="Generate phased remediation plan from one or more audit JSON files")
    plan_p.add_argument("--audits", required=True, nargs="+", metavar="AUDIT_JSON",
                        help="One or more audit output JSON files from MAESTRO layer auditors")
    plan_p.add_argument("--output", default="maestro_remediation_plan.json",
                        help="Output file path (default: maestro_remediation_plan.json)")
    plan_p.add_argument("--title", default="",
                        help="Optional system/project name for the report header")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    all_findings = []
    audit_sources = []
    errors = []

    for path in args.audits:
        try:
            report, findings, skill_name = load_audit(path)
            all_findings.extend(findings)
            audit_sources.append({
                "file": path,
                "skill": skill_name,
                "methodology": report.get("methodology", ""),
                "findings_loaded": len(findings),
                "overall_risk": report.get("overall_risk", "UNKNOWN"),
            })
        except Exception as e:
            errors.append({"file": path, "error": str(e)})

    all_findings = deduplicate(all_findings)
    all_findings.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 9), x.get("layer", ""), x["id"]))

    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_layer: dict = {}
    for f in all_findings:
        sev = f["severity"]
        by_sev[sev] = by_sev.get(sev, 0) + 1
        layer = f.get("layer", "UNKNOWN")
        by_layer[layer] = by_layer.get(layer, 0) + 1

    overall_risk = compute_risk(all_findings)
    phases = build_phases(all_findings)

    layers_covered = sorted(set(f.get("layer", "UNKNOWN") for f in all_findings))
    skills_covered = sorted(set(s["skill"] for s in audit_sources))

    # Build quick-win list: CRITICAL findings with shortest remediation text (proxy for simplicity)
    quick_wins = sorted(
        [f for f in all_findings if f["severity"] == "CRITICAL"],
        key=lambda x: len(x["remediation"])
    )[:5]

    report = {
        "plan_timestamp": datetime.now(timezone.utc).isoformat(),
        "title": args.title or "MAESTRO Consolidated Remediation Plan",
        "methodology": "MAESTRO Remediation Orchestrator — performing-maestro-remediation v1.0",
        "audit_sources": audit_sources,
        "load_errors": errors,
        "skills_covered": skills_covered,
        "layers_covered": layers_covered,
        "total_findings": len(all_findings),
        "by_severity": by_sev,
        "by_layer": by_layer,
        "overall_risk": overall_risk,
        "phases": phases,
        "quick_wins": [
            {
                "id": f["id"],
                "severity": f["severity"],
                "layer": f["layer"],
                "control": f["control"],
                "remediation": f["remediation"],
                "source_skill": f["source_skill"],
            }
            for f in quick_wins
        ],
        "recommendation": (
            f"{by_sev['CRITICAL']} CRITICAL findings across {len(layers_covered)} MAESTRO layers. "
            f"Start with Phase 1 ({by_sev['CRITICAL']} items) — all CRITICAL controls must be resolved "
            "before production deployment. Then address Phase 2 HIGH findings to reduce residual risk below acceptable threshold."
        ) if all_findings else "No findings across all loaded audits. All MAESTRO controls are satisfied.",
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)


if __name__ == "__main__":
    main()
