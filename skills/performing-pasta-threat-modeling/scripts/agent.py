#!/usr/bin/env python3
"""
PASTA Threat Modeling Agent

Three subcommands:
  scaffold — Generate a blank PASTA worksheet (Stages 1–7 template).
  analyze  — Score attack scenarios and produce a risk register.
  report   — Generate the final PASTA executive report.

Usage:
    agent.py scaffold --system "Banking Portal" --output pasta_worksheet.json
    agent.py analyze  --worksheet pasta_worksheet.json --output pasta_risks.json
    agent.py report   --risks pasta_risks.json [--output pasta_report.json]

Worksheet format: JSON object with keys stage1..stage7, each containing
structured fields matching the PASTA methodology stages.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

LIKELIHOOD_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
IMPACT_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

THREAT_ACTOR_TEMPLATES = [
    {
        "name": "Financially Motivated Criminal",
        "sophistication": "MEDIUM",
        "motivation": "Steal funds, sell account data, commit fraud",
        "attack_vectors": ["Credential stuffing", "Phishing", "Account takeover", "Payment fraud"],
        "relevant_techniques": ["T1078", "T1110.004", "T1566", "T1539"],
    },
    {
        "name": "Malicious Insider",
        "sophistication": "LOW",
        "motivation": "Financial gain, grievance, coercion",
        "attack_vectors": ["Abuse of legitimate access", "Data exfiltration", "Record manipulation"],
        "relevant_techniques": ["T1078.002", "T1530", "T1565"],
    },
    {
        "name": "Opportunistic Attacker",
        "sophistication": "LOW",
        "motivation": "Opportunistic exploitation of known vulnerabilities",
        "attack_vectors": ["Automated scanning", "Known CVE exploitation", "Default credentials"],
        "relevant_techniques": ["T1190", "T1133", "T1110.001"],
    },
    {
        "name": "Nation-State Actor",
        "sophistication": "HIGH",
        "motivation": "Espionage, disruption, intellectual property theft",
        "attack_vectors": ["Spear-phishing", "Supply chain compromise", "Zero-day exploitation"],
        "relevant_techniques": ["T1195.002", "T1566.001", "T1190"],
    },
]

ATTACK_SCENARIO_TEMPLATE = {
    "id": "AS-001",
    "name": "Describe the attack scenario name",
    "threat_actor": "Select from threat actors above",
    "attack_chain": [
        {"step": 1, "technique": "T0000", "action": "Describe attacker action at this step"},
        {"step": 2, "weakness": "OWASP A01", "action": "Describe weakness being exploited"},
        {"step": 3, "technique": "T0000", "action": "Describe impact achieved"},
    ],
    "target_assets": ["Asset name 1", "Asset name 2"],
    "entry_point": "URL, API endpoint, or system component",
    "likelihood": "HIGH",
    "business_impact": "CRITICAL",
    "financial_exposure": "$X estimated loss per incident",
    "regulatory_exposure": "Regulation and penalty description",
    "remediations": [
        {"control": "Specific technical control", "effort": "LOW|MEDIUM|HIGH", "priority": 1},
    ],
}


def calculate_risk(likelihood: str, impact: str) -> dict:
    score = LIKELIHOOD_SCORE.get(likelihood, 1) * IMPACT_SCORE.get(impact, 1)
    severity = (
        "CRITICAL" if score >= 12
        else "HIGH" if score >= 6
        else "MEDIUM" if score >= 3
        else "LOW"
    )
    return {"risk_score": score, "severity": severity}


def cmd_scaffold(args) -> None:
    worksheet = {
        "system": args.system,
        "pasta_version": "2",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "stage1_business_objectives": {
            "owner": "",
            "revenue_impact": "",
            "regulatory_exposure": [],
            "risk_tolerance": "LOW|MEDIUM|HIGH",
            "security_goals": [],
            "compliance_deadlines": [],
        },
        "stage2_technical_scope": {
            "in_scope": [],
            "out_of_scope": [],
            "external_dependencies": [],
            "deployment": "",
        },
        "stage3_decomposition": {
            "trust_zones": {},
            "data_flows": [],
            "data_assets": [],
        },
        "stage4_threat_actors": THREAT_ACTOR_TEMPLATES,
        "stage5_vulnerabilities": {
            "scan_findings": [],
            "manual_weaknesses": [],
            "notes": "Add findings from Burp, Nessus, dependency-check, or manual review here.",
        },
        "stage6_attack_scenarios": [ATTACK_SCENARIO_TEMPLATE],
        "stage7_risk_register": [],
    }

    with open(args.output, "w") as f:
        json.dump(worksheet, f, indent=2)

    print(f"[*] PASTA worksheet scaffolded for: {args.system}")
    print(f"[*] Written to {args.output}")
    print(f"[*] Complete stages 1–6, then run: agent.py analyze --worksheet {args.output}")


def cmd_analyze(args) -> dict:
    path = Path(args.worksheet)
    if not path.exists():
        print(f"[error] Worksheet not found: {args.worksheet}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        ws = json.load(f)

    scenarios: list[dict] = ws.get("stage6_attack_scenarios", [])
    risk_register = []

    for scenario in scenarios:
        if scenario.get("id") == "AS-001" and scenario.get("name") == ATTACK_SCENARIO_TEMPLATE["name"]:
            continue  # skip unfilled template

        likelihood = scenario.get("likelihood", "MEDIUM")
        impact = scenario.get("business_impact", "MEDIUM")
        risk = calculate_risk(likelihood, impact)

        risk_register.append({
            "scenario_id": scenario.get("id"),
            "name": scenario.get("name"),
            "threat_actor": scenario.get("threat_actor"),
            "entry_point": scenario.get("entry_point"),
            "target_assets": scenario.get("target_assets", []),
            "likelihood": likelihood,
            "business_impact": impact,
            "risk_score": risk["risk_score"],
            "severity": risk["severity"],
            "financial_exposure": scenario.get("financial_exposure", ""),
            "regulatory_exposure": scenario.get("regulatory_exposure", ""),
            "remediations": scenario.get("remediations", []),
        })

    risk_register.sort(key=lambda x: x["risk_score"], reverse=True)

    # Inject back into worksheet
    ws["stage7_risk_register"] = risk_register

    with open(args.output, "w") as f:
        json.dump(ws, f, indent=2)

    critical = sum(1 for r in risk_register if r["severity"] == "CRITICAL")
    high = sum(1 for r in risk_register if r["severity"] == "HIGH")

    print(f"[*] Risk register built: {len(risk_register)} scenarios scored")
    print(f"[*] CRITICAL: {critical}  HIGH: {high}")
    print(f"[*] Written to {args.output}")
    print(f"[*] Run: agent.py report --risks {args.output}")

    return ws


def cmd_report(args) -> dict:
    path = Path(args.risks)
    if not path.exists():
        print(f"[error] Risks file not found: {args.risks}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        ws = json.load(f)

    system = ws.get("system", "Unknown")
    risk_register: list[dict] = ws.get("stage7_risk_register", [])
    objectives = ws.get("stage1_business_objectives", {})

    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in risk_register:
        sev = r.get("severity", "LOW")
        if sev in by_severity:
            by_severity[sev] += 1

    overall_risk = (
        "CRITICAL" if by_severity["CRITICAL"] > 0
        else "HIGH" if by_severity["HIGH"] > 0
        else "MEDIUM" if by_severity["MEDIUM"] > 0
        else "LOW"
    )

    # Build 30/60/90 day roadmap from top-priority remediations
    roadmap: dict[str, list[str]] = {"30_day": [], "60_day": [], "90_day": []}
    for r in risk_register:
        for rem in r.get("remediations", []):
            priority = rem.get("priority", 3)
            control = rem.get("control", "")
            if control:
                key = "30_day" if priority == 1 else "60_day" if priority == 2 else "90_day"
                if control not in roadmap[key]:
                    roadmap[key].append(control)

    top_risk = risk_register[0] if risk_register else {}

    report = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "system": system,
        "methodology": f"PASTA v{ws.get('pasta_version', '2')}",
        "stages_completed": 7,
        "executive_summary": {
            "attack_scenarios_identified": len(risk_register),
            "critical_risks": by_severity["CRITICAL"],
            "high_risks": by_severity["HIGH"],
            "top_risk": f"{top_risk.get('name', 'N/A')} ({top_risk.get('severity', 'N/A')}, score: {top_risk.get('risk_score', 0)})" if top_risk else "N/A",
            "regulatory_exposure": objectives.get("regulatory_exposure", []),
        },
        "risk_register": risk_register,
        "remediation_roadmap": roadmap,
        "overall_risk": overall_risk,
        "recommendation": (
            f"{by_severity['CRITICAL']} CRITICAL and {by_severity['HIGH']} HIGH risk scenarios identified. "
            f"Prioritise 30-day remediations immediately."
            if overall_risk in ("CRITICAL", "HIGH")
            else "Risk posture is acceptable. Continue monitoring and update threat model quarterly."
        ),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\n[*] PASTA report saved to {args.output}")

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)

    return report


def main():
    parser = argparse.ArgumentParser(description="PASTA Threat Modeling Agent")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_scaffold = sub.add_parser("scaffold", help="Generate blank PASTA worksheet")
    p_scaffold.add_argument("--system", required=True, help="System name")
    p_scaffold.add_argument("--output", default="pasta_worksheet.json")

    p_analyze = sub.add_parser("analyze", help="Score attack scenarios and build risk register")
    p_analyze.add_argument("--worksheet", required=True)
    p_analyze.add_argument("--output", default="pasta_analyzed.json")

    p_report = sub.add_parser("report", help="Generate PASTA executive report")
    p_report.add_argument("--risks", required=True)
    p_report.add_argument("--output", default="pasta_report.json")

    args = parser.parse_args()
    if args.subcommand == "scaffold":
        cmd_scaffold(args)
    elif args.subcommand == "analyze":
        cmd_analyze(args)
    elif args.subcommand == "report":
        cmd_report(args)


if __name__ == "__main__":
    main()
