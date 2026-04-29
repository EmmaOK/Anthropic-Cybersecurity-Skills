#!/usr/bin/env python3
"""
AI Governance and Regulatory Compliance Agent

Subcommands:
  assess — Generate a compliance checklist for EU AI Act, NIST AI RMF, and/or ISO 42001.
  score  — Score a filled-in checklist and produce a compliance gap report.

Usage:
    agent.py assess --system "Loan Underwriting AI" --risk-tier high
                    [--framework eu-ai-act|nist-ai-rmf|iso-42001|all]
                    [--output compliance_report.json]
    agent.py score  --checklist compliance_report.json [--output compliance_scored.json]
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

EU_AI_ACT_HIGH_RISK: list[dict] = [
    {
        "id": "EU-HR-001", "framework": "eu-ai-act", "article": "Article 9",
        "requirement": "Risk management system established and maintained throughout entire lifecycle",
        "severity": "CRITICAL",
        "guidance": "Document risk identification, analysis, estimation, and evaluation. Update after every significant change.",
    },
    {
        "id": "EU-HR-002", "framework": "eu-ai-act", "article": "Article 10",
        "requirement": "Training, validation, and testing data governance with documented quality criteria",
        "severity": "CRITICAL",
        "guidance": "Document data sources, collection methods, preprocessing, and bias mitigation for all datasets.",
    },
    {
        "id": "EU-HR-003", "framework": "eu-ai-act", "article": "Article 11",
        "requirement": "Technical documentation prepared before market placement and kept up to date",
        "severity": "HIGH",
        "guidance": "Maintain documentation covering: system description, design, development process, monitoring procedures, and intended purpose.",
    },
    {
        "id": "EU-HR-004", "framework": "eu-ai-act", "article": "Article 12",
        "requirement": "Automatic logging of system events throughout lifetime (record-keeping)",
        "severity": "HIGH",
        "guidance": "Implement tamper-evident automatic logging of events; retain logs for at least 6 months post-deployment.",
    },
    {
        "id": "EU-HR-005", "framework": "eu-ai-act", "article": "Article 13",
        "requirement": "Transparency and provision of information to deployers (instructions for use)",
        "severity": "HIGH",
        "guidance": "Provide clear documentation for deployers: capabilities, limitations, intended purpose, human oversight requirements.",
    },
    {
        "id": "EU-HR-006", "framework": "eu-ai-act", "article": "Article 14",
        "requirement": "Human oversight measures designed and built into the system",
        "severity": "CRITICAL",
        "guidance": "Enable human review, intervention, and override of AI decisions. Document oversight procedures and train operators.",
    },
    {
        "id": "EU-HR-007", "framework": "eu-ai-act", "article": "Article 15",
        "requirement": "Accuracy, robustness, and cybersecurity requirements met and documented",
        "severity": "HIGH",
        "guidance": "Define accuracy benchmarks; test for adversarial robustness; document cybersecurity measures taken.",
    },
    {
        "id": "EU-HR-008", "framework": "eu-ai-act", "article": "Article 16",
        "requirement": "Conformity assessment completed before market placement",
        "severity": "CRITICAL",
        "guidance": "Complete internal assessment or third-party audit per Annex VI/VII; obtain CE marking for EU market.",
    },
    {
        "id": "EU-HR-009", "framework": "eu-ai-act", "article": "Article 49",
        "requirement": "Registration in EU AI database before deploying high-risk AI system",
        "severity": "HIGH",
        "guidance": "Register system in the EU AI Act database at ai-office.ec.europa.eu before go-live.",
    },
    {
        "id": "EU-HR-010", "framework": "eu-ai-act", "article": "Article 72",
        "requirement": "Post-market monitoring plan established and implemented",
        "severity": "HIGH",
        "guidance": "Define KPIs to monitor after deployment; establish reporting cadence; report serious incidents to market surveillance authority.",
    },
    {
        "id": "EU-HR-011", "framework": "eu-ai-act", "article": "Article 26",
        "requirement": "Deployer obligations: human oversight, input data monitoring, suspension capability",
        "severity": "HIGH",
        "guidance": "Ensure deployer has procedures to monitor inputs, oversee operation, and suspend system when risk identified.",
    },
    {
        "id": "EU-HR-012", "framework": "eu-ai-act", "article": "Article 26(9)",
        "requirement": "Fundamental Rights Impact Assessment (FRIA) for public authority deployers",
        "severity": "MEDIUM",
        "guidance": "If deploying in a public authority context: complete FRIA before deployment; document impact on fundamental rights.",
    },
]

EU_AI_ACT_LIMITED_RISK: list[dict] = [
    {
        "id": "EU-LR-001", "framework": "eu-ai-act", "article": "Article 50",
        "requirement": "Transparency obligation: inform users when interacting with an AI system (chatbot disclosure)",
        "severity": "HIGH",
        "guidance": "Display clear disclosure that users are interacting with an AI system at the start of each interaction.",
    },
    {
        "id": "EU-LR-002", "framework": "eu-ai-act", "article": "Article 50(2)",
        "requirement": "AI-generated content labeling (deepfakes, synthetic media)",
        "severity": "HIGH",
        "guidance": "Label AI-generated images, audio, and video with machine-readable disclosure; implement watermarking where required.",
    },
]

NIST_AI_RMF: list[dict] = [
    {
        "id": "NIST-GOV-001", "framework": "nist-ai-rmf", "function": "GOVERN-1.1",
        "requirement": "Policies, processes, and procedures in place for AI risk management",
        "severity": "CRITICAL",
        "guidance": "Document AI risk policies, assign accountability, define review cadence. Align with organizational risk appetite.",
    },
    {
        "id": "NIST-GOV-002", "framework": "nist-ai-rmf", "function": "GOVERN-1.7",
        "requirement": "Processes for identifying and addressing AI risks to individuals and groups documented",
        "severity": "HIGH",
        "guidance": "Define processes for bias assessment, fairness monitoring, and individual rights impact across the AI lifecycle.",
    },
    {
        "id": "NIST-GOV-003", "framework": "nist-ai-rmf", "function": "GOVERN-4.2",
        "requirement": "Organizational teams understand their AI risk management roles and responsibilities",
        "severity": "HIGH",
        "guidance": "Define RACI for AI risk: who identifies, assesses, mitigates, and monitors risks. Train relevant staff.",
    },
    {
        "id": "NIST-GOV-004", "framework": "nist-ai-rmf", "function": "GOVERN-6.1",
        "requirement": "Policies and procedures for AI incident response established",
        "severity": "HIGH",
        "guidance": "Define incident classification for AI failures; establish response procedures; assign incident response roles.",
    },
    {
        "id": "NIST-MAP-001", "framework": "nist-ai-rmf", "function": "MAP-1.1",
        "requirement": "Context is established for AI system risk assessment (intended use, affected stakeholders)",
        "severity": "HIGH",
        "guidance": "Document intended purpose, deployment context, affected populations, and foreseeable misuse scenarios.",
    },
    {
        "id": "NIST-MAP-002", "framework": "nist-ai-rmf", "function": "MAP-2.1",
        "requirement": "AI risk and benefit analysis conducted with relevant stakeholders",
        "severity": "MEDIUM",
        "guidance": "Engage affected stakeholder groups in risk-benefit analysis; document findings and how they informed design.",
    },
    {
        "id": "NIST-MEA-001", "framework": "nist-ai-rmf", "function": "MEASURE-2.5",
        "requirement": "AI system trustworthiness characteristics measured and monitored",
        "severity": "HIGH",
        "guidance": "Define and track metrics for: accuracy, fairness, robustness, explainability, privacy, and security.",
    },
    {
        "id": "NIST-MEA-002", "framework": "nist-ai-rmf", "function": "MEASURE-2.7",
        "requirement": "AI system performance evaluated for real-world conditions including adversarial contexts",
        "severity": "HIGH",
        "guidance": "Test in conditions representative of real deployment; include adversarial, edge-case, and distribution-shift scenarios.",
    },
    {
        "id": "NIST-MEA-003", "framework": "nist-ai-rmf", "function": "MEASURE-3.1",
        "requirement": "Risks identified in the MEASURE function are prioritized and tracked",
        "severity": "MEDIUM",
        "guidance": "Maintain a live risk register for measured AI risks; assign owners and track remediation.",
    },
    {
        "id": "NIST-MAN-001", "framework": "nist-ai-rmf", "function": "MANAGE-2.2",
        "requirement": "Mechanisms for responding to and recovering from AI-related risks are in place",
        "severity": "HIGH",
        "guidance": "Define response playbooks for AI incidents (model failure, bias incident, security breach); test procedures annually.",
    },
    {
        "id": "NIST-MAN-002", "framework": "nist-ai-rmf", "function": "MANAGE-3.1",
        "requirement": "AI risks are monitored on a continuous basis",
        "severity": "HIGH",
        "guidance": "Implement continuous monitoring of AI outputs, fairness metrics, and security signals; define review triggers.",
    },
]

ISO_42001: list[dict] = [
    {
        "id": "ISO-001", "framework": "iso-42001", "clause": "Clause 4.1",
        "requirement": "Understanding the organization and its context relevant to AI management",
        "severity": "MEDIUM",
        "guidance": "Document internal/external factors affecting AI risk; align with ISO 42001 Annex A objectives.",
    },
    {
        "id": "ISO-002", "framework": "iso-42001", "clause": "Clause 5.2",
        "requirement": "AI policy established and communicated within the organization",
        "severity": "HIGH",
        "guidance": "Define and publish AI policy covering: principles, accountability, ethics, risk management commitment.",
    },
    {
        "id": "ISO-003", "framework": "iso-42001", "clause": "Clause 6.1",
        "requirement": "Risks and opportunities for the AI management system identified and addressed",
        "severity": "HIGH",
        "guidance": "Conduct risk assessment for the AI management system itself; define treatment plans for identified risks.",
    },
    {
        "id": "ISO-004", "framework": "iso-42001", "clause": "Clause 8.4 / Annex A.6",
        "requirement": "AI system impact assessment conducted",
        "severity": "HIGH",
        "guidance": "Assess system impact on individuals, groups, and society; document findings and mitigations.",
    },
    {
        "id": "ISO-005", "framework": "iso-42001", "clause": "Annex A.8",
        "requirement": "Data governance requirements for AI systems documented and implemented",
        "severity": "HIGH",
        "guidance": "Document data provenance, quality controls, bias mitigation, and consent management for all AI training/inference data.",
    },
    {
        "id": "ISO-006", "framework": "iso-42001", "clause": "Clause 9.1",
        "requirement": "Monitoring, measurement, analysis and evaluation of AI system performance",
        "severity": "MEDIUM",
        "guidance": "Define what to monitor, how, at what frequency, and who analyzes results. Document measurement methods.",
    },
    {
        "id": "ISO-007", "framework": "iso-42001", "clause": "Clause 10.1",
        "requirement": "Continual improvement process established for the AI management system",
        "severity": "MEDIUM",
        "guidance": "Document improvement process: identify nonconformity, correct, analyze cause, take corrective action, review effectiveness.",
    },
]

FRAMEWORK_MAP = {
    "eu-ai-act": {"high": EU_AI_ACT_HIGH_RISK, "limited": EU_AI_ACT_LIMITED_RISK, "minimal": []},
    "nist-ai-rmf": {"high": NIST_AI_RMF, "limited": NIST_AI_RMF, "minimal": NIST_AI_RMF[:4]},
    "iso-42001": {"high": ISO_42001, "limited": ISO_42001, "minimal": ISO_42001[:3]},
}


def build_checklist(risk_tier: str, frameworks: list[str]) -> list[dict]:
    items = []
    for fw in frameworks:
        fw_map = FRAMEWORK_MAP.get(fw, {})
        tier_items = fw_map.get(risk_tier, fw_map.get("high", []))
        for item in tier_items:
            items.append({**item, "status": "OPEN"})
    return items


def score_checklist(checklist: list[dict]) -> dict:
    total = len(checklist)
    compliant = sum(1 for x in checklist if x.get("status") == "COMPLIANT")
    open_gaps = [x for x in checklist if x.get("status") == "OPEN"]
    na = sum(1 for x in checklist if x.get("status") == "NOT_APPLICABLE")

    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for x in open_gaps:
        sev = x.get("severity", "LOW")
        if sev in by_sev:
            by_sev[sev] += 1

    pct = round((compliant / total * 100) if total > 0 else 0, 1)
    overall = (
        "CRITICAL" if by_sev["CRITICAL"] > 0 else
        "HIGH" if by_sev["HIGH"] > 0 else
        "MEDIUM" if by_sev["MEDIUM"] > 0 else "LOW"
    )
    priority_gaps = [x["requirement"] for x in open_gaps if x.get("severity") in ("CRITICAL", "HIGH")][:8]

    return {
        "total_requirements": total,
        "compliant": compliant,
        "open_gaps": len(open_gaps),
        "not_applicable": na,
        "compliance_score_pct": pct,
        "by_severity": by_sev,
        "overall_risk": overall,
        "priority_gaps": priority_gaps,
    }


def cmd_assess(args) -> dict:
    frameworks = (
        ["eu-ai-act", "nist-ai-rmf", "iso-42001"]
        if args.framework == "all"
        else [args.framework]
    )
    checklist = build_checklist(args.risk_tier, frameworks)
    scores = score_checklist(checklist)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "system": args.system,
        "risk_tier": args.risk_tier,
        "frameworks_assessed": frameworks,
        "checklist": checklist,
        **scores,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\n[*] Compliance checklist saved to {args.output}", file=sys.stderr)
    print(f"[*] Mark requirements as COMPLIANT or NOT_APPLICABLE, then run:", file=sys.stderr)
    print(f"[*]   agent.py score --checklist {args.output}", file=sys.stderr)

    if scores["overall_risk"] in ("CRITICAL", "HIGH"):
        sys.exit(1)

    return report


def cmd_score(args) -> dict:
    path = Path(args.checklist)
    if not path.exists():
        print(f"[error] File not found: {args.checklist}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        data = json.load(f)

    checklist = data.get("checklist", [])
    scores = score_checklist(checklist)

    report = {
        "scored_at": datetime.now(timezone.utc).isoformat(),
        "system": data.get("system", "Unknown"),
        "risk_tier": data.get("risk_tier", "unknown"),
        "frameworks_assessed": data.get("frameworks_assessed", []),
        "checklist": checklist,
        **scores,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\n[*] Scored report saved to {args.output}", file=sys.stderr)
    print(f"[*] Compliance score: {scores['compliance_score_pct']}% ({scores['compliant']}/{scores['total_requirements']} requirements)", file=sys.stderr)

    if scores["overall_risk"] in ("CRITICAL", "HIGH"):
        sys.exit(1)

    return report


# ── Governance action plan ─────────────────────────────────────────────────

_EFFORT = {"CRITICAL": "HIGH", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}

_ACTION_STEPS: dict[str, dict] = {
    "EU-HR-001": {
        "effort": "HIGH",
        "evidence": "Risk management plan document, risk register, review cadence schedule",
        "steps": [
            "Appoint an AI Risk Officer accountable for lifecycle risk management",
            "Document risk identification, analysis, estimation, and evaluation methodology",
            "Establish risk review cadence (quarterly minimum; after every significant change)",
            "Create and populate initial risk register",
            "Define escalation process for newly identified risks",
        ],
    },
    "EU-HR-002": {
        "effort": "HIGH",
        "evidence": "Data governance policy, dataset inventory with sources/preprocessing/bias mitigations",
        "steps": [
            "Inventory all training, validation, and testing datasets with provenance metadata",
            "Document data collection methods and preprocessing pipelines",
            "Conduct bias analysis on each dataset; document mitigation actions taken",
            "Define data quality criteria and acceptance thresholds",
            "Set up data lineage tracking for ongoing data changes",
        ],
    },
    "EU-HR-003": {
        "effort": "MEDIUM",
        "evidence": "Technical documentation package covering system description, design, development, monitoring",
        "steps": [
            "Create technical documentation per EU AI Act Annex IV requirements",
            "Include: system description, intended purpose, design decisions, architecture diagrams",
            "Document development process: training methodology, evaluation results, known limitations",
            "Add monitoring and maintenance procedures",
            "Establish documentation update process for system changes",
        ],
    },
    "EU-HR-004": {
        "effort": "MEDIUM",
        "evidence": "Audit trail showing automatic logging, tamper-evidence mechanism, retention policy",
        "steps": [
            "Implement automatic event logging covering all significant system decisions",
            "Use tamper-evident log store (append-only, cryptographic chaining)",
            "Configure log retention for minimum 6 months post-deployment",
            "Test log completeness against Article 12 requirements",
            "Document logging architecture and access controls",
        ],
    },
    "EU-HR-005": {
        "effort": "MEDIUM",
        "evidence": "Instructions for use document delivered to deployers",
        "steps": [
            "Draft instructions for use covering: capabilities, limitations, intended purpose",
            "Include human oversight requirements and intervention procedures",
            "Specify performance benchmarks and known edge cases",
            "Establish process for communicating updates to deployers",
            "Store and version instructions alongside system releases",
        ],
    },
    "EU-HR-006": {
        "effort": "HIGH",
        "evidence": "Human oversight design spec, operator training records, override capability demonstration",
        "steps": [
            "Design human review and override mechanisms into system architecture",
            "Implement intervention capability: pause, override, or reject AI decisions",
            "Document oversight procedures for operators",
            "Train all operators on oversight responsibilities and procedures",
            "Test override mechanisms and document test results",
        ],
    },
    "EU-HR-007": {
        "effort": "HIGH",
        "evidence": "Accuracy benchmarks, robustness test results, cybersecurity measures documentation",
        "steps": [
            "Define accuracy benchmarks relevant to intended use case",
            "Conduct adversarial robustness testing (perturbation, evasion, injection attacks)",
            "Document cybersecurity measures in place (encryption, access control, monitoring)",
            "Establish ongoing accuracy and robustness monitoring",
            "Define threshold for triggering re-evaluation or system suspension",
        ],
    },
    "EU-HR-008": {
        "effort": "HIGH",
        "evidence": "Completed conformity assessment, CE marking documentation",
        "steps": [
            "Identify applicable conformity assessment route (internal Annex VI or third-party Annex VII)",
            "Engage notified body if third-party assessment required",
            "Complete conformity assessment covering all Annex IV documentation",
            "Obtain CE marking declaration of conformity",
            "Archive assessment documentation for 10 years post-market",
        ],
    },
    "EU-HR-009": {
        "effort": "LOW",
        "evidence": "EU AI Act database registration confirmation",
        "steps": [
            "Register system at ai-office.ec.europa.eu before go-live",
            "Provide all required system details per Article 49",
            "Keep registration up to date with significant system changes",
        ],
    },
    "EU-HR-010": {
        "effort": "MEDIUM",
        "evidence": "Post-market monitoring plan, KPI dashboard, incident reporting procedure",
        "steps": [
            "Define KPIs to track after deployment (accuracy drift, bias metrics, user complaints)",
            "Establish monitoring review cadence (monthly minimum)",
            "Define thresholds triggering corrective action or suspension",
            "Document incident reporting process to market surveillance authority",
            "Set up post-market monitoring dashboard",
        ],
    },
    "EU-HR-011": {
        "effort": "MEDIUM",
        "evidence": "Deployer procedures for input monitoring, human oversight, suspension capability",
        "steps": [
            "Document deployer obligations per Article 26",
            "Ensure deployer has process to monitor input data quality",
            "Verify deployer has capability to suspend the system when risk identified",
            "Train deployer personnel on oversight obligations",
            "Establish communication channel between provider and deployer for incident reporting",
        ],
    },
    "EU-HR-012": {
        "effort": "HIGH",
        "evidence": "Completed Fundamental Rights Impact Assessment document",
        "steps": [
            "Assess impact on all fundamental rights (privacy, non-discrimination, dignity)",
            "Identify affected populations and potential disparate impacts",
            "Document mitigations for identified impacts",
            "Consult affected communities or representatives where feasible",
            "Review FRIA before each major system change",
        ],
    },
    "EU-LR-001": {
        "effort": "LOW",
        "evidence": "UI/UX screenshots showing AI disclosure at session start",
        "steps": [
            "Add clear disclosure that users are interacting with an AI system",
            "Display disclosure at the start of each interaction (not buried in terms)",
            "Ensure disclosure is visible and in plain language",
            "Test disclosure across all deployment surfaces",
        ],
    },
    "EU-LR-002": {
        "effort": "MEDIUM",
        "evidence": "Watermarking implementation, machine-readable disclosure in AI-generated content",
        "steps": [
            "Label all AI-generated images, audio, and video with machine-readable disclosure",
            "Implement watermarking where technically feasible",
            "Add visible disclosure label on synthetic media outputs",
            "Log all AI-generated content for audit purposes",
        ],
    },
    "NIST-GOV-001": {
        "effort": "HIGH",
        "evidence": "AI risk policy document, accountability assignment, review schedule",
        "steps": [
            "Draft AI risk management policy aligned with organizational risk appetite",
            "Assign accountability roles (AI Risk Officer, system owners)",
            "Define policy review cadence (annual minimum)",
            "Communicate policy to all relevant staff",
            "Establish policy exception and waiver process",
        ],
    },
    "NIST-GOV-002": {
        "effort": "HIGH",
        "evidence": "Bias assessment process, fairness monitoring plan, individual rights impact documentation",
        "steps": [
            "Define processes for bias assessment across the AI lifecycle",
            "Implement fairness monitoring metrics (demographic parity, equalized odds)",
            "Document individual rights impact and mitigation procedures",
            "Establish process for handling bias-related complaints",
            "Schedule regular fairness audits",
        ],
    },
    "NIST-GOV-003": {
        "effort": "MEDIUM",
        "evidence": "RACI matrix for AI risk, training completion records",
        "steps": [
            "Define RACI for AI risk: who identifies, assesses, mitigates, and monitors",
            "Document roles and responsibilities in team charter or policy",
            "Conduct AI risk awareness training for all relevant staff",
            "Track training completion and schedule refreshers",
        ],
    },
    "NIST-GOV-004": {
        "effort": "MEDIUM",
        "evidence": "AI incident response plan, assigned response roles",
        "steps": [
            "Define AI incident classification criteria (model failure, bias incident, security breach)",
            "Document incident response procedures per classification",
            "Assign incident response roles and backup contacts",
            "Test incident response procedures with tabletop exercise",
            "Integrate AI incidents into existing security incident response process",
        ],
    },
    "NIST-MAP-001": {
        "effort": "MEDIUM",
        "evidence": "Context document covering intended use, deployment context, affected populations, misuse scenarios",
        "steps": [
            "Document intended purpose and deployment context",
            "Identify all affected stakeholder populations",
            "Map foreseeable misuse scenarios and attacker motivations",
            "Review context document with legal, ethics, and security teams",
            "Update context document at each major system change",
        ],
    },
    "NIST-MAP-002": {
        "effort": "MEDIUM",
        "evidence": "Stakeholder engagement records, risk-benefit analysis document",
        "steps": [
            "Identify affected stakeholder groups for engagement",
            "Conduct structured risk-benefit analysis with stakeholder input",
            "Document findings and how they informed system design",
            "Establish ongoing stakeholder feedback mechanism",
        ],
    },
    "NIST-MEA-001": {
        "effort": "HIGH",
        "evidence": "Trustworthiness metrics dashboard, measurement methodology documentation",
        "steps": [
            "Define metrics for accuracy, fairness, robustness, explainability, privacy, and security",
            "Implement measurement processes for each metric",
            "Set thresholds for acceptable performance on each metric",
            "Build monitoring dashboard tracking all trustworthiness metrics",
            "Define review frequency and escalation triggers",
        ],
    },
    "NIST-MEA-002": {
        "effort": "HIGH",
        "evidence": "Real-world evaluation results including adversarial and edge-case test reports",
        "steps": [
            "Design evaluation scenarios representative of real deployment conditions",
            "Include adversarial, edge-case, and distribution-shift test scenarios",
            "Document evaluation methodology and dataset sources",
            "Run evaluations and document results with pass/fail criteria",
            "Schedule re-evaluation after significant model or data changes",
        ],
    },
    "NIST-MEA-003": {
        "effort": "MEDIUM",
        "evidence": "Live AI risk register with owners and remediation tracking",
        "steps": [
            "Create AI risk register capturing all measured risks",
            "Assign risk owners and target remediation dates",
            "Track remediation progress in risk register",
            "Review risk register monthly; escalate stale items",
        ],
    },
    "NIST-MAN-001": {
        "effort": "HIGH",
        "evidence": "AI incident response playbooks, annual test records",
        "steps": [
            "Define response playbooks for each AI incident type (model failure, bias, security breach)",
            "Include recovery procedures in each playbook",
            "Assign playbook owners and backup contacts",
            "Test procedures annually via tabletop or simulation exercise",
            "Update playbooks after each incident or exercise",
        ],
    },
    "NIST-MAN-002": {
        "effort": "HIGH",
        "evidence": "Continuous monitoring plan, alert configuration, review cadence documentation",
        "steps": [
            "Implement continuous monitoring of AI outputs and fairness metrics",
            "Set up security signal monitoring (anomalous queries, access patterns)",
            "Define review triggers (threshold breach, anomaly detected, time-based)",
            "Document who reviews monitoring alerts and at what cadence",
            "Test monitoring effectiveness with synthetic anomalies",
        ],
    },
    "ISO-001": {
        "effort": "MEDIUM",
        "evidence": "Context analysis document (internal/external factors, stakeholder analysis)",
        "steps": [
            "Document internal factors: organizational culture, capabilities, risk appetite",
            "Document external factors: regulatory environment, market conditions, technology landscape",
            "Identify interested parties and their requirements",
            "Align AI management objectives with ISO 42001 Annex A",
            "Review context analysis annually",
        ],
    },
    "ISO-002": {
        "effort": "MEDIUM",
        "evidence": "Published AI policy, communication records showing policy distribution",
        "steps": [
            "Draft AI policy covering: principles, accountability, ethics, risk management commitment",
            "Get executive sign-off on the policy",
            "Publish and communicate policy to all relevant staff",
            "Establish policy review cadence (annual minimum)",
            "Make policy available to external parties where appropriate",
        ],
    },
    "ISO-003": {
        "effort": "MEDIUM",
        "evidence": "Risk assessment for AI management system, risk treatment plans",
        "steps": [
            "Conduct risk assessment for the AI management system itself",
            "Identify risks to achieving AI management objectives",
            "Define treatment plans for each identified risk",
            "Assign risk owners and review dates",
            "Integrate AI MS risks into organizational risk management process",
        ],
    },
    "ISO-004": {
        "effort": "HIGH",
        "evidence": "AI system impact assessment document covering individuals, groups, society",
        "steps": [
            "Assess impact on individuals: privacy, autonomy, wellbeing, fundamental rights",
            "Assess impact on groups: bias, discrimination, disparate outcomes",
            "Assess societal impact: environmental, economic, safety implications",
            "Document findings and mitigations for each impact area",
            "Review impact assessment at each major system change",
        ],
    },
    "ISO-005": {
        "effort": "HIGH",
        "evidence": "Data governance policy, data provenance records, consent management documentation",
        "steps": [
            "Document data provenance for all AI training and inference data",
            "Define data quality controls and acceptance criteria",
            "Implement bias mitigation measures and document them",
            "Establish consent management for personal data used in AI",
            "Set up data governance review process for new data sources",
        ],
    },
    "ISO-006": {
        "effort": "MEDIUM",
        "evidence": "Monitoring plan specifying what, how, frequency, and who analyzes results",
        "steps": [
            "Define what to monitor: performance metrics, fairness indicators, security signals",
            "Document measurement methods and tools for each metric",
            "Set monitoring frequency (real-time, daily, weekly, monthly)",
            "Assign analysis responsibilities and reporting cadence",
            "Define process for acting on monitoring results",
        ],
    },
    "ISO-007": {
        "effort": "MEDIUM",
        "evidence": "Documented improvement process, corrective action records",
        "steps": [
            "Document nonconformity identification and correction process",
            "Implement root cause analysis for nonconformities",
            "Track corrective actions and verify their effectiveness",
            "Establish continual improvement review in management review meetings",
            "Measure and report improvement over time",
        ],
    },
}


def cmd_remediate(args) -> dict:
    checklist_path = Path(args.checklist)
    if not checklist_path.exists():
        print(f"[error] Checklist not found: {args.checklist}", file=sys.stderr)
        sys.exit(1)
    with open(checklist_path) as f:
        data = json.load(f)

    checklist = data.get("checklist", [])
    open_items = [x for x in checklist if x.get("status") == "OPEN"]

    if not open_items:
        print("[*] No OPEN gaps in checklist — nothing to plan.")
        return {}

    print(f"\n{'═'*64}")
    print(f"Governance Action Plan Builder — {len(open_items)} open gap(s)")
    print(f"Review each gap and confirm inclusion in your action plan.")
    print(f"{'═'*64}")

    included = []
    skipped_ids = []
    auto_include = False

    for item in open_items:
        iid   = item.get("id", "")
        isev  = item.get("severity", "")
        ireq  = item.get("requirement", "")
        ifw   = item.get("framework", "")
        ref   = item.get("article") or item.get("function") or item.get("clause", "")
        guidance = item.get("guidance", "")

        action_def = _ACTION_STEPS.get(iid, {})
        effort  = action_def.get("effort", _EFFORT.get(isev, "MEDIUM"))
        steps   = action_def.get("steps", ["See guidance above"])
        evidence = action_def.get("evidence", "Documentation demonstrating compliance")

        if auto_include:
            print(f"\n[auto-included] [{iid}] {ireq}")
            decision = "y"
        else:
            print(f"\n{'─'*64}")
            print(f"[{iid}] {isev} — {ifw.upper()} {ref}")
            print(f"Requirement : {ireq}")
            print(f"Guidance    : {guidance}")
            print(f"Effort      : {effort}")
            print(f"Evidence    : {evidence}")
            print(f"Steps       :")
            for i, s in enumerate(steps, 1):
                print(f"  {i}. {s}")
            while True:
                try:
                    ans = input("\nInclude in action plan? [y]es / [n]o / [s]kip all / [a]ll remaining > ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    ans = "s"
                if ans and ans[0] in ("y", "n", "s", "a"):
                    decision = ans[0]
                    break

        if decision == "a":
            auto_include = True
            decision = "y"
        if decision == "s":
            break
        if decision == "n":
            skipped_ids.append(iid)
            continue

        included.append({
            "id": iid,
            "framework": ifw,
            "reference": ref,
            "severity": isev,
            "requirement": ireq,
            "guidance": guidance,
            "action": {
                "owner": "<assign>",
                "target_date": "<assign>",
                "effort": effort,
                "evidence_required": evidence,
                "steps": steps,
                "status": "NOT_STARTED",
            },
        })
        print("  [✓] Added to action plan")

    stem = checklist_path.stem
    suffix = checklist_path.suffix or ".json"
    output_path = args.output or str(checklist_path.parent / f"{stem}_action_plan{suffix}")

    report = {
        "action_plan_timestamp": datetime.now(timezone.utc).isoformat(),
        "system": data.get("system", "Unknown"),
        "risk_tier": data.get("risk_tier", "unknown"),
        "frameworks_assessed": data.get("frameworks_assessed", []),
        "open_gaps_total": len(open_items),
        "included_in_plan": len(included),
        "excluded_from_plan": len(skipped_ids),
        "action_items": included,
        "next_steps": [
            "Assign an owner and target_date to each action item",
            "Track progress in your risk register or project management tool",
            "Re-run 'score' after marking requirements COMPLIANT to measure progress",
            "Schedule a compliance review meeting within 2 weeks",
        ],
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{'═'*64}")
    print(json.dumps(report, indent=2))
    print(f"\n[*] Action plan saved to {output_path}", file=sys.stderr)
    print(f"[*] Fill in owner and target_date for each action item", file=sys.stderr)
    print(f"[*] Re-run score after marking requirements COMPLIANT", file=sys.stderr)
    return report


def main():
    parser = argparse.ArgumentParser(description="AI Governance and Regulatory Compliance Agent")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_assess = sub.add_parser("assess", help="Generate compliance checklist")
    p_assess.add_argument("--system", required=True, help="AI system name")
    p_assess.add_argument(
        "--risk-tier", required=True,
        choices=["high", "limited", "minimal"],
        help="EU AI Act risk tier",
    )
    p_assess.add_argument(
        "--framework", default="all",
        choices=["eu-ai-act", "nist-ai-rmf", "iso-42001", "all"],
        help="Framework(s) to assess against",
    )
    p_assess.add_argument("--output", default="compliance_report.json")

    p_score = sub.add_parser("score", help="Score a completed compliance checklist")
    p_score.add_argument("--checklist", required=True, help="Compliance report JSON with updated statuses")
    p_score.add_argument("--output", default="compliance_scored.json")

    p_rem = sub.add_parser("remediate", help="Build a prioritized action plan for open compliance gaps")
    p_rem.add_argument("--checklist", required=True,
                       help="Scored compliance JSON (from score subcommand)")
    p_rem.add_argument("--output", default=None,
                       help="Output file (default: <checklist>_action_plan.json)")

    args = parser.parse_args()
    if args.subcommand == "assess":
        cmd_assess(args)
    elif args.subcommand == "score":
        cmd_score(args)
    elif args.subcommand == "remediate":
        cmd_remediate(args)


if __name__ == "__main__":
    main()
