#!/usr/bin/env python3
"""
AI Explainability and Formal Verification Auditor
MAESTRO Cross-Layer Mitigations:
  - Explainable AI (XAI) — audit-xai
  - Formal Goal Verification — verify-goals
  - Reputation System Design — reputation-audit
"""
import argparse
import json
import sys
from datetime import datetime, timezone


XAI_CONTROLS = [
    {
        "id": "XAI-001", "category": "Local Explainability",
        "mitigation": "Explainable AI (XAI)",
        "control": "Per-decision local explanation available",
        "field_path": ["xai", "local_explainability_available"],
        "severity": "CRITICAL",
        "finding_false": "No local explainability for individual decisions — analysts and regulators cannot determine why the AI reached a specific decision for a specific input",
        "remediation": "Integrate SHAP, LIME, or Captum to generate per-decision feature importance explanations; surface top contributing features in the decision record",
    },
    {
        "id": "XAI-002", "category": "Local Explainability",
        "mitigation": "Explainable AI (XAI)",
        "control": "Explanation logged per decision",
        "field_path": ["xai", "explanation_per_decision_logged"],
        "severity": "CRITICAL",
        "finding_false": "Explanations are not logged alongside decisions — post-incident reconstruction of why an AI made a specific decision is impossible",
        "remediation": "Log SHAP values or LIME explanation alongside each decision; include model version, input hash, output, and explanation in a tamper-evident decision record",
    },
    {
        "id": "XAI-003", "category": "Global Explainability",
        "mitigation": "Explainable AI (XAI)",
        "control": "Global explainability / feature importance documented",
        "field_path": ["xai", "feature_importance_documented"],
        "severity": "HIGH",
        "finding_false": "No global feature importance documentation — the overall behavior of the model across its decision space is not understood; bias and systematic errors are harder to detect",
        "remediation": "Generate SHAP summary plots and partial dependence plots for the model; document top features and their directional impact; update after every model version change",
    },
    {
        "id": "XAI-004", "category": "Local Explainability",
        "mitigation": "Explainable AI (XAI)",
        "control": "Counterfactual explanations available",
        "field_path": ["xai", "counterfactual_explanations"],
        "severity": "HIGH",
        "finding_false": "No counterfactual explanations — users and regulators cannot understand what minimal input change would have produced a different decision (critical for adverse decision appeals)",
        "remediation": "Integrate DiCE or similar counterfactual generator; surface 'what would need to change' alongside adverse decisions for user-facing and regulator-facing contexts",
    },
    {
        "id": "XAI-005", "category": "Auditability",
        "mitigation": "Explainable AI (XAI)",
        "control": "Explanations accessible to auditors",
        "field_path": ["xai", "explanation_accessible_to_auditors"],
        "severity": "CRITICAL",
        "finding_false": "Explanations are not accessible to auditors or regulators — compliance audits and regulatory examinations cannot be supported",
        "remediation": "Provide auditors with read-only access to decision records including explanations; build audit extraction API that returns decision + explanation by decision_id",
    },
    {
        "id": "XAI-006", "category": "Forensic Capability",
        "mitigation": "Explainable AI (XAI)",
        "control": "Decision reconstruction capability",
        "field_path": ["forensic_capability", "decision_reconstruction_possible"],
        "severity": "CRITICAL",
        "finding_false": "Decision reconstruction is not possible — given a historical decision ID, the input state, model version, and explanation cannot be recovered for forensic use",
        "remediation": "Log input state hash + model version with every decision; retain logs for the regulatory retention period; test reconstruction procedure quarterly",
    },
    {
        "id": "XAI-007", "category": "Forensic Capability",
        "mitigation": "Explainable AI (XAI)",
        "control": "Input state logged per decision",
        "field_path": ["forensic_capability", "input_state_logged_per_decision"],
        "severity": "HIGH",
        "finding_false": "Input state is not logged per decision — the exact input that produced a specific decision cannot be reconstructed; forensic and regulatory investigation is severely hampered",
        "remediation": "Log a hash of the full input state (or the input itself where privacy permits) alongside each decision; link to decision record by decision_id",
    },
    {
        "id": "XAI-008", "category": "Forensic Capability",
        "mitigation": "Explainable AI (XAI)",
        "control": "Model version tracked per decision",
        "field_path": ["forensic_capability", "model_version_tracked_per_decision"],
        "severity": "HIGH",
        "finding_false": "Model version is not tracked per decision — it is impossible to determine which model version produced a specific historical decision, blocking root-cause analysis of errors",
        "remediation": "Tag every decision record with the exact model version (semantic version + commit hash); enforce version tagging at the inference serving layer",
    },
    {
        "id": "XAI-009", "category": "Stakeholder Access",
        "mitigation": "Explainable AI (XAI)",
        "control": "User-facing explanations for adverse decisions",
        "field_path": ["stakeholder_access", "user_facing_explanations"],
        "severity": "HIGH",
        "finding_false": "No user-facing explanations for adverse AI decisions — users affected by negative AI decisions (loan denial, content removal, account suspension) cannot understand or appeal the outcome",
        "remediation": "Surface a simplified explanation (top 3 contributing factors in plain language) in the user-facing interface for any adverse AI decision; include appeal mechanism",
    },
    {
        "id": "XAI-010", "category": "Stakeholder Access",
        "mitigation": "Explainable AI (XAI)",
        "control": "Appeal mechanism supported by explanations",
        "field_path": ["stakeholder_access", "appeal_mechanism_supported"],
        "severity": "HIGH",
        "finding_false": "No appeal mechanism supported — users cannot challenge adverse AI decisions; in regulated contexts (EU AI Act high-risk) this is a compliance violation",
        "remediation": "Implement an appeal flow that surfaces the explanation and allows submission of additional evidence; route appeals to human review with access to the full decision record",
    },
    {
        "id": "XAI-011", "category": "Forensic Capability",
        "mitigation": "Explainable AI (XAI)",
        "control": "Tamper-evident explanation storage",
        "field_path": ["forensic_capability", "explanation_tamper_evident"],
        "severity": "HIGH",
        "finding_false": "Explanation records are not tamper-evident — a party with database access could modify historical explanations to avoid accountability",
        "remediation": "Store decision records and explanations in an append-only, cryptographically chained log; include record hash in subsequent records to detect tampering",
    },
]

GOAL_CONTROLS = [
    {
        "id": "GOAL-001", "category": "Goal Specification",
        "mitigation": "Formal Verification",
        "control": "Goals formally defined",
        "field_path": ["goal_specification", "goals_formally_defined"],
        "severity": "HIGH",
        "finding_false": "Agent goals are defined informally (natural language only) — the goal specification is ambiguous and cannot be verified computationally or tested exhaustively",
        "remediation": "Express agent goals in a formal specification language (TLA+, Alloy, temporal logic) or structured goal ontology; document measurable success criteria for each goal",
    },
    {
        "id": "GOAL-002", "category": "Goal Specification",
        "mitigation": "Formal Verification",
        "control": "Constraints formally specified",
        "field_path": ["goal_specification", "constraints_formally_specified"],
        "severity": "HIGH",
        "finding_false": "Agent constraints (what the agent must never do) are not formally specified — constraint violations may not be detectable at runtime",
        "remediation": "Formally specify invariants (e.g., 'never delete user data without confirmation', 'never spend > $100 without human approval'); implement runtime constraint checker",
    },
    {
        "id": "GOAL-003", "category": "Goal Specification",
        "mitigation": "Formal Verification",
        "control": "Runtime constraint checker implemented",
        "field_path": ["goal_specification", "constraint_checker_implemented"],
        "severity": "CRITICAL",
        "finding_false": "No runtime constraint checker — the agent can violate formally defined constraints without detection or prevention",
        "remediation": "Implement a runtime constraint layer that validates all proposed agent actions against the constraint specification before execution; block and alert on violations",
    },
    {
        "id": "GOAL-004", "category": "Goal Specification",
        "mitigation": "Formal Verification",
        "control": "Goal conflict analysis performed",
        "field_path": ["goal_specification", "goal_conflicts_analyzed"],
        "severity": "HIGH",
        "finding_false": "Goal conflicts have not been analyzed — the agent may have multiple goals that are in tension; optimizing one goal may systematically violate another",
        "remediation": "Perform multi-objective goal conflict analysis before deployment; document known trade-offs; implement priority ordering for conflicting goals",
    },
    {
        "id": "GOAL-005", "category": "Goal Specification",
        "mitigation": "Formal Verification",
        "control": "Reward hacking scenarios tested",
        "field_path": ["goal_specification", "reward_hacking_scenarios_tested"],
        "severity": "HIGH",
        "finding_false": "Reward hacking scenarios have not been tested — the agent may optimize its metric in ways that technically satisfy the specification but violate the intent",
        "remediation": "Generate reward hacking scenarios (Goodhart's Law adversarial cases); test agent behavior in each scenario; add constraints that block discovered hacking patterns",
    },
    {
        "id": "GOAL-006", "category": "Verification",
        "mitigation": "Formal Verification",
        "control": "Simulation testing of goal behavior",
        "field_path": ["verification", "simulation_testing_performed"],
        "severity": "HIGH",
        "finding_false": "No simulation testing of goal behavior across edge cases — the agent has only been tested in controlled scenarios that may not reveal goal misalignment",
        "remediation": "Run extensive simulation testing with adversarial environments; test edge cases where goals conflict with constraints; include domain-specific adversarial scenarios",
    },
    {
        "id": "GOAL-007", "category": "Verification",
        "mitigation": "Formal Verification",
        "control": "Red team goal manipulation testing",
        "field_path": ["verification", "red_team_goal_manipulation_tested"],
        "severity": "HIGH",
        "finding_false": "No red team testing for goal manipulation — an attacker who can influence the agent's context, tool outputs, or environment can redirect the agent's goals without this being tested",
        "remediation": "Conduct red team exercises specifically targeting goal manipulation: inject adversarial context, poison tool outputs, manipulate environmental observations; document discovered manipulation vectors",
    },
    {
        "id": "GOAL-008", "category": "Verification",
        "mitigation": "Formal Verification",
        "control": "Invariant monitoring in production",
        "field_path": ["verification", "invariant_monitoring_in_production"],
        "severity": "CRITICAL",
        "finding_false": "No invariant monitoring in production — constraint violations by the agent in production are not detected until downstream damage is observed",
        "remediation": "Deploy runtime invariant monitor alongside the agent; check all specified constraints against each agent action before and after execution; alert immediately on violations",
    },
    {
        "id": "GOAL-009", "category": "Alignment Testing",
        "mitigation": "Formal Verification",
        "control": "Human review of goal specification performed",
        "field_path": ["alignment_testing", "human_review_of_goals_performed"],
        "severity": "HIGH",
        "finding_false": "No human expert review of the formal goal specification — the specification may contain errors, ambiguities, or misalignments with intended behavior",
        "remediation": "Require sign-off from domain expert, ethics reviewer, and security engineer on the formal goal specification before deployment; document review conclusions",
    },
    {
        "id": "GOAL-010", "category": "Alignment Testing",
        "mitigation": "Formal Verification",
        "control": "Goal changes require review and re-verification",
        "field_path": ["alignment_testing", "goal_change_requires_review"],
        "severity": "HIGH",
        "finding_false": "Goal changes do not require formal review — an attacker or misconfigured pipeline could modify agent goals without triggering re-verification",
        "remediation": "Gate all goal specification changes on formal review and re-verification; treat goal changes with the same rigor as code changes affecting safety properties",
    },
]

REPUTATION_CONTROLS = [
    {
        "id": "REP-001", "category": "Sybil Resistance",
        "mitigation": "Reputation-Based Trust for Distributed Agent Ecosystems",
        "control": "Sybil resistance mechanism implemented",
        "field_path": ["reputation_system", "sybil_resistance_mechanism"],
        "severity": "CRITICAL",
        "finding_false": "No Sybil resistance mechanism — an attacker with many fake identities can dominate reputation scores, promoting malicious agents and suppressing legitimate ones",
        "remediation": "Implement at least one Sybil resistance mechanism: identity verification for reviewers (email, CAPTCHA, linked account), stake-based voting, or coordinated-rating anomaly detection",
        "null_is_finding": True,
    },
    {
        "id": "REP-002", "category": "Sybil Resistance",
        "mitigation": "Reputation-Based Trust for Distributed Agent Ecosystems",
        "control": "Reviewer identity verification",
        "field_path": ["reputation_system", "reviewer_identity_verified"],
        "severity": "HIGH",
        "finding_false": "Reviewer identities are not verified — anyone can create multiple accounts and submit reviews, enabling coordinated Sybil attacks on agent reputation",
        "remediation": "Require reviewer identity verification (verified email, phone, linked professional account) before allowing reputation contributions",
    },
    {
        "id": "REP-003", "category": "Sybil Resistance",
        "mitigation": "Reputation-Based Trust for Distributed Agent Ecosystems",
        "control": "Coordinated rating anomaly detection",
        "field_path": ["reputation_system", "review_anomaly_detection"],
        "severity": "HIGH",
        "finding_false": "No coordinated rating anomaly detection — a burst of positive reviews from recently created accounts goes undetected",
        "remediation": "Apply anomaly detection to rating patterns: flag sudden review bursts, correlated timing, or unusual reviewer demographics; quarantine suspicious reviews for human review",
    },
    {
        "id": "REP-004", "category": "Reputation Dynamics",
        "mitigation": "Reputation-Based Trust for Distributed Agent Ecosystems",
        "control": "Reputation decay implemented",
        "field_path": ["reputation_system", "reputation_decay_implemented"],
        "severity": "MEDIUM",
        "finding_false": "No reputation decay — early actors accumulate disproportionate reputation that cannot be challenged; stale positive reputation persists even as agent behavior degrades",
        "remediation": "Implement time-weighted reputation decay (e.g., exponential decay with 6-month half-life); weight recent interactions more heavily than historical ones",
    },
    {
        "id": "REP-005", "category": "Reputation Dynamics",
        "mitigation": "Reputation-Based Trust for Distributed Agent Ecosystems",
        "control": "Rapid reputation gain detection",
        "field_path": ["trust_controls", "rapid_reputation_gain_flagged"],
        "severity": "HIGH",
        "finding_false": "Rapid reputation gain is not flagged — an agent that accumulates an unusually high reputation in a short time window (indicative of manipulation) goes undetected",
        "remediation": "Monitor rate of reputation change; flag agents gaining more than 3σ above baseline reputation rate within any 30-day window for manual review",
    },
    {
        "id": "REP-006", "category": "Trust Enforcement",
        "mitigation": "Reputation-Based Trust for Distributed Agent Ecosystems",
        "control": "Reputation scores influence agent discovery",
        "field_path": ["trust_controls", "trust_scores_influence_discovery"],
        "severity": "HIGH",
        "finding_false": "Reputation scores do not influence discovery — users are not protected from low-reputation or flagged agents appearing prominently in search results",
        "remediation": "Weight discovery ranking by verified reputation score; de-rank or hide agents below minimum reputation threshold; show reputation prominently in search results",
    },
    {
        "id": "REP-007", "category": "Trust Enforcement",
        "mitigation": "Reputation-Based Trust for Distributed Agent Ecosystems",
        "control": "Low-reputation agents quarantined or restricted",
        "field_path": ["trust_controls", "low_trust_agents_quarantined"],
        "severity": "HIGH",
        "finding_false": "Low-reputation agents have no restrictions — agents that have accumulated negative signals continue operating with full capabilities and visibility",
        "remediation": "Automatically restrict agents falling below minimum reputation threshold: require manual review for new interactions, reduce API call limits, add warning labels in UI",
    },
    {
        "id": "REP-008", "category": "Bootstrap Protection",
        "mitigation": "Reputation-Based Trust for Distributed Agent Ecosystems",
        "control": "Bootstrap manipulation protection",
        "field_path": ["reputation_system", "bootstrap_manipulation_protected"],
        "severity": "HIGH",
        "finding_false": "No bootstrap manipulation protection — a new malicious agent can rapidly build reputation from zero through coordinated reviews before any detection kicks in",
        "remediation": "Apply bootstrap restrictions to new agents: probationary period with limited capabilities, minimum interaction count before full reputation weighing, elevated monitoring for first 30 days",
    },
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def get_nested(data: dict, path: list, default=None):
    for key in path:
        if not isinstance(data, dict):
            return default
        data = data.get(key, default)
    return data


def run_controls(config: dict, controls: list) -> list:
    findings = []
    for ctrl in controls:
        value = get_nested(config, ctrl["field_path"], default=None)
        null_is_finding = ctrl.get("null_is_finding", False)
        is_finding = value is False or (value is None and null_is_finding)
        if is_finding:
            finding_text = ctrl["finding_false"]
            if value is None:
                finding_text = f"Field {'.'.join(ctrl['field_path'])} not configured — {ctrl['finding_false']}"
            findings.append({
                "id": ctrl["id"],
                "severity": ctrl["severity"],
                "category": ctrl["category"],
                "mitigation_category": ctrl["mitigation"],
                "control": ctrl["control"],
                "finding": finding_text,
                "remediation": ctrl["remediation"],
            })
    return findings


def compute_risk(findings: list) -> str:
    severities = {f["severity"] for f in findings}
    if "CRITICAL" in severities:
        return "CRITICAL"
    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"
    if findings:
        return "LOW"
    return "PASS"


def main():
    parser = argparse.ArgumentParser(
        description="AI Explainability and Formal Verification Auditor (MAESTRO Cross-Layer Mitigations)"
    )
    sub = parser.add_subparsers(dest="command")

    xai_p = sub.add_parser("audit-xai", help="Audit XAI posture against 11 explainability/forensic controls")
    xai_p.add_argument("--config", required=True, help="Path to XAI config JSON")
    xai_p.add_argument("--output", default="xai_audit.json", help="Output file path")

    goal_p = sub.add_parser("verify-goals", help="Audit formal goal specification and verification posture against 10 controls")
    goal_p.add_argument("--manifest", required=True, help="Path to agent goals manifest JSON")
    goal_p.add_argument("--output", default="goal_verification.json", help="Output file path")

    rep_p = sub.add_parser("reputation-audit", help="Audit reputation system design against 8 Sybil-resistance controls")
    rep_p.add_argument("--config", required=True, help="Path to reputation system config JSON")
    rep_p.add_argument("--output", default="reputation_audit.json", help="Output file path")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "audit-xai":
        with open(args.config) as f:
            config = json.load(f)
        findings = run_controls(config, XAI_CONTROLS)
        findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        overall_risk = compute_risk(findings)
        report = {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "system_name": config.get("system_name", "unknown"),
            "audit_type": "XAI Posture Audit",
            "methodology": "MAESTRO Cross-Layer Mitigation — ai-explainability-and-formal-verification v1.0",
            "mitigation_category": "Explainable AI (XAI)",
            "total_checks": len(XAI_CONTROLS),
            "findings_count": len(findings),
            "by_severity": by_sev,
            "overall_risk": overall_risk,
            "findings": findings,
            "recommendation": (
                f"{by_sev['CRITICAL']} CRITICAL and {by_sev['HIGH']} HIGH findings. "
                "Implement per-decision logging and auditor access as immediate priorities — "
                "these are the minimum required for regulatory compliance and forensic investigation."
            ) if findings else "No findings. XAI posture satisfies all 11 explainability controls.",
        }
        output_path = args.output

    elif args.command == "verify-goals":
        with open(args.manifest) as f:
            config = json.load(f)
        findings = run_controls(config, GOAL_CONTROLS)
        findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        overall_risk = compute_risk(findings)
        report = {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_name": config.get("agent_name", "unknown"),
            "audit_type": "Formal Goal Verification Audit",
            "methodology": "MAESTRO Cross-Layer Mitigation — ai-explainability-and-formal-verification v1.0",
            "mitigation_category": "Formal Verification",
            "total_checks": len(GOAL_CONTROLS),
            "findings_count": len(findings),
            "by_severity": by_sev,
            "overall_risk": overall_risk,
            "findings": findings,
            "recommendation": (
                f"{by_sev['CRITICAL']} CRITICAL and {by_sev['HIGH']} HIGH findings. "
                "Runtime constraint checker and invariant monitoring are the highest-priority controls — "
                "without these, formal specifications provide no runtime protection."
            ) if findings else "No findings. Goal specification and verification satisfies all 10 formal verification controls.",
        }
        output_path = args.output

    else:  # reputation-audit
        with open(args.config) as f:
            config = json.load(f)
        findings = run_controls(config, REPUTATION_CONTROLS)
        findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        overall_risk = compute_risk(findings)
        report = {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "ecosystem_name": config.get("ecosystem_name", "unknown"),
            "audit_type": "Reputation System Design Audit",
            "methodology": "MAESTRO Cross-Layer Mitigation — ai-explainability-and-formal-verification v1.0",
            "mitigation_category": "Reputation-Based Trust for Distributed Agent Ecosystems",
            "total_checks": len(REPUTATION_CONTROLS),
            "findings_count": len(findings),
            "by_severity": by_sev,
            "overall_risk": overall_risk,
            "findings": findings,
            "recommendation": (
                f"{by_sev['CRITICAL']} CRITICAL and {by_sev['HIGH']} HIGH findings. "
                "Sybil resistance and coordinated-rating detection are the foundational controls — "
                "without these, all other reputation controls can be gamed."
            ) if findings else "No findings. Reputation system design satisfies all 8 Sybil-resistance controls.",
        }
        output_path = args.output

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)


if __name__ == "__main__":
    main()
