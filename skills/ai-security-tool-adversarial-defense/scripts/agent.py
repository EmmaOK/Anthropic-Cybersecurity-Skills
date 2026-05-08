#!/usr/bin/env python3
"""
AI Security Tool Adversarial Defense Auditor
MAESTRO Layer 6 (Security & Compliance) — threat side, 20 controls.
"""
import argparse
import copy
import json
import sys
from datetime import datetime, timezone


CONTROLS = [
    # Training integrity
    {
        "id": "SECTOOL-001", "category": "Training Integrity",
        "threat": "Security Agent Data Poisoning",
        "control": "Training data cryptographic signing",
        "field_path": ["training", "data_signed"],
        "severity": "CRITICAL",
        "finding_false": "Training datasets for the security model are not signed — an attacker with write access to the training pipeline can inject adversarial samples to suppress specific detection signatures",
        "remediation": "Cryptographically sign all training datasets (SHA-256 manifest + GPG signature); verify signatures before any training run; reject unsigned or modified datasets",
    },
    {
        "id": "SECTOOL-002", "category": "Training Integrity",
        "threat": "Security Agent Data Poisoning",
        "control": "Training data provenance tracking",
        "field_path": ["training", "data_provenance_tracked"],
        "severity": "HIGH",
        "finding_false": "Training data provenance is not tracked — the origin and chain of custody of security model training data cannot be verified",
        "remediation": "Implement ML metadata (MLMD) or DVC provenance tracking for all training datasets; store provenance with each model version",
    },
    {
        "id": "SECTOOL-003", "category": "Training Integrity",
        "threat": "Evasion of Security AI Agents",
        "control": "Adversarial samples included in training data",
        "field_path": ["training", "adversarial_samples_included"],
        "severity": "HIGH",
        "finding_false": "Training data contains no adversarial examples — the security model has never encountered evasion attempts during training and will misclassify novel adversarial inputs",
        "remediation": "Augment training data with adversarial examples (FGSM, PGD for classifiers; adversarial network packets for IDS); target coverage of known evasion families",
    },
    {
        "id": "SECTOOL-004", "category": "Training Integrity",
        "threat": "Security Agent Data Poisoning",
        "control": "Training data poisoning detection",
        "field_path": ["training", "poisoning_detection_enabled"],
        "severity": "HIGH",
        "finding_false": "No data poisoning detection in training pipeline — statistical anomalies indicating injected adversarial samples go undetected",
        "remediation": "Apply spectral signatures or activation clustering analysis to training batches; flag samples that deviate significantly from class distribution before training",
    },
    {
        "id": "SECTOOL-005", "category": "Training Integrity",
        "threat": "Security Agent Data Poisoning",
        "control": "Training data access controls",
        "field_path": ["training", "training_data_access_controlled"],
        "severity": "CRITICAL",
        "finding_false": "Training data repositories have no access controls — any pipeline process (or attacker with pipeline access) can modify training data",
        "remediation": "Restrict write access to training data repositories to authorized pipeline service accounts only; require MFA for any direct write operation; audit all mutations",
    },
    # Operational integrity
    {
        "id": "SECTOOL-006", "category": "Operational Integrity",
        "threat": "Evasion of Security AI Agents",
        "control": "Adversarial evasion detection in production",
        "field_path": ["operational", "evasion_detection_enabled"],
        "severity": "HIGH",
        "finding_false": "No adversarial evasion detection in production — the security tool cannot detect that it is being fed adversarially crafted inputs designed to evade detection",
        "remediation": "Deploy input anomaly detection alongside the security model; flag inputs that are statistical outliers or match known adversarial perturbation signatures",
    },
    {
        "id": "SECTOOL-007", "category": "Operational Integrity",
        "threat": "Compromised Security AI Agents",
        "control": "Output consistency monitoring",
        "field_path": ["operational", "output_consistency_monitoring"],
        "severity": "HIGH",
        "finding_false": "Model output consistency is not monitored — sudden changes in detection rate (false positive/negative rates) indicating model corruption or takeover go undetected",
        "remediation": "Track rolling false positive/negative rates and alert on deviations exceeding 2σ from baseline; compare outputs of shadow model against production model",
    },
    {
        "id": "SECTOOL-008", "category": "Operational Integrity",
        "threat": "Lack of Explainability in Security AI Agents",
        "control": "Per-decision explainability",
        "field_path": ["operational", "explainability_available"],
        "severity": "HIGH",
        "finding_false": "Security tool decisions are not explainable — analysts cannot determine which features caused an alert (or non-alert), blocking triage, tuning, and forensic use",
        "remediation": "Integrate SHAP or LIME explanations for every security model decision; surface top-contributing features in the alert UI; log explanations for post-incident review",
    },
    {
        "id": "SECTOOL-009", "category": "Operational Integrity",
        "threat": "Compromised Security AI Agents / Repudiation",
        "control": "Per-decision audit trail",
        "field_path": ["operational", "audit_trail_per_decision"],
        "severity": "HIGH",
        "finding_false": "No per-decision audit trail — security model decisions cannot be reconstructed post-incident; attacker can later deny that specific traffic was classified as benign",
        "remediation": "Log input features, model version, confidence score, decision, and explanation for every security decision; store in tamper-evident log",
    },
    {
        "id": "SECTOOL-010", "category": "Operational Integrity",
        "threat": "Compromised Security AI Agents",
        "control": "Fallback to rule-based detection on anomaly",
        "field_path": ["operational", "fallback_to_rules_on_anomaly"],
        "severity": "MEDIUM",
        "finding_false": "No rule-based fallback when AI detection behaves anomalously — a compromised security model that starts misclassifying all traffic has no backup detection layer",
        "remediation": "Implement a parallel rule-based detection layer (Snort, Sigma, YARA) that activates automatically when AI detection rate deviates significantly from baseline",
    },
    # Coverage and bias
    {
        "id": "SECTOOL-011", "category": "Coverage",
        "threat": "Bias in Security AI Agents",
        "control": "Bias testing across populations and environments",
        "field_path": ["coverage", "bias_testing_performed"],
        "severity": "HIGH",
        "finding_false": "No bias testing performed — the security model may have systematically different detection rates across IP ranges, protocols, or environments due to training data imbalance",
        "remediation": "Test detection rates stratified by source IP range, protocol, time-of-day, and environment type; require parity within acceptable bounds before deployment",
    },
    {
        "id": "SECTOOL-012", "category": "Coverage",
        "threat": "Bias in Security AI Agents",
        "control": "Blind spot monitoring in production",
        "field_path": ["coverage", "blind_spot_monitoring"],
        "severity": "HIGH",
        "finding_false": "No blind spot monitoring — systematic gaps in detection coverage (specific attack families, protocols, or source populations never triggering alerts) are not surfaced",
        "remediation": "Track alert rate by traffic segment; alert on segments where detection rate falls below threshold; run periodic red-team exercises targeting candidate blind spots",
    },
    {
        "id": "SECTOOL-013", "category": "Coverage",
        "threat": "Evasion of Security AI Agents",
        "control": "Adversarial regression testing on model updates",
        "field_path": ["coverage", "adversarial_regression_testing"],
        "severity": "HIGH",
        "finding_false": "Adversarial regression testing is not run on model updates — a model update can degrade robustness against known evasion techniques without detection",
        "remediation": "Add adversarial test suite to model update pipeline (ART, CleverHans, or custom evasion corpus); block deployment if evasion rate exceeds threshold vs. prior version",
    },
    # Access controls
    {
        "id": "SECTOOL-014", "category": "Access Controls",
        "threat": "Compromised Security AI Agents",
        "control": "Model update authentication",
        "field_path": ["access_controls", "model_update_authenticated"],
        "severity": "CRITICAL",
        "finding_false": "Model updates are not authenticated — an attacker with pipeline access can replace the production security model with one trained to ignore specific attack patterns",
        "remediation": "Require signed model artifacts for all production deployments; enforce two-person approval for model updates in production security systems",
    },
    {
        "id": "SECTOOL-015", "category": "Access Controls",
        "threat": "Compromised Security AI Agents / Model Extraction",
        "control": "Model API access restriction",
        "field_path": ["access_controls", "api_access_restricted"],
        "severity": "HIGH",
        "finding_false": "Security model API is not access-restricted — attackers can query the model systematically to extract its decision boundaries (enabling evasion) or probe its detection signatures",
        "remediation": "Restrict API access to authorized consumers only; implement rate limiting; monitor for systematic query patterns indicating model extraction attempts",
    },
    {
        "id": "SECTOOL-016", "category": "Access Controls",
        "threat": "Compromised Security AI Agents",
        "control": "Configuration change audit trail",
        "field_path": ["access_controls", "configuration_change_audited"],
        "severity": "HIGH",
        "finding_false": "Security tool configuration changes are not audited — threshold adjustments, allowlist modifications, and integration changes cannot be attributed or investigated",
        "remediation": "Log all configuration changes to an append-only audit trail with the identity, timestamp, old value, and new value of each change",
    },
    {
        "id": "SECTOOL-017", "category": "Access Controls",
        "threat": "Compromised Security AI Agents",
        "control": "Model artifact integrity verification",
        "field_path": ["access_controls", "model_artifact_integrity_checked"],
        "severity": "HIGH",
        "finding_false": "Model artifacts are not integrity-verified at load time — a tampered model file (modified weights, backdoored layers) will be loaded without detection",
        "remediation": "Compute and verify SHA-256 hash of model artifacts at every load; compare against a signed manifest stored separately from the model file",
    },
    # Incident response
    {
        "id": "SECTOOL-018", "category": "Incident Response",
        "threat": "Compromised Security AI Agents",
        "control": "Kill switch for AI security tool",
        "field_path": ["incident_response", "kill_switch_available"],
        "severity": "CRITICAL",
        "finding_false": "No kill switch for the AI security tool — a compromised or malfunctioning security model cannot be disabled without taking down the entire detection pipeline",
        "remediation": "Implement an out-of-band kill switch that disables the AI detection layer and activates rule-based fallback; test it quarterly in a non-production environment",
    },
    {
        "id": "SECTOOL-019", "category": "Incident Response",
        "threat": "Compromised Security AI Agents",
        "control": "Compromise detection monitoring",
        "field_path": ["incident_response", "compromise_detection_monitoring"],
        "severity": "HIGH",
        "finding_false": "No monitoring for signs of security tool compromise — sudden drops in alert volume, systematic false negatives, or unexpected configuration drift are not alerted on",
        "remediation": "Monitor alert volume, false positive/negative rates, and configuration hashes continuously; alert on anomalies that may indicate security tool compromise",
    },
    {
        "id": "SECTOOL-020", "category": "Incident Response",
        "threat": "Compromised Security AI Agents",
        "control": "Manual override capability",
        "field_path": ["incident_response", "manual_override_capability"],
        "severity": "MEDIUM",
        "finding_false": "No manual override capability — security analysts cannot manually block or allow specific traffic patterns when the AI model is behaving unexpectedly",
        "remediation": "Provide analysts with a manual override interface to add time-bounded allow/block rules that take precedence over AI classification",
    },
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def set_nested(d: dict, path: list, value):
    for key in path[:-1]:
        if key not in d or not isinstance(d[key], dict):
            d[key] = {}
        d = d[key]
    d[path[-1]] = value


def apply_fixes(config: dict, findings: list, controls: list) -> tuple:
    fixed = copy.deepcopy(config)
    changes = []
    ctrl_by_id = {c["id"]: c for c in controls}
    for finding in findings:
        ctrl = ctrl_by_id.get(finding.get("id"))
        if not ctrl:
            continue
        path = ctrl["field_path"]
        changes.append({
            "finding_id": finding["id"],
            "severity": finding["severity"],
            "field": ".".join(str(p) for p in path),
            "old_value": finding.get("value_found", False),
            "new_value": True,
            "remediation_note": ctrl["remediation"][:150],
        })
        set_nested(fixed, path, True)
    return fixed, changes


def get_nested(data: dict, path: list, default=None):
    for key in path:
        if not isinstance(data, dict):
            return default
        data = data.get(key, default)
    return data


def run_audit(config: dict) -> list:
    findings = []
    for ctrl in CONTROLS:
        value = get_nested(config, ctrl["field_path"], default=None)
        if value is False or value is None:
            finding_text = ctrl["finding_false"]
            if value is None:
                finding_text = f"Field {'.'.join(ctrl['field_path'])} missing — {ctrl['finding_false']}"
            findings.append({
                "id": ctrl["id"],
                "severity": ctrl["severity"],
                "layer": "L6",
                "category": ctrl["category"],
                "threat": ctrl["threat"],
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
        description="AI Security Tool Adversarial Defense Auditor (MAESTRO L6 — threat side)"
    )
    sub = parser.add_subparsers(dest="command")

    audit_p = sub.add_parser("audit", help="Audit security tool config against 20 Layer 6 threat controls")
    audit_p.add_argument("--config", required=True, help="Path to security tool config JSON")
    audit_p.add_argument("--output", default="security_tool_audit.json", help="Output file path")

    fix_p = sub.add_parser("fix", help="Generate corrected config from audit output")
    fix_p.add_argument("--audit", required=True)
    fix_p.add_argument("--config", required=True)
    fix_p.add_argument("--output-dir", default="remediation-output")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "audit":
        with open(args.config) as f:
            config = json.load(f)

        findings = run_audit(config)
        findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))

        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

        overall_risk = compute_risk(findings)

        report = {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_name": config.get("tool_name", "unknown"),
            "tool_type": config.get("tool_type", "unknown"),
            "methodology": "MAESTRO Layer 6 (Security & Compliance) — ai-security-tool-adversarial-defense v1.0",
            "total_checks": len(CONTROLS),
            "findings_count": len(findings),
            "by_severity": by_sev,
            "overall_risk": overall_risk,
            "findings": findings,
            "recommendation": (
                f"{by_sev['CRITICAL']} CRITICAL and {by_sev['HIGH']} HIGH findings require remediation. "
                "Prioritize kill switch availability and training data access controls — "
                "a compromised security AI with no fallback is worse than no AI security at all."
            ) if findings else "No findings. Security tool satisfies all 20 MAESTRO Layer 6 adversarial defense controls.",
        }

        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)

        print(json.dumps(report, indent=2))

        if overall_risk in ("CRITICAL", "HIGH"):
            sys.exit(1)

    elif args.command == "fix":
        import os
        with open(args.audit) as f:
            audit_data = json.load(f)
        with open(args.config) as f:
            original_config = json.load(f)
        findings = audit_data.get("findings", [])
        fixed_config, changes = apply_fixes(original_config, findings, CONTROLS)
        os.makedirs(args.output_dir, exist_ok=True)
        config_basename = os.path.basename(args.config)
        fixed_path = os.path.join(args.output_dir, f"fixed_{config_basename}")
        with open(fixed_path, "w") as f:
            json.dump(fixed_config, f, indent=2)
        summary = {
            "fix_timestamp": datetime.now(timezone.utc).isoformat(),
            "source_audit": args.audit,
            "source_config": args.config,
            "fixed_config_path": fixed_path,
            "total_findings": len(findings),
            "fixes_applied": len(changes),
            "changes": changes,
        }
        with open(os.path.join(args.output_dir, "fix_summary.json"), "w") as f:
            json.dump(summary, f, indent=2)
        print(json.dumps(summary, indent=2))
        sys.exit(0)


if __name__ == "__main__":
    main()
