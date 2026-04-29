#!/usr/bin/env python3
"""
AI Model Extraction and Reprogramming Defense Agent

Subcommand:
  audit — Audit a model API config for extraction-resistant and reprogramming-resistant controls.

Usage:
    agent.py audit --config model_api_config.json [--output model_audit.json]
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

EXTRACTION_CONTROLS: list[dict] = [
    {
        "id": "EXT-001", "risk": "extraction",
        "field": "rate_limiting.enabled",
        "check": lambda v: v is True,
        "severity": "CRITICAL",
        "control": "API rate limiting",
        "finding": "rate_limiting.enabled is false — unlimited queries allow trivial model extraction",
        "remediation": "Implement per-user and per-IP rate limits at the API gateway; 60–200 RPM is a common baseline",
    },
    {
        "id": "EXT-002", "risk": "extraction",
        "field": "rate_limiting.anomaly_detection",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Query anomaly detection",
        "finding": "anomaly_detection is false — systematic extraction queries are not detected",
        "remediation": "Monitor for high query volume, low semantic diversity, and grid-search patterns; alert and throttle",
    },
    {
        "id": "EXT-003", "risk": "extraction",
        "field": "output_controls.perturbation",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Output perturbation",
        "finding": "perturbation is false — model outputs are exact, maximizing extraction signal quality",
        "remediation": "Add calibrated output noise for probability outputs; round confidence scores to nearest 0.1",
    },
    {
        "id": "EXT-004", "risk": "extraction",
        "field": "output_controls.confidence_rounding",
        "check": lambda v: v is True,
        "severity": "MEDIUM",
        "control": "Confidence score rounding",
        "finding": "confidence_rounding is false — high-precision probabilities (e.g., 0.9847) maximize extraction signal",
        "remediation": "Return bucketed confidence labels (HIGH/MEDIUM/LOW) or round to 2 decimal places",
    },
    {
        "id": "EXT-005", "risk": "extraction",
        "field": "monitoring.consistency_monitoring",
        "check": lambda v: v is True,
        "severity": "MEDIUM",
        "control": "Output consistency monitoring",
        "finding": "consistency_monitoring is false — cannot detect stolen model by comparing output distributions",
        "remediation": "Log and periodically audit output distributions; enables detection of stolen model copies via fingerprinting",
    },
    {
        "id": "EXT-006", "risk": "extraction",
        "field": "monitoring.extraction_alerts",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Extraction attempt alerting",
        "finding": "extraction_alerts is false — no alerts triggered by systematic extraction behavior",
        "remediation": "Alert on: query volume spikes, low-diversity query sets, adversarial probing patterns",
    },
    {
        "id": "EXT-007", "risk": "extraction",
        "field": "auth.per_tenant_limits",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Per-tenant query limits",
        "finding": "per_tenant_limits is false — a single API key can perform unlimited extraction queries",
        "remediation": "Enforce per-tenant daily/monthly query budgets; require re-authentication or human review on limit breach",
    },
    {
        "id": "EXT-008", "risk": "extraction",
        "field": "membership_inference.differential_privacy",
        "check": lambda v: v is True,
        "severity": "MEDIUM",
        "control": "Differential privacy for membership inference defense",
        "finding": "differential_privacy is false — model may leak whether specific data was in training set",
        "remediation": "Apply differential privacy during training (DP-SGD) or add calibrated noise to output distributions",
    },
    {
        "id": "EXT-009", "risk": "extraction",
        "field": "membership_inference.output_generalization",
        "check": lambda v: v is True,
        "severity": "MEDIUM",
        "control": "Output generalization for membership inference defense",
        "finding": "output_generalization is false — overfitted outputs may reveal training data membership",
        "remediation": "Monitor for memorization; apply regularization; restrict exact-match responses on sensitive queries",
    },
]

REPROGRAMMING_CONTROLS: list[dict] = [
    {
        "id": "REP-001", "risk": "reprogramming",
        "field": "output_controls.policy_layer",
        "check": lambda v: v is True,
        "severity": "CRITICAL",
        "control": "Independent output policy layer",
        "finding": "policy_layer is false — output safety depends solely on the model's own judgment",
        "remediation": "Implement an independent policy layer (rule-based or LLM-as-judge) that validates outputs before delivery",
    },
    {
        "id": "REP-002", "risk": "reprogramming",
        "field": "output_controls.logit_masking",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Logit masking / token blocking",
        "finding": "logit_masking is false — model can generate any token including policy-violating content",
        "remediation": "Apply logit masking to block harmful token categories; use structured output constraints",
    },
    {
        "id": "REP-003", "risk": "reprogramming",
        "field": "fine_tuning_api.access_control",
        "check": lambda v: v is True,
        "severity": "CRITICAL",
        "control": "Fine-tuning API access control",
        "finding": "fine_tuning_api.access_control is false — any user can submit fine-tuning jobs to reprogram the model",
        "remediation": "Restrict fine-tuning API access; require approval workflow; audit all submitted training data",
    },
    {
        "id": "REP-004", "risk": "reprogramming",
        "field": "fine_tuning_api.data_validation",
        "check": lambda v: v is True,
        "severity": "HIGH",
        "control": "Fine-tuning data validation",
        "finding": "fine_tuning_api.data_validation is false — poisoned training data accepted without validation",
        "remediation": "Validate all fine-tuning submissions: check for instruction overrides, role manipulation, policy bypass patterns",
    },
    {
        "id": "REP-005", "risk": "reprogramming",
        "field": "fine_tuning_api.exposed",
        "check": lambda v: v is False,
        "severity": "HIGH",
        "control": "Fine-tuning API exposure",
        "finding": "fine_tuning_api.exposed is true — fine-tuning endpoint is publicly accessible",
        "remediation": "Restrict fine-tuning API to authorized internal services; remove from public-facing API surface if not needed",
    },
]


def get_nested(obj: dict, path: str):
    for p in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(p)
    return obj


def set_nested(obj: dict, path: str, value) -> None:
    parts = path.split(".")
    for p in parts[:-1]:
        obj = obj.setdefault(p, {})
    obj[parts[-1]] = value


def run_controls(config: dict, controls: list[dict]) -> list[dict]:
    findings = []
    for ctrl in controls:
        val = get_nested(config, ctrl["field"])
        if val is None or not ctrl["check"](val):
            findings.append({
                "id": ctrl["id"],
                "risk_category": ctrl["risk"],
                "severity": ctrl["severity"],
                "control": ctrl["control"],
                "finding": ctrl["finding"],
                "remediation": ctrl["remediation"],
                "current_value": val,
            })
    return findings


def cmd_audit(args) -> dict:
    path = Path(args.config)
    if not path.exists():
        print(f"[error] Config not found: {args.config}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        config = json.load(f)

    extraction_findings = run_controls(config, EXTRACTION_CONTROLS)
    reprogramming_findings = run_controls(config, REPROGRAMMING_CONTROLS)
    all_findings = extraction_findings + reprogramming_findings

    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f.get("severity", "LOW")
        if sev in by_sev:
            by_sev[sev] += 1

    extraction_risk = (
        "CRITICAL" if any(f["severity"] == "CRITICAL" for f in extraction_findings)
        else "HIGH" if any(f["severity"] == "HIGH" for f in extraction_findings)
        else "MEDIUM" if extraction_findings else "LOW"
    )
    reprogramming_risk = (
        "CRITICAL" if any(f["severity"] == "CRITICAL" for f in reprogramming_findings)
        else "HIGH" if any(f["severity"] == "HIGH" for f in reprogramming_findings)
        else "MEDIUM" if reprogramming_findings else "LOW"
    )
    overall = "CRITICAL" if by_sev["CRITICAL"] > 0 else "HIGH" if by_sev["HIGH"] > 0 else "MEDIUM" if by_sev["MEDIUM"] > 0 else "LOW"

    report = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "model_name": config.get("model_name", "Unknown"),
        "total_checks": len(EXTRACTION_CONTROLS) + len(REPROGRAMMING_CONTROLS),
        "findings_count": len(all_findings),
        "by_severity": by_sev,
        "extraction_risk_score": extraction_risk,
        "reprogramming_risk_score": reprogramming_risk,
        "overall_risk": overall,
        "extraction_findings": extraction_findings,
        "reprogramming_findings": reprogramming_findings,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\n[*] Model audit saved to {args.output}", file=sys.stderr)

    if overall in ("CRITICAL", "HIGH"):
        sys.exit(1)

    return report


# ── Remediation helpers ────────────────────────────────────────────────────

def _prompt(finding_id: str, severity: str, control: str, finding_text: str,
            proposed_lines: list[str]) -> str:
    print(f"\n{'─'*64}")
    print(f"[{finding_id}] {severity} — {control}")
    print(f"Finding  : {finding_text}")
    print("\nProposed fix:")
    for line in proposed_lines:
        print(f"  {line}")
    while True:
        try:
            ans = input("\nApply? [y]es / [n]o / [s]kip all / [a]ll remaining > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return "s"
        if ans and ans[0] in ("y", "n", "s", "a"):
            return ans[0]


_MODEL_PATCHES: dict[str, dict] = {
    "EXT-001": {"field": "rate_limiting.enabled",                    "value": True,
                "desc": ["rate_limiting.enabled = true",
                         "(set per-user and per-IP rate limits at API gateway; 60–200 RPM baseline)"]},
    "EXT-002": {"field": "rate_limiting.anomaly_detection",          "value": True,
                "desc": ["rate_limiting.anomaly_detection = true",
                         "(monitor for high volume, low semantic diversity, grid-search patterns)"]},
    "EXT-003": {"field": "output_controls.perturbation",             "value": True,
                "desc": ["output_controls.perturbation = true",
                         "(add calibrated noise to probability outputs)"]},
    "EXT-004": {"field": "output_controls.confidence_rounding",      "value": True,
                "desc": ["output_controls.confidence_rounding = true",
                         "(return bucketed labels HIGH/MEDIUM/LOW or round to 2 decimal places)"]},
    "EXT-005": {"field": "monitoring.consistency_monitoring",        "value": True,
                "desc": ["monitoring.consistency_monitoring = true",
                         "(log output distributions; enables stolen-model fingerprint detection)"]},
    "EXT-006": {"field": "monitoring.extraction_alerts",             "value": True,
                "desc": ["monitoring.extraction_alerts = true",
                         "(alert on query volume spikes, low-diversity query sets, adversarial probing)"]},
    "EXT-007": {"field": "auth.per_tenant_limits",                   "value": True,
                "desc": ["auth.per_tenant_limits = true",
                         "(enforce per-tenant daily/monthly query budgets)"]},
    "EXT-008": {"field": "membership_inference.differential_privacy","value": True,
                "desc": ["membership_inference.differential_privacy = true",
                         "(apply DP-SGD during training or add calibrated output noise)"]},
    "EXT-009": {"field": "membership_inference.output_generalization","value": True,
                "desc": ["membership_inference.output_generalization = true",
                         "(apply regularization; restrict exact-match responses on sensitive queries)"]},
    "REP-001": {"field": "output_controls.policy_layer",             "value": True,
                "desc": ["output_controls.policy_layer = true",
                         "(add independent rule-based or LLM-as-judge layer validating outputs before delivery)"]},
    "REP-002": {"field": "output_controls.logit_masking",            "value": True,
                "desc": ["output_controls.logit_masking = true",
                         "(apply logit masking to block harmful token categories)"]},
    "REP-003": {"field": "fine_tuning_api.access_control",           "value": True,
                "desc": ["fine_tuning_api.access_control = true",
                         "(restrict fine-tuning API; require approval workflow; audit all submitted data)"]},
    "REP-004": {"field": "fine_tuning_api.data_validation",          "value": True,
                "desc": ["fine_tuning_api.data_validation = true",
                         "(validate submissions: check for instruction overrides, role manipulation, policy bypass)"]},
    "REP-005": {"field": "fine_tuning_api.exposed",                  "value": False,
                "desc": ["fine_tuning_api.exposed = false",
                         "(remove fine-tuning endpoint from public API surface)"]},
}


def cmd_remediate(args) -> dict:
    audit_path = Path(args.audit)
    if not audit_path.exists():
        print(f"[error] Audit file not found: {args.audit}", file=sys.stderr)
        sys.exit(1)
    with open(audit_path) as f:
        audit = json.load(f)

    all_findings = (audit.get("extraction_findings", []) +
                    audit.get("reprogramming_findings", []))
    if not all_findings:
        print("[*] No findings in audit — nothing to remediate.")
        return {}

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[error] Config not found: {args.config}", file=sys.stderr)
        sys.exit(1)
    with open(config_path) as f:
        config = json.load(f)

    stem = config_path.stem
    suffix = config_path.suffix or ".json"
    output_path = args.output or str(config_path.parent / f"{stem}.patched{suffix}")

    approved = skipped = 0
    auto_approve = False

    for finding in all_findings:
        fid  = finding.get("id", "")
        fsev = finding.get("severity", "")
        fctl = finding.get("control", "")
        ftxt = finding.get("finding", "")

        patch = _MODEL_PATCHES.get(fid)
        if not patch:
            print(f"\n[{fid}] {fsev} — no auto-patch available")
            skipped += 1
            continue

        if auto_approve:
            print(f"\n[auto-approved] [{fid}] {fctl}")
            decision = "y"
        else:
            decision = _prompt(fid, fsev, fctl, ftxt, patch["desc"])

        if decision == "a":
            auto_approve = True
            decision = "y"
        if decision == "s":
            break
        if decision == "n":
            skipped += 1
            continue

        set_nested(config, patch["field"], patch["value"])
        approved += 1
        print("  [✓] Applied")

    with open(output_path, "w") as f:
        json.dump(config, f, indent=2)

    report = {
        "remediation_timestamp": datetime.now(timezone.utc).isoformat(),
        "source_file": str(config_path),
        "output_file": output_path,
        "findings_count": len(all_findings),
        "approved_and_applied": approved,
        "skipped": skipped,
    }
    print(f"\n{'═'*64}")
    print(json.dumps(report, indent=2))
    print(f"\n[*] Patched config written to {output_path}", file=sys.stderr)
    return report


def main():
    parser = argparse.ArgumentParser(description="AI Model Extraction and Reprogramming Defense Agent")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_audit = sub.add_parser("audit", help="Audit model API config for extraction/reprogramming controls")
    p_audit.add_argument("--config", required=True, help="Model API config JSON")
    p_audit.add_argument("--output", default="model_audit.json")

    p_rem = sub.add_parser("remediate", help="Interactively apply fixes from an audit report")
    p_rem.add_argument("--audit",  required=True, help="Audit JSON from the audit subcommand")
    p_rem.add_argument("--config", required=True, help="Original model API config JSON to patch")
    p_rem.add_argument("--output", default=None,  help="Output file (default: <config>.patched.json)")

    args = parser.parse_args()
    if args.subcommand == "audit":
        cmd_audit(args)
    elif args.subcommand == "remediate":
        cmd_remediate(args)


if __name__ == "__main__":
    main()
