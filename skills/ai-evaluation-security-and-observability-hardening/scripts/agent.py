#!/usr/bin/env python3
"""
AI Evaluation Security and Observability Hardening Agent

Subcommands:
  audit-eval      — Audit eval pipeline config for security integrity.
  audit-telemetry — Audit telemetry/logging config for observability security.

Usage:
    agent.py audit-eval      --config eval_config.json      [--output eval_audit.json]
    agent.py audit-telemetry --config telemetry_config.json [--output telemetry_audit.json]
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

EVAL_CONTROLS: list[dict] = [
    {
        "id": "EVAL-001", "field": "benchmark_integrity.datasets_signed",
        "check": lambda v: v is True, "severity": "HIGH",
        "control": "Eval dataset integrity signing",
        "finding": "datasets_signed is false — eval datasets can be tampered to hide failures",
        "remediation": "Sign eval datasets with checksums; verify signature before each evaluation run",
    },
    {
        "id": "EVAL-002", "field": "benchmark_integrity.results_tamper_evident",
        "check": lambda v: v is True, "severity": "HIGH",
        "control": "Tamper-evident eval results",
        "finding": "results_tamper_evident is false — evaluation results can be modified after the fact",
        "remediation": "Store eval results in append-only store with cryptographic chaining",
    },
    {
        "id": "EVAL-003", "field": "regression_testing.adversarial_regression",
        "check": lambda v: v is True, "severity": "HIGH",
        "control": "Adversarial regression testing",
        "finding": "adversarial_regression is false — model updates are not tested against adversarial scenarios",
        "remediation": "Add adversarial test suite (jailbreak, injection, evasion probes) to CI pipeline; block on regression",
    },
    {
        "id": "EVAL-004", "field": "regression_testing.post_update_required",
        "check": lambda v: v is True, "severity": "HIGH",
        "control": "Mandatory post-update evaluation",
        "finding": "post_update_required is false — model can be updated without running safety evaluation",
        "remediation": "Gate all model deployments on passing the full eval suite; fail deployment on missing results",
    },
    {
        "id": "EVAL-005", "field": "eval_infrastructure.isolated_from_production",
        "check": lambda v: v is True, "severity": "HIGH",
        "control": "Eval infrastructure isolation",
        "finding": "isolated_from_production is false — eval infrastructure shares resources with production",
        "remediation": "Run evaluations in isolated environment; prevent production model from influencing its own evaluation",
    },
    {
        "id": "EVAL-006", "field": "eval_infrastructure.access_controlled",
        "check": lambda v: v is True, "severity": "MEDIUM",
        "control": "Eval infrastructure access control",
        "finding": "access_controlled is false — eval infrastructure accessible without authentication",
        "remediation": "Restrict eval API and storage to authorized security/ML team accounts only",
    },
    {
        "id": "EVAL-007", "field": "eval_infrastructure.redundant",
        "check": lambda v: v is True, "severity": "MEDIUM",
        "control": "Eval infrastructure redundancy",
        "finding": "redundant is false — DoS on eval infrastructure would prevent safety evaluation",
        "remediation": "Deploy eval infrastructure with redundancy; ensure evaluations can run even under load",
    },
    {
        "id": "EVAL-008",
        "check_all": True, "collection": "eval_datasets",
        "item_field": "adversarial_coverage",
        "severity": "HIGH",
        "control": "Adversarial dataset coverage",
        "finding_template": "eval dataset '{name}' has adversarial_coverage=false — cannot detect model failures under attack",
        "remediation": "Add adversarial test cases (injection, evasion, backdoor trigger) to every eval dataset",
    },
    {
        "id": "EVAL-009",
        "check_all": True, "collection": "eval_datasets",
        "item_field": "independently_maintained",
        "severity": "HIGH",
        "control": "Independent eval dataset maintenance",
        "finding_template": "eval dataset '{name}' is not independently maintained — creator can game their own evaluation",
        "remediation": "Maintain eval datasets independently from model development team; use third-party or red team datasets",
    },
    {
        "id": "EVAL-010",
        "check_all": True, "collection": "eval_datasets",
        "item_field": "versioned",
        "severity": "MEDIUM",
        "control": "Eval dataset versioning",
        "finding_template": "eval dataset '{name}' is not versioned — changes may silently alter evaluation baselines",
        "remediation": "Version control all eval datasets; track changes with commit history and changelogs",
    },
]

TELEMETRY_CONTROLS: list[dict] = [
    {
        "id": "TEL-001", "field": "logging.tamper_evident",
        "check": lambda v: v is True, "severity": "CRITICAL",
        "control": "Tamper-evident logging",
        "finding": "tamper_evident is false — logs can be modified to hide malicious agent behavior",
        "remediation": "Use append-only log store (CloudWatch with no-delete policy, Loki + immutable storage); chain log entries",
    },
    {
        "id": "TEL-002", "field": "logging.append_only",
        "check": lambda v: v is True, "severity": "CRITICAL",
        "control": "Append-only log store",
        "finding": "append_only is false — log records can be deleted or modified",
        "remediation": "Configure log store with object lock or write-once policy; separate write and delete permissions",
    },
    {
        "id": "TEL-003", "field": "logging.pii_redaction",
        "check": lambda v: v is True, "severity": "HIGH",
        "control": "PII redaction in logs",
        "finding": "pii_redaction is false — agent logs may expose PII from user interactions or retrieved documents",
        "remediation": "Enable automatic PII detection and redaction before log storage; use structured logging with masked fields",
    },
    {
        "id": "TEL-004", "field": "logging.access_controlled",
        "check": lambda v: v is True, "severity": "HIGH",
        "control": "Log access control",
        "finding": "access_controlled is false — logs accessible without authentication",
        "remediation": "Restrict log access to authorized security and operations roles; audit log access",
    },
    {
        "id": "TEL-005", "field": "telemetry.integrity_check",
        "check": lambda v: v is True, "severity": "CRITICAL",
        "control": "Telemetry pipeline integrity",
        "finding": "integrity_check is false — telemetry data can be poisoned to mask incidents",
        "remediation": "Add integrity verification to telemetry pipeline; use HMAC or digital signatures on telemetry batches",
    },
    {
        "id": "TEL-006", "field": "telemetry.authenticated_collectors",
        "check": lambda v: v is True, "severity": "HIGH",
        "control": "Authenticated telemetry collectors",
        "finding": "authenticated_collectors is false — any process can inject data into the telemetry pipeline",
        "remediation": "Authenticate all telemetry collectors with mTLS or signed tokens; reject unauthenticated submissions",
    },
    {
        "id": "TEL-007", "field": "anomaly_detection.behavioral_baselines",
        "check": lambda v: v is True, "severity": "HIGH",
        "control": "Behavioral baseline monitoring",
        "finding": "behavioral_baselines is false — cannot detect gradual goal drift or abnormal agent behavior patterns",
        "remediation": "Establish baselines for tool call distributions, query patterns, and response characteristics; alert on deviations",
    },
    {
        "id": "TEL-008", "field": "anomaly_detection.tool_call_distribution_monitoring",
        "check": lambda v: v is True, "severity": "HIGH",
        "control": "Tool call distribution monitoring",
        "finding": "tool_call_distribution_monitoring is false — unusual tool invocation patterns go undetected",
        "remediation": "Monitor frequency, sequence, and argument patterns of tool calls; alert on statistical deviations",
    },
    {
        "id": "TEL-009", "field": "anomaly_detection.long_term_trend_analysis",
        "check": lambda v: v is True, "severity": "HIGH",
        "control": "Long-term trend analysis",
        "finding": "long_term_trend_analysis is false — low-and-slow attacks that evade short-window detection go undetected",
        "remediation": "Analyze behavioral trends over 7/30/90 day windows; detect slow drift that short-window rules miss",
    },
    {
        "id": "TEL-010", "field": "anomaly_detection.ml_based_detection",
        "check": lambda v: v is True, "severity": "MEDIUM",
        "control": "ML-based anomaly detection",
        "finding": "ml_based_detection is false — only rule-based detection in place; evasion of known rules is trivial",
        "remediation": "Supplement rule-based detection with ML anomaly detection trained on normal agent behavior baselines",
    },
    {
        "id": "TEL-011", "field": "observability_tools.isolated_from_agents",
        "check": lambda v: v is True, "severity": "HIGH",
        "control": "Observability tool isolation from agents",
        "finding": "isolated_from_agents is false — agents can potentially influence or access their own monitoring systems",
        "remediation": "Run observability infrastructure in separate network segment with no inbound access from agent workloads",
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
        if ctrl.get("check_all"):
            for item in config.get(ctrl["collection"], []):
                val = item.get(ctrl["item_field"])
                if val is not True:
                    findings.append({
                        "id": ctrl["id"],
                        "severity": ctrl["severity"],
                        "control": ctrl["control"],
                        "finding": ctrl["finding_template"].format(name=item.get("name", "unknown")),
                        "remediation": ctrl["remediation"],
                    })
        else:
            val = get_nested(config, ctrl["field"])
            if val is None or not ctrl["check"](val):
                findings.append({
                    "id": ctrl["id"],
                    "severity": ctrl["severity"],
                    "control": ctrl["control"],
                    "finding": ctrl["finding"],
                    "remediation": ctrl["remediation"],
                    "current_value": val,
                })
    return findings


def build_report(config: dict, findings: list[dict], report_type: str, output_path: str) -> dict:
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        if sev in by_sev:
            by_sev[sev] += 1
    overall = (
        "CRITICAL" if by_sev["CRITICAL"] > 0 else
        "HIGH" if by_sev["HIGH"] > 0 else
        "MEDIUM" if by_sev["MEDIUM"] > 0 else "LOW"
    )
    report = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "report_type": report_type,
        "pipeline_name": config.get("pipeline_name", config.get("name", "Unknown")),
        "total_checks": len(EVAL_CONTROLS if report_type == "eval" else TELEMETRY_CONTROLS),
        "findings_count": len(findings),
        "by_severity": by_sev,
        "overall_risk": overall,
        "findings": findings,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report, indent=2))
    print(f"\n[*] Audit saved to {output_path}", file=sys.stderr)
    if overall in ("CRITICAL", "HIGH"):
        sys.exit(1)
    return report


def cmd_audit_eval(args) -> dict:
    path = Path(args.config)
    if not path.exists():
        print(f"[error] Config not found: {args.config}", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        config = json.load(f)
    findings = run_controls(config, EVAL_CONTROLS)
    return build_report(config, findings, "eval", args.output)


def cmd_audit_telemetry(args) -> dict:
    path = Path(args.config)
    if not path.exists():
        print(f"[error] Config not found: {args.config}", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        config = json.load(f)
    findings = run_controls(config, TELEMETRY_CONTROLS)
    return build_report(config, findings, "telemetry", args.output)


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


_EVAL_PATCHES: dict[str, dict] = {
    "EVAL-001": {"field": "benchmark_integrity.datasets_signed",          "value": True,
                 "desc": ["benchmark_integrity.datasets_signed = true",
                          "(sign eval datasets with checksums; verify before each run)"]},
    "EVAL-002": {"field": "benchmark_integrity.results_tamper_evident",   "value": True,
                 "desc": ["benchmark_integrity.results_tamper_evident = true",
                          "(store results in append-only store with cryptographic chaining)"]},
    "EVAL-003": {"field": "regression_testing.adversarial_regression",    "value": True,
                 "desc": ["regression_testing.adversarial_regression = true",
                          "(add adversarial test suite to CI; block on regression)"]},
    "EVAL-004": {"field": "regression_testing.post_update_required",      "value": True,
                 "desc": ["regression_testing.post_update_required = true",
                          "(gate all model deployments on passing the full eval suite)"]},
    "EVAL-005": {"field": "eval_infrastructure.isolated_from_production", "value": True,
                 "desc": ["eval_infrastructure.isolated_from_production = true",
                          "(run evaluations in isolated environment separate from production)"]},
    "EVAL-006": {"field": "eval_infrastructure.access_controlled",        "value": True,
                 "desc": ["eval_infrastructure.access_controlled = true",
                          "(restrict eval API and storage to authorized security/ML team accounts)"]},
    "EVAL-007": {"field": "eval_infrastructure.redundant",                "value": True,
                 "desc": ["eval_infrastructure.redundant = true",
                          "(deploy eval infrastructure with redundancy to prevent DoS blocking safety evals)"]},
}

_EVAL_MANUAL: dict[str, str] = {
    "EVAL-008": (
        "Add adversarial test cases (injection, evasion, backdoor trigger) to each eval dataset.\n"
        "  Update adversarial_coverage=true per dataset after adding adversarial examples."
    ),
    "EVAL-009": (
        "Transfer eval dataset maintenance to a team independent from model development.\n"
        "  Update independently_maintained=true per dataset after ownership transfer."
    ),
    "EVAL-010": (
        "Version control all eval datasets with commit history and changelogs.\n"
        "  Update versioned=true per dataset after setting up version control."
    ),
}

_TEL_PATCHES: dict[str, dict] = {
    "TEL-001": {"field": "logging.tamper_evident",                           "value": True,
                "desc": ["logging.tamper_evident = true",
                         "(use append-only log store; chain log entries cryptographically)"]},
    "TEL-002": {"field": "logging.append_only",                              "value": True,
                "desc": ["logging.append_only = true",
                         "(configure log store with object lock or write-once policy)"]},
    "TEL-003": {"field": "logging.pii_redaction",                            "value": True,
                "desc": ["logging.pii_redaction = true",
                         "(enable automatic PII detection and redaction before log storage)"]},
    "TEL-004": {"field": "logging.access_controlled",                        "value": True,
                "desc": ["logging.access_controlled = true",
                         "(restrict log access to authorized security and operations roles)"]},
    "TEL-005": {"field": "telemetry.integrity_check",                        "value": True,
                "desc": ["telemetry.integrity_check = true",
                         "(add HMAC or digital signatures on telemetry batches)"]},
    "TEL-006": {"field": "telemetry.authenticated_collectors",               "value": True,
                "desc": ["telemetry.authenticated_collectors = true",
                         "(authenticate collectors with mTLS or signed tokens; reject unauthenticated submissions)"]},
    "TEL-007": {"field": "anomaly_detection.behavioral_baselines",           "value": True,
                "desc": ["anomaly_detection.behavioral_baselines = true",
                         "(establish baselines for tool call distributions, query patterns, response characteristics)"]},
    "TEL-008": {"field": "anomaly_detection.tool_call_distribution_monitoring","value": True,
                "desc": ["anomaly_detection.tool_call_distribution_monitoring = true",
                         "(monitor frequency, sequence, and argument patterns of tool calls)"]},
    "TEL-009": {"field": "anomaly_detection.long_term_trend_analysis",       "value": True,
                "desc": ["anomaly_detection.long_term_trend_analysis = true",
                         "(analyze behavioral trends over 7/30/90 day windows)"]},
    "TEL-010": {"field": "anomaly_detection.ml_based_detection",             "value": True,
                "desc": ["anomaly_detection.ml_based_detection = true",
                         "(supplement rule-based detection with ML anomaly detection)"]},
    "TEL-011": {"field": "observability_tools.isolated_from_agents",         "value": True,
                "desc": ["observability_tools.isolated_from_agents = true",
                         "(run observability infra in separate network segment; no inbound from agent workloads)"]},
}


def cmd_remediate(args) -> dict:
    audit_path = Path(args.audit)
    if not audit_path.exists():
        print(f"[error] Audit file not found: {args.audit}", file=sys.stderr)
        sys.exit(1)
    with open(audit_path) as f:
        audit = json.load(f)

    findings = audit.get("findings", [])
    if not findings:
        print("[*] No findings in audit — nothing to remediate.")
        return {}

    report_type = audit.get("report_type", "")
    patches = _EVAL_PATCHES if report_type == "eval" else _TEL_PATCHES
    manual  = _EVAL_MANUAL  if report_type == "eval" else {}

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[error] Config not found: {args.config}", file=sys.stderr)
        sys.exit(1)
    with open(config_path) as f:
        config = json.load(f)

    stem = config_path.stem
    suffix = config_path.suffix or ".json"
    output_path = args.output or str(config_path.parent / f"{stem}.patched{suffix}")

    approved = skipped = manual_count = 0
    manual_items: list[dict] = []
    auto_approve = False

    for finding in findings:
        fid  = finding.get("id", "")
        fsev = finding.get("severity", "")
        fctl = finding.get("control", "")
        ftxt = finding.get("finding", "")

        manual_note = manual.get(fid)
        if manual_note:
            print(f"\n{'─'*64}")
            print(f"[{fid}] {fsev} — {fctl}")
            print(f"Finding  : {ftxt}")
            print(f"\n[MANUAL REQUIRED]\n  {manual_note}")
            manual_count += 1
            manual_items.append({"id": fid, "severity": fsev, "finding": ftxt, "manual_steps": manual_note})
            continue

        patch = patches.get(fid)
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
        "report_type": report_type,
        "source_file": str(config_path),
        "output_file": output_path,
        "findings_count": len(findings),
        "approved_and_applied": approved,
        "skipped": skipped,
        "manual_required": manual_count,
        "manual_items": manual_items,
    }
    print(f"\n{'═'*64}")
    print(json.dumps(report, indent=2))
    print(f"\n[*] Patched config written to {output_path}", file=sys.stderr)
    print(f"[*] {manual_count} finding(s) require manual steps — see manual_items above", file=sys.stderr)
    return report


def main():
    parser = argparse.ArgumentParser(description="AI Evaluation Security and Observability Hardening Agent")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_eval = sub.add_parser("audit-eval", help="Audit eval pipeline config")
    p_eval.add_argument("--config", required=True)
    p_eval.add_argument("--output", default="eval_audit.json")

    p_tel = sub.add_parser("audit-telemetry", help="Audit telemetry/logging config")
    p_tel.add_argument("--config", required=True)
    p_tel.add_argument("--output", default="telemetry_audit.json")

    p_rem = sub.add_parser("remediate", help="Interactively apply fixes from an audit-eval or audit-telemetry report")
    p_rem.add_argument("--audit",  required=True, help="Audit JSON from audit-eval or audit-telemetry")
    p_rem.add_argument("--config", required=True, help="Original config JSON to patch")
    p_rem.add_argument("--output", default=None,  help="Output file (default: <config>.patched.json)")

    args = parser.parse_args()
    if args.subcommand == "audit-eval":
        cmd_audit_eval(args)
    elif args.subcommand == "audit-telemetry":
        cmd_audit_telemetry(args)
    elif args.subcommand == "remediate":
        cmd_remediate(args)


if __name__ == "__main__":
    main()
