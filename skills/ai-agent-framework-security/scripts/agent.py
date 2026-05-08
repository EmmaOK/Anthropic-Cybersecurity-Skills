#!/usr/bin/env python3
"""
AI Agent Framework Security Auditor
MAESTRO Layer 3 (Agent Frameworks) — checks 15 security controls.
"""
import argparse
import copy
import json
import sys
from datetime import datetime, timezone


CONTROLS = [
    # Dependency supply chain
    {
        "id": "FWK-001", "category": "Supply Chain",
        "threat": "Compromised Framework Components",
        "control": "Dependency version pinning",
        "field_path": ["dependencies", "pinned"],
        "severity": "HIGH",
        "finding_false": "Framework dependencies are not pinned to exact versions — a compromised newer version will be installed silently on next pip install",
        "remediation": "Pin all framework dependencies to exact versions (pip freeze > requirements.txt); use pip-compile for reproducible builds",
    },
    {
        "id": "FWK-002", "category": "Supply Chain",
        "threat": "Compromised Framework Components",
        "control": "Dependency integrity verification (hash checking)",
        "field_path": ["dependencies", "integrity_verified"],
        "severity": "HIGH",
        "finding_false": "Dependency hashes are not verified — a MITM or compromised PyPI mirror can deliver tampered packages",
        "remediation": "Add --require-hashes to pip install; generate hashes with pip-compile --generate-hashes",
    },
    {
        "id": "FWK-003", "category": "Supply Chain",
        "threat": "Compromised Framework Components",
        "control": "Dependency vulnerability scanning",
        "field_path": ["dependencies", "vulnerability_scanning"],
        "severity": "HIGH",
        "finding_false": "No vulnerability scanner configured for framework dependencies — known CVEs in framework libraries go undetected",
        "remediation": "Run pip-audit or Safety in CI; block deployments with CRITICAL/HIGH CVEs in framework dependencies",
    },
    {
        "id": "FWK-004", "category": "Supply Chain",
        "threat": "Compromised Framework Components / Supply Chain",
        "control": "Software Bill of Materials (SBOM) generation",
        "field_path": ["dependencies", "sbom_generated"],
        "severity": "MEDIUM",
        "finding_false": "No SBOM generated for framework dependency tree — full component inventory unavailable for incident response",
        "remediation": "Generate SBOM with cyclonedx-bom or syft on each build; publish SBOM alongside release artifacts",
    },
    # Tool configuration
    {
        "id": "FWK-005", "category": "Tool Security",
        "threat": "Input Validation Attacks / Framework Evasion",
        "control": "Tool allowlisting",
        "field_path": ["tool_configuration", "allowlist_enabled"],
        "severity": "CRITICAL",
        "finding_false": "No tool allowlist configured — the LLM can invoke any tool name it generates, including attacker-injected tool names",
        "remediation": "Define an explicit tool allowlist; reject any tool_name not in the approved set at the framework layer before dispatch",
    },
    {
        "id": "FWK-006", "category": "Tool Security",
        "threat": "Input Validation Attacks",
        "control": "Tool input schema validation",
        "field_path": ["tool_configuration", "schema_validation"],
        "severity": "HIGH",
        "finding_false": "Tool inputs are not schema-validated — LLM-generated arguments can contain injection payloads (shell metacharacters, SQL fragments, path traversal)",
        "remediation": "Validate all tool inputs against a strict JSON schema before execution; reject inputs with unexpected fields or type mismatches",
    },
    {
        "id": "FWK-007", "category": "Tool Security",
        "threat": "Compromised Framework Components",
        "control": "Unsafe tool patterns blocked (eval, exec, shell=True)",
        "field_path": ["tool_configuration", "unsafe_tools_blocked"],
        "severity": "CRITICAL",
        "finding_false": "Unsafe tool execution patterns (eval, exec, subprocess with shell=True) are not blocked — attacker-controlled input can achieve arbitrary code execution",
        "remediation": "Audit all tool implementations for unsafe patterns; replace shell=True with argument lists; use ast.literal_eval instead of eval",
    },
    {
        "id": "FWK-008", "category": "Tool Security",
        "threat": "Framework Evasion",
        "control": "Code execution tool sandboxing",
        "field_path": ["tool_configuration", "code_execution_sandboxed"],
        "severity": "CRITICAL",
        "finding_false": "Code execution tools (Python REPL, shell tools) run without a sandbox — agent-executed code has full host filesystem and network access",
        "remediation": "Wrap code execution tools in a container sandbox (E2B, Firecracker, gVisor) with no network egress and read-only host filesystem",
    },
    {
        "id": "FWK-009", "category": "Tool Security",
        "threat": "Framework Evasion (prompt injection cascade)",
        "control": "Tool output sanitization",
        "field_path": ["tool_configuration", "tool_output_sanitized"],
        "severity": "HIGH",
        "finding_false": "Tool outputs are passed unsanitized to subsequent tool inputs — enables prompt injection cascade across chained tool calls",
        "remediation": "Treat all tool outputs as untrusted data; sanitize before passing to subsequent tool inputs; do not allow tool outputs to set new tool names",
    },
    # Security settings
    {
        "id": "FWK-010", "category": "Security Settings",
        "threat": "Information Disclosure",
        "control": "Verbose logging disabled in production",
        "field_path": ["security_settings", "verbose_logging_disabled_in_prod"],
        "severity": "MEDIUM",
        "finding_false": "Verbose/debug logging is enabled in production — full prompts, tool inputs/outputs, and intermediate reasoning are written to logs, creating sensitive data exposure",
        "remediation": "Disable verbose mode in production; set framework log level to WARNING or ERROR; apply PII redaction to any agent logs that are retained",
    },
    {
        "id": "FWK-011", "category": "Security Settings",
        "threat": "Framework Evasion",
        "control": "Output filtering enabled",
        "field_path": ["security_settings", "output_filtering_enabled"],
        "severity": "HIGH",
        "finding_false": "No output filter configured — framework allows agents to produce harmful, policy-violating, or injection-containing outputs without interception",
        "remediation": "Configure framework-level output filter (content policy layer, refusal detection, injection pattern scan) that inspects agent final responses before delivery",
    },
    {
        "id": "FWK-012", "category": "Security Settings",
        "threat": "Framework Evasion / Input Validation Attacks",
        "control": "Prompt injection filter at framework layer",
        "field_path": ["security_settings", "prompt_injection_filter"],
        "severity": "HIGH",
        "finding_false": "No prompt injection filter at the framework layer — injections in tool outputs or retrieved content can redirect agent behavior",
        "remediation": "Integrate a prompt injection classifier (e.g., Rebuff, DeBERTa-based detector) at the framework input pipeline; flag and quarantine suspicious inputs",
    },
    # API controls
    {
        "id": "FWK-013", "category": "API Controls",
        "threat": "DoS on Framework APIs",
        "control": "Framework API rate limiting",
        "field_path": ["api_controls", "rate_limiting"],
        "severity": "HIGH",
        "finding_false": "No rate limiting on framework API — an agent loop or external caller can exhaust downstream LLM or tool quotas without bound",
        "remediation": "Implement per-user and per-agent rate limits on framework invocations; add circuit breaker for downstream tool APIs",
    },
    {
        "id": "FWK-014", "category": "API Controls",
        "threat": "Compromised Framework Components / Framework Evasion",
        "control": "Agent action audit logging",
        "field_path": ["api_controls", "audit_logging"],
        "severity": "HIGH",
        "finding_false": "Agent actions (tool calls, LLM invocations, outputs) are not audit-logged — framework evasion and compromised component behaviour cannot be investigated post-incident",
        "remediation": "Enable append-only audit logging for all agent tool calls including input arguments and outputs; retain for at least 90 days",
    },
    # Update policy
    {
        "id": "FWK-015", "category": "Update Policy",
        "threat": "Compromised Framework Components (Backdoor Attacks)",
        "control": "Plugin vetting process",
        "field_path": ["update_policy", "plugin_vetting_process"],
        "severity": "HIGH",
        "finding_false": "No vetting process for framework plugins or extensions — malicious plugins can be loaded without review, introducing backdoors or data exfiltration code",
        "remediation": "Require security review and code audit for any new framework plugin before use in production; maintain an approved plugin registry",
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
            actual_val = value
            finding_text = ctrl["finding_false"]
            if value is None:
                finding_text = f"Field {'.'.join(ctrl['field_path'])} missing from config — {ctrl['finding_false']}"
            findings.append({
                "id": ctrl["id"],
                "severity": ctrl["severity"],
                "layer": "L3",
                "category": ctrl["category"],
                "threat": ctrl["threat"],
                "control": ctrl["control"],
                "finding": finding_text,
                "remediation": ctrl["remediation"],
                "value_found": actual_val,
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
    parser = argparse.ArgumentParser(description="AI Agent Framework Security Auditor (MAESTRO L3)")
    sub = parser.add_subparsers(dest="command")

    audit_p = sub.add_parser("audit", help="Audit framework config against 15 Layer 3 security controls")
    audit_p.add_argument("--config", required=True, help="Path to framework config JSON")
    audit_p.add_argument("--output", default="framework_audit.json", help="Output file path")

    fix_p = sub.add_parser("fix", help="Generate corrected config from audit output")
    fix_p.add_argument("--audit", required=True, help="Path to audit output JSON")
    fix_p.add_argument("--config", required=True, help="Path to original config JSON")
    fix_p.add_argument("--output-dir", default="remediation-output", help="Output directory")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "fix":
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
        summary_path = os.path.join(args.output_dir, "fix_summary.json")
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        print(json.dumps(summary, indent=2))
        sys.exit(0)

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
        "framework_name": config.get("framework_name", "unknown"),
        "framework_version": config.get("version", "unknown"),
        "methodology": "MAESTRO Layer 3 (Agent Frameworks) — ai-agent-framework-security v1.0",
        "total_checks": len(CONTROLS),
        "findings_count": len(findings),
        "by_severity": by_sev,
        "overall_risk": overall_risk,
        "findings": findings,
        "recommendation": (
            f"{by_sev['CRITICAL']} CRITICAL and {by_sev['HIGH']} HIGH findings require remediation. "
            "Address tool allowlisting and code execution sandboxing first — these close the highest-impact "
            "MAESTRO L3 attack paths (framework evasion and input validation attacks)."
        ) if findings else "No findings. Framework configuration satisfies all 15 MAESTRO Layer 3 controls.",
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)


if __name__ == "__main__":
    main()
