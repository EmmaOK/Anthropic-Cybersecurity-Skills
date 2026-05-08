#!/usr/bin/env python3
"""
AI Agent Ecosystem Security Auditor
MAESTRO Layer 7 (Agent Ecosystem) — checks 18 security controls.
"""
import argparse
import copy
import json
import sys
from datetime import datetime, timezone


CONTROLS = [
    # Registry integrity
    {
        "id": "ECO-001", "category": "Registry Integrity",
        "threat": "Compromised Agent Registry",
        "control": "Registry entry integrity signing",
        "field_path": ["registry", "integrity_signing"],
        "severity": "CRITICAL",
        "finding_false": "Registry entries are not cryptographically signed — any modification to agent listings (endpoint URLs, capability descriptions, publisher identity) is undetectable",
        "remediation": "Sign all registry entries with publisher private keys (Sigstore/cosign); verify signatures at agent discovery and invocation time",
    },
    {
        "id": "ECO-002", "category": "Registry Integrity",
        "threat": "Inaccurate Agent Capability Description",
        "control": "Capability attestation",
        "field_path": ["registry", "capability_attestation"],
        "severity": "HIGH",
        "finding_false": "No capability attestation process — agents can claim arbitrary capabilities without verification, leading to unsafe delegation of tasks beyond actual scope",
        "remediation": "Require independently verified capability attestations before listing; include capability evidence (test results, audit reports) in registry entry",
    },
    {
        "id": "ECO-003", "category": "Registry Integrity",
        "threat": "Compromised Agent Registry",
        "control": "Agent vetting and review process",
        "field_path": ["registry", "vetting_process"],
        "severity": "HIGH",
        "finding_false": "No vetting process for agent listings — malicious agents can be published to the registry without security review",
        "remediation": "Enforce a mandatory security review for all new agent listings; require code audit, capability testing, and publisher identity verification",
    },
    {
        "id": "ECO-004", "category": "Registry Integrity",
        "threat": "Compromised Agent Registry",
        "control": "Agent revocation mechanism",
        "field_path": ["registry", "revocation_mechanism"],
        "severity": "HIGH",
        "finding_false": "No revocation mechanism — a compromised or malicious agent listing cannot be disabled without taking down the entire registry",
        "remediation": "Implement agent certificate revocation lists (CRL) or OCSP-equivalent for real-time revocation; propagate revocations within 5 minutes to all discovery nodes",
    },
    {
        "id": "ECO-005", "category": "Registry Integrity",
        "threat": "Compromised Agent Registry",
        "control": "Registry listing change audit trail",
        "field_path": ["registry", "listing_change_audited"],
        "severity": "HIGH",
        "finding_false": "Registry listing changes are not audited — unauthorized modifications to agent endpoints or capabilities cannot be detected or attributed",
        "remediation": "Log all registry mutations to an append-only, tamper-evident audit trail; alert on changes to agent endpoints, capabilities, or publisher identity",
    },
    # Agent identity
    {
        "id": "ECO-006", "category": "Agent Identity",
        "threat": "Agent Identity Attack / Agent Impersonation",
        "control": "Cryptographic agent identities",
        "field_path": ["agent_identity", "cryptographic_ids"],
        "severity": "CRITICAL",
        "finding_false": "Agents have no cryptographic identity — any agent can claim to be any other, enabling impersonation and identity attacks across the ecosystem",
        "remediation": "Issue each agent a unique cryptographic certificate or DID (Decentralized Identifier); require mutual TLS or signed JWTs for all inter-agent communication",
    },
    {
        "id": "ECO-007", "category": "Agent Identity",
        "threat": "Agent Identity Attack / Agent Impersonation",
        "control": "Mutual authentication between agents",
        "field_path": ["agent_identity", "mutual_authentication"],
        "severity": "HIGH",
        "finding_false": "Agents do not mutually authenticate — a malicious agent can pose as a legitimate peer without detection",
        "remediation": "Enforce mTLS or signed-token mutual authentication for all agent-to-agent calls; reject calls from agents whose identity cannot be verified",
    },
    {
        "id": "ECO-008", "category": "Agent Identity",
        "threat": "Repudiation",
        "control": "Per-action agent identity attribution",
        "field_path": ["agent_identity", "per_action_attribution"],
        "severity": "CRITICAL",
        "finding_false": "Agent actions are not attributed to a specific agent identity at the action level — agents can repudiate performed actions (send messages, delete records, make API calls) with no cryptographic evidence binding the action to the agent",
        "remediation": "Attach signed agent identity tokens to every action record; store in tamper-evident audit log; make attribution available to auditors and affected users",
    },
    {
        "id": "ECO-009", "category": "Agent Identity",
        "threat": "Agent Identity Attack",
        "control": "Session isolation between agent interactions",
        "field_path": ["agent_identity", "session_isolation"],
        "severity": "MEDIUM",
        "finding_false": "Agent sessions are not isolated — credentials or context from one session may leak into another, enabling session hijacking across agent interactions",
        "remediation": "Enforce per-invocation session tokens; clear agent context between sessions; do not share credential scopes across agent instances",
    },
    # Audit and non-repudiation
    {
        "id": "ECO-010", "category": "Audit",
        "threat": "Repudiation",
        "control": "Non-repudiable audit logs",
        "field_path": ["audit", "non_repudiable_logs"],
        "severity": "CRITICAL",
        "finding_false": "Audit logs are not non-repudiable — log entries can be deleted or modified, destroying evidence of agent actions",
        "remediation": "Use append-only, cryptographically chained log storage (AWS CloudTrail, Azure Monitor Logs with immutable storage, Loki with object storage backend)",
    },
    {
        "id": "ECO-011", "category": "Audit",
        "threat": "Repudiation",
        "control": "Append-only log storage",
        "field_path": ["audit", "append_only_storage"],
        "severity": "HIGH",
        "finding_false": "Audit log storage is not append-only — logs can be overwritten or truncated by a compromised agent or administrator",
        "remediation": "Configure log storage with immutability (S3 Object Lock, Azure Immutable Blob, Splunk with locked index); test immutability quarterly",
    },
    {
        "id": "ECO-012", "category": "Audit",
        "threat": "Repudiation",
        "control": "Action-to-agent-identity binding in audit logs",
        "field_path": ["audit", "action_to_identity_binding"],
        "severity": "CRITICAL",
        "finding_false": "Audit log entries do not include the agent's cryptographic identity — actions cannot be reliably attributed to a specific agent for forensic or legal purposes",
        "remediation": "Include signed agent identity token in every audit log entry; log: agent_id, action_type, target, timestamp, input_hash, output_hash, signature",
    },
    # Integration security
    {
        "id": "ECO-013", "category": "Integrations",
        "threat": "Integration Risks",
        "control": "OAuth/API scope minimization",
        "field_path": ["integrations", "scope_minimization"],
        "severity": "HIGH",
        "finding_false": "Integration tokens are not scope-minimized — agent integration credentials grant broader access than required for the agent's task",
        "remediation": "Audit all OAuth scopes and API key permissions; reduce to minimum required; use fine-grained scopes (read-only where write is not needed)",
    },
    {
        "id": "ECO-014", "category": "Integrations",
        "threat": "Integration Risks",
        "control": "Webhook signature verification",
        "field_path": ["integrations", "webhook_authentication"],
        "severity": "HIGH",
        "finding_false": "Incoming webhooks are not signature-verified — an attacker can forge webhook events to trigger arbitrary agent actions",
        "remediation": "Enforce HMAC-SHA256 signature verification on all incoming webhooks; reject any payload without a valid signature header",
    },
    {
        "id": "ECO-015", "category": "Integrations",
        "threat": "Integration Risks",
        "control": "Integration input validation",
        "field_path": ["integrations", "input_validation"],
        "severity": "HIGH",
        "finding_false": "Integration API inputs are not validated — malformed or adversarial inputs from external systems can trigger unexpected agent behavior",
        "remediation": "Validate all integration inputs against strict schemas at the API gateway layer; sanitize before passing to agent context",
    },
    # Discovery and marketplace
    {
        "id": "ECO-016", "category": "Discovery",
        "threat": "Malicious Agent Discovery / Marketplace Manipulation",
        "control": "Malicious agent detection in discovery",
        "field_path": ["discovery", "malicious_agent_filtering"],
        "severity": "HIGH",
        "finding_false": "Discovery/search has no malicious agent filtering — searches for legitimate agent types may surface malicious look-alikes at the top of results",
        "remediation": "Apply behavioral analysis and anomaly detection to agent listings; flag newly published agents with suspiciously similar names to established agents",
    },
    {
        "id": "ECO-017", "category": "Discovery",
        "threat": "Marketplace Manipulation",
        "control": "Reputation scoring with Sybil resistance",
        "field_path": ["discovery", "reputation_scoring"],
        "severity": "HIGH",
        "finding_false": "No reputation scoring system — marketplace ratings can be gamed by fake accounts promoting malicious agents or suppressing legitimate ones",
        "remediation": "Implement reputation scoring with Sybil resistance (identity verification for reviewers, stake-based voting, coordinated-rating anomaly detection)",
    },
    # Pricing integrity
    {
        "id": "ECO-018", "category": "Pricing Integrity",
        "threat": "Agent Pricing Model Manipulation",
        "control": "Per-call rate limits and spend anomaly detection",
        "field_path": ["pricing", "anomaly_detection_on_spend"],
        "severity": "MEDIUM",
        "finding_false": "No spend anomaly detection — pricing manipulation attacks (crafting expensive calls, exploiting billing edge cases) are not detected until after financial damage",
        "remediation": "Implement per-agent and per-user spend monitoring; alert and throttle when spend exceeds baseline by 3× within any 1-hour window",
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
                finding_text = f"Field {'.'.join(ctrl['field_path'])} missing from config — {ctrl['finding_false']}"
            findings.append({
                "id": ctrl["id"],
                "severity": ctrl["severity"],
                "layer": "L7",
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
    parser = argparse.ArgumentParser(description="AI Agent Ecosystem Security Auditor (MAESTRO L7)")
    sub = parser.add_subparsers(dest="command")

    audit_p = sub.add_parser("audit", help="Audit ecosystem config against 18 Layer 7 security controls")
    audit_p.add_argument("--config", required=True, help="Path to ecosystem config JSON")
    audit_p.add_argument("--output", default="ecosystem_audit.json", help="Output file path")

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
        "ecosystem_name": config.get("ecosystem_name", "unknown"),
        "methodology": "MAESTRO Layer 7 (Agent Ecosystem) — ai-agent-ecosystem-security v1.0",
        "total_checks": len(CONTROLS),
        "findings_count": len(findings),
        "by_severity": by_sev,
        "overall_risk": overall_risk,
        "findings": findings,
        "recommendation": (
            f"{by_sev['CRITICAL']} CRITICAL and {by_sev['HIGH']} HIGH findings require remediation. "
            "Prioritize non-repudiable logs and cryptographic agent identity — these are the foundational "
            "controls that all other MAESTRO L7 accountability mechanisms depend on."
        ) if findings else "No findings. Ecosystem configuration satisfies all 18 MAESTRO Layer 7 controls.",
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)


if __name__ == "__main__":
    main()
