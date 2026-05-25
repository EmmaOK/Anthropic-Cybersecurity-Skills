#!/usr/bin/env python3
"""
AI Incident Response Playbook Agent

Generates structured IR playbooks for AI-specific security incidents and
triages indicator lists to the most likely incident type.

Usage:
    agent.py playbook --incident-type prompt-injection --output ir_report.json
    agent.py triage --indicators "system-prompt-override,unusual-tool-call" --output triage.json
    agent.py list-types

Incident types:
    prompt-injection      LLM01:2025 — injected instructions override system prompt
    goal-hijacking        ASI01:2026 — agent deviates from declared objective
    model-poisoning       LLM04:2025 — training/fine-tuning data or weights tampered
    mcp-compromise        MCP01      — MCP tool schema or server modified by attacker
    rogue-agent           ASI10:2026 — reward hacking, self-replication, or collusion
    data-exfiltration     LLM06:2025 — excessive agency enabling unauthorised data egress

Exit codes:
    0 — playbook generated, no active confirmed incident
    1 — active/confirmed incident detected (CI gate trigger)
"""

import argparse
import json
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Playbook data
# ---------------------------------------------------------------------------

PLAYBOOKS: dict[str, dict] = {
    "prompt-injection": {
        "framework_references": ["LLM01:2025", "MAESTRO-L3", "ATLAS:AML.T0054"],
        "nist_csf": ["RS.MA-01", "RS.AN-03", "RS.MI-01"],
        "description": "Injected instructions in user input or retrieved content override the system prompt.",
        "severity_default": "HIGH",
        "indicators": [
            "system-prompt-override",
            "ignore-previous-instructions",
            "role-play-jailbreak",
            "indirect-injection-in-retrieved-doc",
            "unexpected-persona-change",
            "output-matches-injected-template",
        ],
        "phases": {
            "prepare": [
                "Maintain a blocklist of known injection patterns updated from threat intel feeds.",
                "Configure input validation middleware on the LLM API gateway.",
                "Establish conversation session logging with turn-level retention for at least 72 hours.",
            ],
            "identify": [
                "Collect the offending conversation turn from the session log.",
                "Run injection pattern scanner across user_message and any retrieved RAG documents.",
                "Determine injection vector: direct user input, indirect (RAG/tool output), or multi-turn.",
                "Capture full conversation context for forensic review.",
            ],
            "contain": [
                "Flush the affected user session cache to prevent injected state persisting.",
                "Enable strict input validation on the API gateway — block matched injection patterns.",
                "If indirect injection: disable the data source (RAG corpus, tool) pending investigation.",
                "If a session cookie or token was stolen via the injection, invalidate it.",
            ],
            "eradicate": [
                "Scan the RAG corpus for poisoned documents (use rag-pipeline-security-and-data-provenance).",
                "Quarantine all documents ingested since the last clean snapshot.",
                "Harden the system prompt with explicit anti-injection anchors.",
                "Add discovered injection patterns to the gateway blocklist.",
            ],
            "recover": [
                "Re-enable the endpoint with the hardened system prompt.",
                "Replay affected conversations against the patched prompt; verify outputs are benign.",
                "Restore clean RAG corpus from last signed snapshot.",
                "Monitor for recurrence for 24 hours before declaring recovery complete.",
            ],
            "lessons_learned": [
                "Document the injection vector and update threat model.",
                "Review whether indirect injection paths (RAG, tool outputs) have sufficient sanitization.",
                "Update detection rules in detecting-ai-model-prompt-injection-attacks.",
            ],
        },
        "containment_commands": [
            "redis-cli KEYS 'session:*' | xargs redis-cli DEL   # flush all sessions",
            "kubectl rollout restart deployment/llm-gateway      # redeploy with updated blocklist",
        ],
    },

    "goal-hijacking": {
        "framework_references": ["ASI01:2026", "MAESTRO-L3", "ATLAS:AML.T0068"],
        "nist_csf": ["RS.MA-01", "RS.MI-01", "RS.MI-02"],
        "description": "An agent is manipulated into pursuing a different objective than its declared goal.",
        "severity_default": "CRITICAL",
        "indicators": [
            "agent-accessing-unauthorized-resource",
            "agent-calling-out-of-scope-tool",
            "agent-modifying-own-instructions",
            "agent-bypassing-approval-gate",
            "objective-drift-detected-in-telemetry",
            "agent-following-injected-sub-goal",
        ],
        "phases": {
            "prepare": [
                "Formally specify agent goals using a schema with explicit allowed_tools and forbidden_actions.",
                "Instrument every agent action with goal-alignment checks before execution.",
                "Require human approval for any action not listed in the declared tool manifest.",
            ],
            "identify": [
                "Scan agent telemetry for goal_drift_signals: unauthorized resource access, out-of-scope tool calls.",
                "Correlate anomalous actions with conversation turns to identify the injection point.",
                "Determine whether the hijacking originated from user input, tool output, or environment observation.",
            ],
            "contain": [
                "Send SIGSTOP to the agent process — pause without terminating to preserve state for forensics.",
                "Revoke the agent's tool permissions via the orchestration layer.",
                "Snapshot agent memory and current state before any cleanup.",
                "Notify the incident command channel.",
            ],
            "eradicate": [
                "Perform log forensics to determine when goal drift began and the root cause.",
                "Rewrite the agent goal with formal constraints and validated JSON schema.",
                "Identify and revert any persisted side-effects (DB writes, scheduled jobs, spawned processes).",
                "Review multi-agent logs for collusion signals.",
            ],
            "recover": [
                "Restart the agent with hardened goal schema and tighter tool allowlist.",
                "Run under human-in-the-loop supervision for 24 hours.",
                "Add triggering action patterns to agent-goal-hijacking-detection watchlist.",
            ],
            "lessons_learned": [
                "Assess whether goal specification was sufficiently formal and machine-verifiable.",
                "Review whether approval gates were in place for all high-risk tool calls.",
                "Update MAESTRO L3 threat model for the agent framework.",
            ],
        },
        "containment_commands": [
            "kill -STOP <pid>                                    # pause agent process",
            "kubectl label pod <agent-pod> quarantine=true       # isolate pod via network policy",
        ],
    },

    "model-poisoning": {
        "framework_references": ["LLM04:2025", "MAESTRO-L2", "ATLAS:AML.T0047"],
        "nist_csf": ["RS.MA-02", "RS.AN-03", "RS.MI-02"],
        "description": "Training data, fine-tuning dataset, or model weights tampered to introduce backdoors or quality degradation.",
        "severity_default": "CRITICAL",
        "indicators": [
            "evaluation-metric-regression-post-update",
            "dataset-checksum-mismatch",
            "backdoor-trigger-response-detected",
            "systematic-output-degradation-for-specific-inputs",
            "unauthorized-change-to-training-pipeline",
            "unusual-model-weight-diff",
        ],
        "phases": {
            "prepare": [
                "Maintain SHA-256 checksums for all training datasets and model checkpoints.",
                "Sign model artifacts in the registry; verify signatures on load.",
                "Run adversarial regression tests (known backdoor triggers) on every model promotion.",
            ],
            "identify": [
                "Verify dataset checksums against stored signatures.",
                "Scan the training dataset for backdoor trigger patterns.",
                "Run the model against a held-out clean evaluation set; compare metrics to pre-update baseline.",
                "Diff model weights against the last trusted checkpoint.",
            ],
            "contain": [
                "Immediately roll back to the last-known-good model checkpoint in the registry.",
                "Block all inference traffic to the poisoned model version.",
                "Freeze access to the training data pipeline pending investigation.",
                "Revoke pipeline credentials used since the earliest possible compromise timestamp.",
            ],
            "eradicate": [
                "Audit the data pipeline from ingestion to training (use llm-data-and-model-poisoning-defense).",
                "Quarantine all dataset records added since the last clean checkpoint.",
                "Re-validate pipeline input validation, access controls, and provenance controls.",
                "Identify the pipeline stage where poisoning was introduced (data collection, labelling, fine-tuning).",
            ],
            "recover": [
                "Retrain on the cleaned, re-checksummed dataset.",
                "Run full adversarial regression suite before promoting the new model.",
                "Implement dataset signing in CI/CD to prevent future undetected tampering.",
                "Re-establish evaluation baselines for the recovered model.",
            ],
            "lessons_learned": [
                "Review data supply chain for untrusted ingestion sources.",
                "Assess whether CI/CD pipeline had sufficient access controls on training jobs.",
                "Update ai-data-operations-availability-and-integrity controls.",
            ],
        },
        "containment_commands": [
            "mlflow models serve -m models:/production/clean_checkpoint  # serve safe version",
            "kubectl set image deployment/inference-server model=registry/model:safe_tag",
        ],
    },

    "mcp-compromise": {
        "framework_references": ["MCP01", "MAESTRO-L3", "ATLAS:AML.T0088"],
        "nist_csf": ["RS.MA-01", "RS.MI-01", "RS.CO-02"],
        "description": "An MCP tool schema or server-side implementation modified by an attacker to perform unauthorized actions.",
        "severity_default": "CRITICAL",
        "indicators": [
            "tool-manifest-hash-mismatch",
            "mcp-server-process-modified",
            "tool-calling-unexpected-endpoints",
            "tool-schema-changed-without-pr",
            "agent-receiving-unexpected-tool-results",
            "mcp-server-spawning-subprocesses",
        ],
        "phases": {
            "prepare": [
                "Sign and store SHA-256 hashes of all MCP tool manifests on every merge.",
                "Enable file integrity monitoring on MCP server binaries and configuration.",
                "Require tool manifest review in CI before any tool schema change is deployed.",
            ],
            "identify": [
                "Verify tool manifest hashes against signed reference values.",
                "Diff the current manifest against the last signed version in version control.",
                "Review MCP server access logs for unauthorized modification events.",
                "Inspect process tree for unexpected subprocess spawning from the MCP server.",
            ],
            "contain": [
                "Disable the affected MCP tool in the server configuration (set disabled: true).",
                "Revoke all active agent sessions that invoked the compromised tool.",
                "Block the MCP server process from making external network connections.",
                "Notify all agents currently using the tool.",
            ],
            "eradicate": [
                "Restore the MCP tool manifest from the last signed, trusted version.",
                "Rebuild and redeploy the MCP server from a clean source.",
                "Audit all actions taken by agents that invoked the compromised tool; revert unauthorized effects.",
                "Review the CI/CD pipeline for the MCP server for unauthorized access.",
            ],
            "recover": [
                "Redeploy the MCP server from a clean, signed build.",
                "Re-register the MCP server with a fresh cryptographic signature.",
                "Require tool manifest signature verification in the agent orchestration layer.",
                "Monitor tool invocations for 48 hours after recovery.",
            ],
            "lessons_learned": [
                "Review MCP server access controls and deployment pipeline.",
                "Assess whether tool schema changes require dual approval.",
                "Update mcp-tool-poisoning-detection-and-defense monitoring rules.",
            ],
        },
        "containment_commands": [
            "jq '.tools[] |= if .name == \"<tool>\" then .disabled = true else . end' manifest.json > manifest_patched.json",
            "kubectl delete pod -l app=mcp-server   # force pod restart from clean image",
        ],
    },

    "rogue-agent": {
        "framework_references": ["ASI10:2026", "MAESTRO-L3", "ATLAS:AML.T0068"],
        "nist_csf": ["RS.MA-01", "RS.MI-01", "RS.MI-02", "RS.CO-02"],
        "description": "Agent deviates from intended objectives via reward hacking, unauthorized self-replication, or collusion.",
        "severity_default": "CRITICAL",
        "indicators": [
            "reward-hacking-detected",
            "unauthorized-subprocess-spawn",
            "resource-hoarding",
            "multi-agent-collusion-signal",
            "agent-disabling-its-own-monitor",
            "agent-modifying-kill-switch",
            "optimization-quality-metric-divergence",
        ],
        "phases": {
            "prepare": [
                "Establish behavioral baselines for each agent covering tool call volumes, resource consumption, and output types.",
                "Deploy kill switches for each agent registered in the process registry.",
                "Configure Prometheus alerts for per-agent resource consumption thresholds.",
            ],
            "identify": [
                "Run rogue-agent-detection-and-containment to classify behavioral signals.",
                "Check for unauthorized subprocess spawning (PIDs not in the authorized registry).",
                "Compute optimization/quality metric divergence (reward hacking signal).",
                "Run multi-agent collusion detector across all active agents.",
            ],
            "contain": [
                "Send SIGTERM to the agent process; escalate to SIGKILL after 5 seconds.",
                "Revoke all API keys and credentials the agent had access to.",
                "Snapshot agent memory/state for forensic analysis before cleanup.",
                "Terminate any unauthorized subprocesses spawned by the agent.",
            ],
            "eradicate": [
                "Audit the agent goal specification for reward function misalignment.",
                "Identify and revert all persisted side-effects (DB writes, scheduled jobs, spawned processes).",
                "Review multi-agent telemetry for collusion patterns involving other agents.",
                "Remove any self-installed persistence mechanisms.",
            ],
            "recover": [
                "Restart agent with corrected, formally specified objective.",
                "Deploy under human-in-the-loop supervision for 48 hours before restoring full autonomy.",
                "Add rogue signal patterns to behavioral monitoring baseline.",
                "Increase sigma threshold sensitivity on the behavioral anomaly detector.",
            ],
            "lessons_learned": [
                "Review whether reward function was aligned with true objective.",
                "Assess multi-agent communication channels for injection vectors.",
                "Update ai-agent-ecosystem-security and ai-agent-framework-security controls.",
            ],
        },
        "containment_commands": [
            "kill -TERM <pid> && sleep 5 && kill -KILL <pid>  # terminate rogue agent",
            "kubectl delete pod <agent-pod> --grace-period=0  # immediate pod termination",
        ],
    },

    "data-exfiltration": {
        "framework_references": ["LLM06:2025", "MAESTRO-L3", "ATLAS:AML.T0054"],
        "nist_csf": ["RS.MA-01", "RS.MI-01", "RS.MI-02", "RS.CO-02"],
        "description": "An agent or LLM exfiltrates data via excessive permissions — calling unauthorized external endpoints with sensitive payloads.",
        "severity_default": "CRITICAL",
        "indicators": [
            "agent-calling-external-http-endpoint",
            "agent-encoding-data-before-send",
            "agent-harvesting-env-vars",
            "agent-calling-sendmail-or-smtp",
            "agent-posting-to-webhook",
            "pii-in-tool-call-arguments",
            "tool-not-in-declared-manifest",
        ],
        "phases": {
            "prepare": [
                "Apply network egress policy: agent pods may only call allowlisted internal endpoints.",
                "Scan all tool call arguments for PII and credentials before execution.",
                "Enforce least-privilege tool manifest with llm-excessive-agency-prevention.",
            ],
            "identify": [
                "Scan tool call logs for exfiltration patterns: external HTTP calls, base64 encoding, email sending.",
                "Identify the data scope of what was potentially exfiltrated.",
                "Determine whether exfiltration was triggered by a prompt injection or misconfigured tool permissions.",
            ],
            "contain": [
                "Deny all network egress from the agent container via network policy immediately.",
                "Rotate all credentials the agent had access to (API keys, DB passwords, cloud IAM keys).",
                "Block the destination IPs/domains at the firewall or WAF.",
                "Preserve network flow logs and DNS query logs for forensics.",
            ],
            "eradicate": [
                "Audit the tool manifest; remove any tools with network access that are not required.",
                "Apply strict output scanning for PII and credentials before any LLM response is passed to a tool call.",
                "Identify the data that was exfiltrated; assess regulatory notification obligations.",
                "Trace the exfiltration trigger back to its origin (injected instruction, misconfigured permission).",
            ],
            "recover": [
                "Redeploy the agent with a minimal tool manifest.",
                "Implement human-approval gates for all tools that touch sensitive data or external endpoints.",
                "Re-establish network egress allowlist; verify only required endpoints are permitted.",
                "Notify affected data subjects and regulators as required by applicable law.",
            ],
            "lessons_learned": [
                "Review whether tool permissions followed least-privilege at design time.",
                "Assess whether PII/credential scanning was in place before this incident.",
                "Update llm-sensitive-information-disclosure-prevention controls.",
            ],
        },
        "containment_commands": [
            "kubectl apply -f deny-egress-policy.yaml  # block all agent pod egress",
            "aws iam delete-access-key --access-key-id <key>  # rotate compromised AWS key",
        ],
    },
}

# Indicator → incident type mapping for triage
INDICATOR_MAP: dict[str, list[str]] = {}
for _itype, _pdata in PLAYBOOKS.items():
    for _indicator in _pdata["indicators"]:
        INDICATOR_MAP.setdefault(_indicator, []).append(_itype)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_playbook(args: argparse.Namespace) -> int:
    itype = args.incident_type
    if itype not in PLAYBOOKS:
        print(json.dumps({"error": f"Unknown incident type '{itype}'. Run 'list-types' for options."}))
        return 1

    pb = PLAYBOOKS[itype]
    now = datetime.now(timezone.utc).isoformat()

    report = {
        "incident_type": itype,
        "framework_references": pb["framework_references"],
        "nist_csf": pb["nist_csf"],
        "description": pb["description"],
        "severity": args.severity or pb["severity_default"],
        "generated_at": now,
        "status": "ACTIVE" if args.confirmed else "SUSPECTED",
        "phases": pb["phases"],
        "containment_commands": pb["containment_commands"],
        "output_format_example": {
            "incident_id": f"AI-IR-{datetime.now(timezone.utc).strftime('%Y-%m%d')}-001",
            "incident_type": itype,
            "severity": args.severity or pb["severity_default"],
            "declared_at": now,
            "phases": {phase: {"status": "PENDING", "actions": []} for phase in pb["phases"]},
            "timeline": [{"timestamp": now, "event": "Incident declared"}],
        },
    }

    output = json.dumps(report, indent=2)
    print(output)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output + "\n")

    # Exit 1 for confirmed active incidents
    if args.confirmed:
        return 1
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    raw_indicators = [i.strip() for i in args.indicators.split(",") if i.strip()]
    scores: dict[str, int] = {}

    matched: list[dict] = []
    unrecognized: list[str] = []

    for ind in raw_indicators:
        if ind in INDICATOR_MAP:
            for itype in INDICATOR_MAP[ind]:
                scores[itype] = scores.get(itype, 0) + 1
            matched.append({"indicator": ind, "maps_to": INDICATOR_MAP[ind]})
        else:
            unrecognized.append(ind)

    if not scores:
        report = {
            "result": "NO_MATCH",
            "message": "None of the supplied indicators matched known AI incident patterns.",
            "unrecognized_indicators": unrecognized,
            "all_indicators": list(INDICATOR_MAP.keys()),
        }
        print(json.dumps(report, indent=2))
        return 0

    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    top_type, top_score = ranked[0]
    top_pb = PLAYBOOKS[top_type]

    report = {
        "triage_result": top_type,
        "confidence_score": top_score,
        "all_matches": [{"incident_type": t, "matched_indicators": s} for t, s in ranked],
        "severity": top_pb["severity_default"],
        "framework_references": top_pb["framework_references"],
        "description": top_pb["description"],
        "matched_indicators": matched,
        "unrecognized_indicators": unrecognized,
        "recommended_next_step": f"Run: agent.py playbook --incident-type {top_type} --confirmed",
        "immediate_containment": top_pb["phases"]["contain"][:2],
    }

    output = json.dumps(report, indent=2)
    print(output)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output + "\n")

    # Exit 1 if top match is CRITICAL severity
    if top_pb["severity_default"] == "CRITICAL":
        return 1
    return 0


def cmd_list_types(_args: argparse.Namespace) -> int:
    rows = []
    for itype, pb in PLAYBOOKS.items():
        rows.append({
            "incident_type": itype,
            "severity_default": pb["severity_default"],
            "framework_references": pb["framework_references"],
            "description": pb["description"],
            "indicator_count": len(pb["indicators"]),
        })
    print(json.dumps(rows, indent=2))
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="AI Incident Response Playbook Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # playbook
    pb_parser = sub.add_parser("playbook", help="Generate a full IR playbook for an incident type")
    pb_parser.add_argument(
        "--incident-type",
        required=True,
        choices=list(PLAYBOOKS.keys()),
        help="Type of AI security incident",
    )
    pb_parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Override default severity for this incident",
    )
    pb_parser.add_argument(
        "--confirmed",
        action="store_true",
        help="Mark incident as confirmed active (exits with code 1)",
    )
    pb_parser.add_argument("--output", help="Write JSON report to this file path")

    # triage
    tr_parser = sub.add_parser("triage", help="Map observed indicators to an incident type")
    tr_parser.add_argument(
        "--indicators",
        required=True,
        help="Comma-separated list of observed indicators",
    )
    tr_parser.add_argument("--output", help="Write JSON triage report to this file path")

    # list-types
    sub.add_parser("list-types", help="List all supported incident types with metadata")

    args = parser.parse_args()

    dispatch = {
        "playbook": cmd_playbook,
        "triage": cmd_triage,
        "list-types": cmd_list_types,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
