#!/usr/bin/env python3
"""
AI/ML System Threat Modeling Agent

Three subcommands:
  init    — Scaffold a blank AI system component inventory.
  analyze — Apply AI threat taxonomy (OWASP LLM/Agentic Top 10 + MITRE ATLAS)
            to each component and generate a threat list.
  report  — Summarize threats into a prioritized AI threat model report.

Usage:
    agent.py init    --system "Support Agent" --arch-type agentic --output ai_components.json
    agent.py analyze --components ai_components.json --output ai_threats.json
    agent.py report  --threats ai_threats.json [--output ai_tm_report.json]

Supported arch types: llm_app, rag, agentic, training_pipeline, multi_agent

Component inventory format (JSON array):
    [
      {"id": "llm-1",   "type": "llm_endpoint",    "name": "Claude API",          "user_reachable": true},
      {"id": "rag-1",   "type": "rag_store",        "name": "Pinecone Vector DB",  "public_ingest": false},
      {"id": "tool-1",  "type": "tool",             "name": "email_send",          "irreversible": true},
      {"id": "mem-1",   "type": "agent_memory",     "name": "Long-term memory",    "persists": true},
      {"id": "mcp-1",   "type": "mcp_server",       "name": "Filesystem MCP",      "privileged": true},
      {"id": "orch-1",  "type": "orchestrator",     "name": "LangChain agent"},
      {"id": "train-1", "type": "training_pipeline","name": "Fine-tune pipeline",  "external_data": true},
      {"id": "model-1", "type": "model_artifact",   "name": "Fine-tuned weights"},
      {"id": "sys-1",   "type": "system_prompt",    "name": "Operator instructions"},
      {"id": "user-1",  "type": "user_input",       "name": "Chat UI / API"},
    ]
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

AI_COMPONENT_TYPES = (
    "llm_endpoint", "rag_store", "tool", "agent_memory", "mcp_server",
    "orchestrator", "training_pipeline", "model_artifact", "system_prompt",
    "user_input",
)

ARCH_TYPE_COMPONENTS = {
    "llm_app": [
        {"id": "sys-1",  "type": "system_prompt",    "name": "System prompt / persona"},
        {"id": "user-1", "type": "user_input",        "name": "User chat input",       "user_reachable": True},
        {"id": "llm-1",  "type": "llm_endpoint",      "name": "LLM API endpoint",      "user_reachable": True},
    ],
    "rag": [
        {"id": "sys-1",  "type": "system_prompt",    "name": "System prompt"},
        {"id": "user-1", "type": "user_input",        "name": "User query",            "user_reachable": True},
        {"id": "llm-1",  "type": "llm_endpoint",      "name": "LLM API endpoint",      "user_reachable": True},
        {"id": "rag-1",  "type": "rag_store",         "name": "Vector database",       "public_ingest": False},
    ],
    "agentic": [
        {"id": "sys-1",  "type": "system_prompt",    "name": "Operator system prompt"},
        {"id": "user-1", "type": "user_input",        "name": "User task input",       "user_reachable": True},
        {"id": "llm-1",  "type": "llm_endpoint",      "name": "LLM API endpoint",      "user_reachable": True},
        {"id": "orch-1", "type": "orchestrator",      "name": "Agent orchestrator"},
        {"id": "tool-1", "type": "tool",              "name": "Tool / function calls",  "irreversible": False},
        {"id": "mem-1",  "type": "agent_memory",      "name": "Agent memory store",    "persists": True},
        {"id": "rag-1",  "type": "rag_store",         "name": "RAG / knowledge base",  "public_ingest": False},
    ],
    "training_pipeline": [
        {"id": "train-1","type": "training_pipeline", "name": "Training data pipeline","external_data": True},
        {"id": "model-1","type": "model_artifact",    "name": "Model weights / adapters"},
        {"id": "llm-1",  "type": "llm_endpoint",      "name": "Inference endpoint",    "user_reachable": True},
    ],
    "multi_agent": [
        {"id": "sys-1",  "type": "system_prompt",    "name": "Orchestrator system prompt"},
        {"id": "orch-1", "type": "orchestrator",      "name": "Orchestrator agent"},
        {"id": "llm-1",  "type": "llm_endpoint",      "name": "LLM endpoint (orchestrator)", "user_reachable": True},
        {"id": "llm-2",  "type": "llm_endpoint",      "name": "LLM endpoint (sub-agent)"},
        {"id": "tool-1", "type": "tool",              "name": "Tool / function calls",  "irreversible": False},
        {"id": "mem-1",  "type": "agent_memory",      "name": "Shared agent memory"},
    ],
}

# AI threat templates per component type
AI_THREATS: dict[str, list[dict]] = {
    "llm_endpoint": [
        {"id": "LLM01-D", "taxonomy": ["OWASP LLM01", "AML.T0051"],
         "description": "Direct prompt injection — user crafts input that overrides system prompt instructions",
         "question": "Is there input validation or a privileged/unprivileged context separation preventing user instructions from overriding operator instructions?",
         "severity": "HIGH"},
        {"id": "LLM01-I", "taxonomy": ["OWASP LLM01", "AML.T0051"],
         "description": "Indirect prompt injection — external content retrieved into context contains adversarial instructions",
         "question": "Is external content (web pages, emails, documents, tool results) sanitized before being injected into the model context?",
         "severity": "CRITICAL"},
        {"id": "LLM02",   "taxonomy": ["OWASP LLM02", "AML.T0057"],
         "description": "Sensitive information disclosure — model leaks system prompt, training data PII, or credentials",
         "question": "Are canary tokens embedded in the system prompt? Is output scanned for credential/PII patterns before delivery?",
         "severity": "HIGH"},
        {"id": "LLM06",   "taxonomy": ["OWASP LLM06", "AML.T0068"],
         "description": "Excessive agency — model takes irreversible actions without confirmation gate",
         "question": "Are all irreversible or high-risk tool calls gated by human approval or a confirmation step?",
         "severity": "HIGH"},
        {"id": "LLM10",   "taxonomy": ["OWASP LLM10", "AML.T0088"],
         "description": "Unbounded resource consumption — adversarial prompts cause runaway token or API cost",
         "question": "Are per-user token budgets, rate limits, and prompt complexity checks enforced?",
         "severity": "MEDIUM"},
    ],
    "system_prompt": [
        {"id": "LLM02-SP","taxonomy": ["OWASP LLM02", "AML.T0057"],
         "description": "System prompt extracted by user via prompt injection or direct elicitation",
         "question": "Does the system prompt instruct the model not to reveal its contents? Are extraction probes regularly tested?",
         "severity": "MEDIUM"},
        {"id": "LLM01-SP","taxonomy": ["OWASP LLM01", "AML.T0051"],
         "description": "System prompt instructions can be overridden by sufficiently crafted user input",
         "question": "Has the system prompt been tested against known jailbreak and override techniques?",
         "severity": "HIGH"},
    ],
    "user_input": [
        {"id": "LLM01-UI","taxonomy": ["OWASP LLM01", "AML.T0051"],
         "description": "User input channel accepts arbitrary text including injection payloads",
         "question": "Is there an input validation or classification layer to detect injection attempts before they reach the model?",
         "severity": "MEDIUM"},
        {"id": "LLM10-UI","taxonomy": ["OWASP LLM10", "AML.T0088"],
         "description": "No rate limiting on user input — DoS via resource exhaustion",
         "question": "Are rate limits, request size limits, and per-user quotas enforced on the input channel?",
         "severity": "MEDIUM"},
    ],
    "rag_store": [
        {"id": "LLM08-P", "taxonomy": ["OWASP LLM08", "AML.T0056"],
         "description": "RAG poisoning — attacker inserts adversarial document that scores highly across diverse queries",
         "question": "Is document ingestion access-controlled? Are anomalously high-scoring retrievals monitored?",
         "severity": "CRITICAL"},
        {"id": "LLM08-E", "taxonomy": ["OWASP LLM08", "AML.T0043"],
         "description": "Embedding extraction — attacker reconstructs training/document content via repeated semantic queries",
         "question": "Are semantic similarity queries rate-limited? Is differential privacy applied to embeddings?",
         "severity": "MEDIUM"},
        {"id": "LLM08-T", "taxonomy": ["OWASP LLM08", "ASI06"],
         "description": "Tenant isolation failure — one user's queries retrieve another tenant's documents",
         "question": "Are vector store namespaces strictly partitioned by tenant? Is namespace isolation tested?",
         "severity": "HIGH"},
    ],
    "tool": [
        {"id": "LLM06-T", "taxonomy": ["OWASP LLM06", "AML.T0068"],
         "description": "Irreversible tool action (delete, send, pay) executed without human confirmation",
         "question": "Are destructive or irreversible tool calls gated by a human-in-the-loop approval step?",
         "severity": "CRITICAL"},
        {"id": "ASI02",   "taxonomy": ["OWASP ASI02", "AML.T0051"],
         "description": "Tool misuse — agent uses a legitimate tool for unintended purpose (e.g. email_send to exfiltrate data)",
         "question": "Are tool outputs monitored for data loss patterns? Are tool call scopes constrained by schema?",
         "severity": "HIGH"},
        {"id": "MCP05",   "taxonomy": ["OWASP MCP05", "AML.T0051"],
         "description": "Command injection — user input passed unsanitized into a shell-executing tool",
         "question": "Are all tool inputs sanitized and parameterized? Is shell execution sandboxed?",
         "severity": "CRITICAL"},
    ],
    "mcp_server": [
        {"id": "MCP03",   "taxonomy": ["OWASP MCP03", "AML.T0054"],
         "description": "Tool poisoning — MCP tool description contains hidden instructions to the model",
         "question": "Are MCP tool definitions stored in an immutable, version-controlled allowlist? Are descriptions reviewed?",
         "severity": "CRITICAL"},
        {"id": "MCP01",   "taxonomy": ["OWASP MCP01"],
         "description": "Token/secret exposure — MCP server logs or transmits credentials to the model context",
         "question": "Are secrets injected via environment variables only? Is the MCP server's log output scanned for credentials?",
         "severity": "HIGH"},
        {"id": "MCP07",   "taxonomy": ["OWASP MCP07"],
         "description": "Insufficient authentication — MCP server accessible without authentication",
         "question": "Does the MCP server require mutual TLS or token-based auth for all connections?",
         "severity": "HIGH"},
    ],
    "agent_memory": [
        {"id": "ASI06",   "taxonomy": ["OWASP ASI06", "AML.T0056"],
         "description": "Memory poisoning — attacker injects false information into the agent's long-term memory",
         "question": "Are memory writes integrity-checked? Is human review required for safety-critical memory updates?",
         "severity": "HIGH"},
        {"id": "LLM02-M", "taxonomy": ["OWASP LLM02", "AML.T0057"],
         "description": "Memory leakage — sensitive data from one user's session persists into another's context",
         "question": "Is memory partitioned strictly per user/session? Is memory retention time-limited and rotated?",
         "severity": "HIGH"},
    ],
    "orchestrator": [
        {"id": "ASI08",   "taxonomy": ["OWASP ASI08", "AML.T0088"],
         "description": "Cascading failures — orchestrator propagates a compromised sub-agent's output without validation",
         "question": "Is output validated at each agent boundary? Are circuit breakers in place for sub-agent failures?",
         "severity": "HIGH"},
        {"id": "ASI10",   "taxonomy": ["OWASP ASI10", "AML.T0068"],
         "description": "Rogue orchestrator — orchestrator deviates from intended goal via reward hacking or self-replication",
         "question": "Are behavioral baselines established? Are resource quotas and kill switches implemented?",
         "severity": "HIGH"},
        {"id": "ASI07",   "taxonomy": ["OWASP ASI07", "AML.T0088"],
         "description": "Insecure inter-agent communication — messages between agents are unauthenticated or unencrypted",
         "question": "Is mTLS or message signing used for all inter-agent communication?",
         "severity": "HIGH"},
    ],
    "training_pipeline": [
        {"id": "LLM04-B", "taxonomy": ["OWASP LLM04", "AML.T0054"],
         "description": "Backdoor injection — poisoned training samples introduce trigger-activated behavior",
         "question": "Is training data scanned for backdoor trigger patterns? Is data provenance tracked end-to-end?",
         "severity": "CRITICAL"},
        {"id": "LLM04-P", "taxonomy": ["OWASP LLM04", "AML.T0056"],
         "description": "Bias injection — poisoned RLHF preference pairs shift model values adversarially",
         "question": "Are preference datasets access-controlled and audited? Is the labeling pipeline verified?",
         "severity": "HIGH"},
        {"id": "ASI04",   "taxonomy": ["OWASP ASI04", "AML.T0082"],
         "description": "Supply chain compromise — malicious ML framework, adapter, or dataset introduced via dependency",
         "question": "Are ML dependencies pinned to verified hashes? Is an SBOM maintained for the training pipeline?",
         "severity": "HIGH"},
    ],
    "model_artifact": [
        {"id": "LLM04-A", "taxonomy": ["OWASP LLM04", "AML.T0054"],
         "description": "Model artifact tampering — weights modified post-training to introduce backdoor",
         "question": "Are model artifacts cryptographically signed and verified before deployment?",
         "severity": "CRITICAL"},
        {"id": "AML-E",   "taxonomy": ["AML.T0043"],
         "description": "Model extraction — attacker queries the model to reconstruct weights or training data",
         "question": "Are output perturbation or watermarking techniques applied? Are query rates monitored?",
         "severity": "MEDIUM"},
    ],
}

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def cmd_init(args) -> None:
    arch = args.arch_type
    if arch not in ARCH_TYPE_COMPONENTS:
        print(f"[error] Unknown arch-type '{arch}'. Choose from: {', '.join(ARCH_TYPE_COMPONENTS)}", file=sys.stderr)
        sys.exit(1)

    template = ARCH_TYPE_COMPONENTS[arch]
    inventory = {
        "system": args.system,
        "arch_type": arch,
        "components": template,
    }

    with open(args.output, "w") as f:
        json.dump(inventory, f, indent=2)

    print(f"[*] AI component inventory scaffolded for: {args.system} ({arch})")
    print(f"[*] {len(template)} components written to {args.output}")
    print(f"[*] Edit to match your actual architecture, then run: agent.py analyze --components {args.output}")


def cmd_analyze(args) -> None:
    path = Path(args.components)
    if not path.exists():
        print(f"[error] Components file not found: {args.components}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        inv = json.load(f)

    components = inv.get("components", inv) if isinstance(inv, dict) else inv
    system = inv.get("system", "Unknown") if isinstance(inv, dict) else "Unknown"

    threats = []
    tid = 1

    for comp in components:
        ctype = comp.get("type", "")
        if ctype not in AI_COMPONENT_TYPES:
            continue

        for tmpl in AI_THREATS.get(ctype, []):
            # Boost severity for irreversible tools or publicly reachable components
            sev = tmpl["severity"]
            if comp.get("irreversible") and sev == "HIGH":
                sev = "CRITICAL"
            if comp.get("privileged") and sev == "MEDIUM":
                sev = "HIGH"

            threats.append({
                "id": f"AI-T-{tid:03d}",
                "component_id": comp.get("id"),
                "component_name": comp.get("name"),
                "component_type": ctype,
                "threat_ref": tmpl["id"],
                "taxonomy": tmpl["taxonomy"],
                "description": tmpl["description"],
                "question": tmpl["question"],
                "severity": sev,
                "status": "OPEN",
                "mitigation": "",
                "owner": "",
                "notes": "",
            })
            tid += 1

    with open(args.output, "w") as f:
        json.dump({"system": system, "threats": threats}, f, indent=2)

    print(f"[*] Generated {len(threats)} AI threats across {len(components)} components")
    print(f"[*] Written to {args.output}")
    print(f"[*] Review, add mitigations and owners, then run: agent.py report --threats {args.output}")


def cmd_report(args) -> dict:
    path = Path(args.threats)
    if not path.exists():
        print(f"[error] Threats file not found: {args.threats}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        data = json.load(f)

    threats: list[dict] = data.get("threats", data) if isinstance(data, dict) else data
    system = data.get("system", "Unknown") if isinstance(data, dict) else "Unknown"

    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_taxonomy: dict[str, int] = {}
    open_threats = []

    for t in threats:
        sev = t.get("severity", "LOW")
        if sev in by_severity:
            by_severity[sev] += 1
        for tax in t.get("taxonomy", []):
            by_taxonomy[tax] = by_taxonomy.get(tax, 0) + 1
        if t.get("status", "OPEN") != "MITIGATED":
            open_threats.append(t)

    open_threats.sort(key=lambda x: SEV_ORDER.get(x.get("severity", "LOW"), 0), reverse=True)

    overall_risk = (
        "CRITICAL" if by_severity["CRITICAL"] > 0
        else "HIGH" if by_severity["HIGH"] > 0
        else "MEDIUM" if by_severity["MEDIUM"] > 0
        else "LOW"
    )

    report = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "system": system,
        "threats_analyzed": len(threats),
        "open": len(open_threats),
        "by_severity": by_severity,
        "by_taxonomy": dict(sorted(by_taxonomy.items(), key=lambda x: x[1], reverse=True)),
        "overall_risk": overall_risk,
        "top_threats": open_threats[:10],
        "recommendation": (
            f"{by_severity['CRITICAL']} CRITICAL and {by_severity['HIGH']} HIGH AI-specific threats identified. "
            "Prioritise confirmation gates on irreversible tool calls, indirect prompt injection defences, and RAG store access controls."
            if overall_risk in ("CRITICAL", "HIGH")
            else "No critical or high AI threats open. Continue monitoring and re-assess on architecture changes."
        ),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\n[*] AI threat model report saved to {args.output}")

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)

    return report


def main():
    parser = argparse.ArgumentParser(description="AI/ML System Threat Modeling Agent")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_init = sub.add_parser("init", help="Scaffold AI component inventory")
    p_init.add_argument("--system", required=True)
    p_init.add_argument("--arch-type", default="agentic",
                        choices=list(ARCH_TYPE_COMPONENTS.keys()))
    p_init.add_argument("--output", default="ai_components.json")

    p_analyze = sub.add_parser("analyze", help="Apply AI threat taxonomy to components")
    p_analyze.add_argument("--components", required=True)
    p_analyze.add_argument("--output", default="ai_threats.json")

    p_report = sub.add_parser("report", help="Generate AI threat model report")
    p_report.add_argument("--threats", required=True)
    p_report.add_argument("--output", default="ai_tm_report.json")

    args = parser.parse_args()
    if args.subcommand == "init":
        cmd_init(args)
    elif args.subcommand == "analyze":
        cmd_analyze(args)
    elif args.subcommand == "report":
        cmd_report(args)


if __name__ == "__main__":
    main()
