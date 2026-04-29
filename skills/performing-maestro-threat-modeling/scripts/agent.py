#!/usr/bin/env python3
"""
MAESTRO Threat Modeling Agent

Three subcommands:
  init    — Scaffold a MAESTRO assessment worksheet for a system.
  analyze — Apply 7-layer threat taxonomy to generate a threat list.
  report  — Generate a prioritized MAESTRO threat report.

Usage:
    agent.py init    --system "Payment AI Agent"
                     --arch-type single|multi|hierarchical|distributed|
                                 conversational|task_oriented|human_in_loop|self_learning
                     [--output maestro_assessment.json]
    agent.py analyze --assessment maestro_assessment.json [--output maestro_threats.json]
    agent.py report  --threats maestro_threats.json [--output maestro_report.json]
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

LAYER_DESCRIPTIONS = {
    1: "Foundation Models — Core AI brain (LLMs, base models) providing reasoning and generation",
    2: "Data Operations — Ingestion, storage, RAG pipelines, vector databases, embeddings",
    3: "Agent Frameworks — Orchestration software (LangChain, AutoGen) wiring models to tools",
    4: "Deployment & Infrastructure — Cloud/on-premise runtime: containers, Kubernetes, CI/CD",
    5: "Evaluation & Observability — Telemetry, logging, eval harnesses, safety monitors",
    6: "Security & Compliance — Cross-cutting governance, policy enforcement, auditability",
    7: "Agent Ecosystem — Marketplace, multi-agent interactions, registries, end users",
}

LAYER_THREATS: dict[int, list[dict]] = {
    1: [
        {
            "id": "L1-T01", "name": "Adversarial Examples",
            "description": "Crafted inputs cause incorrect outputs, policy bypass, hallucinated actions, or unsafe tool use",
            "question": "Are inputs validated for adversarial patterns before reaching the model?",
            "mitigation": "Adversarial training, input validation, output policy enforcement, red teaming",
            "default_severity": "HIGH",
        },
        {
            "id": "L1-T02", "name": "Model Stealing / Extraction",
            "description": "Attackers reproduce model capabilities via repeated API queries for offline attacks or IP theft",
            "question": "Are rate limits, query anomaly detection, and output perturbation in place?",
            "mitigation": "Rate limiting, query fingerprinting, output perturbation, access controls",
            "default_severity": "HIGH",
        },
        {
            "id": "L1-T03", "name": "Backdoor Attacks",
            "description": "Hidden triggers embedded via training or supply chain cause targeted malicious behavior when activated",
            "question": "Is model provenance verified? Are backdoor probes run after every model update?",
            "mitigation": "Model provenance checks, backdoor scanning, adversarial regression testing",
            "default_severity": "CRITICAL",
        },
        {
            "id": "L1-T04", "name": "Membership Inference",
            "description": "Attacker infers whether specific records were in training data, causing privacy or regulatory exposure",
            "question": "Are differential privacy techniques applied? Is training data governance in place?",
            "mitigation": "Differential privacy, data minimization, training data access controls",
            "default_severity": "MEDIUM",
        },
        {
            "id": "L1-T05", "name": "Data Poisoning (Training Phase)",
            "description": "Malicious data injected into training set corrupts model behavior or embeds activation triggers",
            "question": "Is training data provenance tracked and validated before model training?",
            "mitigation": "Data provenance, anomaly detection in training data, signed datasets",
            "default_severity": "CRITICAL",
        },
        {
            "id": "L1-T06", "name": "Reprogramming Attacks",
            "description": "Model repurposed for malicious tasks different from original intent via adversarial prompts or misused fine-tuning",
            "question": "Are behavioral guardrails enforced independently of the model's own outputs?",
            "mitigation": "External policy enforcement, behavioral guardrails, output validation layer",
            "default_severity": "HIGH",
        },
        {
            "id": "L1-T07", "name": "DoS / Sponge Attacks",
            "description": "Adversarially crafted inputs maximize compute consumption, degrading availability and increasing cost",
            "question": "Are token limits, timeout policies, and cost anomaly detection configured?",
            "mitigation": "Token limits, rate limiting, cost monitoring, request timeouts",
            "default_severity": "MEDIUM",
        },
    ],
    2: [
        {
            "id": "L2-T01", "name": "Data Poisoning",
            "description": "Malicious data in retrieval corpora or fine-tuning sets biases agent outputs or embeds triggers",
            "question": "Are retrieval sources validated? Is ingestion pipeline integrity monitored?",
            "mitigation": "Signed data sources, ingestion allowlists, anomaly detection on embeddings",
            "default_severity": "CRITICAL",
        },
        {
            "id": "L2-T02", "name": "Data Exfiltration",
            "description": "Sensitive data leaked through retrieval, logging, embeddings, or tool outputs",
            "question": "Are access controls and PII detection in place for all data stores?",
            "mitigation": "PII detection, least-privilege access, output filtering, audit logging",
            "default_severity": "HIGH",
        },
        {
            "id": "L2-T03", "name": "DoS on Data Infrastructure",
            "description": "Disruption of data access prevents agent function; bulk writes exhaust storage capacity",
            "question": "Are quotas, rate limits, and redundancy configured for data infrastructure?",
            "mitigation": "Write quotas, rate limits, redundancy, automated backup/recovery",
            "default_severity": "MEDIUM",
        },
        {
            "id": "L2-T04", "name": "Data Tampering",
            "description": "AI data modified in transit or at rest leads to incorrect agent behavior",
            "question": "Are encryption at rest, integrity checksums, and in-transit TLS enforced?",
            "mitigation": "Encryption at rest and in transit, integrity checksums, immutable audit logs",
            "default_severity": "HIGH",
        },
        {
            "id": "L2-T05", "name": "Compromised RAG Pipelines",
            "description": "Attacker injects malicious documents or manipulates retrieval so agent receives adversary-controlled context",
            "question": "Are retrieval sources allowlisted? Is retrieved content sanitized for injection?",
            "mitigation": "Content sanitization, retrieval isolation, prompt-injection filtering on retrieved text",
            "default_severity": "CRITICAL",
        },
    ],
    3: [
        {
            "id": "L3-T01", "name": "Compromised Framework Components",
            "description": "Malicious code in LangChain/AutoGen or other framework libraries causes unexpected agent behavior",
            "question": "Are framework dependencies pinned, signed, and continuously scanned?",
            "mitigation": "SBOMs, pinned dependencies, signed artifacts, continuous dependency scanning",
            "default_severity": "CRITICAL",
        },
        {
            "id": "L3-T02", "name": "Backdoor Attacks in Framework",
            "description": "Hidden vulnerabilities in orchestration framework exploited for unauthorized access or control",
            "question": "Is framework source audited? Are integrity checks performed on each version?",
            "mitigation": "Framework source auditing, integrity verification, version pinning",
            "default_severity": "CRITICAL",
        },
        {
            "id": "L3-T03", "name": "Input Validation Attacks / Prompt Injection",
            "description": "Weak input handling enables code injection, prompt injection, or instruction hijacking by attackers",
            "question": "Are all inputs validated? Is user/retrieved content treated as data, not instructions?",
            "mitigation": "Input validation, prompt boundary enforcement, parameterized tool calls",
            "default_severity": "HIGH",
        },
        {
            "id": "L3-T04", "name": "Supply Chain Attacks on Frameworks",
            "description": "Dependency confusion, typosquatting, or compromised CI artifacts infect framework components",
            "question": "Are package sources verified? Is dependency provenance tracked end-to-end?",
            "mitigation": "Verified registries, SBOM generation, artifact signing, dependency pinning",
            "default_severity": "CRITICAL",
        },
        {
            "id": "L3-T05", "name": "DoS on Framework APIs",
            "description": "Overloading framework API services prevents normal agent operation",
            "question": "Are rate limits and circuit breakers applied to all framework API endpoints?",
            "mitigation": "Rate limiting, quotas, circuit breakers, load balancing",
            "default_severity": "MEDIUM",
        },
        {
            "id": "L3-T06", "name": "Framework Evasion",
            "description": "AI agents bypass the framework's own security controls and safety filters through adversarial behavior",
            "question": "Are agent actions validated by an independent system outside the agent's reasoning loop?",
            "mitigation": "External policy enforcement, tool-call allowlists, independent safety monitors",
            "default_severity": "HIGH",
        },
    ],
    4: [
        {
            "id": "L4-T01", "name": "Compromised Container Images",
            "description": "Malicious code in AI agent container images infects production, enabling backdoors or data theft",
            "question": "Are container images signed, vulnerability-scanned, and pulled from restricted registries?",
            "mitigation": "Image signing, vulnerability scanning, restricted registries, admission controllers",
            "default_severity": "CRITICAL",
        },
        {
            "id": "L4-T02", "name": "Orchestration Attacks",
            "description": "Kubernetes RBAC weaknesses, admission controller bypass, or malicious sidecars compromise AI deployments",
            "question": "Are RBAC policies least-privilege? Are pod security standards and network policies enforced?",
            "mitigation": "Least-privilege RBAC, network policies, pod security standards, runtime monitoring",
            "default_severity": "HIGH",
        },
        {
            "id": "L4-T03", "name": "IaC Manipulation",
            "description": "Terraform/CloudFormation/Helm tampering silently weakens IAM, networking, or secrets for AI infrastructure",
            "question": "Is IaC reviewed, version-controlled, and policy-as-code checked before apply?",
            "mitigation": "Policy-as-code gates, code review, drift detection, GitOps controls",
            "default_severity": "HIGH",
        },
        {
            "id": "L4-T04", "name": "Denial of Service on Infrastructure",
            "description": "AI agent infrastructure overwhelmed makes agents unavailable to legitimate users",
            "question": "Are DDoS protections, auto-scaling, and resource quotas configured?",
            "mitigation": "DDoS protection, auto-scaling, rate limiting, resource quotas",
            "default_severity": "MEDIUM",
        },
        {
            "id": "L4-T05", "name": "Resource Hijacking",
            "description": "Compromised AI infrastructure used for cryptomining or illicit compute, degrading agent performance",
            "question": "Is resource usage monitored? Are anomalous compute spikes detected and alerted?",
            "mitigation": "Resource quotas, usage monitoring, anomaly detection, egress controls",
            "default_severity": "MEDIUM",
        },
        {
            "id": "L4-T06", "name": "Lateral Movement from AI Infrastructure",
            "description": "Compromise of one agent pod enables pivot to vector databases, secret stores, or CI runners",
            "question": "Are network segmentation and least-privilege service accounts enforced?",
            "mitigation": "Network policies, per-service identities, secret isolation, egress filtering",
            "default_severity": "CRITICAL",
        },
    ],
    5: [
        {
            "id": "L5-T01", "name": "Manipulation of Evaluation Metrics",
            "description": "Adversaries game safety benchmarks or bias eval datasets to hide failures during testing",
            "question": "Are eval datasets adversarial, diverse, and independently maintained?",
            "mitigation": "Diverse eval suites, adversarial test cases, independent evaluation, regression testing",
            "default_severity": "HIGH",
        },
        {
            "id": "L5-T02", "name": "Compromised Observability Tools",
            "description": "Malicious code in monitoring systems exfiltrates data or conceals malicious agent behavior",
            "question": "Are observability tools integrity-checked, access-controlled, and isolated from agents?",
            "mitigation": "Integrity verification of monitoring tools, access controls, separation of duties",
            "default_severity": "HIGH",
        },
        {
            "id": "L5-T03", "name": "DoS on Evaluation Infrastructure",
            "description": "Disrupting evaluation prevents detection of compromised agent behavior",
            "question": "Is evaluation infrastructure independently resourced and resilient?",
            "mitigation": "Independent evaluation infrastructure, redundancy, resource quotas",
            "default_severity": "MEDIUM",
        },
        {
            "id": "L5-T04", "name": "Evasion of Detection",
            "description": "Agents craft gradual or low-and-slow interactions to avoid triggering monitoring alerts",
            "question": "Does monitoring use behavioral baselines and long-term anomaly detection?",
            "mitigation": "Behavioral baselines, ML-based anomaly detection, long-term trend analysis",
            "default_severity": "HIGH",
        },
        {
            "id": "L5-T05", "name": "Data Leakage through Observability",
            "description": "Sensitive data inadvertently exposed through logs, traces, or monitoring dashboards",
            "question": "Are logs scrubbed of PII and secrets? Are dashboard access controls enforced?",
            "mitigation": "Log scrubbing, PII redaction, access controls on observability infrastructure",
            "default_severity": "HIGH",
        },
        {
            "id": "L5-T06", "name": "Poisoning Observability Data",
            "description": "Telemetry pipeline data manipulated to hide incidents and mask malicious activity",
            "question": "Are logs tamper-evident and append-only? Are telemetry pipelines integrity-checked?",
            "mitigation": "Tamper-evident logging, append-only stores, integrity checks on telemetry",
            "default_severity": "CRITICAL",
        },
    ],
    6: [
        {
            "id": "L6-T01", "name": "Security Agent Data Poisoning",
            "description": "Training or operational data for AI security tools manipulated to cause missed detections",
            "question": "Is data feeding security AI agents validated and provenance-tracked?",
            "mitigation": "Data provenance, input anomaly detection, human oversight of security agent decisions",
            "default_severity": "CRITICAL",
        },
        {
            "id": "L6-T02", "name": "Evasion of Security AI Agents",
            "description": "Adversarial techniques bypass AI security tooling, preventing threat detection",
            "question": "Are security AI agents adversarially tested for evasion resistance?",
            "mitigation": "Adversarial testing, ensemble detection, human-in-the-loop for high-risk decisions",
            "default_severity": "HIGH",
        },
        {
            "id": "L6-T03", "name": "Compromised Security AI Agents",
            "description": "Attackers gain control of AI security tools, disabling defenses or weaponizing them",
            "question": "Are security agents isolated, access-controlled, and monitored for anomalous behavior?",
            "mitigation": "Isolation, least-privilege, anomaly monitoring of security agents themselves",
            "default_severity": "CRITICAL",
        },
        {
            "id": "L6-T04", "name": "Regulatory Non-Compliance",
            "description": "AI agents violate privacy regulations (GDPR, EU AI Act) due to misconfiguration or coverage gaps",
            "question": "Are compliance controls documented, tested, and continuously monitored?",
            "mitigation": "Policy-as-code, compliance monitoring, regular audits, EU AI Act/ISO 42001 alignment",
            "default_severity": "HIGH",
        },
        {
            "id": "L6-T05", "name": "Bias in Security AI Agents",
            "description": "Biases in AI security tooling lead to uneven protection or discriminatory outcomes",
            "question": "Are security AI agents tested for bias across populations and scenarios?",
            "mitigation": "Bias testing, fairness metrics, diverse training data, human review of edge cases",
            "default_severity": "MEDIUM",
        },
        {
            "id": "L6-T06", "name": "Lack of Explainability",
            "description": "Opaque AI agent decision-making makes audit, compliance, and incident response impossible",
            "question": "Can the agent explain its decisions? Are human-readable audit trails generated?",
            "mitigation": "XAI techniques, structured audit trails, decision logging, human accountability points",
            "default_severity": "MEDIUM",
        },
        {
            "id": "L6-T07", "name": "Model Extraction of Security Agents",
            "description": "Attackers extract the underlying model of AI security tools to understand and bypass detection logic",
            "question": "Are security agent APIs rate-limited and monitored for systematic querying?",
            "mitigation": "Rate limiting, query anomaly detection, output perturbation, access controls",
            "default_severity": "HIGH",
        },
    ],
    7: [
        {
            "id": "L7-T01", "name": "Compromised Agents in Ecosystem",
            "description": "Malicious agents infiltrate the ecosystem posing as legitimate services to capture credentials or cause harm",
            "question": "Is agent identity cryptographically signed and provenance-verified before any interaction?",
            "mitigation": "Agent signing, provenance verification, allowlisted registries",
            "default_severity": "CRITICAL",
        },
        {
            "id": "L7-T02", "name": "Agent Impersonation",
            "description": "Malicious actors deceive users or other agents by masquerading as trusted AI agents",
            "question": "Is strong agent identity enforced with certificates or verifiable credentials?",
            "mitigation": "Strong agent identity, mTLS, verifiable credentials, impersonation detection",
            "default_severity": "HIGH",
        },
        {
            "id": "L7-T03", "name": "Agent Identity Attack",
            "description": "Agent authentication and authorization mechanisms compromised, enabling unauthorized access",
            "question": "Are agent credentials short-lived, rotated, and revocable?",
            "mitigation": "Short-lived credentials, identity revocation, per-agent identity isolation",
            "default_severity": "HIGH",
        },
        {
            "id": "L7-T04", "name": "Agent Tool Misuse",
            "description": "Agents manipulated to use their tools in unintended ways causing harmful ecosystem actions",
            "question": "Are tool-use schemas validated? Are dangerous tools behind human approval gates?",
            "mitigation": "Tool allowlists, schema validation, human approval for high-risk tool invocations",
            "default_severity": "HIGH",
        },
        {
            "id": "L7-T05", "name": "Agent Goal Manipulation",
            "description": "Attackers manipulate agent objectives causing pursuit of harmful goals instead of intended ones",
            "question": "Are agent goals isolated from external data? Are goal deviations monitored?",
            "mitigation": "Goal isolation, objective consistency monitoring, human oversight for critical decisions",
            "default_severity": "CRITICAL",
        },
        {
            "id": "L7-T06", "name": "Marketplace Manipulation",
            "description": "False ratings or recommendations promote malicious agents or undermine legitimate ones",
            "question": "Are anti-sybil measures and independent verification in place for agent ratings?",
            "mitigation": "Anti-sybil measures, anomaly detection on ratings/usage, independent verification",
            "default_severity": "MEDIUM",
        },
        {
            "id": "L7-T07", "name": "Integration Risks",
            "description": "Vulnerabilities in APIs or SDKs used to integrate agents lead to compromised interactions",
            "question": "Are all integration points security-tested? Are SDK dependencies audited?",
            "mitigation": "API security testing, SDK dependency auditing, secure integration patterns",
            "default_severity": "HIGH",
        },
        {
            "id": "L7-T08", "name": "Compromised Agent Registry",
            "description": "Registry manipulation injects malicious agent listings or modifies legitimate agent metadata",
            "question": "Is the registry integrity-checked with staged rollouts and version verification?",
            "mitigation": "Registry integrity checks, staged rollouts, transparent versioning, anomaly detection",
            "default_severity": "HIGH",
        },
        {
            "id": "L7-T09", "name": "Malicious Agent Discovery",
            "description": "Discovery mechanisms promote malicious agents or suppress legitimate ones",
            "question": "Is agent discovery based on verified identity and integrity, not just metadata?",
            "mitigation": "Verified discovery, reputation systems, independent audit of discovery results",
            "default_severity": "MEDIUM",
        },
        {
            "id": "L7-T10", "name": "Agent Pricing Model Manipulation",
            "description": "Exploitation of pricing models causes financial losses or economic denial-of-service",
            "question": "Are per-task budgets, cost anomaly detection, and billing alerts configured?",
            "mitigation": "Per-task budgets, cost monitoring, billing anomaly detection, quota enforcement",
            "default_severity": "MEDIUM",
        },
        {
            "id": "L7-T11", "name": "Repudiation",
            "description": "Agents deny actions they performed, creating accountability and audit trail gaps",
            "question": "Are all agent actions logged with non-repudiable, tamper-evident audit trails?",
            "mitigation": "Immutable audit logs, digital signatures on agent actions, accountability frameworks",
            "default_severity": "MEDIUM",
        },
        {
            "id": "L7-T12", "name": "Inaccurate Agent Capability Description",
            "description": "Misleading capability descriptions cause misuse, over-reliance, or unexpected harmful outcomes",
            "question": "Are agent capability descriptions independently verified and kept current?",
            "mitigation": "Capability verification, regular description audits, user warnings for high-risk capabilities",
            "default_severity": "LOW",
        },
    ],
}

CROSS_LAYER_THREATS: list[dict] = [
    {
        "id": "CL-T01", "name": "Supply Chain Cascade",
        "description": "Compromised component in one layer (e.g., library in L3) propagates to other layers (L1, L7)",
        "affected_layers": [3, 4, 1],
        "mitigation": "Defense in depth, layer isolation, end-to-end SBOM tracking",
        "default_severity": "CRITICAL",
    },
    {
        "id": "CL-T02", "name": "Lateral Movement Across Layers",
        "description": "Attacker gains L4 infrastructure access and pivots to L2 data stores or L1 model weights",
        "affected_layers": [4, 2, 1],
        "mitigation": "Network segmentation, least-privilege per layer, inter-layer communication controls",
        "default_severity": "CRITICAL",
    },
    {
        "id": "CL-T03", "name": "Cross-Layer Privilege Escalation",
        "description": "Agent or attacker gains unauthorized privileges in one layer and uses them to access others",
        "affected_layers": [3, 4, 7],
        "mitigation": "Per-layer authorization, privilege audit, access pattern anomaly detection",
        "default_severity": "HIGH",
    },
    {
        "id": "CL-T04", "name": "Cross-Layer Data Leakage",
        "description": "Sensitive data from one layer exposed through another (e.g., training data via L5 observability dashboards)",
        "affected_layers": [2, 5, 1],
        "mitigation": "Data classification, cross-layer DLP controls, access controls on all data paths",
        "default_severity": "HIGH",
    },
    {
        "id": "CL-T05", "name": "Goal Misalignment Cascade",
        "description": "Goal misalignment in one agent (from L2 data poisoning) propagates to others through L7 ecosystem interactions",
        "affected_layers": [2, 7, 1],
        "mitigation": "Per-agent goal isolation, cascade monitoring, circuit breakers between agents",
        "default_severity": "CRITICAL",
    },
]

ARCH_PATTERNS: dict[str, dict] = {
    "single": {
        "description": "Single AI agent operating independently to achieve a goal",
        "key_risk": "Goal Manipulation — attacker changes optimization objective to harmful variant",
        "extra_threats": [
            {"ref": "L7-T05", "arch_note": "Primary risk in single-agent systems — no peer agents to detect goal deviation"},
        ],
    },
    "multi": {
        "description": "Multiple AI agents collaborating through communication channels",
        "key_risk": "Communication Channel Attacks and Agent Identity Attacks between peer agents",
        "extra_threats": [
            {"ref": "L7-T02", "arch_note": "Peer agents may impersonate each other within the agent network"},
            {"ref": "L7-T03", "arch_note": "Inter-agent authentication is an expanded attack surface vs. single-agent"},
        ],
    },
    "conversational": {
        "description": "Conversational AI processing wide-ranging user inputs without tight constraints",
        "key_risk": "Prompt Injection and Jailbreaking via adversarial user inputs",
        "extra_threats": [
            {"ref": "L3-T03", "arch_note": "Primary jailbreak/injection vector in conversational systems"},
            {"ref": "L1-T06", "arch_note": "Reprogramming via adversarial conversation is elevated risk"},
        ],
    },
    "task_oriented": {
        "description": "Agent designed for specific tasks primarily via API calls to external systems",
        "key_risk": "DoS through API Overload and Tool Misuse for direct system access",
        "extra_threats": [
            {"ref": "L3-T05", "arch_note": "Task-execution APIs are high-value DoS targets"},
            {"ref": "L7-T04", "arch_note": "Tool misuse risk elevated when agents have direct system access"},
        ],
    },
    "hierarchical": {
        "description": "Orchestrator agents controlling subordinate agents in a command hierarchy",
        "key_risk": "Orchestrator Compromise enables cascade control of all subordinates",
        "extra_threats": [
            {"ref": "L7-T01", "arch_note": "Orchestrator compromise propagates to all subordinate agents"},
            {"ref": "CL-T02", "arch_note": "Lateral movement from orchestrator tier is high-impact in hierarchies"},
        ],
    },
    "distributed": {
        "description": "Decentralized ecosystem of many peer agents in a shared environment",
        "key_risk": "Sybil Attacks — fake agent identities gain disproportionate ecosystem influence",
        "extra_threats": [
            {"ref": "L7-T02", "arch_note": "Sybil attacks via large-scale agent impersonation are the primary risk"},
            {"ref": "L7-T06", "arch_note": "Marketplace manipulation by colluding fake agents"},
        ],
    },
    "human_in_loop": {
        "description": "Agents interact with human users in iterative approval workflows",
        "key_risk": "Manipulation of Human Input/Feedback to skew agent behavior or decisions",
        "extra_threats": [
            {"ref": "L6-T05", "arch_note": "Bias injected through manipulated human feedback persists across sessions"},
            {"ref": "L7-T05", "arch_note": "Goal manipulation through crafted human inputs exploits approval workflows"},
        ],
    },
    "self_learning": {
        "description": "Agents autonomously improve over time via environment feedback loops",
        "key_risk": "Backdoor Trigger Injection via poisoned online learning or RLHF data",
        "extra_threats": [
            {"ref": "L1-T05", "arch_note": "Backdoor triggers injected via online learning/RLHF data are the primary risk"},
            {"ref": "L2-T01", "arch_note": "Training data poisoning through feedback loops is amplified in self-learning systems"},
        ],
    },
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def cmd_init(args) -> None:
    arch_info = ARCH_PATTERNS.get(args.arch_type, {})
    assessment = {
        "system": args.system,
        "maestro_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "arch_type": args.arch_type,
        "arch_description": arch_info.get("description", ""),
        "arch_key_risk": arch_info.get("key_risk", ""),
        "layers": {
            str(layer_num): {
                "name": LAYER_DESCRIPTIONS[layer_num],
                "components": [],
                "notes": "",
                "applicable": True,
            }
            for layer_num in range(1, 8)
        },
    }
    with open(args.output, "w") as f:
        json.dump(assessment, f, indent=2)

    print(f"[*] MAESTRO assessment scaffolded: {args.system}")
    print(f"[*] Architecture pattern : {args.arch_type} — {arch_info.get('description', '')}")
    print(f"[*] Key risk for pattern  : {arch_info.get('key_risk', 'N/A')}")
    print(f"[*] Written to {args.output}")
    print(f"[*] Add your components to each layer, then run:")
    print(f"[*]   agent.py analyze --assessment {args.output}")


def cmd_analyze(args) -> dict:
    path = Path(args.assessment)
    if not path.exists():
        print(f"[error] Assessment not found: {args.assessment}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        assessment = json.load(f)

    arch_type = assessment.get("arch_type", "single")
    arch_info = ARCH_PATTERNS.get(arch_type, {})
    extra_threat_notes: dict[str, str] = {
        e["ref"]: e["arch_note"] for e in arch_info.get("extra_threats", [])
    }

    threats: list[dict] = []
    tid = 1

    for layer_num in range(1, 8):
        layer_config = assessment.get("layers", {}).get(str(layer_num), {})
        if not layer_config.get("applicable", True):
            continue
        for tmpl in LAYER_THREATS.get(layer_num, []):
            arch_note = extra_threat_notes.get(tmpl["id"], "")
            threats.append({
                "id": f"MT-{tid:03d}",
                "ref_id": tmpl["id"],
                "layer": layer_num,
                "layer_name": f"L{layer_num}",
                "name": tmpl["name"],
                "description": tmpl["description"],
                "question": tmpl["question"],
                "default_severity": tmpl["default_severity"],
                "severity": tmpl["default_severity"],
                "status": "OPEN",
                "mitigation": tmpl["mitigation"],
                "arch_pattern_note": arch_note,
                "is_arch_specific": bool(arch_note),
                "owner": "",
                "notes": "",
            })
            tid += 1

    for cl in CROSS_LAYER_THREATS:
        arch_note = extra_threat_notes.get(cl["id"], "")
        threats.append({
            "id": f"MT-{tid:03d}",
            "ref_id": cl["id"],
            "layer": 0,
            "layer_name": "Cross-Layer",
            "name": cl["name"],
            "description": cl["description"],
            "question": f"Are controls across layers {cl['affected_layers']} preventing this cascade?",
            "default_severity": cl["default_severity"],
            "severity": cl["default_severity"],
            "status": "OPEN",
            "mitigation": cl["mitigation"],
            "affected_layers": cl["affected_layers"],
            "arch_pattern_note": arch_note,
            "is_arch_specific": bool(arch_note),
            "owner": "",
            "notes": "",
        })
        tid += 1

    assessment["threats"] = threats
    assessment["analyzed_at"] = datetime.now(timezone.utc).isoformat()

    with open(args.output, "w") as f:
        json.dump(assessment, f, indent=2)

    layer_count = sum(1 for t in threats if t["layer"] > 0)
    cross_count = sum(1 for t in threats if t["layer"] == 0)
    arch_count = sum(1 for t in threats if t["is_arch_specific"])
    critical = sum(1 for t in threats if t["severity"] == "CRITICAL")
    high = sum(1 for t in threats if t["severity"] == "HIGH")

    print(f"[*] {len(threats)} threats generated: {layer_count} layer-specific, {cross_count} cross-layer")
    print(f"[*] {arch_count} threats flagged for {arch_type} architecture pattern")
    print(f"[*] Severity: CRITICAL={critical} HIGH={high}")
    print(f"[*] Written to {args.output}")
    print(f"[*] Review threats (set status to MITIGATED or NOT_APPLICABLE), then run:")
    print(f"[*]   agent.py report --threats {args.output}")

    return assessment


def cmd_report(args) -> dict:
    path = Path(args.threats)
    if not path.exists():
        print(f"[error] File not found: {args.threats}", file=sys.stderr)
        sys.exit(1)

    with open(path) as f:
        assessment = json.load(f)

    threats: list[dict] = assessment.get("threats", [])
    system = assessment.get("system", "Unknown")
    arch_type = assessment.get("arch_type", "unknown")

    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_layer: dict[str, int] = {}
    open_threats: list[dict] = []
    mitigated = 0

    for t in threats:
        if t.get("status") in ("MITIGATED", "NOT_APPLICABLE"):
            mitigated += 1
            continue
        sev = t.get("severity", "LOW")
        if sev in by_severity:
            by_severity[sev] += 1
        lname = t.get("layer_name", "Unknown")
        by_layer[lname] = by_layer.get(lname, 0) + 1
        open_threats.append(t)

    open_threats.sort(
        key=lambda x: SEVERITY_ORDER.get(x.get("severity", "LOW"), 0), reverse=True
    )

    critical_cross = [
        t for t in open_threats
        if t.get("layer") == 0 and t.get("severity") == "CRITICAL"
    ]
    arch_specific_open = [t for t in open_threats if t.get("is_arch_specific")]

    overall_risk = (
        "CRITICAL" if by_severity["CRITICAL"] > 0
        else "HIGH" if by_severity["HIGH"] > 0
        else "MEDIUM" if by_severity["MEDIUM"] > 0
        else "LOW"
    )

    report = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "system": system,
        "arch_type": arch_type,
        "methodology": "MAESTRO v1.0 (Multi-Agent Environment, Security, Threat, Risk, and Outcome)",
        "total_threats": len(threats),
        "mitigated_or_na": mitigated,
        "open_threats_count": len(open_threats),
        "by_severity": by_severity,
        "by_layer": by_layer,
        "overall_risk": overall_risk,
        "critical_cross_layer_threats": [
            {"id": t["id"], "name": t["name"], "mitigation": t["mitigation"]}
            for t in critical_cross
        ],
        "arch_pattern_specific_open": [
            {"id": t["id"], "name": t["name"], "note": t.get("arch_pattern_note", "")}
            for t in arch_specific_open
        ],
        "top_open_threats": open_threats[:20],
        "recommendation": (
            f"{by_severity['CRITICAL']} CRITICAL and {by_severity['HIGH']} HIGH threats require immediate remediation. "
            f"Address cross-layer threats first — they compound risk across multiple layers."
            if overall_risk in ("CRITICAL", "HIGH")
            else "Risk posture is acceptable. Update threat model after major system changes or quarterly."
        ),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))
    print(f"\n[*] MAESTRO report saved to {args.output}", file=sys.stderr)

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)

    return report


def main():
    parser = argparse.ArgumentParser(description="MAESTRO Threat Modeling Agent")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_init = sub.add_parser("init", help="Scaffold MAESTRO assessment worksheet")
    p_init.add_argument("--system", required=True, help="System name")
    p_init.add_argument(
        "--arch-type",
        required=True,
        choices=list(ARCH_PATTERNS.keys()),
        help="Agentic architecture pattern",
    )
    p_init.add_argument("--output", default="maestro_assessment.json")

    p_analyze = sub.add_parser("analyze", help="Apply 7-layer threat taxonomy")
    p_analyze.add_argument("--assessment", required=True)
    p_analyze.add_argument("--output", default="maestro_threats.json")

    p_report = sub.add_parser("report", help="Generate prioritized MAESTRO threat report")
    p_report.add_argument("--threats", required=True)
    p_report.add_argument("--output", default="maestro_report.json")

    args = parser.parse_args()
    if args.subcommand == "init":
        cmd_init(args)
    elif args.subcommand == "analyze":
        cmd_analyze(args)
    elif args.subcommand == "report":
        cmd_report(args)


if __name__ == "__main__":
    main()
