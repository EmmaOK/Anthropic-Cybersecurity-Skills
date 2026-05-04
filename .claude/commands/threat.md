Your goal is to analyze the application code in this project for security threats.

Start by detecting the application type, then apply the appropriate threat framework(s). Always run STRIDE as the baseline. If the application is an AI/agentic system, layer on MAESTRO and the AI-specific frameworks automatically.

---

## 1. Detect application type

Scan the codebase to classify the application before choosing frameworks. Check for these signals:

### Standard application signals
| Signal | Type |
|---|---|
| Web routes, controllers, REST/GraphQL endpoints | Web application / API |
| Database models, ORM schemas, migrations | Data-layer application |
| Message queues, event buses, pub/sub | Distributed / event-driven |
| Auth flows, OAuth, JWT, session handling | Identity-aware application |
| Dockerfiles, K8s manifests, Terraform, cloud configs | Infrastructure / cloud-native |
| Mobile manifests (`AndroidManifest.xml`, `Info.plist`) | Mobile application |
| gRPC / Thrift / protobuf definitions | Microservices / RPC |

### AI / Agentic application signals
| Signal | Type |
|---|---|
| Imports: `anthropic`, `openai`, `langchain`, `llama_index`, `transformers`, `autogen`, `crewai`, `semantic_kernel` | LLM application |
| Vector DB clients: `pinecone`, `weaviate`, `chromadb`, `qdrant`, `pgvector` | RAG pipeline |
| Tool/function definitions passed to a model (`tools=`, `functions=`, `tool_choice=`) | Agentic tool use |
| Multi-agent orchestration: `Agent`, `Crew`, `AutoGen`, `supervisor`, `worker` patterns | Multi-agent system |
| Embedding pipelines, model fine-tuning scripts, training data ingestion | ML/training infrastructure |
| Memory systems: `ConversationBufferMemory`, `VectorStoreRetrieverMemory`, external memory stores | Stateful AI agent |
| MCP servers / clients (`mcp`, `@modelcontextprotocol/sdk`) | MCP-connected agent |

If neither standard nor AI signals are detected, report findings and stop.

---

## 2. Apply STRIDE (all application types)

STRIDE is the baseline framework for every application. Apply it regardless of whether AI signals are present.

**Six STRIDE threat categories:**

| Category | Question to ask per component |
|---|---|
| **S**poofing | Can an attacker impersonate a user, service, or identity? |
| **T**ampering | Can data in transit or at rest be modified without detection? |
| **R**epudiation | Can a user or service deny performing an action? |
| **I**nformation Disclosure | Can sensitive data be read by an unauthorized party? |
| **D**enial of Service | Can the service be made unavailable or degraded? |
| **E**levation of Privilege | Can an attacker gain permissions beyond what was granted? |

**How to apply:**

1. Identify all components: processes, data stores, external entities, data flows, trust boundaries.
2. For each component, enumerate threats under each STRIDE category.
3. Assign severity (Critical / High / Medium / Low) based on impact × likelihood.
4. Map each threat to a mitigation.

Use the `performing-stride-threat-modeling` skill for detailed per-component-type STRIDE mappings (web APIs, databases, auth services, message queues, microservices, cloud storage).

To run the executable script:
```bash
cd skills/performing-stride-threat-modeling/scripts
python agent.py init --system "<system name>"
python agent.py analyze --components components.json
python agent.py report --threats threats.json
```

---

## 3. If AI / Agentic signals detected — apply MAESTRO

MAESTRO (Multi-Agent Environment, Security, Threat, Risk, and Outcome) is the primary framework for agentic AI systems. It covers 7 layers and identifies threats that STRIDE misses (prompt injection, model extraction, goal hijacking, agent collusion, etc.).

**MAESTRO 7 layers:**

| Layer | Scope |
|---|---|
| L1 Foundation Models | Model integrity, adversarial inputs, extraction, reprogramming |
| L2 Data Operations | RAG pipelines, training data, vector DBs, data provenance |
| L3 Agent Frameworks | Orchestration security, tool allowlisting, sandboxing, dependency integrity |
| L4 Deployment & Infrastructure | Container hardening, K8s RBAC, secret management, network policy |
| L5 Evaluation & Observability | Eval pipeline integrity, telemetry tampering, behavioral baselines |
| L6 Security & Compliance | AI-based security tool evasion, adversarial classifier attacks |
| L7 Agent Ecosystem | Registry signing, agent identity, inter-agent trust, marketplace vetting |

**Also check cross-layer threats:** prompt injection cascades, goal drift, reward hacking, Sybil-resistant reputation, formal constraint violations.

Use the `performing-maestro-threat-modeling` skill for the full 7-layer threat inventory.

To run the executable script:
```bash
cd skills/performing-maestro-threat-modeling/scripts
python agent.py init --system "<system name>" --arch-type <pattern>
# arch-type options: single | multi | hierarchical | distributed | conversational | task_oriented | human_in_loop | self_learning
python agent.py analyze --assessment assessment.json
python agent.py report --assessment assessment.json
```

---

## 4. If AI / Agentic signals detected — apply AI-specific frameworks

Layer these on top of MAESTRO for full AI threat coverage:

### OWASP LLM Top 10 (2025)
Apply when LLM API calls, prompt construction, or model outputs are present.

| ID | Threat |
|---|---|
| LLM01 | Prompt Injection |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Supply Chain Vulnerabilities |
| LLM04 | Data and Model Poisoning |
| LLM05 | Improper Output Handling |
| LLM06 | Excessive Agency |
| LLM07 | System Prompt Leakage |
| LLM08 | Vector and Embedding Weaknesses |
| LLM09 | Misinformation |
| LLM10 | Unbounded Consumption |

Use the `threat-modeling-for-ai-ml-systems` skill (covers OWASP LLM Top 10 + MITRE ATLAS taxonomy).

To run:
```bash
cd skills/threat-modeling-for-ai-ml-systems/scripts
python agent.py init --system "<system name>" --arch-type <type>
# arch-type options: agentic | rag | llm_app | training_pipeline | multi_agent
python agent.py analyze
python agent.py report
```

### OWASP Agentic Top 10 (2026)
Apply when tool use, multi-agent coordination, or autonomous task execution is present.

| ID | Threat |
|---|---|
| ASI01 | Agent Goal Hijacking |
| ASI02 | Rogue Agent Behavior |
| ASI03 | Excessive Permissions / Agency |
| ASI04 | Insecure Inter-Agent Communication |
| ASI05 | Human Oversight Bypass |
| ASI06 | Resource and Compute Abuse |
| ASI07 | Supply Chain Compromise in Agent Pipelines |
| ASI08 | Data Exfiltration via Agent Actions |
| ASI09 | Prompt Injection via External Content |
| ASI10 | Unverified Agent Identity |

### OWASP MCP Top 10 (v0.1)
Apply when MCP servers/clients, tool registries, or plugin systems are present.

| ID | Threat |
|---|---|
| MCP01 | Tool Poisoning |
| MCP02 | Command Injection via Tool Parameters |
| MCP03 | Excessive Tool Permissions |
| MCP04 | Unauthenticated Tool Invocation |
| MCP05 | Insecure Tool Output Handling |
| MCP06 | Tool Registry Tampering |
| MCP07 | Denial of Service via Tool Flooding |
| MCP08 | Sensitive Data Exposure in Tool Responses |
| MCP09 | Cross-Agent Tool Confusion |
| MCP10 | Lack of Tool Audit Logging |

### MITRE ATLAS
Apply for any ML model training, inference serving, or adversarial ML scenarios. Key techniques to check:

- `AML.T0043` — Craft Adversarial Data
- `AML.T0047` — ML Supply Chain Compromise
- `AML.T0051` — LLM Prompt Injection
- `AML.T0054` — LLM Jailbreak
- `AML.T0056` — LLM Data Extraction
- `AML.T0057` — LLM Backdoor
- `AML.T0068` — Evade ML Model
- `AML.T0082` — Exploit Public-Facing ML Model
- `AML.T0088` — Model Reprogramming

---

## 5. Search the Phantom skill library for additional coverage

After applying the frameworks above, search the Phantom skill library for skills relevant to the specific components found in the codebase. This surfaces additional, more targeted threat analysis capabilities.

**If the Phantom MCP server is connected** (`mcp__phantom-skills__search_skills` is available as a tool):

Use it with queries matching detected components. Examples:

```
search_skills("RAG pipeline security")
search_skills("prompt injection detection")
search_skills("agent goal hijacking")
search_skills("MCP tool poisoning")
search_skills("model extraction defense")
search_skills("API authentication weakness")
search_skills("container security hardening")
search_skills("JWT attack")
```

Load and apply any relevant skills found using `mcp__phantom-skills__load_skill`.

**If the Phantom MCP server is not connected** (tool unavailable):

Apply your built-in knowledge of the detected frameworks directly. For each component with AI/agentic signals, reason through the applicable MAESTRO layer controls and OWASP LLM/Agentic/MCP items from your training. The analysis is still complete — Phantom adds depth but is not required for coverage.

---

## 6. Report findings and save threat register

Produce a structured threat report with the following sections:

### Application profile
- Application type(s) detected
- AI/agentic signals found (if any)
- Frameworks applied

### Threat register
For each threat found, report:

| Field | Value |
|---|---|
| ID | STRIDE-S-01, MAESTRO-L2-01, LLM03, ASI05, etc. |
| Framework | STRIDE / MAESTRO / OWASP-LLM / OWASP-Agentic / OWASP-MCP / ATLAS |
| Component | Which file, class, function, or system component |
| Threat | Description of the threat |
| Severity | Critical / High / Medium / Low |
| Likelihood | High / Medium / Low |
| Impact | What breaks or is exposed if exploited |
| Mitigation | Concrete remediation step |
| Skill | Phantom skill that can help (if applicable) |

### Summary counts
- Total threats by severity
- Total threats by framework
- Top 5 highest-priority threats to fix first

### Recommended next steps
- List mitigations in priority order (Critical → High → Medium → Low)
- Flag any threat that requires architectural change vs. a code-level fix
- Suggest which Phantom skills to run for deeper automated analysis

---

## 7. Save threat register to file

After producing the report, write the full threat register to `threat-report.json` in the project root using the `write_file` tool or direct file write. This file is the input to `/remediate` and persists across sessions.

The file must follow this structure:

```json
{
  "generated_at": "<ISO 8601 timestamp>",
  "project": "<detected project name or directory>",
  "application_profile": {
    "types": ["web-api", "ai-agentic"],
    "ai_signals": ["anthropic", "langchain"],
    "frameworks_applied": ["STRIDE", "MAESTRO", "OWASP-LLM"]
  },
  "summary": {
    "total": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "findings": [
    {
      "id": "STRIDE-S-01",
      "framework": "STRIDE",
      "component": "src/auth/login.py:42",
      "threat": "...",
      "severity": "High",
      "likelihood": "Medium",
      "impact": "...",
      "mitigation": "...",
      "skill": "performing-stride-threat-modeling",
      "status": "open"
    }
  ]
}
```

Confirm to the user that `threat-report.json` has been written and is ready for `/remediate`.
