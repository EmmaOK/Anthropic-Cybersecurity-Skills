Your goal is to fix the security findings produced by the most recent `/threat` run in this session.

You apply fixes directly to the developer's codebase. Use the Phantom skill library (via `mcp__phantom-skills__search_skills` and `mcp__phantom-skills__load_skill`) to load the precise fix guidance for each finding. You do not require developers to clone any external repository.

---

## 1. Load the threat register

Check for input in this order of priority:

1. **File argument** — if the user passed a file path (e.g., `/remediate threat-report.json`), load that file
2. **Default file** — check if `threat-report.json` exists in the project root (written automatically by `/threat`)
3. **Session state** — if `/threat` was run earlier in this session, use that threat register
4. **None found** — tell the user to run `/threat` first (it saves `threat-report.json` automatically) and stop

The threat register file follows the JSON structure written by `/threat`. Each finding has: `id`, `framework`, `component`, `threat`, `severity`, `likelihood`, `impact`, `mitigation`, `skill`, `status`.

Display a triage summary before proceeding:

```
Threat register loaded
─────────────────────
Source:          threat-report.json  (or session / filename)
Generated:       <timestamp from file>
Total findings:  <n>
  Critical:      <n>
  High:          <n>
  Medium:        <n>
  Low:           <n>

Frameworks:      STRIDE | MAESTRO | OWASP-LLM | OWASP-Agentic | OWASP-MCP | ATLAS
```

---

## 2. Classify findings into three buckets

Sort all findings Critical → High → Medium → Low, then assign each to one of:

| Bucket | Criteria | Action |
|---|---|---|
| **Fix now** | Targeted code change: missing check, insecure pattern, hardcoded value, wrong config | Apply fix directly to the identified file/component |
| **Skill-guided fix** | Requires security-domain knowledge beyond a single code change (output validation pipeline, RBAC redesign, rate limiting strategy, AI-specific control) | Load the relevant Phantom skill, follow its fix guidance, apply to the codebase |
| **Architectural change** | Requires redesigning a trust boundary, adding a new service, or changing the system topology | Document the required change, flag for the next sprint, do not attempt to auto-fix |

Pause and surface any **Critical architectural findings** to the user before proceeding — these indicate the system may not be safe to deploy until addressed.

---

## 3. Fix STRIDE findings

For every STRIDE finding in the **Fix now** or **Skill-guided fix** buckets, apply the mitigation to the identified component using the patterns below.

### Spoofing (S)
- Enforce authentication at every trust boundary — verify tokens, API keys, or mutual TLS before processing any request
- Add token expiry validation and replay protection (nonce or timestamp check)
- For service-to-service calls: use short-lived signed tokens, not long-lived shared secrets

### Tampering (T)
- Enforce parameterized queries or prepared statements — never interpolate user input into SQL, shell commands, or file paths
- Add HMAC or digital signature verification on data crossing trust boundaries
- Validate all input at system entry points: type, length, format, range — reject and log anything unexpected
- Enforce TLS on all data in transit; enable encryption at rest for sensitive stores

### Repudiation (R)
- Add append-only audit logging for every sensitive action (auth events, data mutations, privilege use, external API calls)
- Include: timestamp, actor identity, action, resource affected, outcome
- Minimum 90-day retention; logs must be write-protected from the application process

### Information Disclosure (I)
- Strip internal stack traces and system details from all error responses — return a generic error ID instead
- Scrub PII, credentials, and secrets from all log lines
- Enforce strict CORS policy; remove or scope overly permissive `Access-Control-Allow-Origin: *`
- Audit API response payloads — remove fields the caller does not need

### Denial of Service (D)
- Add rate limiting at the entry point (per-user, per-IP, or per-API-key)
- Enforce payload size limits on all request bodies
- Add timeouts on all outbound calls and database queries
- Add circuit breakers on downstream dependencies

### Elevation of Privilege (E)
- Enforce server-side authorization on every privileged endpoint — never trust client-supplied role claims without verification
- Validate JWT claims server-side (signature, expiry, audience, issuer)
- Apply least-privilege service accounts — remove unused permissions
- Separate admin functions behind a distinct auth layer

After applying all STRIDE fixes, run the project's test suite to verify no regressions.

---

## 4. Fix MAESTRO findings (skip if no AI/agentic signals were detected by `/threat`)

For each MAESTRO finding, search the Phantom skill library for the matching control skill, load it, and apply its fix guidance to the codebase.

### Layer routing

| MAESTRO Layer | Search query | What to fix |
|---|---|---|
| L1 Foundation Models | `"model extraction defense"` / `"adversarial robustness"` | Rate limiting on model API, output perturbation, anomaly detection on inference patterns |
| L2 Data Operations | `"RAG pipeline security"` / `"data provenance"` | Prompt injection filters on ingested documents, vector DB access controls, embedding integrity checks |
| L3 Agent Frameworks | `"agent framework security"` | Dependency pinning, tool allowlisting, unsafe pattern removal (`eval`, `exec`, `shell=True`), sandbox enforcement |
| L4 Infrastructure | `"AI workload infrastructure hardening"` | Non-root containers, resource limits, network policy, RBAC, secrets in vault not env vars |
| L5 Evaluation & Observability | `"evaluation security observability"` | Tamper-evident logging, PII redaction in telemetry, behavioral baseline alerts |
| L6 Security & Compliance | `"AI security tool adversarial defense"` | Training data signing, adversarial sample coverage, output consistency monitoring |
| L7 Agent Ecosystem | `"agent ecosystem security"` | Registry signing, cryptographic agent identity, mutual auth between agents |
| Cross-layer | `"AI explainability formal verification"` | Per-decision explanations, runtime constraint checkers, reward hacking tests |

### How to apply

For each affected layer:
```
1. mcp__phantom-skills__search_skills("<query from table above>")
2. mcp__phantom-skills__load_skill("<matched skill name>")
3. Read the skill's Workflow section
4. Apply each control it specifies to the relevant files in this project
```

---

## 5. Fix OWASP LLM / Agentic / MCP findings (skip if no AI/agentic signals)

Route each finding to its Phantom skill, load the fix guidance, and apply it.

### OWASP LLM Top 10

| ID | Threat | Phantom search query | Fix focus |
|---|---|---|---|
| LLM01 | Prompt Injection | `"prompt injection detection"` | Input classifier, indirect injection filter on external content |
| LLM02 | Sensitive Information Disclosure | `"sensitive information disclosure prevention"` | PII detection in outputs, credential scrubbing, output filters |
| LLM03 | Supply Chain | `"AI supply chain"` | Pin model versions, verify model checksums, vet plugins |
| LLM04 | Data & Model Poisoning | `"data model poisoning defense"` | Training data signing, anomaly detection on fine-tune inputs |
| LLM05 | Improper Output Handling | `"LLM output validation sanitization"` | HTML sanitization, XSS/SQLi/SSRF/cmd pattern scanning on outputs |
| LLM06 | Excessive Agency | `"excessive agency prevention"` | Tool manifest audit, HITL gates on irreversible actions, least-capability tools |
| LLM07 | System Prompt Leakage | `"system prompt leakage prevention"` | Canary tokens, extraction probe hardening, prompt confidentiality checks |
| LLM08 | Vector & Embedding Weaknesses | `"RAG pipeline security"` | Embedding integrity, vector DB access isolation, retrieval filtering |
| LLM09 | Misinformation | `"AI explainability"` | Output confidence scores, citation requirements, factual grounding checks |
| LLM10 | Unbounded Consumption | `"rate limiting"` / `"denial of service"` | Token budgets, per-session limits, cost circuit breakers |

### OWASP Agentic Top 10

| ID | Threat | Phantom search query | Fix focus |
|---|---|---|---|
| ASI01 | Goal Hijacking | `"agent goal hijacking detection"` | Goal drift monitoring, injection pattern detection in agent logs |
| ASI02 | Rogue Agent | `"rogue agent detection"` | Reward hacking detection, self-replication checks, behavioral drift alerts |
| ASI03 | Excessive Permissions | `"excessive agency prevention"` | Tool scope reduction, action allowlisting |
| ASI04 | Insecure Inter-Agent Communication | `"securing inter-agent communication"` | Mutual auth between agents, signed message envelopes |
| ASI05 | Human Oversight Bypass | `"human agent trust boundaries"` | HITL enforcement, override audit logging |
| ASI06 | Resource Abuse | `"AI workload infrastructure hardening"` | Compute quotas, memory limits, agent sandboxing |
| ASI07 | Supply Chain in Pipelines | `"agentic supply chain integrity"` | Dependency verification, plugin vetting, SBOM |
| ASI08 | Data Exfiltration via Agent | `"agent tool misuse detection"` | Egress filtering, tool output auditing |
| ASI09 | Prompt Injection via External Content | `"prompt injection detection"` | Sanitize all external content before injecting into prompts |
| ASI10 | Unverified Agent Identity | `"agent identity governance"` | Cryptographic agent identity, attestation at invocation |

### OWASP MCP Top 10

For any MCP finding, search:
```
mcp__phantom-skills__search_skills("MCP <threat name>")
```
Example queries: `"MCP tool poisoning"`, `"MCP command injection"`, `"MCP authentication"`.

Load the matched skill and follow its fix guidance for the MCP server/client code in this project.

---

## 6. Verify and report closure

### Run verification

1. **Test suite** — run the project's existing tests (same commands as `/audit` Section 3)
2. **Re-check critical patterns** — for any finding where you changed a security control, grep the codebase to confirm the vulnerable pattern no longer exists
3. **Re-search Phantom** for any finding you were unsure about — load the skill and verify the fix matches what it recommends

### Closure report

Produce a final summary:

```
Remediation complete
────────────────────
Fixed:             <n> findings  (Critical: n, High: n, Medium: n, Low: n)
Pending:           <n> findings  (reasons listed below)
Architectural:     <n> findings  (flagged for sprint planning)

Residual risk:     Critical | High | Medium | Low | Pass
```

For each **pending** finding: state what was attempted, what blocked closure, and the exact next step needed.

For each **architectural** finding: write a one-paragraph description of the design change required, suitable for adding to a sprint backlog item.

If any **Critical findings remain open**, end with:
```
⚠ PRODUCTION GATE: <n> Critical finding(s) unresolved. Do not deploy until addressed.
```

### Update threat-report.json

After remediation, write the updated status of every finding back to `threat-report.json`:
- Set `"status": "fixed"` for resolved findings
- Set `"status": "pending"` with a `"blocked_by"` field explaining what remains
- Set `"status": "architectural"` for findings requiring design changes, with a `"sprint_note"` field
- Update `"summary"` counts to reflect current state

This ensures `/remediate` can be re-run incrementally as findings are closed over time, and the file serves as a persistent audit trail of security progress across sessions.
