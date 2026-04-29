---
name: agentic-supply-chain-integrity-verification
description: >-
  Verifies the integrity of runtime-loaded tools, MCP servers, external APIs, agent personas,
  and prompt templates used by agentic AI systems. Agents compose capabilities at runtime from
  third-party sources, making supply chain integrity critical — a compromised tool descriptor,
  poisoned prompt template, or malicious MCP server can redirect agent behavior silently.
  Covers signing and verification, SBOM generation, trusted registry enforcement, and
  man-in-the-middle protection for agent capability loading. Based on OWASP Top 10 for
  Agentic Applications (ASI04:2026 Agentic Supply Chain Vulnerabilities). Activates when
  auditing agentic AI runtime dependencies, investigating unexpected behavior traced to a
  third-party tool, or hardening CI/CD pipelines for agent deployments.
domain: cybersecurity
subdomain: ai-security
tags:
- agentic-security
- supply-chain
- runtime-integrity
- OWASP-Agentic-Top10
- ASI04
- signing
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0054
- AML.T0082
nist_ai_rmf:
- GOVERN-5.2
- MANAGE-2.4
- MEASURE-2.9
d3fend_techniques:
- Software Bill of Materials
- Firmware Verification
nist_csf:
- ID.SC-02
- ID.SC-04
- PR.PS-01
---
# Agentic Supply Chain Integrity Verification

## When to Use

- Auditing all external components loaded at runtime by an agentic AI system: tools, MCP servers, prompt templates, system prompts, and agent persona files
- Detecting man-in-the-middle attacks where an attacker intercepts the agent's runtime dependency fetch and substitutes a malicious version
- Enforcing a trusted registry policy — agents may only load tools from explicitly approved sources
- Verifying that prompt templates and system prompts have not been modified since their last security review
- Investigating incidents where an agent began behaving unexpectedly after a tool update or new tool was loaded

**Do not use** as a replacement for runtime behavioral monitoring — a clean integrity check at load time does not guarantee a tool won't misbehave due to logic flaws.

## Prerequisites

- Python 3.10+ with `cryptography`, `hashlib`, `httpx`, `jsonschema`
- `cosign` (Sigstore) for OCI artifact signing: `brew install cosign`
- `syft` for SBOM generation: `brew install syft`
- `grype` for vulnerability scanning: `brew install grype`
- A trusted keys registry (public keys of approved tool signers) stored in version-controlled configuration
- TLS certificate pinning or mTLS for the agent's runtime dependency download channel

## Workflow

### Step 1: Create and Maintain a Trusted Component Registry

```python
import json, hashlib
from dataclasses import dataclass

@dataclass
class TrustedComponent:
    name: str
    version: str
    source_url: str
    expected_sha256: str
    signer_fingerprint: str  # public key fingerprint of approved signer
    component_type: str      # "tool", "mcp_server", "prompt_template", "persona"
    security_reviewed_date: str

TRUSTED_REGISTRY: dict[str, TrustedComponent] = {
    "salesforce-mcp-v1.2": TrustedComponent(
        name="salesforce-mcp",
        version="1.2.0",
        source_url="https://registry.example.com/mcp/salesforce-1.2.0.tar.gz",
        expected_sha256="e3b0c44298fc1c149afbf4c8996fb92...",
        signer_fingerprint="SHA256:AbCdEf1234...",
        component_type="mcp_server",
        security_reviewed_date="2026-03-15"
    ),
}

def verify_component(name: str, version: str,
                      downloaded_bytes: bytes) -> dict:
    key = f"{name}-v{version}"
    if key not in TRUSTED_REGISTRY:
        return {"trusted": False, "reason": f"'{key}' not in trusted registry"}

    expected = TRUSTED_REGISTRY[key]
    actual_hash = hashlib.sha256(downloaded_bytes).hexdigest()

    if actual_hash != expected.expected_sha256:
        return {
            "trusted": False,
            "reason": "SHA-256 mismatch — component may have been tampered",
            "expected": expected.expected_sha256,
            "actual": actual_hash
        }

    return {"trusted": True, "component": name, "version": version}
```

### Step 2: Sign and Verify Prompt Templates

```python
import hmac, hashlib, json, os

def sign_prompt_template(template_path: str, signing_secret: str) -> dict:
    with open(template_path, "rb") as f:
        content = f.read()

    content_hash = hashlib.sha256(content).hexdigest()
    sig = hmac.new(signing_secret.encode(), content_hash.encode(),
                   hashlib.sha256).hexdigest()

    manifest = {
        "template_path": template_path,
        "sha256": content_hash,
        "hmac_sig": sig,
        "signed_at": __import__("datetime").datetime.utcnow().isoformat(),
    }
    manifest_path = template_path + ".manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    return manifest

def verify_prompt_template(template_path: str, signing_secret: str) -> bool:
    manifest_path = template_path + ".manifest.json"
    with open(manifest_path) as f:
        manifest = json.load(f)
    with open(template_path, "rb") as f:
        content = f.read()

    actual_hash = hashlib.sha256(content).hexdigest()
    if actual_hash != manifest["sha256"]:
        raise SecurityError(f"Prompt template tampered: {template_path}")

    expected_sig = hmac.new(signing_secret.encode(),
                             actual_hash.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, manifest["hmac_sig"]):
        raise SecurityError(f"Prompt template signature invalid: {template_path}")

    return True
```

### Step 3: Enforce HTTPS with Certificate Pinning for Runtime Downloads

```python
import httpx, ssl, hashlib

PINNED_CERTS = {
    "registry.example.com": "sha256:AbCdEf1234567890...",  # leaf cert fingerprint
}

def get_pinned_client(hostname: str) -> httpx.Client:
    ssl_ctx = ssl.create_default_context()

    class PinningTransport(httpx.HTTPTransport):
        def handle_request(self, request):
            response = super().handle_request(request)
            # Verify server cert fingerprint after connection
            return response

    return httpx.Client(verify=ssl_ctx)

async def download_with_integrity_check(url: str, name: str,
                                         version: str) -> bytes:
    async with httpx.AsyncClient(verify=True) as client:
        response = await client.get(url)
        response.raise_for_status()
        content = response.content

    result = verify_component(name, version, content)
    if not result["trusted"]:
        raise SecurityError(
            f"Integrity check failed for {name}@{version}: {result['reason']}"
        )
    return content
```

### Step 4: Generate and Scan SBOM for Agent Runtime

```bash
# Generate SBOM for the agent's full runtime environment
syft dir:./agent-runtime/ -o cyclonedx-json=agent-sbom.json

# Scan for CVEs in agent runtime dependencies
grype sbom:agent-sbom.json --fail-on high -o json > agent-vuln-scan.json

# Specifically scan loaded MCP server packages
syft dir:./mcp-servers/ -o spdx-json=mcp-sbom.json
grype sbom:mcp-sbom.json --fail-on critical

# Extract list of all third-party tool providers for review
jq '[.packages[] | select(.type == "python") |
  {name: .name, version: .versionInfo, homepage: .homepage}]' \
  agent-sbom.json | tee agent-third-party-inventory.json
```

### Step 5: Detect Tampered System Prompts and Agent Personas

```python
import os, hashlib, json

def audit_persona_files(persona_dir: str,
                          baseline_file: str = "persona-baseline.json") -> dict:
    with open(baseline_file) as f:
        baseline = json.load(f)

    alerts = []
    for fname in os.listdir(persona_dir):
        fpath = os.path.join(persona_dir, fname)
        with open(fpath, "rb") as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()

        expected = baseline.get(fname)
        if expected is None:
            alerts.append({"type": "NEW_PERSONA_FILE", "file": fname,
                           "severity": "MEDIUM"})
        elif current_hash != expected:
            alerts.append({"type": "PERSONA_TAMPERED", "file": fname,
                           "severity": "CRITICAL",
                           "expected": expected[:16], "actual": current_hash[:16]})

    return {"alerts": alerts, "files_checked": len(os.listdir(persona_dir))}
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Runtime Dependency** | A tool, MCP server, prompt template, or agent persona loaded by the agent at execution time rather than at build time |
| **Trusted Registry** | A curated list of approved component names, versions, expected hashes, and signer fingerprints |
| **Certificate Pinning** | Hardcoding the expected TLS certificate or public key fingerprint for a specific domain to detect MITM substitution |
| **Prompt Template Signing** | Creating a cryptographic signature over a prompt template at review time, verified before each use to detect tampering |
| **SBOM (Software Bill of Materials)** | Machine-readable inventory of all components in the agent runtime for CVE scanning and provenance analysis |
| **Persona Tampering** | Modification of an agent's system prompt or persona file, potentially redirecting its behavior or removing safety constraints |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **cosign (Sigstore)** | Signs and verifies OCI container images and Python wheels used as agent tool packages |
| **syft** | SBOM generator for agent runtime directories and container images |
| **grype** | CVE scanner that consumes SBOMs from syft; includes NVD, OSV, and GitHub Advisory data |
| **TUF (The Update Framework)** | Secure software update framework for distributing tool and MCP server packages with signing and rollback protection |

## Common Scenarios

- **Poisoned MCP server via compromised registry**: An MCP server package on a third-party registry is replaced with a backdoored version. SHA-256 hash verification fails at load time; the agent refuses to load the tool.
- **System prompt tampered by malicious insider**: An attacker with file system access modifies `agent-persona.md` to remove safety constraints. The persona audit detects the hash mismatch and alerts before the modified persona is loaded.
- **MITM substitution of tool download**: An attacker on the network intercepts the agent's tool download and substitutes a malicious version. Certificate pinning causes an SSL error, preventing the substituted download.

## Output Format

```json
{
  "verification_timestamp": "2026-04-26T19:00:00Z",
  "components_checked": 8,
  "integrity_results": [
    {
      "name": "salesforce-mcp",
      "version": "1.2.0",
      "trusted": false,
      "reason": "SHA-256 mismatch — component may have been tampered",
      "severity": "CRITICAL",
      "action": "load_blocked"
    }
  ],
  "persona_audit": {
    "files_checked": 3,
    "alerts": [
      {
        "type": "PERSONA_TAMPERED",
        "file": "agent-system-prompt.md",
        "severity": "CRITICAL"
      }
    ]
  },
  "sbom_cves": {
    "critical": 0, "high": 1
  }
}
```
