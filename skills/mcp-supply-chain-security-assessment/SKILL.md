---
name: mcp-supply-chain-security-assessment
description: >-
  Assesses and hardens the Model Context Protocol dependency supply chain against malicious
  open-source packages, compromised registries, and backdoored components. Covers SBOM
  generation for MCP server dependencies, dependency pinning with hash verification, CVE
  scanning, and runtime integrity validation of loaded packages. Based on OWASP MCP Top 10
  (MCP04:2025 Software Supply Chain Attacks & Dependency Tampering). Activates when auditing
  MCP server dependencies for supply chain risk, responding to upstream package compromise
  alerts, or enforcing software composition security in AI agent deployments.
domain: cybersecurity
subdomain: ai-security
tags:
- mcp-security
- supply-chain
- dependency-security
- OWASP-MCP-Top10
- SBOM
- vulnerability-scanning
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
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
- DE.AE-04
---
# MCP Supply Chain Security Assessment

## When to Use

- Auditing MCP server `requirements.txt`, `package.json`, or `go.mod` for vulnerable or malicious dependencies
- Generating a Software Bill of Materials (SBOM) for all MCP server components before deployment
- Scanning for typosquatted packages installed in an MCP environment (e.g., `anthropic-mcp` vs. `anthropic_mcp`)
- Verifying that installed package hashes match pinned expected values after a dependency update
- Responding to a reported supply chain compromise affecting a library used by an MCP server
- Enforcing dependency provenance policies in CI/CD pipelines that deploy MCP tools

**Do not use** as a replacement for runtime behavior monitoring — a clean SBOM scan does not guarantee a package behaves safely at runtime.

## Prerequisites

- Python 3.10+ with `pip-audit`, `safety` for Python dep scanning
- Node.js environment with `npm audit` for JavaScript MCP packages
- `syft` for SBOM generation: `brew install syft`
- `grype` for vulnerability scanning against the SBOM: `brew install grype`
- `cosign` for artifact signature verification: `brew install cosign`
- Access to MCP server source directory and dependency lock files

## Workflow

### Step 1: Generate an SBOM for the MCP Server

```bash
# Generate SBOM in SPDX format for a Python MCP server
syft dir:./mcp-server -o spdx-json=sbom.spdx.json

# Generate SBOM for a containerized MCP server image
syft ghcr.io/example/mcp-server:latest -o cyclonedx-json=sbom.cyclonedx.json

# For Node.js-based MCP servers
syft dir:./mcp-server-node -o spdx-json=sbom-node.spdx.json

# List all direct and transitive dependencies
cat sbom.spdx.json | jq '[.packages[] | {name: .name, version: .versionInfo, source: .downloadLocation}]'
```

### Step 2: Scan for Known CVEs

```bash
# Scan SBOM for vulnerabilities using grype
grype sbom:sbom.spdx.json -o json > vuln-scan.json

# Fail CI if any CRITICAL or HIGH CVEs are found
grype sbom:sbom.spdx.json --fail-on critical

# Python-specific audit with pip-audit
pip-audit --requirement requirements.txt --format json > pip-audit.json

# Node.js
npm audit --json > npm-audit.json

# Python safety check (includes malware database)
safety check --file requirements.txt --json > safety-report.json
```

### Step 3: Detect Typosquatting and Suspicious Packages

```python
import json
from difflib import SequenceMatcher

KNOWN_LEGITIMATE = [
    "anthropic", "mcp", "openai", "langchain", "httpx",
    "pydantic", "fastapi", "uvicorn", "requests", "aiohttp"
]

def find_typosquats(installed: list[str], threshold: float = 0.88) -> list[dict]:
    suspects = []
    for pkg in installed:
        for legit in KNOWN_LEGITIMATE:
            ratio = SequenceMatcher(None, pkg.lower(), legit.lower()).ratio()
            if threshold <= ratio < 1.0:
                suspects.append({
                    "installed": pkg,
                    "resembles": legit,
                    "similarity": round(ratio, 3),
                    "risk": "potential typosquatting"
                })
    return suspects

# Extract installed package names from SBOM
with open("sbom.spdx.json") as f:
    sbom = json.load(f)
installed = [p["name"] for p in sbom.get("packages", [])]
suspects = find_typosquats(installed)
if suspects:
    print("Typosquatting suspects:", json.dumps(suspects, indent=2))
```

### Step 4: Pin Dependencies with Hash Verification

```bash
# Generate pinned requirements with hashes (Python)
pip-compile requirements.in \
  --generate-hashes \
  --output-file requirements.txt

# Example pinned entry (do not edit manually)
# anthropic==0.39.0 \
#   --hash=sha256:abc123... \
#   --hash=sha256:def456...

# Verify all hashes match during install
pip install --require-hashes -r requirements.txt

# For Node.js — use package-lock.json with integrity field
npm ci   # uses lock file; fails if package-lock.json is modified
```

### Step 5: Verify Package Signatures (Sigstore/cosign)

```bash
# Verify a Python package against its Sigstore transparency log entry
cosign verify-blob \
  --certificate mcp_server-1.0.0-py3-none-any.whl.crt \
  --signature mcp_server-1.0.0-py3-none-any.whl.sig \
  mcp_server-1.0.0-py3-none-any.whl

# For npm packages with provenance (npm 9.5+)
npm audit signatures   # verifies registry signatures for all installed packages

# Check PyPI provenance (PEP 740 attestations)
pip install pypi-attestations
python -m pypi_attestations verify anthropic==0.39.0
```

### Step 6: Enforce in CI/CD Pipeline

```yaml
# .github/workflows/mcp-supply-chain.yml (example)
- name: Generate SBOM
  run: syft dir:. -o cyclonedx-json=sbom.json

- name: Scan for CVEs
  run: grype sbom:sbom.json --fail-on high

- name: Audit Python dependencies
  run: pip-audit --requirement requirements.txt

- name: Check hash integrity
  run: pip install --require-hashes -r requirements.txt --dry-run
```

## Key Concepts

| Term | Definition |
|------|------------|
| **SBOM (Software Bill of Materials)** | Machine-readable inventory of all software components, versions, and their relationships in a system |
| **Typosquatting** | Registering a malicious package with a name nearly identical to a popular legitimate package to catch mistyped installs |
| **Dependency Pinning** | Specifying exact package versions (and optionally hashes) to prevent unexpected updates from pulling in malicious code |
| **Sigstore/cosign** | Open-source supply chain security tool for signing and verifying software artifacts using short-lived certificates |
| **Transitive Dependency** | A package that an MCP server's direct dependency depends on — often the entry point for supply chain attacks |
| **Provenance Attestation** | Cryptographic statement from a build system asserting where and how a package was built |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **syft** | Generates SBOMs in SPDX or CycloneDX format from container images or source directories |
| **grype** | CVE vulnerability scanner that consumes SBOMs and queries NVD, OSV, and GitHub Advisory databases |
| **pip-audit** | Audits Python requirements against the OSV vulnerability database with hash-based deduplication |
| **safety** | Python dependency scanner with a malware and known-bad-package database beyond CVEs |
| **cosign (Sigstore)** | Signs and verifies container images, Python wheels, and arbitrary blobs against transparency logs |
| **npm audit** | Built-in Node.js tool for scanning package dependencies against the npm security advisory database |

## Common Scenarios

- **Compromised upstream library**: The MCP server uses `requests==2.31.0`; a CVE is disclosed for that version. `grype` flags CRITICAL severity. Pin to the patched version and re-validate hashes.
- **Typosquatted package installed**: A developer installs `anthroplc` (lowercase L instead of I). The typosquatting scanner flags it at 0.94 similarity to `anthropic`. Remove immediately, investigate for malicious behavior.
- **Backdoored transitive dependency**: The direct dependency `mcp-utils` pulls in a compromised `httpx-patch` via its own requirements. SBOM scan reveals it; pin `mcp-utils` to a safe version or replace it.

## Output Format

```json
{
  "sbom_generated": "2026-04-26T11:00:00Z",
  "component_count": 87,
  "vulnerabilities": {
    "critical": 1,
    "high": 3,
    "medium": 9,
    "low": 14
  },
  "critical_findings": [
    {
      "package": "cryptography",
      "installed_version": "41.0.0",
      "cve": "CVE-2024-26130",
      "cvss": 9.1,
      "fix_version": "42.0.4",
      "action": "update immediately"
    }
  ],
  "typosquat_suspects": [],
  "hash_verification": "PASS",
  "signature_verification": "PASS",
  "supply_chain_risk": "HIGH"
}
```
