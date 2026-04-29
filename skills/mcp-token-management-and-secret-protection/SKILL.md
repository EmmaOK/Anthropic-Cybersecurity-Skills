---
name: mcp-token-management-and-secret-protection
description: >-
  Detects and prevents token mismanagement and secret exposure in Model Context Protocol
  deployments. Scans MCP server configs, protocol logs, and agent context for hardcoded
  credentials and long-lived tokens. Implements vault-based secret injection, rotation
  policies, and runtime log redaction. Based on OWASP MCP Top 10 (MCP01:2025 Token
  Mismanagement & Secret Exposure). Activates when auditing MCP infrastructure for credential
  hygiene, investigating token leakage incidents in AI agent pipelines, or hardening secret
  management for MCP server deployments.
domain: cybersecurity
subdomain: ai-security
tags:
- mcp-security
- secrets-management
- token-rotation
- OWASP-MCP-Top10
- credential-hygiene
- vault-integration
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0057
nist_ai_rmf:
- GOVERN-1.7
- MANAGE-2.4
- MEASURE-2.5
d3fend_techniques:
- Credential Hardening
- Software Bill of Materials
nist_csf:
- PR.AA-05
- PR.DS-01
- DE.AE-02
---
# MCP Token Management and Secret Protection

## When to Use

- Auditing MCP server config files, environment variables, and tool manifests for hardcoded API keys, bearer tokens, or passwords
- Scanning MCP protocol logs for credentials accidentally surfaced in headers, payloads, or error messages
- Reviewing agent conversation context for tokens leaked via prompt injection or debug output
- Setting up vault-based secret injection to eliminate hardcoded credentials in MCP deployments
- Implementing token rotation policies for long-lived OAuth/API tokens used by MCP servers
- Investigating incidents where attackers retrieved tokens via compromised agent context or intercepted MCP debug traces

**Do not use** as a substitute for application-level authorization — token hygiene prevents exposure but does not enforce what authenticated callers can do.

## Prerequisites

- Read access to MCP server config files, `.env` files, and tool definition JSON/YAML manifests
- `trufflehog` v3+: `pip install trufflehog` or download binary from GitHub releases
- `gitleaks` v8+: `brew install gitleaks` or download from GitHub releases
- `detect-secrets` (Yelp): `pip install detect-secrets`
- HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault for remediation
- Python 3.10+ with `hvac` (Vault) or `boto3` (AWS) for programmatic integration
- Access to MCP protocol logs (JSON lines format)

## Workflow

### Step 1: Scan MCP Configuration for Hardcoded Secrets

```bash
# Scan MCP server filesystem for secrets
trufflehog filesystem ./mcp-server/ --json > secrets-scan.json

# Scan full git history including deleted files
trufflehog git file://./mcp-server/ --since-commit HEAD~100 --json

# Run gitleaks for additional regex-based detection
gitleaks detect --source ./mcp-server/ \
  --report-format json --report-path gitleaks-report.json

# Baseline scan with detect-secrets
detect-secrets scan ./mcp-server/ --all-files > .secrets.baseline
detect-secrets audit .secrets.baseline   # review interactively
```

Review output for `VerifiedResult: true` — these are confirmed live credentials requiring immediate rotation.

### Step 2: Audit MCP Protocol Logs for Token Leakage

```python
import json, re, sys

PATTERNS = {
    "bearer_token": r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
    "api_key":      r'(?i)(api[_-]?key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-_]{20,})',
    "aws_key":      r"AKIA[0-9A-Z]{16}",
    "github_token": r"gh[pousr]_[A-Za-z0-9]{36,255}",
    "private_key":  r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
}

findings = []
with open("mcp-protocol.log") as f:
    for lineno, line in enumerate(f, 1):
        try:
            text = json.dumps(json.loads(line))
        except json.JSONDecodeError:
            text = line
        for name, pat in PATTERNS.items():
            if re.search(pat, text):
                findings.append({"line": lineno, "type": name, "preview": text[:120]})

print(json.dumps({"total": len(findings), "findings": findings}, indent=2))
```

### Step 3: Replace Hardcoded Credentials with Vault Injection

```python
import hvac, os

def load_mcp_secrets() -> dict:
    client = hvac.Client(
        url=os.environ["VAULT_ADDR"],
        token=os.environ["VAULT_TOKEN"]
    )
    return client.secrets.kv.v2.read_secret_version(
        path="mcp/production", mount_point="secret"
    )["data"]["data"]

# Inject at MCP server startup — never persist to env files
secrets = load_mcp_secrets()
os.environ["MCP_API_KEY"] = secrets["api_key"]
os.environ["MCP_DB_PASSWORD"] = secrets["db_password"]
```

For AWS Secrets Manager:

```bash
export MCP_API_KEY=$(aws secretsmanager get-secret-value \
  --secret-id mcp/production/api-key \
  --query SecretString --output text | jq -r .api_key)
```

### Step 4: Implement Token Rotation

```bash
# HashiCorp Vault dynamic database credentials (1-hour TTL)
vault write database/roles/mcp-server-role \
  db_name=mcp-db \
  creation_statements="CREATE ROLE '{{name}}' LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';" \
  default_ttl="1h" max_ttl="24h"
```

```python
from datetime import datetime, timedelta
import jwt, os

def issue_short_lived_token(subject: str, ttl_minutes: int = 60) -> str:
    return jwt.encode({
        "sub": subject,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=ttl_minutes),
        "scope": "mcp:tools:read mcp:tools:invoke",
    }, os.environ["JWT_SECRET"], algorithm="HS256")
```

### Step 5: Add Runtime Log Redaction

```python
import re, logging

_REDACT = re.compile(
    r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*|"
    r"(AKIA)[0-9A-Z]{16}|"
    r"(gh[pousr]_)[A-Za-z0-9]{36,}"
)

class SecretRedactingFilter(logging.Filter):
    def filter(self, record):
        record.msg = _REDACT.sub(r"\1[REDACTED]", str(record.msg))
        return True

logging.getLogger("mcp").addFilter(SecretRedactingFilter())
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Long-lived Token** | Credential with no expiry or an expiry measured in months/years; high-value target because compromise window is unlimited |
| **Vault Injection** | Pattern where secrets are fetched from a secrets manager at runtime rather than stored in config files or env vars |
| **Token Rotation** | Replacing a credential with a new one and invalidating the old one to limit the exposure window after compromise |
| **Secret Scanning** | Automated analysis of code, configs, and logs to detect accidentally committed or logged credentials |
| **Prompt Memory Leakage** | When an LLM agent surfaces a previously processed credential in a later response because it persisted in context |
| **MCP Protocol Log** | JSON-RPC structured log capturing all tool calls, responses, and context mutations in an MCP session |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **truffleHog** | Deep secrets scanner; checks git history entropy and regex; supports filesystem, S3, and API targets |
| **gitleaks** | Fast SAST tool for detecting hardcoded secrets using customizable TOML rule sets |
| **detect-secrets** | Yelp's baseline-driven secrets detector that tracks known acceptable findings and alerts on new ones |
| **HashiCorp Vault** | Full secrets lifecycle management with dynamic credentials, leases, and automatic rotation |
| **AWS Secrets Manager** | Managed secret storage with built-in rotation lambdas for RDS, Redshift, and custom secrets |
| **MCP Inspector** | Official MCP debugging UI that reveals the full context and tool list visible in an active session |

## Common Scenarios

- **Hardcoded dev key in production config**: Developer commits `MCP_API_KEY=sk-abc123` to `.env` in the repo. truffleHog finds it in git history even after deletion. Rotate the key immediately, then migrate to vault injection.
- **Token surfaced in debug trace**: MCP server logs full request headers at DEBUG level in production; `Authorization: Bearer ghp_...` appears in conversation history and is extractable by subsequent prompts. Add log redaction filter and set log level to INFO.
- **Long-lived shared OAuth token**: One service-account token with no expiry is reused across 12 MCP tool connections. One compromise exposes all. Issue per-agent scoped tokens with 1-hour TTL from Vault dynamic secrets.

## Output Format

```json
{
  "scan_target": "./mcp-server/",
  "scan_timestamp": "2026-04-26T14:32:00Z",
  "secrets_found": 3,
  "findings": [
    {
      "file": "config/mcp-tools.json",
      "line": 47,
      "type": "api_key",
      "detector": "trufflehog",
      "verified": true,
      "severity": "CRITICAL",
      "preview": "\"api_key\": \"sk-proj-[REDACTED]\"",
      "remediation": "rotate immediately, migrate to vault injection"
    },
    {
      "file": "logs/mcp-protocol.log",
      "line": 1203,
      "type": "bearer_token",
      "detector": "log_scanner",
      "verified": false,
      "severity": "HIGH",
      "preview": "Authorization: Bearer [REDACTED]"
    }
  ],
  "rotation_status": {
    "tokens_with_no_expiry": 2,
    "tokens_expiring_within_30d": 1,
    "recommendation": "migrate all to vault dynamic secrets with max_ttl=24h"
  }
}
```
