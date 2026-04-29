---
name: mcp-authentication-and-authorization-hardening
description: >-
  Hardens Model Context Protocol server authentication and per-tool authorization to prevent
  unauthorized access during agent-tool interactions. Implements mutual TLS, OAuth 2.0 scopes,
  per-action approval gates, and identity verification for MCP server endpoints. Covers
  authentication misconfiguration detection, authorization bypass testing, and hardening
  checklists for MCP deployments. Based on OWASP MCP Top 10 (MCP07:2025 Insufficient
  Authentication & Authorization). Activates when auditing MCP server access controls,
  implementing zero-trust authentication for AI agent infrastructure, or investigating
  unauthorized MCP tool access incidents.
domain: cybersecurity
subdomain: ai-security
tags:
- mcp-security
- authentication
- authorization
- OWASP-MCP-Top10
- mTLS
- OAuth
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0067
nist_ai_rmf:
- GOVERN-1.1
- GOVERN-6.2
- MANAGE-3.1
d3fend_techniques:
- Multi-factor Authentication
- Credential Hardening
nist_csf:
- PR.AA-01
- PR.AA-03
- PR.AA-05
---
# MCP Authentication and Authorization Hardening

## When to Use

- Auditing MCP server endpoints for missing or weak authentication mechanisms
- Implementing mutual TLS between MCP clients and servers in production deployments
- Configuring OAuth 2.0 scopes and token validation for MCP tool access
- Testing for authorization bypasses such as IDOR, scope confusion, or missing per-action checks
- Hardening MCP server configuration after a default-credential or unauthenticated access incident
- Building a zero-trust access model for multi-agent MCP infrastructures

**Do not use** this skill for managing the credentials themselves — use `mcp-token-management-and-secret-protection` for credential hygiene and rotation.

## Prerequisites

- MCP server with configurable authentication middleware
- OpenSSL or `mkcert` for generating mTLS certificates in dev/test
- An OAuth 2.0 provider (Keycloak, Auth0, Okta, or cloud IAM)
- Python 3.10+ with `cryptography`, `PyJWT`, `httpx` packages
- `nuclei` or `ffuf` for authentication bypass testing (authorized environments only)

## Workflow

### Step 1: Audit Current Authentication Configuration

```bash
# Check if MCP server requires authentication on all endpoints
curl -v http://localhost:3000/tools                    # should return 401
curl -v http://localhost:3000/tools/execute            # should return 401
curl -v http://localhost:3000/admin/                   # should return 401 or 403

# Check for default credentials
curl -u admin:admin http://localhost:3000/admin/       # should fail
curl -u admin:password http://localhost:3000/admin/

# Check TLS configuration
openssl s_client -connect mcp-server:443 -showcerts </dev/null 2>&1 | \
  grep -E "(Protocol|Cipher|subject|issuer)"
```

### Step 2: Implement JWT Bearer Authentication

```python
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt, os
from datetime import datetime

app = FastAPI()
bearer_scheme = HTTPBearer()
JWT_SECRET = os.environ["JWT_SECRET"]
ALGORITHM = "RS256"  # use asymmetric keys in production

def verify_mcp_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM],
                             options={"require": ["sub", "exp", "scope"]})
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    if datetime.utcnow().timestamp() > payload["exp"]:
        raise HTTPException(status_code=401, detail="Token expired")

    return payload

@app.post("/tools/execute")
def execute_tool(tool_name: str, args: dict, token_data: dict = Depends(verify_mcp_token)):
    required_scope = f"mcp:tools:{tool_name}:execute"
    if required_scope not in token_data.get("scope", "").split():
        raise HTTPException(status_code=403, detail=f"Missing scope: {required_scope}")
    # ... execute tool
```

### Step 3: Configure Mutual TLS (mTLS)

```bash
# Generate CA and server/client certificates for MCP mTLS
# CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 \
  -subj "/CN=MCP-CA" -out ca.crt

# MCP server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=mcp-server" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -days 365 -sha256 -out server.crt

# MCP client certificate (one per agent)
openssl genrsa -out agent-client.key 2048
openssl req -new -key agent-client.key -subj "/CN=agent-01" -out agent-client.csr
openssl x509 -req -in agent-client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -days 90 -sha256 -out agent-client.crt
```

```python
import ssl, httpx

# Agent making mTLS-authenticated MCP calls
ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="ca.crt")
ssl_ctx.load_cert_chain("agent-client.crt", "agent-client.key")
ssl_ctx.verify_mode = ssl.CERT_REQUIRED

async with httpx.AsyncClient(verify=ssl_ctx) as client:
    response = await client.post(
        "https://mcp-server:443/tools/execute",
        json={"tool": "file_read", "args": {"path": "/data/report.txt"}},
        headers={"Authorization": f"Bearer {agent_token}"}
    )
```

### Step 4: Implement Per-Action Authorization Checks

```python
from enum import Enum

class ActionRisk(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

ACTION_RISK_MAP = {
    "file_read":      ActionRisk.LOW,
    "file_write":     ActionRisk.HIGH,
    "file_delete":    ActionRisk.CRITICAL,
    "email_send":     ActionRisk.HIGH,
    "code_execute":   ActionRisk.CRITICAL,
    "api_get":        ActionRisk.LOW,
    "api_post":       ActionRisk.MEDIUM,
    "database_read":  ActionRisk.LOW,
    "database_write": ActionRisk.HIGH,
}

def authorize_action(token_data: dict, tool_name: str,
                     action: str, args: dict) -> bool:
    risk = ACTION_RISK_MAP.get(action, ActionRisk.CRITICAL)
    scopes = token_data.get("scope", "").split()

    if risk == ActionRisk.CRITICAL:
        # Require explicit high-privilege scope AND recent authentication (max 5 min)
        if f"mcp:actions:{action}:execute" not in scopes:
            return False
        auth_time = token_data.get("auth_time", 0)
        if datetime.utcnow().timestamp() - auth_time > 300:
            raise HTTPException(status_code=401,
                detail="Re-authentication required for critical actions")

    # Per-resource authorization for file operations
    if tool_name == "file_read" and "path" in args:
        allowed_roots = token_data.get("allowed_paths", [])
        if not any(args["path"].startswith(root) for root in allowed_roots):
            return False

    return True
```

### Step 5: Test for Authorization Bypass

```bash
# Test scope confusion — try to execute with a read-only token
READ_TOKEN=$(get_token_with_scope "mcp:tools:read")
curl -X POST http://localhost:3000/tools/execute \
  -H "Authorization: Bearer $READ_TOKEN" \
  -d '{"tool":"file_delete","args":{"path":"/data/report.txt"}}' \
  # Expected: 403 Forbidden

# Test IDOR — try to access another agent's resources
curl http://localhost:3000/sessions/other-agent-session-id \
  -H "Authorization: Bearer $MY_TOKEN" \
  # Expected: 403 Forbidden

# Run nuclei authentication templates (in authorized test environments)
nuclei -u http://localhost:3000 -t nuclei-templates/authentication/ -json
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Mutual TLS (mTLS)** | TLS variant where both client and server authenticate with certificates, preventing impersonation from either side |
| **OAuth 2.0 Scope** | Fine-grained permission string in a JWT that restricts what actions the bearer is authorized to perform |
| **Per-Action Authorization** | Checking permissions at the individual operation level rather than just at login time |
| **Re-authentication** | Requiring the user/agent to re-prove their identity before performing high-risk operations, even within an active session |
| **IDOR (Insecure Direct Object Reference)** | Authorization flaw where an agent can access another session's resources by guessing or manipulating resource IDs |
| **Zero-Trust** | Security model where no agent is inherently trusted regardless of network location; every request is authenticated and authorized |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Keycloak** | Open-source OAuth 2.0/OIDC provider for issuing scoped JWTs to MCP clients |
| **mkcert** | Developer tool for generating locally-trusted TLS certificates for testing mTLS configurations |
| **PyJWT** | Python library for signing, verifying, and decoding JWT tokens in MCP server middleware |
| **nuclei** | Template-based vulnerability scanner with authentication bypass templates for API security testing |
| **OWASP API Security Top 10** | API2:2023 Broken Authentication and API5:2023 Broken Object Level Authorization provide complementary guidance |

## Common Scenarios

- **Unauthenticated tool listing**: An MCP server exposes `/tools` without authentication, leaking the full capability list to unauthenticated callers. All endpoints should require Bearer token; add the JWT middleware to the tools router.
- **Scope confusion attack**: An agent with only `mcp:tools:read` scope attempts to call `file_delete` by crafting the request manually. Per-action scope check rejects with 403; audit log records the attempt.
- **Stale session executing critical action**: An agent session authenticated 3 hours ago attempts to execute `code_execute`. Re-authentication requirement for CRITICAL actions triggers a 401, requiring fresh credentials.

## Output Format

```json
{
  "audit_timestamp": "2026-04-26T13:00:00Z",
  "mcp_server": "mcp-server:443",
  "authentication_findings": [
    {
      "endpoint": "/tools",
      "finding": "unauthenticated_access_allowed",
      "severity": "CRITICAL",
      "remediation": "add JWT bearer middleware to /tools router"
    }
  ],
  "tls_config": {
    "protocol": "TLSv1.3",
    "mutual_tls": false,
    "finding": "client certificates not required",
    "severity": "HIGH"
  },
  "authorization_test_results": [
    {
      "test": "scope_confusion_file_delete_with_read_token",
      "result": "PASS",
      "http_status": 403
    },
    {
      "test": "idor_cross_session_access",
      "result": "FAIL",
      "http_status": 200,
      "severity": "CRITICAL"
    }
  ]
}
```
