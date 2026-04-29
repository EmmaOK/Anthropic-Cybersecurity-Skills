---
name: agent-identity-and-privilege-governance
description: >-
  Governs AI agent identities, prevents credential caching and reuse across privilege levels,
  and closes the attribution gap in multi-agent systems. Implements per-agent cryptographic
  identity, confused deputy prevention, session isolation, and per-action re-verification
  for high-risk operations. Addresses the unique challenge that AI agents often operate
  without a distinct, auditable identity, enabling privilege escalation through inter-agent
  trust. Based on OWASP Top 10 for Agentic Applications (ASI03:2026 Identity & Privilege
  Abuse). Activates when designing multi-agent authentication architectures, auditing agent
  permission models for privilege escalation paths, or investigating unauthorized actions
  traced to agent identity abuse.
domain: cybersecurity
subdomain: ai-security
tags:
- agentic-security
- identity-management
- privilege-escalation
- OWASP-Agentic-Top10
- ASI03
- confused-deputy
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0067
nist_ai_rmf:
- GOVERN-1.1
- GOVERN-6.1
- MANAGE-3.1
d3fend_techniques:
- Credential Hardening
- User Privilege Analysis
nist_csf:
- PR.AA-01
- PR.AA-05
- DE.CM-01
---
# Agent Identity and Privilege Governance

## When to Use

- Designing the identity model for a multi-agent system where agents delegate tasks to sub-agents
- Auditing existing agent deployments for confused deputy vulnerabilities — where a high-privilege agent acts on behalf of a low-privilege caller without verifying authorization
- Implementing per-agent JWT identities with explicit privilege bounds and auditable action attribution
- Preventing credential caching across sessions — SSH keys, API tokens, or database credentials persisting in agent memory after a task completes
- Investigating incidents where unauthorized actions were traced to an agent operating with inherited or cached credentials it should not have retained

**Do not use** as a substitute for network-level access controls — identity governance provides attribution and authorization, but does not replace firewall or IAM rules.

## Prerequisites

- Python 3.10+ with `PyJWT`, `cryptography`
- An identity provider (Keycloak, Auth0) or internal PKI for issuing agent certificates
- Access to the agent orchestration framework's agent-registration and task-delegation APIs
- A CMDB or agent registry documenting each agent's intended capabilities and maximum privilege level
- Structured audit logs to verify that attribution is correct after identity enforcement is deployed

## Workflow

### Step 1: Issue Cryptographic Identities to Each Agent

```python
import jwt, time, uuid, os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate RSA key pair for agent identity
def generate_agent_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Issue a signed agent identity token
def issue_agent_identity(agent_name: str, max_privilege: str,
                          allowed_tools: list[str], ttl_seconds: int,
                          signing_key) -> str:
    return jwt.encode({
        "iss": "agent-identity-service",
        "sub": agent_name,
        "jti": str(uuid.uuid4()),
        "iat": time.time(),
        "exp": time.time() + ttl_seconds,
        "max_privilege": max_privilege,     # "read_only", "write", "admin"
        "allowed_tools": allowed_tools,
        "agent_id": str(uuid.uuid4()),
        "delegated_by": None,               # populated when delegating to sub-agents
    }, signing_key, algorithm="RS256")

# Register agent with identity service
orchestrator_token = issue_agent_identity(
    agent_name="research-agent-01",
    max_privilege="read_only",
    allowed_tools=["web_search", "file_read", "document_summarize"],
    ttl_seconds=3600,
    signing_key=ORCHESTRATOR_PRIVATE_KEY
)
```

### Step 2: Prevent Confused Deputy Attacks in Agent Delegation

```python
def delegate_to_subagent(parent_token: str, subagent_name: str,
                           task: str, tools_needed: list[str],
                           signing_key) -> str:
    parent_claims = jwt.decode(parent_token, SIGNING_PUBLIC_KEY, algorithms=["RS256"])

    # Critical: sub-agent can only get EQUAL OR LESS privilege than parent
    parent_tools = set(parent_claims["allowed_tools"])
    requested_tools = set(tools_needed)
    excess_tools = requested_tools - parent_tools

    if excess_tools:
        raise PermissionError(
            f"Confused deputy blocked: parent agent '{parent_claims['sub']}' "
            f"cannot delegate tools it doesn't have: {excess_tools}"
        )

    # Sub-agent token inherits parent's max_privilege ceiling
    return issue_agent_identity(
        agent_name=subagent_name,
        max_privilege=parent_claims["max_privilege"],
        allowed_tools=list(requested_tools),
        ttl_seconds=min(int(parent_claims["exp"] - time.time()), 1800),
        signing_key=signing_key,
    )

# Attempting to give sub-agent tools the parent doesn't have
try:
    subtoken = delegate_to_subagent(
        orchestrator_token, "file-writer-sub",
        task="write results to disk",
        tools_needed=["file_write"],  # parent only has file_read
        signing_key=SIGNING_PRIVATE_KEY
    )
except PermissionError as e:
    print(f"CONFUSED DEPUTY BLOCKED: {e}")
```

### Step 3: Purge Cached Credentials After Task Completion

```python
import gc
import ctypes

class CredentialVault:
    def __init__(self):
        self._credentials: dict[str, str] = {}

    def store(self, key: str, value: str, ttl_seconds: int = 300):
        self._credentials[key] = value
        # Schedule purge
        import threading
        threading.Timer(ttl_seconds, self._purge, args=[key]).start()

    def get(self, key: str) -> str | None:
        return self._credentials.get(key)

    def _purge(self, key: str):
        val = self._credentials.pop(key, None)
        if val:
            # Overwrite memory before gc (best-effort; CPython specific)
            try:
                ctypes.memset(id(val), 0, len(val))
            except Exception:
                pass
        gc.collect()

    def purge_all(self):
        keys = list(self._credentials.keys())
        for k in keys:
            self._purge(k)

# Use in agent task handler
vault = CredentialVault()
vault.store("db_password", os.environ["DB_PASSWORD"], ttl_seconds=300)

# After task completes — explicit purge
try:
    result = run_database_query(vault.get("db_password"))
finally:
    vault.purge_all()
    print("Credentials purged from agent memory")
```

### Step 4: Verify Agent Identity on Every High-Privilege Action

```python
PRIVILEGE_LEVELS = {"read_only": 1, "write": 2, "admin": 3}

HIGH_PRIVILEGE_ACTIONS = {
    "file_delete": "write",
    "database_write": "write",
    "user_management": "admin",
    "code_execute": "write",
    "admin_api": "admin",
}

def authorize_action_for_agent(agent_token: str, action: str) -> bool:
    claims = jwt.decode(agent_token, SIGNING_PUBLIC_KEY,
                        algorithms=["RS256"],
                        options={"require": ["sub", "exp", "max_privilege"]})

    if time.time() > claims["exp"]:
        raise PermissionError(f"Agent token expired for '{claims['sub']}'")

    required_privilege = HIGH_PRIVILEGE_ACTIONS.get(action, "read_only")
    agent_privilege = claims["max_privilege"]

    if PRIVILEGE_LEVELS[agent_privilege] < PRIVILEGE_LEVELS[required_privilege]:
        raise PermissionError(
            f"Agent '{claims['sub']}' has privilege '{agent_privilege}' "
            f"but action '{action}' requires '{required_privilege}'"
        )

    # Re-authentication required for admin actions if token is > 5 minutes old
    if required_privilege == "admin":
        token_age = time.time() - claims["iat"]
        if token_age > 300:
            raise PermissionError(
                f"Admin action '{action}' requires fresh authentication "
                f"(token age: {token_age:.0f}s)"
            )

    return True
```

### Step 5: Audit Agent Identity Attribution in Logs

```bash
# Find all actions where agent privilege exceeded their registered maximum
jq 'select(.action_privilege_required > .agent_max_privilege)' \
  /var/log/mcp/audit.jsonl | \
  jq '{agent: .agent_id, action: .tool_name, required: .action_privilege_required,
       agent_max: .agent_max_privilege, timestamp: .timestamp}'

# Find actions taken by agents with no registered identity (attribution gap)
jq 'select(.agent_id == null or .agent_id == "")' /var/log/mcp/audit.jsonl | \
  jq '{tool: .tool_name, session: .session_id, timestamp: .timestamp}'
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Attribution Gap** | The security problem where AI agents lack a distinct, governed identity, making it impossible to audit which agent performed which action |
| **Confused Deputy** | Vulnerability where a high-privilege agent is manipulated into acting on behalf of a lower-privilege caller, bypassing authorization |
| **Credential Caching** | Storing authentication credentials in agent memory or context beyond the scope of the task that required them |
| **Per-Agent Identity** | Assigning each agent a unique cryptographic identity (JWT, certificate) with explicit, limited capabilities |
| **Privilege Ceiling** | The maximum privilege level an agent can hold; cannot be exceeded even when delegating to sub-agents |
| **Re-authentication** | Requiring fresh credential verification before executing admin or high-risk actions, even within an active session |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Keycloak** | Open-source identity provider for issuing scoped JWTs to AI agents with configurable privilege levels |
| **PyJWT** | JWT signing and verification library used to issue and validate agent identity tokens |
| **SPIFFE/SPIRE** | Workload identity framework that provides cryptographic identities to agent processes in cloud-native environments |
| **OpenTelemetry** | Tracing library that propagates agent identity context across distributed agent calls for attribution |

## Common Scenarios

- **Confused deputy via inter-agent trust**: A low-privilege research agent sends a task to a high-privilege executor agent without the executor verifying the original caller's privileges. The delegation validator detects that the executor has tools the caller doesn't, and blocks the escalation.
- **SSH key retained in agent context**: An agent fetches an SSH private key to perform a one-time deployment task, then continues operating with the key in memory. CredentialVault's TTL-based purge removes it after 300 seconds.
- **Unauthenticated agent performing admin action**: An agent spawned without a registered identity attempts to call `user_management`. Authorization check finds `agent_id == null` and raises a PermissionError, logging the attribution-gap event.

## Output Format

```json
{
  "audit_timestamp": "2026-04-26T18:00:00Z",
  "agent_identity_events": [
    {
      "event_type": "CONFUSED_DEPUTY_BLOCKED",
      "parent_agent": "research-agent-01",
      "subagent_requested": "file-writer-sub",
      "excess_tools_requested": ["file_delete", "database_write"],
      "severity": "CRITICAL",
      "action": "delegation_denied"
    },
    {
      "event_type": "CREDENTIAL_PURGED",
      "agent_id": "research-agent-01",
      "credential_key": "db_password",
      "purge_reason": "task_completed",
      "severity": "INFO"
    }
  ],
  "attribution_gaps": 0,
  "privilege_violations": 1
}
```
