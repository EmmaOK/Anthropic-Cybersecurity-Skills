---
name: mcp-privilege-scope-enforcement
description: >-
  Audits and enforces least-privilege scope boundaries on Model Context Protocol server
  permissions. Detects scope expansion over time (scope creep) and revokes excessive
  capabilities before they enable unintended repository modification, data exfiltration,
  or lateral movement. Implements permission diffing, OPA-based policy enforcement, and
  automated scope review workflows. Based on OWASP MCP Top 10 (MCP02:2025 Privilege
  Escalation via Scope Creep). Activates when auditing MCP agent permissions, reviewing
  scope changes in AI infrastructure, or hardening least-privilege posture for MCP tools.
domain: cybersecurity
subdomain: ai-security
tags:
- mcp-security
- privilege-escalation
- least-privilege
- OWASP-MCP-Top10
- scope-management
- access-control
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
- User Privilege Analysis
- Permission Graph Analysis
nist_csf:
- PR.AA-01
- PR.AA-05
- DE.CM-01
---
# MCP Privilege Scope Enforcement

## When to Use

- Performing a least-privilege audit of MCP server tool permissions and OAuth scopes
- Detecting scope creep by comparing current agent permissions against an approved baseline
- Enforcing scope boundaries using policy-as-code to block over-privileged MCP tool registrations
- Reviewing permission changes after MCP server updates to detect unauthorized scope expansions
- Responding to incidents where an MCP agent performed unexpected actions beyond its intended scope

**Do not use** for authentication enforcement — scope controls what an authenticated agent can do, not whether it should be allowed in at all.

## Prerequisites

- MCP server configuration files documenting tool permissions and OAuth scopes
- `jq` for JSON permission diffing
- Open Policy Agent (OPA): `brew install opa` or download from openpolicyagent.org
- Python 3.10+ for permission inventory scripts
- A baseline permissions snapshot (created during initial deployment)
- Access to MCP server runtime API or config to query current scopes

## Workflow

### Step 1: Inventory Current MCP Tool Permissions

Extract all tool definitions and their declared permission scopes from the MCP server manifest:

```bash
# Dump current tool list with permissions from MCP server
curl -s http://localhost:3000/tools | jq '[.tools[] | {
  name: .name,
  permissions: .permissions,
  oauth_scopes: .oauth_scopes,
  last_modified: .last_modified
}]' > current-permissions.json

# For file-based MCP configs, parse all tool definitions
grep -r "permissions\|scopes\|capabilities" ./mcp-config/ --include="*.json" | \
  python3 -c "
import sys, json, re
findings = []
for line in sys.stdin:
  fname, _, content = line.partition(':')
  findings.append({'file': fname, 'content': content.strip()})
print(json.dumps(findings, indent=2))
" > permission-inventory.json
```

### Step 2: Compare Against Approved Baseline

```bash
# Create baseline on initial deployment
cp current-permissions.json permissions-baseline.json

# On subsequent runs, diff against baseline
jq -n \
  --slurpfile baseline permissions-baseline.json \
  --slurpfile current current-permissions.json '
  ($current[0] | map({(.name): .permissions}) | add) as $cur |
  ($baseline[0] | map({(.name): .permissions}) | add) as $base |
  {
    new_tools: ([$cur | keys[] | select(. as $k | $base | has($k) | not)] | sort),
    removed_tools: ([$base | keys[] | select(. as $k | $cur | has($k) | not)] | sort),
    scope_changes: [
      $cur | to_entries[] |
      select(.key as $k | $base | has($k)) |
      select(.value != $base[.key]) |
      {tool: .key, old: $base[.key], new: .value}
    ]
  }
' > scope-diff.json

cat scope-diff.json
```

### Step 3: Define and Enforce Scope Policy with OPA

Create a Rego policy that blocks over-privileged tool registrations:

```rego
# policy/mcp_scope.rego
package mcp.scope

import future.keywords.if

# Maximum allowed scopes per tool category
allowed_scopes := {
  "read_only": {"files:read", "calendar:read", "email:read"},
  "write":     {"files:read", "files:write", "calendar:write"},
  "admin":     {"files:read", "files:write", "admin:users:read"},
}

# Deny any tool requesting scopes outside its declared category
deny[msg] if {
  tool := input.tools[_]
  scope := tool.oauth_scopes[_]
  not scope in allowed_scopes[tool.category]
  msg := sprintf("Tool '%v' requests unauthorized scope '%v' for category '%v'",
    [tool.name, scope, tool.category])
}

# Deny tools with wildcard scopes
deny[msg] if {
  tool := input.tools[_]
  scope := tool.oauth_scopes[_]
  contains(scope, "*")
  msg := sprintf("Tool '%v' uses wildcard scope '%v' — not permitted", [tool.name, scope])
}
```

```bash
# Validate MCP config against policy
opa eval --data policy/mcp_scope.rego \
  --input current-permissions.json \
  'data.mcp.scope.deny' --format pretty

# Returns empty set if compliant, violations if not
```

### Step 4: Revoke Excessive Scopes

```python
import json, requests

def revoke_excess_scopes(tool_name: str, scopes_to_remove: list[str],
                          mcp_admin_url: str, admin_token: str) -> dict:
    resp = requests.patch(
        f"{mcp_admin_url}/tools/{tool_name}/scopes",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"remove_scopes": scopes_to_remove}
    )
    resp.raise_for_status()
    return resp.json()

# Example: remove admin scope from a read-only tool
with open("scope-diff.json") as f:
    diff = json.load(f)

for change in diff["scope_changes"]:
    excess = list(set(change["new"]) - set(change["old"]))
    if excess:
        result = revoke_excess_scopes(
            tool_name=change["tool"],
            scopes_to_remove=excess,
            mcp_admin_url="http://localhost:3000/admin",
            admin_token="ADMIN_TOKEN"
        )
        print(f"Revoked {excess} from {change['tool']}: {result}")
```

### Step 5: Schedule Automated Scope Reviews

```bash
# Add to cron or CI pipeline — run nightly scope audit
#!/bin/bash
set -e
curl -s http://localhost:3000/tools > current-permissions.json
DIFF=$(jq '.scope_changes | length' scope-diff.json)
if [ "$DIFF" -gt "0" ]; then
  echo "ALERT: $DIFF scope changes detected" | \
    mail -s "[MCP] Scope Creep Alert" security@example.com
  cat scope-diff.json >> /var/log/mcp/scope-audit.log
fi
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Scope Creep** | Gradual, often unnoticed expansion of agent permissions beyond what was originally approved |
| **Least Privilege** | Security principle granting only the minimum permissions required for an agent to perform its intended function |
| **OAuth Scope** | A string identifier that restricts what actions a bearer token can authorize (e.g., `files:read`, `email:write`) |
| **Permission Baseline** | Approved snapshot of all tool permissions at a known-good point, used for drift detection |
| **OPA (Open Policy Agent)** | Policy-as-code engine that evaluates JSON-structured data against Rego policies at decision time |
| **Confused Deputy** | Vulnerability where a high-privilege agent is tricked into acting on behalf of a less-privileged caller |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Open Policy Agent (OPA)** | Policy-as-code enforcement engine; evaluates MCP tool permissions against Rego rules |
| **jq** | Command-line JSON processor for diffing permission snapshots and extracting scope changes |
| **MCP Inspector** | Official MCP debug UI; shows all tool permissions and scopes visible in an active session |
| **AWS IAM Access Analyzer** | Validates IAM policies attached to MCP-invoked AWS resources for excessive permissions |
| **Trivy** | Misconfiguration scanner that can flag overprivileged service account bindings in MCP container deployments |

## Common Scenarios

- **Incremental scope expansion**: An MCP tool initially registered with `email:read` is updated to include `email:write` and `calendar:write` without a security review. The baseline diff surfaces this; the write scopes are revoked pending approval.
- **Wildcard scope in development carried to production**: A developer sets `oauth_scopes: ["*"]` during local testing. The OPA policy catches the wildcard and blocks the deployment pipeline.
- **Orphaned tool with admin scope**: A deprecated analytics tool retains `admin:users:read` from a previous integration. Periodic scope audit flags it as a removed-but-still-permissioned tool; the scope is revoked during cleanup.

## Output Format

```json
{
  "audit_timestamp": "2026-04-26T09:00:00Z",
  "baseline_date": "2026-03-01T00:00:00Z",
  "policy_violations": [
    {
      "tool": "data-export-tool",
      "violation": "requests scope 'admin:users:delete' outside category 'write'",
      "severity": "CRITICAL",
      "action": "block_registration"
    }
  ],
  "scope_drift": {
    "new_tools": ["experimental-search-v2"],
    "scope_changes": [
      {
        "tool": "calendar-assistant",
        "old_scopes": ["calendar:read"],
        "new_scopes": ["calendar:read", "calendar:write"],
        "change_type": "expansion",
        "approved": false
      }
    ]
  },
  "recommendation": "revoke calendar:write from calendar-assistant pending security review"
}
```
