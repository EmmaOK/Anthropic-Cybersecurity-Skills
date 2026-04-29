---
name: llm-excessive-agency-prevention
description: >-
  Prevents LLM-powered applications from being granted or exercising more autonomy, permissions,
  and capabilities than required for their intended function. Excessive agency occurs when LLMs
  are given overly broad tool access, unnecessary permissions, or operate without human oversight
  on high-impact actions — enabling prompt injection and goal hijacking to cause disproportionate
  harm. Covers capability minimization, permission scoping, human-in-the-loop enforcement, and
  autonomous action boundary definition. Based on OWASP LLM Top 10 (LLM06:2025 Excessive Agency).
  Activates when designing tool access policies for LLM agents, auditing deployed LLM applications
  for over-permissioned capabilities, or building containment controls for autonomous AI workflows.
domain: cybersecurity
subdomain: ai-security
tags:
- LLM-security
- OWASP-LLM-Top10
- LLM06
- excessive-agency
- least-privilege
- human-in-the-loop
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0067
- AML.T0068
nist_ai_rmf:
- GOVERN-1.1
- GOVERN-1.7
- MANAGE-3.1
d3fend_techniques:
- User Privilege Analysis
- Application Hardening
nist_csf:
- PR.AA-01
- PR.AA-05
- GV.OC-03
---
# LLM Excessive Agency Prevention

## When to Use

- Auditing an LLM agent's tool list for capabilities it does not need for its intended function
- Reviewing the permission model of an LLM application to identify over-privileged integrations (full mailbox access when only reading is needed)
- Implementing human confirmation requirements for irreversible or high-impact LLM-triggered actions
- Designing the capability boundary for a new LLM agent to enforce least-privilege from the start
- Investigating an incident where prompt injection caused an LLM to take unauthorized actions it had the capability to perform

**Do not use** human-in-the-loop as a catch-all — excessive agency must be addressed at the capability grant level, not just by adding approval steps to an over-privileged agent.

## Prerequisites

- Python 3.10+ with `anthropic` SDK or equivalent
- Documented list of the LLM application's intended functions and required tools
- Access to the agent's tool definition manifest (JSON)
- An approval workflow system (for high-impact action confirmation)

## Workflow

### Step 1: Audit Current Tool Capabilities Against Intended Function

```python
import json

def audit_tool_necessity(tool_manifest: list[dict],
                          intended_function: str,
                          function_required_tools: list[str]) -> dict:
    all_tools = {t["name"] for t in tool_manifest}
    required = set(function_required_tools)
    excess_tools = all_tools - required

    findings = []
    for tool in tool_manifest:
        name = tool["name"]
        scopes = tool.get("oauth_scopes", [])

        if name in excess_tools:
            findings.append({
                "tool": name,
                "finding": "NOT_REQUIRED",
                "severity": "HIGH",
                "detail": f"Tool not needed for '{intended_function}' — remove from manifest",
            })

        # Check for write access when only read is needed
        for scope in scopes:
            if any(rw in scope for rw in [":write", ":delete", ":admin", ":manage"]):
                if name in required:
                    findings.append({
                        "tool": name,
                        "finding": "EXCESSIVE_SCOPE",
                        "scope": scope,
                        "severity": "MEDIUM",
                        "detail": f"Write/delete scope on a tool that only needs read access",
                    })

    return {
        "total_tools": len(all_tools),
        "required_tools": len(required),
        "excess_tools": list(excess_tools),
        "findings": findings,
        "risk": "HIGH" if excess_tools else "LOW",
    }

# Example: email summarizer that only needs to read emails
email_tools = [
    {"name": "email_read",   "oauth_scopes": ["email:read"]},
    {"name": "email_send",   "oauth_scopes": ["email:write"]},
    {"name": "email_delete", "oauth_scopes": ["email:delete"]},
    {"name": "calendar_write", "oauth_scopes": ["calendar:write"]},
]
audit = audit_tool_necessity(email_tools, "summarize inbox", ["email_read"])
print(json.dumps(audit, indent=2))
```

### Step 2: Define Minimum-Capability Tool Manifests

```python
# Principle: define tools with the minimum scope and parameters needed

# EXCESSIVE — full filesystem access
EXCESSIVE_FILESYSTEM_TOOL = {
    "name": "filesystem",
    "description": "Read and write any file on the system",
    "inputSchema": {
        "type": "object",
        "properties": {
            "operation": {"type": "string", "enum": ["read", "write", "delete", "list"]},
            "path": {"type": "string"}  # unbounded path
        }
    }
}

# MINIMAL — read-only access to a specific directory
MINIMAL_FILESYSTEM_TOOL = {
    "name": "report_reader",
    "description": "Read files from the /data/reports/ directory only. Cannot write, delete, or access other directories.",
    "inputSchema": {
        "type": "object",
        "required": ["filename"],
        "properties": {
            "filename": {
                "type": "string",
                "pattern": "^[a-zA-Z0-9_\\-\\.]+\\.pdf$",  # only PDFs, no path traversal
                "maxLength": 64,
            }
        },
        "additionalProperties": False,
    }
}

def enforce_minimal_tool_schema(tool_def: dict) -> list[str]:
    issues = []
    schema = tool_def.get("inputSchema", {})

    if schema.get("additionalProperties", True) is not False:
        issues.append("Tool schema allows additionalProperties — restrict to defined fields only")

    props = schema.get("properties", {})
    for prop_name, prop_schema in props.items():
        if prop_schema.get("type") == "string" and "pattern" not in prop_schema and "enum" not in prop_schema:
            issues.append(f"String property '{prop_name}' has no pattern or enum constraint — add validation")
        if prop_schema.get("type") == "string" and "maxLength" not in prop_schema:
            issues.append(f"String property '{prop_name}' has no maxLength — add a reasonable limit")

    if "required" not in schema or not schema["required"]:
        issues.append("Tool schema has no required fields — define which fields are mandatory")

    return issues
```

### Step 3: Implement Human-in-the-Loop for High-Agency Actions

```python
from enum import Enum

class AgencyLevel(Enum):
    READ_ONLY = 1       # no confirmation needed
    REVERSIBLE_WRITE = 2  # soft confirmation
    IRREVERSIBLE = 3    # hard confirmation + audit
    AUTONOMOUS = 4      # never allowed without explicit override

TOOL_AGENCY_MAP = {
    "email_read":        AgencyLevel.READ_ONLY,
    "file_read":         AgencyLevel.READ_ONLY,
    "web_search":        AgencyLevel.READ_ONLY,
    "calendar_read":     AgencyLevel.READ_ONLY,
    "file_write":        AgencyLevel.REVERSIBLE_WRITE,
    "calendar_write":    AgencyLevel.REVERSIBLE_WRITE,
    "email_send":        AgencyLevel.IRREVERSIBLE,
    "file_delete":       AgencyLevel.IRREVERSIBLE,
    "payment_initiate":  AgencyLevel.IRREVERSIBLE,
    "infrastructure_provision": AgencyLevel.AUTONOMOUS,  # never auto
}

def enforce_agency_level(tool_name: str, args: dict,
                          ask_user, max_agency: AgencyLevel) -> bool:
    level = TOOL_AGENCY_MAP.get(tool_name, AgencyLevel.AUTONOMOUS)

    if level.value > max_agency.value:
        raise PermissionError(
            f"Tool '{tool_name}' requires agency level {level.name} "
            f"but max allowed is {max_agency.name}"
        )

    if level == AgencyLevel.AUTONOMOUS:
        raise PermissionError(
            f"Tool '{tool_name}' is never allowed without explicit human override"
        )

    if level == AgencyLevel.IRREVERSIBLE:
        description = f"{tool_name}: {json.dumps(args)[:200]}"
        decision = ask_user(
            f"[IRREVERSIBLE ACTION CONFIRMATION]\n"
            f"Action: {description}\n"
            f"This cannot be undone. Approve? (yes/no): "
        ).strip().lower()
        return decision in ("yes", "y")

    return True  # READ_ONLY and REVERSIBLE_WRITE proceed
```

### Step 4: Implement Extensionless Plugin Policies

```python
def audit_plugin_agency(plugins: list[dict]) -> list[dict]:
    HIGH_AGENCY_CAPABILITIES = {
        "send_email", "delete_files", "execute_code", "make_payment",
        "modify_database", "call_external_api", "create_users",
        "modify_permissions", "access_credentials",
    }

    findings = []
    for plugin in plugins:
        capabilities = set(plugin.get("capabilities", []))
        excess = capabilities & HIGH_AGENCY_CAPABILITIES
        if excess:
            findings.append({
                "plugin": plugin["name"],
                "high_agency_capabilities": list(excess),
                "severity": "HIGH",
                "recommendation": f"Remove {excess} or require explicit user authorization per invocation"
            })
    return findings
```

### Step 5: Log and Alert on Agency Boundary Violations

```python
import logging, json, datetime

agency_log = logging.getLogger("llm.agency")

def log_agency_event(tool_name: str, agency_level: str,
                      outcome: str, user_id: str, session_id: str):
    event = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "user_id": user_id,
        "session_id": session_id,
        "tool": tool_name,
        "agency_level": agency_level,
        "outcome": outcome,
        "alert": outcome == "BLOCKED" or agency_level == "IRREVERSIBLE"
    }
    agency_log.warning(json.dumps(event))

# Summary report of agency violations over 24h
def agency_violation_report(log_file: str, hours: int = 24) -> dict:
    with open(log_file) as f:
        events = [json.loads(l) for l in f if l.strip()]

    blocked = [e for e in events if e.get("outcome") == "BLOCKED"]
    irreversible_auto = [
        e for e in events
        if e.get("agency_level") == "IRREVERSIBLE" and e.get("outcome") == "AUTO_APPROVED"
    ]

    return {
        "period_hours": hours,
        "total_events": len(events),
        "blocked_actions": len(blocked),
        "irreversible_auto_approved": len(irreversible_auto),
        "top_blocked_tools": [e["tool"] for e in blocked[:10]],
        "risk": "HIGH" if irreversible_auto else ("MEDIUM" if blocked else "LOW")
    }
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Excessive Agency** | Granting an LLM more tools, permissions, or autonomy than necessary for its intended function |
| **Capability Minimization** | Defining the smallest set of tools and scopes that allow an LLM to perform its intended task |
| **Human-in-the-Loop (HITL)** | Requiring human confirmation before the LLM executes high-impact or irreversible actions |
| **Irreversible Action** | An action that cannot be undone once taken — sending an email, deleting a file, initiating a payment |
| **Plugin Policy** | Governance rules controlling which capabilities third-party plugins may expose to the LLM |
| **Agency Level** | A classification of how much autonomous impact a tool action can have, used to calibrate the required confirmation level |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Anthropic tool_use API** | Defines the tool list presented to Claude; removing tools from this list is the most robust capability minimization |
| **OAuth 2.0 Scope Management** | Limits what API integrations can do on behalf of the LLM; request minimum scopes only |
| **OPA (Open Policy Agent)** | Policy-as-code enforcement for tool call authorization in LLM agent frameworks |
| **LangChain Tool Callbacks** | Pre-call hooks for enforcing agency level checks before any tool executes |

## Common Scenarios

- **Email bot with send permission**: A customer support LLM for reading emails is granted `email:write` scope. A prompt injection via a malicious email causes it to send 10,000 spam messages. Removing the send tool entirely prevents the attack vector.
- **Code assistant with shell access**: An LLM coding assistant is given a full bash tool. A user tricks it into running `rm -rf ~/projects`. Agency level for shell is set to IRREVERSIBLE — a confirmation gate would block this.
- **Plugin with unnecessary payment capability**: A document summarizer plugin includes a `make_payment` capability from its vendor's SDK. Audit flags `make_payment` as HIGH agency; the capability is disabled in the plugin manifest.

## Output Format

```json
{
  "audit_timestamp": "2026-04-27T13:00:00Z",
  "intended_function": "summarize customer emails",
  "tool_audit": {
    "total_tools": 6,
    "required_tools": 1,
    "excess_tools": ["email_send", "email_delete", "calendar_write", "file_write", "code_execute"],
    "risk": "HIGH"
  },
  "agency_violations_24h": {
    "blocked_actions": 3,
    "irreversible_auto_approved": 0,
    "top_blocked_tools": ["email_send", "file_delete"]
  },
  "recommendation": "Remove 5 excess tools; keep only email_read"
}
```
