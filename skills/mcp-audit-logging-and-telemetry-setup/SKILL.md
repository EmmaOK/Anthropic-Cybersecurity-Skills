---
name: mcp-audit-logging-and-telemetry-setup
description: >-
  Implements comprehensive, immutable audit logging and telemetry for Model Context Protocol
  tool invocations, context changes, and agent interactions. Builds structured event pipelines
  that capture who called what tool, with what arguments, and what was returned, enabling
  forensic investigation and incident response for AI agent environments. Based on OWASP MCP
  Top 10 (MCP08:2025 Lack of Audit and Telemetry). Activates when building observability for
  MCP deployments, investigating security incidents in AI agent pipelines, or meeting compliance
  requirements for AI system audit trails.
domain: cybersecurity
subdomain: ai-security
tags:
- mcp-security
- audit-logging
- telemetry
- OWASP-MCP-Top10
- observability
- incident-response
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0088
nist_ai_rmf:
- GOVERN-6.1
- GOVERN-6.2
- MEASURE-3.1
d3fend_techniques:
- Audit Log Analysis
- System Call Analysis
nist_csf:
- DE.CM-01
- DE.CM-09
- RS.AN-01
---
# MCP Audit Logging and Telemetry Setup

## When to Use

- Building the audit logging layer for a new MCP server deployment before going to production
- Retrofitting observability into an existing MCP deployment that currently has no structured event trail
- Configuring tamper-evident log storage so audit records cannot be deleted or modified after the fact
- Investigating a security incident in an MCP pipeline — correlating tool calls, context retrievals, and agent decisions
- Meeting regulatory or compliance requirements for audit trails in AI systems (SOC 2, ISO 27001, NIST AI RMF GOVERN-6)

**Do not use** high-verbosity DEBUG logging in production — it may leak sensitive data into logs. Log arguments at INFO level with PII/secret redaction enabled.

## Prerequisites

- Python 3.10+ with `structlog`, `opentelemetry-api`, `opentelemetry-sdk` packages
- A log storage backend: Elasticsearch + Kibana, Splunk, AWS CloudWatch Logs, or Loki + Grafana
- OpenTelemetry Collector for aggregating and routing telemetry
- Write-once log storage (S3 with Object Lock, Azure Immutable Blob Storage) for tamper evidence
- `falco` (optional) for kernel-level syscall auditing of MCP server processes

## Workflow

### Step 1: Implement Structured Audit Event Schema

Define a consistent event schema for all MCP tool interactions:

```python
import structlog, uuid, time
from dataclasses import dataclass, asdict
from typing import Any

@dataclass
class MCPAuditEvent:
    event_id: str
    timestamp: float
    session_id: str
    agent_id: str
    user_id: str
    event_type: str          # TOOL_CALL, TOOL_RESULT, CONTEXT_RETRIEVED, AUTH_FAILURE
    tool_name: str | None
    args_summary: dict       # sanitized args — no secrets, truncated values
    result_summary: str | None
    latency_ms: float | None
    outcome: str             # SUCCESS, ERROR, BLOCKED
    risk_level: str          # LOW, MEDIUM, HIGH, CRITICAL
    source_ip: str | None

def create_tool_call_event(session_id: str, agent_id: str, user_id: str,
                            tool_name: str, args: dict, source_ip: str) -> MCPAuditEvent:
    return MCPAuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp=time.time(),
        session_id=session_id,
        agent_id=agent_id,
        user_id=user_id,
        event_type="TOOL_CALL",
        tool_name=tool_name,
        args_summary=sanitize_args(args),
        result_summary=None,
        latency_ms=None,
        outcome="PENDING",
        risk_level=classify_risk(tool_name),
        source_ip=source_ip
    )
```

### Step 2: Add Audit Middleware to MCP Server

```python
import structlog, time
from functools import wraps

log = structlog.get_logger()

def audit_tool_call(func):
    @wraps(func)
    async def wrapper(tool_name: str, args: dict, context: dict, *a, **kw):
        event = create_tool_call_event(
            session_id=context["session_id"],
            agent_id=context["agent_id"],
            user_id=context["user_id"],
            tool_name=tool_name,
            args=args,
            source_ip=context.get("source_ip")
        )
        start = time.monotonic()
        try:
            result = await func(tool_name, args, context, *a, **kw)
            event.outcome = "SUCCESS"
            event.result_summary = summarize_result(result)
            return result
        except SecurityError as e:
            event.outcome = "BLOCKED"
            event.result_summary = str(e)
            raise
        except Exception as e:
            event.outcome = "ERROR"
            event.result_summary = type(e).__name__
            raise
        finally:
            event.latency_ms = (time.monotonic() - start) * 1000
            log.info("mcp_tool_audit", **asdict(event))
    return wrapper

def sanitize_args(args: dict) -> dict:
    import re
    REDACT = re.compile(r"(token|key|password|secret|bearer)", re.I)
    return {
        k: "[REDACTED]" if REDACT.search(k) else str(v)[:128]
        for k, v in args.items()
    }
```

### Step 3: Configure OpenTelemetry Tracing

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

provider = TracerProvider()
provider.add_span_processor(
    BatchSpanProcessor(OTLPSpanExporter(endpoint="http://otel-collector:4317"))
)
trace.set_tracer_provider(provider)
tracer = trace.get_tracer("mcp-server")

async def traced_tool_call(tool_name: str, args: dict, context: dict):
    with tracer.start_as_current_span(f"mcp.tool.{tool_name}") as span:
        span.set_attribute("mcp.tool.name", tool_name)
        span.set_attribute("mcp.session.id", context["session_id"])
        span.set_attribute("mcp.agent.id", context["agent_id"])
        span.set_attribute("mcp.user.id", context["user_id"])
        span.set_attribute("mcp.risk_level", classify_risk(tool_name))
        # Execute tool...
```

### Step 4: Ship Logs to Tamper-Evident Storage

```bash
# Ship structured JSON logs to S3 with Object Lock (WORM)
aws s3 cp audit-logs/ s3://mcp-audit-logs-immutable/ \
  --recursive \
  --storage-class STANDARD_IA

# Enable Object Lock on the S3 bucket (run once at bucket creation)
aws s3api put-object-lock-configuration \
  --bucket mcp-audit-logs-immutable \
  --object-lock-configuration \
    'ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=COMPLIANCE,Days=365}}'

# Configure Vector to forward logs to both local file and S3
cat > /etc/vector/mcp-audit.toml << 'EOF'
[sources.mcp_logs]
type = "file"
include = ["/var/log/mcp/audit.jsonl"]

[sinks.s3_immutable]
type = "aws_s3"
inputs = ["mcp_logs"]
bucket = "mcp-audit-logs-immutable"
key_prefix = "mcp/{{ timestamp }}"

[sinks.elasticsearch]
type = "elasticsearch"
inputs = ["mcp_logs"]
endpoints = ["http://elasticsearch:9200"]
index = "mcp-audit-%Y.%m.%d"
EOF
```

### Step 5: Create Security Dashboards and Alerts

```bash
# Kibana/Elasticsearch query — detect unusual tool call volumes (possible abuse)
curl -X POST http://elasticsearch:9200/mcp-audit-*/_search -H 'Content-Type: application/json' -d '{
  "aggs": {
    "by_agent": {
      "terms": {"field": "agent_id", "size": 20},
      "aggs": {
        "call_count": {"value_count": {"field": "event_id"}},
        "blocked_count": {
          "filter": {"term": {"outcome": "BLOCKED"}}
        },
        "high_risk_count": {
          "filter": {"terms": {"risk_level": ["HIGH", "CRITICAL"]}}
        }
      }
    }
  },
  "query": {"range": {"timestamp": {"gte": "now-1h"}}}
}'

# Alert rule: more than 10 BLOCKED events from same agent in 5 minutes
# Configure in Kibana Alerting or Grafana Alertmanager
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Tamper-Evident Logging** | Log storage configuration (WORM/Object Lock) that prevents log records from being modified or deleted after writing |
| **Structured Logging** | Emitting log events as machine-readable JSON rather than free-text strings, enabling reliable querying and alerting |
| **OpenTelemetry** | Vendor-neutral observability standard for traces, metrics, and logs; enables correlation across distributed MCP components |
| **Audit Trail** | Ordered, complete record of all significant events in a system that can be used for forensic investigation |
| **SIEM** | Security Information and Event Management — platform that aggregates, correlates, and alerts on security events from audit logs |
| **WORM Storage** | Write Once Read Many — storage that prevents modification of written data, ensuring log integrity |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **structlog** | Python structured logging library that emits JSON-formatted audit events with contextual bindings |
| **OpenTelemetry SDK** | Distributed tracing and metrics library for correlating MCP tool calls across services |
| **Vector** | High-performance log routing tool that can forward MCP audit logs to multiple backends simultaneously |
| **Elasticsearch + Kibana** | Log storage and visualization stack for searching, visualizing, and alerting on MCP audit events |
| **Falco** | Kernel-level runtime security monitor that can detect unusual syscalls from MCP server processes |

## Common Scenarios

- **Missing audit trail during incident response**: An MCP agent exfiltrated data but there is no record of which tool was called or what arguments were passed. After this incident, the audit middleware is deployed and tamper-evident storage configured.
- **Detecting credential harvesting via tool abuse**: The audit dashboard shows agent `agent-007` making 847 calls to `secrets_read` in 10 minutes (baseline: 3/hour). The anomaly alert fires and the session is suspended.
- **Compliance audit for AI system**: A SOC 2 auditor requests evidence that all MCP tool invocations were logged with user attribution. The structured JSONL audit log, stored in S3 Object Lock, provides a complete, unmodifiable record.

## Output Format

```json
{
  "event_id": "evt-f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "timestamp": 1745669400.123,
  "session_id": "session-abc123",
  "agent_id": "agent-007",
  "user_id": "user@example.com",
  "event_type": "TOOL_CALL",
  "tool_name": "file_read",
  "args_summary": {"path": "/data/report.txt"},
  "result_summary": "success: 4.2KB text returned",
  "latency_ms": 142.7,
  "outcome": "SUCCESS",
  "risk_level": "LOW",
  "source_ip": "10.0.1.45"
}
```
