---
name: ai-data-operations-availability-and-integrity
description: >-
  Hardens data infrastructure underlying AI agent operations against MAESTRO Layer 2
  (Data Operations) threats not covered by rag-pipeline-security-and-data-provenance:
  denial-of-service attacks targeting SQL databases, vector stores, object stores, and
  event streaming pipelines (L2-T03); and data tampering attacks against structured data
  in transit or at rest outside RAG contexts (L2-T04). Audits connection limits, query
  timeouts, replication and failover configuration, encryption in transit and at rest,
  integrity checksums, immutable storage controls, change data capture audit trails,
  and anomaly detection on data access patterns for all data infrastructure components
  that AI agents depend on.
domain: cybersecurity
subdomain: ai-security
tags:
  - MAESTRO
  - data-operations
  - data-integrity
  - data-availability
  - database-security
  - event-streaming
  - DoS-prevention
  - data-tampering
  - agentic-ai
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - PR.DS-01
  - PR.DS-05
  - PR.IR-01
  - DE.CM-01
  - DE.AE-04
atlas_techniques:
  - AML.T0043
  - AML.T0056
nist_ai_rmf:
  - GOVERN-5.2
  - MANAGE-2.4
  - MEASURE-2.9
d3fend_techniques:
  - Data Integrity Verification
  - Network Traffic Filtering
  - Content Validation
  - Audit Log Analysis
---
# AI Data Operations Availability and Integrity

## When to Use

- Auditing SQL databases, vector stores, object stores, or event streams that AI agents depend on for availability and integrity controls
- Assessing whether data infrastructure can withstand connection exhaustion, query flooding, or availability attacks
- Checking that data tampered in transit (e.g., via man-in-the-middle on database connections) or at rest (e.g., direct storage manipulation) would be detected
- Building a MAESTRO Layer 2 (Data Operations) L2-T03/L2-T04 evidence package for a threat model
- Reviewing data infrastructure after an incident where agent behavior became anomalous due to corrupted or unavailable data

**Complements `rag-pipeline-security-and-data-provenance`:** That skill covers RAG-specific pipelines (retrieval, embedding, vector DB injection). This skill covers the broader data infrastructure availability and integrity controls applicable to all data stores AI agents use, not just RAG architectures.

## Prerequisites

- Python 3.9+ (no external dependencies — stdlib only)
- A data ops config JSON describing the data infrastructure (see Workflow for schema)

## Workflow

### 1. Create a data ops config

```json
{
  "system": "Agent Data Infrastructure",
  "databases": [
    {
      "name": "agent-state-db",
      "type": "postgresql",
      "encryption_at_rest": false,
      "encryption_in_transit": false,
      "connection_limits_configured": false,
      "query_timeout_configured": false,
      "access_controlled": true,
      "backup_enabled": false,
      "point_in_time_recovery": false,
      "integrity_checksums": false,
      "change_data_capture": false,
      "replication_enabled": false,
      "anomaly_detection": false
    }
  ],
  "event_streams": [
    {
      "name": "agent-events",
      "type": "kafka",
      "encryption_in_transit": false,
      "client_authentication": false,
      "consumer_group_isolation": false,
      "message_integrity_verification": false,
      "retention_policy": false,
      "rate_limiting_per_producer": false
    }
  ],
  "object_stores": [
    {
      "name": "model-artifacts",
      "type": "s3",
      "versioning_enabled": false,
      "integrity_checksums": false,
      "access_logging": false,
      "mfa_delete_enabled": false,
      "replication_enabled": false,
      "immutability_lock": false
    }
  ],
  "availability": {
    "health_monitoring": false,
    "auto_failover": false,
    "query_rate_limiting": false,
    "ddos_protection_enabled": false,
    "connection_pool_limits": false,
    "circuit_breaker_pattern": false
  }
}
```

### 2. Audit data operations infrastructure

```bash
python agent.py audit --config data_ops_config.json --output data_ops_audit.json
```

### 3. Review findings

Prioritize: `encryption_in_transit`, `connection_limits_configured`, `integrity_checksums`, and `auto_failover` — these four controls block the most impactful L2-T03 and L2-T04 attacks.

## Key Concepts

| Concept | Description |
|---|---|
| DoS on Data Infrastructure (L2-T03) | Overwhelming database connections, exhausting event stream consumers, or flooding object store APIs to deny AI agents access to required data |
| Data Tampering (L2-T04) | Modifying agent state data, training artifacts, or configuration records in transit (MITM on unencrypted DB connections) or at rest (direct storage manipulation) |
| Integrity Checksums | Hash-based verification of stored data blocks — detects at-rest tampering by comparing computed vs. stored hashes |
| Change Data Capture (CDC) | Streaming of all database mutations to an append-only audit log — enables detection of unauthorized writes |
| Connection Pool Exhaustion | DoS variant: attacker opens many idle database connections to prevent legitimate agent queries from acquiring a connection slot |
| Circuit Breaker | Pattern that detects downstream data store failures and fails fast (instead of queuing requests), preventing cascade failures in agent pipelines |
| Immutability Lock | Object store feature (S3 Object Lock, Azure Immutable Blob) that prevents deletion or modification of objects for a defined retention period |

## Tools & Systems

| Tool | Purpose |
|---|---|
| agent.py `audit` | Static audit of data infrastructure config against 22 Layer 2 availability/integrity controls |
| pgBouncer / PgCat | PostgreSQL connection poolers with connection limit enforcement |
| Kafka ACLs / mTLS | Kafka access control and in-transit encryption |
| AWS Macie / Datadog | Anomaly detection on data access patterns |
| Percona PMM | Database monitoring and query anomaly detection |
| S3 Object Lock | WORM (Write-Once-Read-Many) immutability for model artifacts |

## Common Scenarios

**AI agent state database without connection limits:**
`connection_limits_configured: false` is HIGH — a malfunctioning or compromised agent can exhaust the connection pool, denying service to all agents sharing the database.

**Event stream without client authentication:**
`client_authentication: false` is CRITICAL — any process with network access can inject forged events into the agent event pipeline, corrupting agent state.

**Model artifacts in S3 without versioning or integrity checksums:**
Both `versioning_enabled: false` and `integrity_checksums: false` are HIGH — an overwrite attack replaces production model artifacts without detection or rollback capability.

**Database connections without encryption in transit:**
`encryption_in_transit: false` is CRITICAL — agent queries and responses (including internal state, retrieved data, and tool results) traverse the network in plaintext.

**No auto-failover for primary agent database:**
`auto_failover: false` is HIGH — a database restart or crash causes total agent unavailability with no automated recovery path.

## Output Format

```json
{
  "audit_timestamp": "2026-05-02T10:00:00+00:00",
  "system": "Agent Data Infrastructure",
  "total_checks": 22,
  "findings": [
    {
      "id": "DATA-001",
      "severity": "CRITICAL",
      "layer": "L2",
      "threat": "Data Tampering (L2-T04)",
      "control": "Database encryption in transit",
      "finding": "encryption_in_transit is false for agent-state-db — database traffic is unencrypted",
      "remediation": "Enable TLS on PostgreSQL connections (ssl = on in postgresql.conf); require ssl_mode=require in all client connection strings"
    },
    {
      "id": "DATA-002",
      "severity": "CRITICAL",
      "layer": "L2",
      "threat": "DoS on Data Infrastructure (L2-T03)",
      "control": "Event stream client authentication",
      "finding": "client_authentication is false for agent-events Kafka — any client can produce or consume",
      "remediation": "Enable Kafka mTLS or SASL authentication; apply ACLs restricting topic access to authorized agent service accounts"
    },
    {
      "id": "DATA-005",
      "severity": "HIGH",
      "layer": "L2",
      "threat": "Data Tampering (L2-T04)",
      "control": "Object store integrity and versioning",
      "finding": "versioning_enabled and integrity_checksums are both false for model-artifacts store",
      "remediation": "Enable S3 versioning and Object Lock; verify SHA-256 checksums on model artifact download in serving code"
    }
  ],
  "by_severity": { "CRITICAL": 3, "HIGH": 9, "MEDIUM": 7, "LOW": 3 },
  "overall_risk": "CRITICAL",
  "recommendation": "3 CRITICAL findings require immediate remediation. Encrypt all data in transit before addressing integrity and availability controls."
}
```
