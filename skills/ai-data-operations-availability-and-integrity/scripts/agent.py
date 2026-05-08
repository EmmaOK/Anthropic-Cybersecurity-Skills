#!/usr/bin/env python3
"""
AI Data Operations Availability and Integrity Auditor
MAESTRO Layer 2 (Data Operations) — L2-T03 DoS on Data Infrastructure,
L2-T04 Data Tampering. Checks 22 controls across databases,
event streams, object stores, and availability infrastructure.
"""
import argparse
import copy
import json
import sys
from datetime import datetime, timezone


DB_CONTROLS = [
    {
        "id": "DATA-001", "category": "Database",
        "threat": "Data Tampering (L2-T04)",
        "control": "Database encryption in transit",
        "config_key": "encryption_in_transit",
        "severity": "CRITICAL",
        "finding_false": "Database connections are not encrypted in transit — agent queries, internal state, tool results, and retrieved data traverse the network in plaintext",
        "remediation": "Enable TLS on all database connections; set ssl_mode=require in all client connection strings; rotate certificates annually",
    },
    {
        "id": "DATA-002", "category": "Database",
        "threat": "Data Tampering (L2-T04)",
        "control": "Database encryption at rest",
        "config_key": "encryption_at_rest",
        "severity": "HIGH",
        "finding_false": "Database storage is not encrypted at rest — physical or snapshot access to storage media exposes all agent state data",
        "remediation": "Enable storage-level encryption (AWS RDS encryption, PostgreSQL pgcrypto for sensitive columns, disk-level encryption for self-managed databases)",
    },
    {
        "id": "DATA-003", "category": "Database",
        "threat": "DoS on Data Infrastructure (L2-T03)",
        "control": "Database connection limits",
        "config_key": "connection_limits_configured",
        "severity": "HIGH",
        "finding_false": "No connection limits configured — a malfunctioning or compromised agent can exhaust the database connection pool, denying service to all agents sharing the database",
        "remediation": "Configure max_connections in the database; deploy a connection pooler (pgBouncer) with per-client connection limits; set pool_size appropriate to agent concurrency",
    },
    {
        "id": "DATA-004", "category": "Database",
        "threat": "DoS on Data Infrastructure (L2-T03)",
        "control": "Query timeout configuration",
        "config_key": "query_timeout_configured",
        "severity": "HIGH",
        "finding_false": "No query timeouts configured — a pathologically slow or deliberately crafted query can hold database locks indefinitely, blocking other agents",
        "remediation": "Set statement_timeout (PostgreSQL) or max_execution_time (MySQL) appropriate to expected query patterns; apply lock_timeout to prevent indefinite lock waits",
    },
    {
        "id": "DATA-005", "category": "Database",
        "threat": "DoS on Data Infrastructure (L2-T03)",
        "control": "Database replication / high availability",
        "config_key": "replication_enabled",
        "severity": "HIGH",
        "finding_false": "No database replication — a single database failure causes complete agent data unavailability with no automatic failover",
        "remediation": "Configure primary-replica replication with automated failover (RDS Multi-AZ, Patroni, CloudSQL HA); test failover quarterly",
    },
    {
        "id": "DATA-006", "category": "Database",
        "threat": "DoS on Data Infrastructure (L2-T03)",
        "control": "Backup and point-in-time recovery",
        "config_key": "backup_enabled",
        "severity": "HIGH",
        "finding_false": "Database backups are not enabled — data destroyed by DoS or tampering cannot be recovered; agent system cannot be restored to a known-good state",
        "remediation": "Enable automated daily backups with at least 7-day retention; test restore procedure quarterly; configure point-in-time recovery (PITR) for granular recovery",
    },
    {
        "id": "DATA-007", "category": "Database",
        "threat": "Data Tampering (L2-T04)",
        "control": "Data integrity checksums",
        "config_key": "integrity_checksums",
        "severity": "HIGH",
        "finding_false": "No integrity checksums on stored data — at-rest tampering (direct storage manipulation, snapshot modification) is undetectable",
        "remediation": "Enable page-level checksums (PostgreSQL data_checksums); add application-level HMAC for sensitive rows; verify checksums on restore",
    },
    {
        "id": "DATA-008", "category": "Database",
        "threat": "Data Tampering (L2-T04)",
        "control": "Change data capture (mutation audit trail)",
        "config_key": "change_data_capture",
        "severity": "HIGH",
        "finding_false": "No change data capture — unauthorized writes, deletions, or modifications to agent data cannot be detected or attributed after the fact",
        "remediation": "Enable CDC (PostgreSQL logical replication, Debezium) streaming all mutations to an append-only audit log; retain for 90 days minimum",
    },
    {
        "id": "DATA-009", "category": "Database",
        "threat": "Data Tampering / DoS (L2-T03 / L2-T04)",
        "control": "Anomaly detection on data access patterns",
        "config_key": "anomaly_detection",
        "severity": "MEDIUM",
        "finding_false": "No anomaly detection on database access — bulk reads, unusual update patterns, or access from unexpected service accounts go undetected",
        "remediation": "Configure query analytics (pg_stat_statements, Datadog DBM) and alert on anomalies: bulk reads, high row delete rates, access from unknown principals",
    },
]

STREAM_CONTROLS = [
    {
        "id": "DATA-010", "category": "Event Stream",
        "threat": "Data Tampering (L2-T04)",
        "control": "Event stream encryption in transit",
        "config_key": "encryption_in_transit",
        "severity": "CRITICAL",
        "finding_false": "Event stream traffic is not encrypted — agent events, state transitions, and inter-agent messages are exposed in plaintext on the network",
        "remediation": "Enable TLS on all Kafka/Kinesis/Pub-Sub connections; require TLS in all producer and consumer configurations",
    },
    {
        "id": "DATA-011", "category": "Event Stream",
        "threat": "Data Tampering / DoS (L2-T03 / L2-T04)",
        "control": "Event stream client authentication",
        "config_key": "client_authentication",
        "severity": "CRITICAL",
        "finding_false": "No client authentication on event stream — any process with network access can produce forged events or consume agent messages, enabling data injection and eavesdropping",
        "remediation": "Enable Kafka mTLS or SASL/SCRAM authentication; apply ACLs restricting topic access to authorized agent service accounts; reject unauthenticated producers",
    },
    {
        "id": "DATA-012", "category": "Event Stream",
        "threat": "DoS on Data Infrastructure (L2-T03)",
        "control": "Consumer group isolation",
        "config_key": "consumer_group_isolation",
        "severity": "MEDIUM",
        "finding_false": "No consumer group isolation — a malfunctioning agent consumer can slow processing for all agents sharing the same consumer group",
        "remediation": "Assign separate consumer groups per agent type; configure lag monitoring and alert when consumer lag exceeds threshold for any agent group",
    },
    {
        "id": "DATA-013", "category": "Event Stream",
        "threat": "Data Tampering (L2-T04)",
        "control": "Message integrity verification",
        "config_key": "message_integrity_verification",
        "severity": "HIGH",
        "finding_false": "Event stream messages are not integrity-verified — a man-in-the-middle or compromised broker can modify messages without detection",
        "remediation": "Add HMAC-SHA256 signature to event payloads at producer; verify at consumer before processing; reject messages with invalid signatures",
    },
    {
        "id": "DATA-014", "category": "Event Stream",
        "threat": "DoS on Data Infrastructure (L2-T03)",
        "control": "Per-producer rate limiting",
        "config_key": "rate_limiting_per_producer",
        "severity": "HIGH",
        "finding_false": "No per-producer rate limits — a flooding agent or external attacker can overwhelm the event stream, causing consumer lag and agent starvation",
        "remediation": "Configure Kafka quota per producer principal (quota.producer.byte-rate); implement back-pressure at the API gateway for event submission endpoints",
    },
]

OBJECT_STORE_CONTROLS = [
    {
        "id": "DATA-015", "category": "Object Store",
        "threat": "Data Tampering (L2-T04)",
        "control": "Object versioning enabled",
        "config_key": "versioning_enabled",
        "severity": "HIGH",
        "finding_false": "Object versioning is not enabled — model artifacts, training data, or configuration files overwritten by a tampering attack cannot be recovered",
        "remediation": "Enable S3 versioning or equivalent; retain at least 30 days of version history; enable MFA delete for the most sensitive artifact buckets",
    },
    {
        "id": "DATA-016", "category": "Object Store",
        "threat": "Data Tampering (L2-T04)",
        "control": "Object integrity checksums",
        "config_key": "integrity_checksums",
        "severity": "HIGH",
        "finding_false": "No integrity checksums on object store artifacts — a modified model weight file or training dataset cannot be detected at download time",
        "remediation": "Store SHA-256 checksums for all critical objects in a signed manifest; verify checksums after download before using artifacts in training or inference",
    },
    {
        "id": "DATA-017", "category": "Object Store",
        "threat": "Data Tampering / DoS (L2-T03 / L2-T04)",
        "control": "Object store access logging",
        "config_key": "access_logging",
        "severity": "HIGH",
        "finding_false": "Object store access is not logged — unauthorized reads or writes to model artifacts, training data, or configuration are undetectable",
        "remediation": "Enable S3 server access logging or CloudTrail data events for all buckets containing AI artifacts; alert on unexpected access patterns",
    },
    {
        "id": "DATA-018", "category": "Object Store",
        "threat": "Data Tampering (L2-T04)",
        "control": "Immutability lock on critical artifacts",
        "config_key": "immutability_lock",
        "severity": "MEDIUM",
        "finding_false": "No immutability lock on critical model artifacts — a compromised pipeline can silently overwrite production model weights",
        "remediation": "Apply S3 Object Lock (COMPLIANCE mode) to production model artifact versions; set retention period covering the model's active deployment window",
    },
]

AVAILABILITY_CONTROLS = [
    {
        "id": "DATA-019", "category": "Availability",
        "threat": "DoS on Data Infrastructure (L2-T03)",
        "control": "Health monitoring for all data stores",
        "config_key": "health_monitoring",
        "severity": "HIGH",
        "finding_false": "Data store health is not monitored — a failing database, degraded event stream, or object store outage may not be detected until agents begin failing",
        "remediation": "Configure health checks for all data stores (RDS Enhanced Monitoring, Kafka JMX, S3 bucket metrics); alert on latency spikes and error rates",
    },
    {
        "id": "DATA-020", "category": "Availability",
        "threat": "DoS on Data Infrastructure (L2-T03)",
        "control": "Automated failover capability",
        "config_key": "auto_failover",
        "severity": "HIGH",
        "finding_false": "No automated failover — a primary data store failure causes complete agent unavailability until manual intervention restores service",
        "remediation": "Configure automated failover for all critical data stores; test failover by forcing primary failure in staging quarterly; measure RTO against SLA",
    },
    {
        "id": "DATA-021", "category": "Availability",
        "threat": "DoS on Data Infrastructure (L2-T03)",
        "control": "Query rate limiting to prevent overload",
        "config_key": "query_rate_limiting",
        "severity": "HIGH",
        "finding_false": "No query rate limiting — a single agent in a tight loop or a connection flood can saturate database CPU, degrading all agents sharing the data store",
        "remediation": "Implement per-client query rate limits at the connection pooler or application layer; apply exponential backoff in agent data access clients",
    },
    {
        "id": "DATA-022", "category": "Availability",
        "threat": "DoS on Data Infrastructure (L2-T03)",
        "control": "Circuit breaker pattern for data store access",
        "config_key": "circuit_breaker_pattern",
        "severity": "MEDIUM",
        "finding_false": "No circuit breaker — agents queue requests to a failing data store indefinitely, amplifying the DoS by exhausting agent thread pools and downstream memory",
        "remediation": "Implement circuit breaker (resilience4j, Hystrix) around all data store clients; fail fast with a cached fallback or degraded response when data store is unhealthy",
    },
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def audit_list(config_list: list, controls: list, name_key: str = "name") -> list:
    findings = []
    for item in config_list:
        item_name = item.get(name_key, "unknown")
        for ctrl in controls:
            value = item.get(ctrl["config_key"], None)
            if value is False or value is None:
                finding_text = ctrl["finding_false"]
                if value is None:
                    finding_text = f"Field '{ctrl['config_key']}' missing — {ctrl['finding_false']}"
                findings.append({
                    "id": ctrl["id"],
                    "severity": ctrl["severity"],
                    "layer": "L2",
                    "category": ctrl["category"],
                    "resource": item_name,
                    "threat": ctrl["threat"],
                    "control": ctrl["control"],
                    "finding": f"[{item_name}] {finding_text}",
                    "remediation": ctrl["remediation"],
                })
    return findings


def audit_dict(config_dict: dict, controls: list) -> list:
    findings = []
    for ctrl in controls:
        value = config_dict.get(ctrl["config_key"], None)
        if value is False or value is None:
            finding_text = ctrl["finding_false"]
            if value is None:
                finding_text = f"Field '{ctrl['config_key']}' missing — {ctrl['finding_false']}"
            findings.append({
                "id": ctrl["id"],
                "severity": ctrl["severity"],
                "layer": "L2",
                "category": ctrl["category"],
                "threat": ctrl["threat"],
                "control": ctrl["control"],
                "finding": finding_text,
                "remediation": ctrl["remediation"],
            })
    return findings


def compute_risk(findings: list) -> str:
    severities = {f["severity"] for f in findings}
    if "CRITICAL" in severities:
        return "CRITICAL"
    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"
    if findings:
        return "LOW"
    return "PASS"


def main():
    parser = argparse.ArgumentParser(
        description="AI Data Operations Availability and Integrity Auditor (MAESTRO L2 — L2-T03/L2-T04)"
    )
    sub = parser.add_subparsers(dest="command")

    audit_p = sub.add_parser("audit", help="Audit data infrastructure against 22 Layer 2 availability/integrity controls")
    audit_p.add_argument("--config", required=True, help="Path to data ops config JSON")
    audit_p.add_argument("--output", default="data_ops_audit.json", help="Output file path")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    with open(args.config) as f:
        config = json.load(f)

    findings = []
    findings += audit_list(config.get("databases", []), DB_CONTROLS)
    findings += audit_list(config.get("event_streams", []), STREAM_CONTROLS)
    findings += audit_list(config.get("object_stores", []), OBJECT_STORE_CONTROLS)
    findings += audit_dict(config.get("availability", {}), AVAILABILITY_CONTROLS)

    # Deduplicate on id+resource (multiple databases may trigger same control)
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["id"], f.get("resource", ""))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    unique_findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))

    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in unique_findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    overall_risk = compute_risk(unique_findings)
    total_checks = (
        len(config.get("databases", [])) * len(DB_CONTROLS)
        + len(config.get("event_streams", [])) * len(STREAM_CONTROLS)
        + len(config.get("object_stores", [])) * len(OBJECT_STORE_CONTROLS)
        + len(AVAILABILITY_CONTROLS)
    )

    report = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "system": config.get("system", "unknown"),
        "methodology": "MAESTRO Layer 2 (Data Operations) — ai-data-operations-availability-and-integrity v1.0",
        "maestro_threats_covered": ["L2-T03 (DoS on Data Infrastructure)", "L2-T04 (Data Tampering)"],
        "total_checks": total_checks,
        "findings_count": len(unique_findings),
        "by_severity": by_sev,
        "overall_risk": overall_risk,
        "findings": unique_findings,
        "recommendation": (
            f"{by_sev['CRITICAL']} CRITICAL and {by_sev['HIGH']} HIGH findings. "
            "Encrypt all data in transit first (CRITICAL), then address connection limits and integrity checksums. "
            "Event stream authentication is the highest-impact single control to implement."
        ) if unique_findings else f"No findings. Data infrastructure satisfies all {total_checks} MAESTRO Layer 2 availability and integrity controls.",
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))

    if overall_risk in ("CRITICAL", "HIGH"):
        sys.exit(1)


if __name__ == "__main__":
    main()
