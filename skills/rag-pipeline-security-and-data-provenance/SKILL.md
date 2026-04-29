---
name: rag-pipeline-security-and-data-provenance
description: >-
  Audits Retrieval-Augmented Generation (RAG) pipeline configurations and document
  corpora for security vulnerabilities specific to MAESTRO Layer 2 (Data Operations).
  Detects prompt injection patterns embedded in documents, verifies data source provenance
  controls, checks vector database access controls and encryption, identifies RAG
  retrieval misconfigurations that enable adversarial context injection, and validates
  embedding pipeline integrity. Covers data poisoning prevention, PII leakage in
  retrieval outputs, and anomaly detection for unusual retrieval patterns.
domain: cybersecurity
subdomain: ai-security
tags:
  - RAG-security
  - data-provenance
  - data-poisoning
  - vector-database
  - prompt-injection
  - MAESTRO
  - agentic-ai
  - LLM-security
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - ID.AM-05
  - PR.DS-01
  - PR.DS-05
  - DE.AE-02
  - DE.CM-09
atlas_techniques:
  - AML.T0056
  - AML.T0043
  - AML.T0051
nist_ai_rmf:
  - GOVERN-1.1
  - MEASURE-2.7
  - MANAGE-2.2
  - MANAGE-2.4
d3fend_techniques:
  - Content Validation
  - Data Integrity Verification
  - Data Masking
---
# RAG Pipeline Security and Data Provenance

## When to Use

- Auditing an existing RAG pipeline for MAESTRO Layer 2 (Data Operations) vulnerabilities
- Checking a document corpus for prompt injection payloads before ingestion
- Validating that data sources are provenance-tracked, signed, and access-controlled
- Reviewing vector database configuration for encryption, access controls, and isolation
- Scanning ingestion pipeline config for missing sanitization, PII controls, or injection filters
- Building a RAG security checklist as part of an AI system security review

## Prerequisites

- Python 3.9+ (no external dependencies)
- A RAG pipeline config JSON describing the pipeline's components (see Workflow for schema)
- Optionally: a directory of documents to scan for injection patterns

## Workflow

### 1. Audit the RAG pipeline configuration

Create `rag_config.json` describing your pipeline:

```json
{
  "name": "Customer Support RAG",
  "data_sources": [
    {"name": "product-docs", "type": "s3", "signed": false, "access_control": true, "encryption_at_rest": true}
  ],
  "vector_db": {"type": "pinecone", "access_control": true, "encryption_at_rest": false, "network_isolated": false},
  "retrieval": {"sanitize_output": false, "injection_filter": false, "max_results": 50, "trust_boundary": "external"},
  "embeddings": {"integrity_check": false, "model_pinned": true},
  "logging": {"enabled": true, "pii_redaction": false, "tamper_evident": false}
}
```

```bash
python agent.py audit --config rag_config.json --output rag_audit.json
```

### 2. Scan documents for injection patterns

```bash
python agent.py scan-documents --dir ./knowledge-base/ --output injection_scan.json
```

Scans `.txt`, `.md`, and `.json` files for prompt injection signatures (instruction overrides, role-play escapes, system prompt fragments).

## Key Concepts

| Concept | Description |
|---|---|
| Indirect Prompt Injection | Malicious instructions embedded in documents/web pages retrieved by the RAG system, hijacking agent behavior |
| Embedding Poisoning | Adversarial content crafted to dominate similarity search, causing systematic retrieval of attacker content |
| Data Provenance | Cryptographic or metadata chain establishing origin and integrity of data entering the corpus |
| Retrieval Isolation | Separating indexes by trust level so public/untrusted documents cannot influence high-privilege retrievals |
| RAG trust boundary | Whether retrieved content comes from fully trusted internal sources, partially trusted, or external/user-supplied |

## Tools & Systems

| Tool | Purpose |
|---|---|
| agent.py `audit` | Static config audit against 12 RAG security controls |
| agent.py `scan-documents` | Pattern-based injection scan across document corpus |
| Pinecone / Weaviate / Chroma | Common vector DB targets — check access control and encryption config |
| LangChain / LlamaIndex | RAG framework targets — check for unsafe retrieval defaults |

## Common Scenarios

**Documents ingested from the public internet:**
Use `scan-documents` before ingestion. Flag any documents containing instruction-override patterns.

**Shared vector DB across multiple AI apps:**
`audit` will flag missing access control isolation (`network_isolated: false`) as HIGH.

**PII in retrieved documents returned to users:**
`audit` will flag `pii_redaction: false` in logging config as HIGH.

## Output Format

```json
{
  "audit_timestamp": "2026-04-29T06:00:00+00:00",
  "pipeline_name": "Customer Support RAG",
  "total_checks": 12,
  "findings": [
    {
      "id": "RAG-001", "severity": "CRITICAL",
      "control": "Retrieval injection filter",
      "finding": "injection_filter is disabled — retrieved content not sanitized for prompt injection",
      "remediation": "Enable content sanitization and treat retrieved text as data, not instructions"
    },
    {
      "id": "RAG-002", "severity": "HIGH",
      "control": "Vector DB encryption at rest",
      "finding": "encryption_at_rest is false for vector database",
      "remediation": "Enable encryption at rest for all vector database indexes"
    }
  ],
  "by_severity": { "CRITICAL": 3, "HIGH": 4, "MEDIUM": 2, "LOW": 1 },
  "overall_risk": "CRITICAL"
}
```
