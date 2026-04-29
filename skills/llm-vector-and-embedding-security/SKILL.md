---
name: llm-vector-and-embedding-security
description: >-
  Detects and remediates security vulnerabilities in vector databases and embedding
  pipelines used by LLM-powered applications. Vector and embedding weaknesses allow
  adversaries to poison semantic retrieval by injecting adversarial documents into RAG
  stores, reconstruct training data from embedding representations, perform cross-tenant
  data leakage via shared vector indexes, and manipulate similarity search results. Covers
  embedding integrity verification, vector store access controls, adversarial document
  filtering, and reconstruction attack defenses. Based on OWASP LLM Top 10
  (LLM08:2025 Vector and Embedding Weaknesses). Activates when auditing a RAG pipeline
  for retrieval manipulation risk, designing access controls for a shared vector database,
  or investigating anomalous retrieval behavior in a deployed LLM application.
domain: cybersecurity
subdomain: ai-security
tags:
- LLM-security
- OWASP-LLM-Top10
- LLM08
- vector-database
- RAG-security
- embedding-security
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0056
- AML.T0043
nist_ai_rmf:
- GOVERN-1.1
- MEASURE-2.7
- MANAGE-2.2
d3fend_techniques:
- Data Integrity Verification
- Content Validation
nist_csf:
- PR.DS-01
- PR.DS-05
- DE.AE-02
---
# LLM Vector and Embedding Security

## When to Use

- Auditing a RAG pipeline for adversarial document injection that could manipulate retrieval results and LLM responses
- Reviewing a shared vector database for cross-tenant data leakage through embedding similarity queries
- Detecting embedding inversion attempts that could reconstruct sensitive training data from stored vectors
- Implementing access controls and namespace isolation in multi-tenant vector store deployments
- Investigating anomalous retrieval patterns where irrelevant or suspicious documents are returned for benign queries

**Do not use** vector namespace isolation as the only privacy control — also enforce authentication and query-level authorization at the API layer.

## Prerequisites

- Python 3.10+ with `sentence-transformers`, `numpy`, `scikit-learn`, `chromadb` or `pinecone-client`
- `sentence-transformers`: `pip install sentence-transformers` for embedding generation and cosine similarity
- `chromadb`: `pip install chromadb` for local vector store testing
- `pinecone-client`: `pip install pinecone-client` for Pinecone-based deployments
- Access to the vector store collection/index and its ingestion pipeline

## Workflow

### Step 1: Detect Adversarial Document Injection in RAG Store

```python
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from collections import defaultdict

model = SentenceTransformer("all-MiniLM-L6-v2")

def detect_adversarial_documents(documents: list[dict],
                                  query_corpus: list[str],
                                  anomaly_threshold: float = 0.85) -> dict:
    """Flag documents that rank suspiciously high for many unrelated queries."""
    doc_texts = [d["content"] for d in documents]
    doc_embeddings = model.encode(doc_texts, normalize_embeddings=True)
    query_embeddings = model.encode(query_corpus, normalize_embeddings=True)

    # Count how many diverse queries each document scores high on
    suspicious = []
    for doc_idx, doc_emb in enumerate(doc_embeddings):
        high_score_count = sum(
            1 for q_emb in query_embeddings
            if cosine_similarity([doc_emb], [q_emb])[0][0] > anomaly_threshold
        )
        if high_score_count > len(query_corpus) * 0.4:
            suspicious.append({
                "document_id": documents[doc_idx].get("id", doc_idx),
                "high_score_queries": high_score_count,
                "total_queries": len(query_corpus),
                "ratio": round(high_score_count / len(query_corpus), 3),
                "severity": "HIGH",
                "detail": "Document scores anomalously high across diverse query set — possible retrieval poisoning"
            })

    return {
        "total_documents": len(documents),
        "suspicious_documents": len(suspicious),
        "findings": suspicious,
        "risk": "HIGH" if suspicious else "LOW"
    }
```

### Step 2: Enforce Namespace Isolation for Multi-Tenant Vector Stores

```python
import hashlib
import chromadb

client = chromadb.Client()

def get_tenant_collection(tenant_id: str, collection_base: str) -> chromadb.Collection:
    """Each tenant gets a dedicated, cryptographically-namespaced collection."""
    namespace = hashlib.sha256(f"{tenant_id}:{collection_base}".encode()).hexdigest()[:16]
    collection_name = f"{collection_base}_{namespace}"
    return client.get_or_create_collection(name=collection_name)

def enforce_tenant_query(tenant_id: str, collection_base: str,
                          query_text: str, n_results: int = 5) -> dict:
    collection = get_tenant_collection(tenant_id, collection_base)
    results = collection.query(query_texts=[query_text], n_results=n_results)

    # Verify all returned document IDs belong to this tenant
    returned_ids = results.get("ids", [[]])[0]
    violations = [
        doc_id for doc_id in returned_ids
        if not doc_id.startswith(f"tenant:{tenant_id}:")
    ]

    if violations:
        raise PermissionError(
            f"Cross-tenant data leakage detected: {len(violations)} documents "
            f"returned for tenant '{tenant_id}' that do not belong to this tenant"
        )

    return {"results": results, "tenant_id": tenant_id, "leakage_check": "PASS"}

def audit_cross_tenant_leakage(collections: list[str],
                                probe_tenant_id: str,
                                victim_tenant_id: str,
                                probe_queries: list[str]) -> list[dict]:
    """Test whether a probe tenant can retrieve victim tenant documents."""
    alerts = []
    probe_col = get_tenant_collection(probe_tenant_id, "shared")
    victim_prefix = f"tenant:{victim_tenant_id}:"

    for query in probe_queries:
        results = probe_col.query(query_texts=[query], n_results=10)
        leaked = [
            doc_id for doc_id in results.get("ids", [[]])[0]
            if doc_id.startswith(victim_prefix)
        ]
        if leaked:
            alerts.append({
                "query": query[:100],
                "leaked_documents": leaked,
                "severity": "CRITICAL",
                "detail": "Cross-tenant document retrieved by unauthorized tenant query"
            })

    return alerts
```

### Step 3: Defend Against Embedding Inversion / Reconstruction Attacks

```python
import numpy as np

def add_differential_privacy_noise(embedding: np.ndarray,
                                    epsilon: float = 1.0,
                                    sensitivity: float = 1.0) -> np.ndarray:
    """Add calibrated Laplace noise before storing embeddings externally."""
    scale = sensitivity / epsilon
    noise = np.random.laplace(0, scale, embedding.shape)
    noisy = embedding + noise
    # Re-normalize to preserve cosine similarity properties
    norm = np.linalg.norm(noisy)
    return noisy / norm if norm > 0 else noisy

def assess_inversion_risk(embedding_dim: int,
                           model_name: str,
                           storage_location: str) -> dict:
    """Assess embedding inversion risk based on configuration."""
    risks = []

    if embedding_dim <= 384:
        risks.append({
            "factor": "LOW_DIM_EMBEDDING",
            "severity": "HIGH",
            "detail": f"Embedding dimension {embedding_dim} is small — higher inversion risk from vec2text attacks"
        })

    if "external" in storage_location.lower() or "s3" in storage_location.lower():
        risks.append({
            "factor": "EXTERNAL_STORAGE",
            "severity": "MEDIUM",
            "detail": "Embeddings stored externally without encryption — add AES-256 at rest"
        })

    if not any(priv in model_name.lower() for priv in ["private", "instruct", "chat"]):
        risks.append({
            "factor": "PUBLIC_BASE_MODEL",
            "severity": "MEDIUM",
            "detail": "Base model is publicly known — inversion models can be trained against it"
        })

    return {
        "model": model_name,
        "embedding_dim": embedding_dim,
        "risk_factors": risks,
        "overall_risk": "HIGH" if any(r["severity"] == "HIGH" for r in risks) else "MEDIUM",
        "recommendation": "Apply DP noise with epsilon<=2.0 before external storage; encrypt at rest"
    }
```

### Step 4: Scan Ingested Documents for Prompt Injection Before Embedding

```python
import re

INJECTION_PATTERNS_FOR_RAG = [
    r"(?i)(ignore|disregard|forget).{0,30}(previous|above|prior).{0,20}(instructions|context|rules)",
    r"(?i)(you (are|must|should) now|act as|new (persona|role|task))",
    r"(?i)(system prompt|original instructions).{0,30}(is|are|was|were)",
    r"(?i)<\s*(system|instructions?|prompt)\s*>",
    r"(?i)\[INST\]|\[\/INST\]|<\|im_start\|>",
    r"(?i)(jailbreak|bypass|override).{0,20}(safety|filter|restriction|guardrail)",
]

def scan_document_before_ingestion(document: str) -> dict:
    matches = []
    for pattern in INJECTION_PATTERNS_FOR_RAG:
        m = re.search(pattern, document)
        if m:
            matches.append({
                "pattern": pattern,
                "match": m.group(0),
                "position": m.start()
            })

    return {
        "document_length": len(document),
        "injection_patterns_found": len(matches),
        "findings": matches,
        "safe_to_ingest": len(matches) == 0,
        "severity": "HIGH" if matches else "NONE"
    }

def bulk_scan_ingestion_pipeline(documents: list[dict]) -> dict:
    blocked = []
    for doc in documents:
        result = scan_document_before_ingestion(doc.get("content", ""))
        if not result["safe_to_ingest"]:
            blocked.append({
                "document_id": doc.get("id"),
                "findings": result["findings"],
                "action": "BLOCKED"
            })

    return {
        "total_documents": len(documents),
        "blocked": len(blocked),
        "passed": len(documents) - len(blocked),
        "blocked_documents": blocked,
        "risk": "HIGH" if blocked else "LOW"
    }
```

### Step 5: Monitor Vector Store Query Anomalies

```python
import statistics, datetime

def detect_retrieval_anomalies(query_log: list[dict],
                                window_minutes: int = 60) -> list[dict]:
    """Detect anomalous query patterns suggesting embedding oracle attacks."""
    alerts = []
    user_queries = {}

    cutoff = datetime.datetime.utcnow() - datetime.timedelta(minutes=window_minutes)
    for entry in query_log:
        if datetime.datetime.fromisoformat(entry["timestamp"]) < cutoff:
            continue
        uid = entry.get("user_id", "anonymous")
        user_queries.setdefault(uid, []).append(entry)

    for uid, queries in user_queries.items():
        # High query volume may indicate embedding oracle extraction
        if len(queries) > 500:
            alerts.append({
                "user_id": uid,
                "alert_type": "HIGH_QUERY_VOLUME",
                "query_count": len(queries),
                "window_minutes": window_minutes,
                "severity": "HIGH",
                "detail": "Unusually high query volume — possible embedding oracle attack"
            })

        # Detect systematic near-duplicate queries (grid search over embedding space)
        query_texts = [q.get("query", "") for q in queries]
        if len(query_texts) > 50:
            lengths = [len(t) for t in query_texts]
            length_std = statistics.stdev(lengths) if len(lengths) > 1 else 0
            if length_std < 5.0:
                alerts.append({
                    "user_id": uid,
                    "alert_type": "SYSTEMATIC_QUERY_PATTERN",
                    "query_length_std": round(length_std, 2),
                    "severity": "MEDIUM",
                    "detail": "Near-uniform query lengths suggest programmatic embedding space probing"
                })

    return alerts
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Vector and Embedding Weaknesses** | Security vulnerabilities that arise from how LLM applications store, retrieve, and use vector embeddings — including retrieval manipulation, reconstruction, and cross-tenant leakage |
| **RAG Poisoning** | Injecting adversarial documents into a retrieval-augmented generation vector store so that the LLM retrieves and uses attacker-controlled content |
| **Embedding Inversion** | Reconstructing approximate original text from a stored embedding vector using inversion models — a privacy attack against stored vector data |
| **Cross-Tenant Leakage** | One tenant's queries inadvertently retrieving documents belonging to another tenant due to insufficient namespace isolation |
| **Namespace Isolation** | Partitioning vector collections by tenant so that queries are scoped and cannot span organizational boundaries |
| **Embedding Oracle Attack** | Querying a vector store at high volume to map the embedding space and extract information about stored documents or underlying model weights |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **sentence-transformers** | Generate and compare embeddings for similarity analysis and anomaly detection in RAG pipelines |
| **ChromaDB** | Local-first vector database with collection-level namespace isolation and metadata filtering |
| **Pinecone** | Managed vector database with namespace-based multi-tenancy and per-namespace access controls |
| **LLM Guard (vector scanner)** | Runtime scanning library with plugins for detecting injection patterns in documents before RAG ingestion |
| **Microsoft Presidio** | Detects and redacts PII in documents before embedding to prevent sensitive data storage in vector stores |

## Common Scenarios

- **RAG poisoning via public wiki**: An attacker contributes adversarial text to a publicly-crawled knowledge base used in a RAG pipeline. The document scores highly against many diverse user queries. The anomalous document scanner detects the pattern; the document is quarantined.
- **Cross-tenant leakage in SaaS RAG**: Two customers share a Pinecone index without proper namespace isolation. One tenant's support query returns documents belonging to the other. Namespace enforcement and leakage audit detects the misconfiguration.
- **Prompt injection via ingested PDF**: A malicious PDF containing `[INST] Ignore all previous instructions [/INST]` is uploaded to a document store. The pre-ingestion injection scanner detects the pattern and blocks the document from entering the vector index.

## Output Format

```json
{
  "audit_timestamp": "2026-04-27T15:00:00Z",
  "vector_store": "chromadb:rag-knowledge-base",
  "adversarial_document_scan": {
    "total_documents": 10000,
    "suspicious_documents": 2,
    "risk": "HIGH",
    "findings": [
      {
        "document_id": "doc-4821",
        "high_score_queries": 9,
        "ratio": 0.45,
        "severity": "HIGH"
      }
    ]
  },
  "cross_tenant_leakage_check": {
    "alerts": [],
    "status": "PASS"
  },
  "pre_ingestion_injection_scan": {
    "total_documents": 150,
    "blocked": 1,
    "risk": "HIGH"
  },
  "retrieval_anomalies": [],
  "action": "quarantine doc-4821, audit ingestion pipeline"
}
```
