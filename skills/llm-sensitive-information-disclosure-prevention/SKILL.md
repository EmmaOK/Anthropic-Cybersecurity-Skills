---
name: llm-sensitive-information-disclosure-prevention
description: >-
  Prevents LLM applications from leaking sensitive information including PII, credentials,
  training data, system internals, and confidential business data in model outputs. Covers
  output scanning and redaction pipelines, context window sanitization before inference,
  training data memorization detection, and data minimization patterns for RAG pipelines.
  Based on OWASP LLM Top 10 (LLM02:2025 Sensitive Information Disclosure). Activates when
  auditing LLM application outputs for data leakage, building output filtering for
  customer-facing AI products, or investigating incidents where an LLM surfaced confidential
  data in its responses.
domain: cybersecurity
subdomain: ai-security
tags:
- LLM-security
- OWASP-LLM-Top10
- LLM02
- data-leakage
- PII-protection
- output-filtering
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0057
- AML.T0056
nist_ai_rmf:
- GOVERN-1.1
- MEASURE-2.9
- MANAGE-2.4
d3fend_techniques:
- Data Masking
- Content Filtering
nist_csf:
- PR.DS-01
- PR.DS-05
- DE.AE-02
---
# LLM Sensitive Information Disclosure Prevention

## When to Use

- Auditing outputs of an LLM application for PII (names, SSNs, credit cards, emails) before they reach end users
- Building output redaction pipelines for customer-facing AI chatbots or copilots that process confidential documents
- Detecting training data memorization — where the model can reproduce verbatim excerpts of its training data on request
- Sanitizing the context window before passing documents to an LLM to avoid sending data the model should not see
- Responding to an incident where an LLM response contained credentials, internal API keys, or confidential customer data

**Do not use** output filtering as the only privacy control — avoid sending sensitive data to the LLM in the first place (data minimization is more robust than post-hoc redaction).

## Prerequisites

- Python 3.10+ with `presidio-analyzer`, `presidio-anonymizer`: `pip install presidio-analyzer presidio-anonymizer`
- `spacy` language models: `python -m spacy download en_core_web_lg`
- `anthropic` or equivalent LLM SDK for hooking into inference pipelines
- A PII baseline for your application's sensitive data types
- Optional: `detect-secrets` for credential pattern scanning in outputs

## Workflow

### Step 1: Define Sensitive Entity Types for Your Application

```python
from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Entity types to detect and redact
SENSITIVE_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
    "IBAN_CODE", "US_SSN", "US_PASSPORT", "US_DRIVER_LICENSE",
    "IP_ADDRESS", "CRYPTO", "MEDICAL_LICENSE", "URL",
    "NRP",  # national registration/ID numbers
]

# Custom redaction operators
REDACTION_OPERATORS = {
    "PERSON":         OperatorConfig("replace", {"new_value": "[PERSON]"}),
    "EMAIL_ADDRESS":  OperatorConfig("replace", {"new_value": "[EMAIL]"}),
    "CREDIT_CARD":    OperatorConfig("replace", {"new_value": "[CARD]"}),
    "US_SSN":         OperatorConfig("replace", {"new_value": "[SSN]"}),
    "PHONE_NUMBER":   OperatorConfig("replace", {"new_value": "[PHONE]"}),
    "DEFAULT":        OperatorConfig("replace", {"new_value": "[REDACTED]"}),
}

def scan_and_redact(text: str, language: str = "en") -> dict:
    results = analyzer.analyze(text=text, entities=SENSITIVE_ENTITIES, language=language)
    redacted = anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators=REDACTION_OPERATORS
    ).text
    return {
        "pii_detected": bool(results),
        "entity_types": list({r.entity_type for r in results}),
        "entity_count": len(results),
        "original_text": text,
        "redacted_text": redacted,
    }
```

### Step 2: Add Output Filtering Middleware to LLM Calls

```python
import anthropic, json

client = anthropic.Anthropic()

def safe_llm_call(system_prompt: str, user_message: str,
                   model: str = "claude-sonnet-4-6") -> dict:
    response = client.messages.create(
        model=model,
        max_tokens=2048,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}]
    )
    raw_output = response.content[0].text

    # Scan output for sensitive data before returning to caller
    scan = scan_and_redact(raw_output)

    if scan["pii_detected"]:
        # Log the incident for security review
        log_disclosure_event(
            entity_types=scan["entity_types"],
            original_length=len(raw_output),
            redacted_length=len(scan["redacted_text"])
        )
        return {
            "output": scan["redacted_text"],
            "pii_redacted": True,
            "entity_types_found": scan["entity_types"]
        }

    return {"output": raw_output, "pii_redacted": False}
```

### Step 3: Sanitize Context Window Before Sending to LLM

```python
import re

# Patterns for secrets and credentials in context
CREDENTIAL_PATTERNS = [
    (r"(api[_-]?key\s*[:=]\s*)['\"]?[A-Za-z0-9\-_]{20,}", r"\1[REDACTED]"),
    (r"(password\s*[:=]\s*)['\"]?\S+", r"\1[REDACTED]"),
    (r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer [REDACTED]"),
    (r"AKIA[0-9A-Z]{16}", "[AWS_KEY_REDACTED]"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----.*?-----END.*?-----",
     "[PRIVATE_KEY_REDACTED]", re.DOTALL),
]

def sanitize_context(text: str) -> tuple[str, list[str]]:
    redactions = []
    for pattern, replacement, *flags in CREDENTIAL_PATTERNS:
        flag = flags[0] if flags else 0
        if re.search(pattern, text, flag):
            text = re.sub(pattern, replacement, text, flags=flag)
            redactions.append(pattern)
    return text, redactions

def build_rag_context(documents: list[str]) -> str:
    sanitized_parts = []
    all_redactions = []
    for doc in documents:
        sanitized, redactions = sanitize_context(doc)
        # Also redact PII from context before sending to LLM
        pii_scan = scan_and_redact(sanitized)
        sanitized_parts.append(pii_scan["redacted_text"])
        all_redactions.extend(redactions + pii_scan["entity_types"])
    if all_redactions:
        print(f"[SECURITY] Context sanitized: {set(all_redactions)}")
    return "\n\n".join(sanitized_parts)
```

### Step 4: Detect Training Data Memorization

```python
import hashlib

# Store hashes of known sensitive training-adjacent text
SENSITIVE_TEXT_HASHES: set[str] = set()

def register_sensitive_text(text: str):
    h = hashlib.sha256(text.strip().lower().encode()).hexdigest()
    SENSITIVE_TEXT_HASHES.add(h)

def detect_memorization(llm_output: str,
                          window_size: int = 50) -> list[dict]:
    findings = []
    words = llm_output.split()
    for i in range(len(words) - window_size + 1):
        window = " ".join(words[i:i + window_size])
        h = hashlib.sha256(window.strip().lower().encode()).hexdigest()
        if h in SENSITIVE_TEXT_HASHES:
            findings.append({
                "type": "TRAINING_DATA_MEMORIZATION",
                "window_start": i,
                "excerpt": window[:100],
                "severity": "HIGH"
            })
    return findings
```

### Step 5: Implement Data Minimization for RAG Pipelines

```python
def minimize_rag_chunk(chunk: str, query: str,
                        max_chars: int = 500) -> str:
    """Return only the most relevant portion of a chunk, not the full document."""
    # Simple keyword-based minimization — replace with semantic search in production
    query_terms = set(query.lower().split())
    sentences = chunk.split(". ")
    relevant = [s for s in sentences
                if any(t in s.lower() for t in query_terms)]
    result = ". ".join(relevant)[:max_chars]
    return result if result else chunk[:max_chars]

def audit_context_sensitivity(context_chunks: list[str]) -> dict:
    total_pii_entities = 0
    flagged_chunks = []
    for i, chunk in enumerate(context_chunks):
        scan = scan_and_redact(chunk)
        if scan["pii_detected"]:
            flagged_chunks.append({"chunk_index": i, "entities": scan["entity_types"]})
            total_pii_entities += scan["entity_count"]
    return {
        "total_chunks": len(context_chunks),
        "flagged_chunks": len(flagged_chunks),
        "total_pii_entities": total_pii_entities,
        "details": flagged_chunks,
        "recommendation": "redact or exclude flagged chunks before sending to LLM" if flagged_chunks else "clean"
    }
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Sensitive Information Disclosure** | LLM outputting confidential data — PII, credentials, internal system details, or training data — that should not be visible to the user |
| **Training Data Memorization** | Phenomenon where an LLM can reproduce verbatim text from its training data, potentially exposing private or copyrighted content |
| **Output Redaction** | Post-processing LLM responses to remove or mask sensitive entities before returning them to callers |
| **Data Minimization** | Sending only the minimum necessary context to the LLM, reducing the surface area for accidental disclosure |
| **PII (Personally Identifiable Information)** | Any data that can identify an individual — names, SSNs, email addresses, phone numbers |
| **Context Window Sanitization** | Cleaning RAG-retrieved documents and conversation history before including them in the LLM prompt |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Presidio (Microsoft)** | PII detection and anonymization library supporting 20+ entity types with customizable operators |
| **spaCy** | NLP library used by Presidio for named entity recognition (PERSON, ORG, GPE) |
| **detect-secrets** | Credential pattern scanner for detecting API keys, tokens, and passwords in LLM outputs |
| **LLM Guard** | Open-source LLM I/O scanning library with a Sensitive Information scanner |
| **AWS Macie / Azure Purview** | Cloud-native data classification services for auditing LLM context sources for sensitive data |

## Common Scenarios

- **PII in RAG-retrieved document**: An HR chatbot retrieves an employee record containing SSN and salary data. Context sanitization redacts these before the LLM sees them; output filtering catches any residual leakage.
- **API key in user-pasted code**: A developer pastes code containing `api_key = "sk-proj-abc123"` into a chat. The output scanner detects the credential in the LLM's echoed response and redacts it before display.
- **Training data verbatim recall**: Prompted correctly, an LLM reproduces a paragraph from a confidential document in its training set. The memorization detector matches the SHA-256 hash of the output window and flags the incident.

## Output Format

```json
{
  "scan_timestamp": "2026-04-27T09:00:00Z",
  "llm_model": "claude-sonnet-4-6",
  "output_pii_scan": {
    "pii_detected": true,
    "entity_types": ["PERSON", "EMAIL_ADDRESS", "CREDIT_CARD"],
    "entity_count": 3,
    "action": "redacted"
  },
  "context_sanitization": {
    "chunks_scanned": 5,
    "chunks_with_pii": 2,
    "credential_patterns_found": 1,
    "action": "sanitized_before_inference"
  },
  "memorization_check": {
    "windows_checked": 120,
    "matches_found": 0
  }
}
```
