---
name: llm-misinformation-detection-and-control
description: >-
  Detects, flags, and mitigates LLM-generated misinformation including hallucinated facts,
  fabricated citations, misleading summaries, and politically or factually distorted outputs.
  LLM misinformation risks arise from overconfident generation, knowledge cutoff gaps, and
  adversarial prompting that elicits false outputs presented as authoritative. Covers output
  confidence scoring, grounded generation with source citation, hallucination detection via
  entailment checking, factual consistency validation, and content policy enforcement for
  high-stakes domains. Based on OWASP LLM Top 10 (LLM09:2025 Misinformation). Activates
  when deploying an LLM in a high-stakes domain (medical, legal, financial, news), validating
  LLM outputs for factual accuracy, or building safeguards against hallucinated citations
  and fabricated statistics.
domain: cybersecurity
subdomain: ai-security
tags:
- LLM-security
- OWASP-LLM-Top10
- LLM09
- misinformation
- hallucination-detection
- factual-accuracy
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0048
- AML.T0051
nist_ai_rmf:
- GOVERN-1.1
- MEASURE-2.5
- MANAGE-2.4
d3fend_techniques:
- Content Filtering
- Content Validation
nist_csf:
- PR.PS-01
- DE.AE-02
- DE.CM-01
---
# LLM Misinformation Detection and Control

## When to Use

- Deploying an LLM in a medical, legal, financial, or news-publishing context where factual accuracy is safety-critical
- Validating LLM-generated citations and sources before displaying them to end users
- Implementing grounded generation pipelines where responses must be traceable to authoritative sources
- Detecting hallucinated statistics, fabricated quotes, or invented references in LLM outputs
- Building a content moderation layer that flags overconfident LLM responses in low-certainty domains

**Do not use** automated confidence scoring as the only safeguard in safety-critical domains — human expert review remains essential for high-stakes outputs.

## Prerequisites

- Python 3.10+ with `anthropic`, `sentence-transformers`, `transformers` (for NLI), `requests`
- `sentence-transformers`: `pip install sentence-transformers` for semantic consistency checks
- NLI model: `pip install transformers` — use `cross-encoder/nli-deberta-v3-base` for entailment scoring
- A reference knowledge base or retrieval API (e.g., Wikipedia API, internal document store) for ground-truth checking
- `anthropic` SDK for Claude API-based verification pipeline

## Workflow

### Step 1: Detect Hallucinated Citations and Fabricated References

```python
import re
import httpx

CITATION_PATTERNS = [
    r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+\((\d{4})\)",      # Author (Year)
    r"\b(?:doi|DOI):\s*10\.\d{4,}/\S+",                         # DOI
    r"https?://[^\s\)\"\']+",                                    # URL
    r"\"[^\"]{10,80}\"\s+—\s+[A-Z][a-z]+",                     # "Quote" — Source
]

async def verify_url_citations(text: str) -> list[dict]:
    """Check that cited URLs are reachable and content-relevant."""
    urls = re.findall(r"https?://[^\s\)\"\'\]]+", text)
    results = []

    async with httpx.AsyncClient(timeout=10) as client:
        for url in urls[:10]:  # cap to 10 per response
            try:
                resp = await client.head(url, follow_redirects=True)
                results.append({
                    "url": url,
                    "status_code": resp.status_code,
                    "reachable": resp.status_code < 400,
                    "severity": "LOW" if resp.status_code < 400 else "HIGH"
                })
            except Exception as e:
                results.append({
                    "url": url,
                    "reachable": False,
                    "error": str(e),
                    "severity": "HIGH",
                    "detail": "Citation URL unreachable — possible hallucinated reference"
                })

    return results

def extract_and_flag_citations(text: str) -> dict:
    """Extract all citation patterns and flag for verification."""
    found_citations = []
    for pattern in CITATION_PATTERNS:
        matches = re.findall(pattern, text)
        for match in matches:
            citation_text = match if isinstance(match, str) else " ".join(match)
            found_citations.append({
                "citation": citation_text,
                "pattern_type": pattern[:40],
                "status": "UNVERIFIED",
                "recommendation": "Verify against authoritative source before displaying to user"
            })

    return {
        "citations_found": len(found_citations),
        "citations": found_citations,
        "risk": "HIGH" if found_citations else "LOW",
        "note": "All citations require external verification — LLMs frequently hallucinate plausible-looking references"
    }
```

### Step 2: Check Factual Consistency with Entailment Scoring

```python
from transformers import pipeline

nli_pipeline = pipeline(
    "text-classification",
    model="cross-encoder/nli-deberta-v3-base",
    device=-1  # CPU; set to 0 for GPU
)

def check_claim_entailment(claim: str, source_text: str) -> dict:
    """
    Verify whether source_text entails, contradicts, or is neutral to claim.
    Returns: ENTAILMENT (consistent), CONTRADICTION (misinformation), NEUTRAL (unverifiable).
    """
    input_pair = f"{source_text} [SEP] {claim}"
    result = nli_pipeline(input_pair, truncation=True, max_length=512)[0]

    label_map = {
        "ENTAILMENT": ("CONSISTENT", "LOW"),
        "CONTRADICTION": ("CONTRADICTED", "HIGH"),
        "NEUTRAL": ("UNVERIFIABLE", "MEDIUM"),
    }
    status, severity = label_map.get(result["label"].upper(), ("UNKNOWN", "MEDIUM"))

    return {
        "claim": claim[:200],
        "source_preview": source_text[:200],
        "nli_label": result["label"],
        "confidence": round(result["score"], 3),
        "status": status,
        "severity": severity
    }

def validate_response_against_sources(llm_response: str,
                                       source_documents: list[str]) -> dict:
    """Split LLM response into sentences and check each against provided sources."""
    import re
    sentences = re.split(r'(?<=[.!?])\s+', llm_response.strip())
    sentences = [s for s in sentences if len(s) > 30]

    findings = []
    for sentence in sentences[:20]:  # limit processing per response
        best_result = None
        for source in source_documents:
            result = check_claim_entailment(sentence, source[:512])
            if best_result is None or result["confidence"] > best_result["confidence"]:
                best_result = result

        if best_result and best_result["status"] in ("CONTRADICTED", "UNVERIFIABLE"):
            findings.append(best_result)

    contradicted = [f for f in findings if f["status"] == "CONTRADICTED"]
    return {
        "sentences_checked": len(sentences),
        "issues_found": len(findings),
        "contradictions": len(contradicted),
        "findings": findings,
        "misinformation_risk": "HIGH" if contradicted else ("MEDIUM" if findings else "LOW")
    }
```

### Step 3: Implement Grounded Generation with Source Attribution

```python
import anthropic

def generate_grounded_response(user_query: str,
                                retrieved_sources: list[dict],
                                model: str = "claude-sonnet-4-6") -> dict:
    """Force Claude to ground its response in retrieved documents and cite sources."""
    client = anthropic.Anthropic()

    sources_block = "\n\n".join(
        f"[SOURCE {i+1}] {src['title']}\n{src['content'][:800]}"
        for i, src in enumerate(retrieved_sources)
    )

    system_prompt = (
        "You are a factual assistant. Answer ONLY based on the provided sources. "
        "For every factual claim, cite the source number in brackets (e.g., [SOURCE 1]). "
        "If the sources do not contain enough information to answer, say: "
        "'I don't have sufficient information to answer this accurately.' "
        "Never fabricate facts, statistics, names, or citations not present in the sources."
    )

    user_message = f"Sources:\n{sources_block}\n\nQuestion: {user_query}"

    response = client.messages.create(
        model=model,
        max_tokens=1000,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}]
    ).content[0].text

    # Verify all cited sources are real
    cited_sources = re.findall(r"\[SOURCE (\d+)\]", response)
    invalid_citations = [
        c for c in cited_sources if int(c) > len(retrieved_sources)
    ]

    return {
        "response": response,
        "cited_sources": [int(c) for c in set(cited_sources)],
        "invalid_citations": invalid_citations,
        "grounding_check": "FAIL" if invalid_citations else "PASS",
        "source_count": len(retrieved_sources)
    }
```

### Step 4: Flag High-Stakes Domain Overconfidence

```python
HIGH_STAKES_DOMAINS = {
    "medical": [
        r"(?i)(diagnos|treat|prescri|medic|dosage|drug|symptom|cancer|disease)",
        r"(?i)(you (should|must|need to)|take \d+ mg|consult|clinically)"
    ],
    "legal": [
        r"(?i)(legal advice|court|lawsuit|sue|liable|contract|regulation|statute)",
        r"(?i)(you are (entitled|required)|legally (must|obligated))"
    ],
    "financial": [
        r"(?i)(invest(ment)?|stock|portfolio|return|yield|fund|crypto|guaranteed)",
        r"(?i)(you (should|will) (make|earn|gain|profit))"
    ],
}

OVERCONFIDENCE_PATTERNS = [
    r"(?i)(definitely|certainly|absolutely|always|never|guaranteed|proven|fact)",
    r"(?i)(100%|without (a )?doubt|no question|undeniably|scientifically proven)",
]

def assess_output_overconfidence(text: str, domain: str = "general") -> dict:
    flags = []

    domain_patterns = HIGH_STAKES_DOMAINS.get(domain, [])
    domain_matches = any(
        re.search(pat, text) for pat in domain_patterns
    )

    overconfidence_matches = [
        pat for pat in OVERCONFIDENCE_PATTERNS
        if re.search(pat, text)
    ]

    if domain_matches and overconfidence_matches:
        flags.append({
            "type": "HIGH_STAKES_OVERCONFIDENT",
            "domain": domain,
            "overconfidence_patterns": overconfidence_matches[:3],
            "severity": "HIGH",
            "recommendation": f"Add disclaimer: results in {domain} domain require expert verification"
        })
    elif domain_matches:
        flags.append({
            "type": "HIGH_STAKES_DOMAIN_CONTENT",
            "domain": domain,
            "severity": "MEDIUM",
            "recommendation": f"Add standard {domain} disclaimer to response"
        })

    return {
        "domain": domain,
        "flags": flags,
        "requires_disclaimer": bool(flags),
        "risk": "HIGH" if any(f["severity"] == "HIGH" for f in flags) else "LOW"
    }
```

### Step 5: Build a Misinformation Audit Pipeline

```python
import datetime

def run_misinformation_audit(llm_response: str,
                              source_documents: list[dict],
                              domain: str = "general") -> dict:
    source_texts = [s["content"] for s in source_documents]

    citation_check = extract_and_flag_citations(llm_response)
    consistency_check = validate_response_against_sources(llm_response, source_texts)
    overconfidence_check = assess_output_overconfidence(llm_response, domain)

    overall_risk = "HIGH" if any([
        citation_check["risk"] == "HIGH",
        consistency_check["misinformation_risk"] == "HIGH",
        overconfidence_check["risk"] == "HIGH"
    ]) else "MEDIUM" if any([
        consistency_check["misinformation_risk"] == "MEDIUM",
        overconfidence_check["risk"] == "MEDIUM"
    ]) else "LOW"

    return {
        "audit_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "domain": domain,
        "citation_check": citation_check,
        "consistency_check": consistency_check,
        "overconfidence_check": overconfidence_check,
        "overall_risk": overall_risk,
        "action": "block_display" if overall_risk == "HIGH" else (
            "add_disclaimer" if overall_risk == "MEDIUM" else "pass"
        )
    }
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Misinformation** | False or inaccurate information generated by an LLM — whether through hallucination, fabricated citations, outdated knowledge, or adversarial prompting |
| **Hallucination** | An LLM confidently generating plausible-sounding but factually incorrect statements, citations, or statistics not present in its training data or context |
| **Grounded Generation** | A RAG pattern that restricts LLM responses to information explicitly present in retrieved source documents, with mandatory citation of sources |
| **Entailment Checking** | Using a Natural Language Inference model to verify whether a retrieved source document supports (entails), contradicts, or is neutral to an LLM-generated claim |
| **Citation Hallucination** | An LLM fabricating plausible-looking but non-existent paper references, URLs, or author names — a common and difficult-to-detect misinformation pattern |
| **Overconfidence** | An LLM using absolute language ("definitely," "proven," "100%") for claims that are uncertain, contested, or outside its knowledge boundary |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **cross-encoder/nli-deberta-v3-base** | State-of-the-art NLI model for claim-source entailment checking; detects contradictions between LLM output and ground-truth sources |
| **sentence-transformers** | Semantic similarity scoring for measuring how well LLM responses align with source document content |
| **Anthropic Claude API (citations)** | Claude supports grounded generation with explicit instructions to cite sources; use system prompt constraints to enforce attribution |
| **Google Fact Check API** | Public API for checking factual claims against indexed fact-checks from news publishers |
| **Guardrails AI** | Framework for defining output validators including factual consistency checks and hallucination detectors |

## Common Scenarios

- **Hallucinated medical dosage**: An LLM health assistant states "Take 1200mg ibuprofen daily — this is safe for adults." Entailment checking against medical references returns CONTRADICTION; the response is blocked and replaced with a physician-consult recommendation.
- **Fabricated legal citation**: An LLM legal assistant cites "Smith v. Jones (2019), 847 F.3d 221" which does not exist. The citation extractor flags it as UNVERIFIED; URL verification confirms no such case. Response is withheld pending human review.
- **Overconfident financial claim**: An LLM financial advisor states "This portfolio will definitely return 15% annually." Overconfidence detection flags "definitely" + "return" + financial domain as HIGH risk; a mandatory disclaimer is prepended.

## Output Format

```json
{
  "audit_timestamp": "2026-04-27T16:00:00Z",
  "domain": "medical",
  "citation_check": {
    "citations_found": 2,
    "risk": "HIGH",
    "citations": [
      {"citation": "Johnson et al. (2023)", "status": "UNVERIFIED"}
    ]
  },
  "consistency_check": {
    "sentences_checked": 8,
    "contradictions": 1,
    "misinformation_risk": "HIGH",
    "findings": [
      {
        "claim": "ibuprofen is safe at 1200mg daily",
        "status": "CONTRADICTED",
        "confidence": 0.91
      }
    ]
  },
  "overconfidence_check": {
    "flags": [{"type": "HIGH_STAKES_OVERCONFIDENT", "severity": "HIGH"}],
    "risk": "HIGH"
  },
  "overall_risk": "HIGH",
  "action": "block_display"
}
```
