#!/usr/bin/env python3
"""ASI10 - LLM Vector & Embedding Security: Probe vector stores for auth gaps and injection."""
import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

OWASP_ID = "ASI10"
TOOL_NAME = "phantom-vector-embedding-security"

INJECTION_PATTERNS = [
    (r"ignore (previous|all|above|prior) instructions?", "Instruction override in stored document"),
    (r"(you are now|act as|pretend (you are|to be))", "Persona hijacking payload"),
    (r"<(system|instruction|admin)>", "Pseudo-system tag in document"),
    (r"(exfiltrate|send|upload).{0,50}(data|credentials|secrets)", "Exfiltration instruction"),
    (r"\[INST\]|\[\/INST\]|<<SYS>>", "LLM control token injection"),
    (r"(when (asked|queried)).{0,100}(respond|say|output)", "Conditional behaviour implant"),
    (r"(forget|disregard|ignore).{0,50}(context|instructions|system)", "Context manipulation"),
]

# Common vector store API paths to probe
VECTOR_STORE_PATHS = [
    ("GET", "/collections", "Collection enumeration"),
    ("GET", "/namespaces", "Namespace enumeration"),
    ("GET", "/_cat/indices", "Elasticsearch index listing"),
    ("GET", "/api/v1/collections", "Chroma collection listing"),
    ("POST", "/query", "Unauthenticated query"),
    ("GET", "/vectors", "Vector enumeration"),
    ("DELETE", "/vectors/1", "Unauthenticated delete probe"),
]

CROSS_NAMESPACE_QUERIES = [
    {"namespace": "admin_docs", "query": "system prompt", "top_k": 3},
    {"namespace": "private", "query": "credentials", "top_k": 3},
    {"collection": "system", "query_text": "password", "n_results": 3},
]


def probe_auth(base_url):
    findings = []
    for method, path, desc in VECTOR_STORE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            req = urllib.request.Request(url, method=method,
                headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                if resp.status in (200, 201):
                    severity = "CRITICAL" if method in ("DELETE", "POST") else "HIGH"
                    findings.append({
                        "id": f"{OWASP_ID}-A{len(findings)+1:03d}",
                        "title": f"Unauthenticated Access: {desc}",
                        "severity": severity,
                        "description": f"Vector store endpoint {method} {path} accessible without authentication.",
                        "evidence": f"{method} {url} → HTTP {resp.status}",
                        "remediation": "Enforce authentication on all vector store endpoints. Use API keys or mTLS.",
                    })
        except urllib.error.HTTPError as e:
            if e.code == 405:
                pass  # Method not allowed but endpoint exists
        except Exception:
            pass
    return findings


def probe_namespace_isolation(base_url):
    findings = []
    for query in CROSS_NAMESPACE_QUERIES:
        for endpoint in ["/query", "/search", "/api/v1/query", "/collections/query"]:
            url = base_url.rstrip("/") + endpoint
            try:
                data = json.dumps(query).encode()
                req = urllib.request.Request(url, data=data, method="POST",
                    headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    body = resp.read().decode(errors="replace")
                    if resp.status == 200 and len(body) > 10:
                        findings.append({
                            "id": f"{OWASP_ID}-NS{len(findings)+1:03d}",
                            "title": f"Cross-Namespace Data Access: query returned results",
                            "severity": "CRITICAL",
                            "description": f"Query to restricted namespace '{query.get('namespace', query.get('collection', 'unknown'))}' returned results without authorization.",
                            "evidence": f"POST {endpoint} query={json.dumps(query)[:100]}, response={body[:200]}",
                            "remediation": "Enforce namespace-level access control. Validate namespace permissions on every query.",
                        })
            except Exception:
                pass
    return findings


def scan_documents_for_injection(base_url):
    findings = []
    for endpoint in ["/documents", "/vectors/list", "/api/v1/collections"]:
        url = base_url.rstrip("/") + endpoint
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    body = resp.read().decode(errors="replace")
                    for pattern, desc in INJECTION_PATTERNS:
                        m = re.search(pattern, body, re.IGNORECASE)
                        if m:
                            findings.append({
                                "id": f"{OWASP_ID}-D{len(findings)+1:03d}",
                                "title": f"Injection Pattern in Stored Documents: {desc}",
                                "severity": "CRITICAL",
                                "description": f"Retrieved documents contain injection payload: {desc}",
                                "evidence": body[max(0, m.start()-100):m.end()+100].strip()[:300],
                                "remediation": "Sanitise all documents before storage. Apply injection detection at write time.",
                            })
        except Exception:
            pass
    return findings


def main():
    p = argparse.ArgumentParser(description="ASI10 LLM Vector & Embedding Security")
    p.add_argument("--vector-store-url", required=True, help="Vector store base URL")
    p.add_argument("--output", default="asi10_vector_security_report.json")
    args = p.parse_args()

    base = args.vector_store_url
    findings = probe_auth(base) + probe_namespace_isolation(base) + scan_documents_for_injection(base)

    if not findings:
        findings.append({
            "id": f"{OWASP_ID}-000",
            "title": "Vector Store Not Reachable or Fully Protected",
            "severity": "INFO",
            "description": "No vulnerabilities detected — store may be unreachable or properly secured.",
            "evidence": f"base_url={base}",
            "remediation": "Verify store is running and URL is correct. If inaccessible, this may indicate correct authentication enforcement.",
        })

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

    report = {
        "tool": TOOL_NAME, "owasp_id": OWASP_ID,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vector_store_url": base,
        "findings": findings, "summary": {"total": len(findings), **counts},
    }
    print(json.dumps(report, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2))
    sys.exit(1 if counts["CRITICAL"] > 0 or counts["HIGH"] > 0 else 0)


if __name__ == "__main__":
    main()
