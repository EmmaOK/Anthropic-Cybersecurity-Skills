---
name: llm-output-validation-and-sanitization
description: >-
  Validates and sanitizes LLM outputs before they are passed to downstream systems,
  rendered in browsers, executed as code, or used to construct database queries. Improper
  output handling occurs when an application blindly trusts LLM responses, enabling XSS,
  SQL injection, command injection, and SSRF via model-generated content. Covers output
  schema enforcement, injection pattern scanning in generated code and queries, HTML
  sanitization for rendered outputs, and structured output validation. Based on OWASP
  LLM Top 10 (LLM05:2025 Improper Output Handling). Activates when building pipelines
  that pass LLM outputs to databases, browsers, shells, or APIs, or auditing an existing
  LLM application for downstream injection vulnerabilities.
domain: cybersecurity
subdomain: ai-security
tags:
- LLM-security
- OWASP-LLM-Top10
- LLM05
- output-validation
- XSS
- injection-prevention
version: '1.0'
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0051
- AML.T0062
nist_ai_rmf:
- GOVERN-1.1
- MANAGE-2.2
- MEASURE-2.8
d3fend_techniques:
- Application Hardening
- Content Filtering
nist_csf:
- PR.PS-01
- PR.PS-04
- DE.CM-01
---
# LLM Output Validation and Sanitization

## When to Use

- Building a pipeline where LLM-generated SQL queries are executed against a database
- Rendering LLM output as HTML in a browser or web application where XSS is a risk
- Passing LLM-generated shell commands to a subprocess executor
- Enforcing structured output schemas (JSON, XML) when LLMs are used to generate data for downstream APIs
- Auditing an existing LLM application for downstream injection vectors introduced by unvalidated model outputs

**Do not use** as the only injection defense — also parameterize database queries, escape HTML in rendering layers, and sandbox code execution independently of output scanning.

## Prerequisites

- Python 3.10+ with `pydantic`, `bleach`, `jsonschema`, `sqlparse`
- `bleach`: `pip install bleach` for HTML sanitization
- `sqlparse`: `pip install sqlparse` for SQL output analysis
- `semgrep` for static analysis of generated code: `brew install semgrep`
- `pydantic` v2 for strict output schema enforcement

## Workflow

### Step 1: Enforce Structured Output Schema with Pydantic

```python
from pydantic import BaseModel, field_validator, model_validator
from typing import Literal
import json, re

class LLMStructuredOutput(BaseModel):
    action: Literal["summarize", "classify", "extract", "answer"]
    result: str
    confidence: float
    sources: list[str] = []

    @field_validator("confidence")
    @classmethod
    def confidence_in_range(cls, v):
        assert 0.0 <= v <= 1.0, f"confidence {v} out of [0,1]"
        return v

    @field_validator("result")
    @classmethod
    def result_not_empty(cls, v):
        assert len(v.strip()) > 0, "result cannot be empty"
        assert len(v) < 10_000, "result suspiciously long"
        return v

def parse_llm_output(raw: str) -> LLMStructuredOutput | None:
    try:
        data = json.loads(raw)
        return LLMStructuredOutput(**data)
    except (json.JSONDecodeError, ValueError, AssertionError) as e:
        print(f"Output validation failed: {e}")
        return None
```

### Step 2: Sanitize LLM Output for HTML Rendering

```python
import bleach

# Allowlist of safe HTML tags and attributes for rendering LLM output
ALLOWED_TAGS = ["p", "br", "strong", "em", "ul", "ol", "li", "code", "pre", "blockquote"]
ALLOWED_ATTRIBUTES = {"a": ["href", "title"], "img": []}  # no img src to prevent SSRF
ALLOWED_PROTOCOLS = ["https"]  # no javascript: or data: URIs

def sanitize_for_html(llm_output: str) -> str:
    # Strip all HTML/JS first
    cleaned = bleach.clean(
        llm_output,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
        strip_comments=True,
    )
    # Linkify URLs but only HTTPS
    cleaned = bleach.linkify(cleaned, callbacks=[], skip_tags=["pre", "code"])
    return cleaned

def check_for_xss(text: str) -> list[str]:
    XSS_PATTERNS = [
        r"<script[\s>]",
        r"javascript\s*:",
        r"on\w+\s*=",              # onerror=, onload=, etc.
        r"<iframe",
        r"<object",
        r"data\s*:\s*text/html",
        r"vbscript\s*:",
        r"expression\s*\(",
    ]
    return [p for p in XSS_PATTERNS if re.search(p, text, re.IGNORECASE)]
```

### Step 3: Validate LLM-Generated SQL Before Execution

```python
import sqlparse
from sqlparse.sql import Statement
from sqlparse.tokens import Keyword, DDL

BLOCKED_SQL_KEYWORDS = {
    "DROP", "TRUNCATE", "DELETE", "ALTER", "CREATE",
    "GRANT", "REVOKE", "EXEC", "EXECUTE", "xp_cmdshell",
    "LOAD_FILE", "INTO OUTFILE", "INTO DUMPFILE",
}

def validate_generated_sql(sql: str) -> tuple[bool, list[str]]:
    issues = []

    # Parse and check statement type
    parsed = sqlparse.parse(sql)
    for stmt in parsed:
        stmt_type = stmt.get_type()
        if stmt_type not in ("SELECT", None):
            issues.append(f"Non-SELECT statement type: {stmt_type}")

        # Flatten tokens and check for blocked keywords
        flat_tokens = [t.normalized.upper() for t in stmt.flatten()]
        for keyword in BLOCKED_SQL_KEYWORDS:
            if keyword in flat_tokens:
                issues.append(f"Blocked SQL keyword: {keyword}")

        # Check for multiple statements (semicolon injection)
        if ";" in sql.rstrip(";"):
            issues.append("Multiple statements detected — possible SQL injection")

        # Check for comment-based injection
        if re.search(r"--|\bOR\b.{0,20}=|UNION.{0,30}SELECT", sql, re.IGNORECASE):
            issues.append("SQL injection pattern detected (comment/UNION/OR)")

    return not bool(issues), issues

# Always use parameterized queries — never concatenate LLM output into SQL directly
def safe_db_query(llm_generated_sql: str, db_cursor) -> list | None:
    valid, issues = validate_generated_sql(llm_generated_sql)
    if not valid:
        raise SecurityError(f"Generated SQL failed validation: {issues}")
    # Even with validation, use read-only connection for LLM-generated queries
    db_cursor.execute(llm_generated_sql)
    return db_cursor.fetchall()
```

### Step 4: Scan LLM-Generated Code for Injection Patterns

```python
import subprocess, tempfile, os

DANGEROUS_CODE_PATTERNS = [
    r"(os\.system|subprocess\.call|subprocess\.run)\s*\(.*shell\s*=\s*True",
    r"eval\s*\(",
    r"exec\s*\(",
    r"__import__\s*\(",
    r"open\s*\(.+['\"]w['\"]",
    r"(rm|del|shutil\.rmtree)\s*\(",
    r"socket\s*\.\s*(connect|bind)",
    r"requests\.(get|post)\s*\(",
]

def scan_generated_code(code: str, language: str = "python") -> dict:
    issues = []
    for pattern in DANGEROUS_CODE_PATTERNS:
        m = re.search(pattern, code, re.IGNORECASE)
        if m:
            issues.append({"pattern": pattern, "match": m.group(0), "severity": "HIGH"})

    if language == "python" and issues:
        # Also run semgrep for deeper analysis
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(code)
            tmp = f.name
        try:
            result = subprocess.run(
                ["semgrep", "--config", "p/dangerous-os-exec", tmp,
                 "--json", "--quiet"],
                capture_output=True, text=True, timeout=10
            )
            semgrep_out = json.loads(result.stdout) if result.stdout else {}
            issues += [{"source": "semgrep", "rule": r["check_id"],
                        "severity": r["extra"]["severity"]}
                       for r in semgrep_out.get("results", [])]
        finally:
            os.unlink(tmp)

    return {"issues": issues, "blocked": bool(issues), "issue_count": len(issues)}
```

### Step 5: Validate LLM-Generated URLs and Webhook Targets (SSRF Prevention)

```python
import ipaddress
from urllib.parse import urlparse

BLOCKED_HOSTS = {
    "169.254.169.254",  # AWS metadata endpoint
    "metadata.google.internal",
    "169.254.170.2",    # ECS metadata
    "localhost",
    "127.0.0.1",
    "::1",
}
ALLOWED_SCHEMES = {"https"}

def validate_generated_url(url: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Invalid URL: {e}"

    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"Scheme '{parsed.scheme}' not allowed (only https)"

    hostname = parsed.hostname or ""

    # Block known metadata endpoints and loopback
    if hostname in BLOCKED_HOSTS:
        return False, f"Blocked host: {hostname}"

    # Block private IP ranges
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return False, f"Private/loopback IP blocked: {hostname}"
    except ValueError:
        pass  # not an IP — hostname, fine

    # Block internal hostnames
    if re.search(r"\.(internal|local|corp|intranet)$", hostname, re.IGNORECASE):
        return False, f"Internal hostname blocked: {hostname}"

    return True, "ok"
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Improper Output Handling** | Passing LLM-generated text to downstream systems (databases, shells, browsers) without validation, trusting it as safe input |
| **Downstream Injection** | An injection attack (XSS, SQL, command) that originates from LLM output rather than direct user input |
| **Structured Output Enforcement** | Requiring LLM output to match a defined schema (JSON with specific fields and types) before processing |
| **SSRF (Server-Side Request Forgery)** | Using an LLM-generated URL to make the server issue requests to internal infrastructure (e.g., cloud metadata endpoints) |
| **HTML Sanitization** | Stripping or escaping dangerous HTML from LLM output before rendering it in a browser |
| **SQL Injection via LLM** | An LLM output containing malicious SQL fragments that, if concatenated into a query, modify the query's semantics |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **bleach** | Python HTML sanitization library with allowlist-based tag/attribute filtering for LLM output rendering |
| **pydantic v2** | Strict Python data validation for enforcing LLM structured output schemas with field-level validators |
| **sqlparse** | SQL parsing library for validating LLM-generated queries before execution |
| **semgrep** | Multi-language static analyzer for scanning LLM-generated code for injection patterns |
| **DOMPurify** | JavaScript library for sanitizing LLM HTML outputs on the client side in browser-based LLM applications |

## Common Scenarios

- **SQL injection via LLM**: An LLM generates `SELECT * FROM users WHERE id=1 UNION SELECT password FROM admins`. The SQL validator detects `UNION SELECT` and blocks execution.
- **XSS in rendered chatbot response**: The LLM outputs `Click <a href="javascript:alert(1)">here</a>`. Bleach sanitization strips the `javascript:` URI before rendering.
- **SSRF via LLM-suggested webhook**: An LLM suggests registering a webhook at `http://169.254.169.254/latest/meta-data/`. URL validation blocks the AWS metadata IP and returns an error.

## Output Format

```json
{
  "validation_timestamp": "2026-04-27T12:00:00Z",
  "output_type": "sql",
  "validation_result": {
    "valid": false,
    "issues": [
      "Blocked SQL keyword: DROP",
      "Multiple statements detected — possible SQL injection"
    ]
  },
  "xss_check": {
    "patterns_found": [],
    "safe": true
  },
  "url_check": {
    "url": "http://169.254.169.254/latest/meta-data/",
    "valid": false,
    "reason": "Private/loopback IP blocked"
  },
  "action": "blocked"
}
```
