---
name: triaging-defectdojo-findings
description: >-
  AI-assisted triage of DefectDojo findings using Claude: automatically evaluates unverified
  findings for true positive vs false positive, records reasoning as auditable notes in
  DefectDojo, marks findings verified or false_p, and creates Jira tickets for confirmed
  true positives — replacing the manual human review-and-push workflow.
domain: cybersecurity
subdomain: vulnerability-management
tags:
- defectdojo
- jira
- vulnerability-management
- triage
- false-positive
- ai-triage
- devsecops
- automation
version: '1.0'
author: EmmaOK
license: Apache-2.0
nist_csf:
- ID.RA-01
- ID.RA-06
- RS.AN-03
- DE.AE-02
---

# Triaging DefectDojo Findings

## When to Use

- "triage my DefectDojo findings"
- "review false positives in DefectDojo"
- "prioritize my security findings"
- "review unverified findings"
- "mark false positives in DefectDojo"
- "push verified findings to Jira"
- "AI triage my vulnerability backlog"

## Prerequisites

- DefectDojo running and accessible (`DEFECTDOJO_URL`, `DEFECTDOJO_API_KEY`)
- Jira project configured (`JIRA_URL`, `JIRA_USER`, `JIRA_TOKEN`, `JIRA_PROJECT_KEY`)
- Anthropic API key (`ANTHROPIC_API_KEY`) for AI-assisted verdict generation
- Python 3.11+ with `anthropic` package installed

## Workflow

1. Fetch unverified, active findings from DefectDojo (filtered by product/severity/limit)
2. For each finding, call Claude (`claude-sonnet-4-6`) with: title, description, severity, tool name, affected endpoint, CVE, and CWE
3. Claude returns a structured verdict: `true_positive`, `false_positive`, or `risk_accepted` with confidence score and reasoning
4. In dry-run mode (default): print verdicts to stdout as a JSON triage report
5. With `--apply --no-dry-run`:
   - **False positive** → `PATCH /api/v2/findings/{id}/` (false_p=true, active=false) + `POST /api/v2/notes/` (Claude's reasoning)
   - **True positive** → `PATCH /api/v2/findings/{id}/` (verified=true) + add note + JQL-search Jira for existing ticket; if none exists, **create Jira ticket** (replaces manual push step)
   - **Risk accepted** → `PATCH /api/v2/findings/{id}/` (risk_accepted=true) + add note
6. Output JSON triage report: per-finding verdict, confidence, reasoning, and Jira ticket key (if created)

## Steps

```bash
# Dry-run triage (preview verdicts, no changes)
python skills/triaging-defectdojo-findings/scripts/agent.py \
  --product-id 1 --severity Critical,High --limit 20

# Apply decisions (mark in DefectDojo + create Jira tickets)
python skills/triaging-defectdojo-findings/scripts/agent.py \
  --product-id 1 --severity Critical,High --limit 20 \
  --apply --no-dry-run

# Save triage report
python skills/triaging-defectdojo-findings/scripts/agent.py \
  --product-id 1 --output triage_report.json --apply --no-dry-run

# All products, all active unverified findings
python skills/triaging-defectdojo-findings/scripts/agent.py \
  --limit 50 --apply --no-dry-run
```

## Key Concepts

| Concept | Description |
|---|---|
| Unverified finding | Finding imported by a scanner that has not been reviewed by a human or AI |
| True positive | Finding confirmed as a real vulnerability — gets verified=true in DD + Jira ticket |
| False positive | Finding confirmed as incorrect scanner output — gets false_p=true, deactivated |
| Risk accepted | Real finding the organization chooses not to remediate — marked risk_accepted=true |
| Triage note | Auditable note added to each finding recording Claude's reasoning |
| DD→Jira push | Normally a manual human step; this skill automates it for verified findings |

## Output Format

```json
{
  "product_id": 1,
  "total_fetched": 15,
  "total_triaged": 15,
  "dry_run": false,
  "summary": {
    "true_positives": 8,
    "false_positives": 5,
    "risk_accepted": 2,
    "jira_tickets_created": 8,
    "errors": 0
  },
  "findings": [
    {
      "id": 42,
      "title": "SQL Injection in /api/search",
      "severity": "Critical",
      "verdict": "true_positive",
      "confidence": 95,
      "reasoning": "Finding includes parameterized query context showing raw string concatenation...",
      "jira_key": "SEC-201",
      "dd_note_added": true,
      "dd_patched": true
    }
  ]
}
```
