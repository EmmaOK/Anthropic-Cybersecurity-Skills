#!/usr/bin/env python3
"""
DefectDojo AI Triage Agent

Fetches unverified findings from DefectDojo, uses Claude to determine
true positive / false positive / risk accepted verdict, then:
  - Records the reasoning as an auditable note in DefectDojo
  - Marks the finding verified, false_p, or risk_accepted
  - Creates a Jira ticket for confirmed true positives (replacing the manual push step)

Usage:
  agent.py --product-id 1 --severity Critical,High --limit 20
  agent.py --product-id 1 --apply --no-dry-run --output triage_report.json
"""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

try:
    import anthropic
except ImportError:
    print("anthropic package not installed. Run: pip install anthropic", file=sys.stderr)
    sys.exit(1)

DD_URL         = os.environ.get("DEFECTDOJO_URL", "http://localhost:8080").rstrip("/")
DD_API_KEY     = os.environ.get("DEFECTDOJO_API_KEY", "")
JIRA_URL       = os.environ.get("JIRA_URL", "").rstrip("/")
JIRA_USER      = os.environ.get("JIRA_USER", "")
JIRA_TOKEN     = os.environ.get("JIRA_TOKEN", "")
JIRA_PROJECT   = os.environ.get("JIRA_PROJECT_KEY", "SEC")
ANTHROPIC_KEY  = os.environ.get("ANTHROPIC_API_KEY", "")

SEVERITY_TO_PRIORITY = {
    "Critical": "Highest",
    "High":     "High",
    "Medium":   "Medium",
    "Low":      "Low",
    "Info":     "Lowest",
}


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _dd_headers():
    return {
        "Authorization": f"Token {DD_API_KEY}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }


def _jira_headers():
    token = base64.b64encode(f"{JIRA_USER}:{JIRA_TOKEN}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }


def _get(base_url, endpoint, params=None, headers=None):
    url = f"{base_url}/api/v2/{endpoint.lstrip('/')}/"
    if params:
        url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "detail": e.read().decode(errors="replace")}
    except Exception as e:
        return {"error": str(e)}


def _patch(base_url, endpoint, data, headers=None):
    url = f"{base_url}/api/v2/{endpoint.lstrip('/')}/"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers or {}, method="PATCH")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "detail": e.read().decode(errors="replace")}
    except Exception as e:
        return {"error": str(e)}


def _post(base_url, endpoint, data, headers=None, api_prefix="/api/v2"):
    url = f"{base_url}{api_prefix}/{endpoint.lstrip('/')}/"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers or {}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return json.loads(raw) if raw.strip() else {"success": True}
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "detail": e.read().decode(errors="replace")}
    except Exception as e:
        return {"error": str(e)}


# ── DefectDojo API calls ───────────────────────────────────────────────────────

def dd_list_findings(product_id=None, severity=None, limit=50):
    params = {
        "limit":    limit,
        "active":   "true",
        "verified": "false",
    }
    if product_id:
        params["product"] = product_id
    if severity:
        params["severity"] = severity
    return _get(DD_URL, "findings", params, _dd_headers())


def dd_get_finding(finding_id):
    return _get(DD_URL, f"findings/{finding_id}", headers=_dd_headers())


def dd_patch_finding(finding_id, patch_data):
    return _patch(DD_URL, f"findings/{finding_id}", patch_data, _dd_headers())


def dd_add_note(finding_id, note_text):
    return _post(DD_URL, "notes", {"entry": note_text, "finding": finding_id}, _dd_headers())


# ── Jira API calls ─────────────────────────────────────────────────────────────

def jira_search_existing(title, finding_id):
    if not JIRA_URL or not JIRA_TOKEN:
        return None
    jql = f'project = {JIRA_PROJECT} AND labels = "dd-{finding_id}" AND statusCategory != Done'
    url = f"{JIRA_URL}/rest/api/2/search?jql={urllib.parse.quote(jql)}&maxResults=1&fields=summary,status"
    req = urllib.request.Request(url, headers=_jira_headers())
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            issues = data.get("issues", [])
            return issues[0]["key"] if issues else None
    except Exception:
        return None


def jira_create_issue(finding, reasoning):
    if not JIRA_URL or not JIRA_TOKEN:
        return None, "Jira not configured (missing JIRA_URL / JIRA_TOKEN)"

    priority = SEVERITY_TO_PRIORITY.get(finding.get("severity", "Medium"), "Medium")
    labels   = ["security", f"dd-{finding['id']}"]
    if finding.get("cve"):
        labels.append(finding["cve"].upper())

    description = (
        f"*DefectDojo Finding ID:* {finding['id']}\n\n"
        f"*Severity:* {finding.get('severity', 'Unknown')}\n"
        f"*Tool:* {', '.join(finding.get('found_by', []) or []) or 'Unknown'}\n"
        f"*Endpoints:* {', '.join(finding.get('endpoints', []) or []) or 'N/A'}\n"
        f"*CVE:* {finding.get('cve') or 'N/A'}\n\n"
        f"*AI Triage Reasoning:*\n{reasoning}\n\n"
        f"*Description:*\n{(finding.get('description') or '')[:2000]}"
    )

    payload = {
        "fields": {
            "project":   {"key": JIRA_PROJECT},
            "summary":   f"[{finding.get('severity', '?')}] {finding.get('title', 'Security Finding')}",
            "issuetype": {"name": "Bug"},
            "priority":  {"name": priority},
            "labels":    labels,
            "description": description,
        }
    }

    url = f"{JIRA_URL}/rest/api/2/issue/"
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, headers=_jira_headers(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            return result.get("key"), None
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        return None, f"HTTP {e.code}: {detail}"
    except Exception as e:
        return None, str(e)


# ── AI triage using Claude ─────────────────────────────────────────────────────

TRIAGE_SYSTEM = """\
You are a senior application security engineer performing AI-assisted vulnerability triage.
You will be given a security finding from a SAST/DAST/SCA scanner. Your job is to determine
whether this is a true positive, false positive, or risk accepted finding.

Respond ONLY with valid JSON in this exact structure:
{
  "verdict": "true_positive" | "false_positive" | "risk_accepted",
  "confidence": <integer 0-100>,
  "reasoning": "<2-4 sentence explanation for your verdict>",
  "recommended_priority": "immediate" | "high" | "medium" | "low" | "informational"
}

Guidelines:
- true_positive: The finding represents a real, exploitable vulnerability
- false_positive: The finding is incorrect scanner output (test code, sanitized input, unreachable path, scanner noise)
- risk_accepted: Real finding but low likelihood, compensating controls present, or acceptable business risk
- Be conservative: when uncertain, lean toward true_positive (security engineers can override)
- confidence reflects how certain you are, not how severe the finding is
"""


def triage_finding_with_ai(finding):
    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)

    endpoints = finding.get("endpoints", []) or []
    found_by  = finding.get("found_by", []) or []

    prompt = (
        f"Finding Title: {finding.get('title', 'Unknown')}\n"
        f"Severity: {finding.get('severity', 'Unknown')}\n"
        f"CVE: {finding.get('cve') or 'N/A'}\n"
        f"CWE: {finding.get('cwe') or 'N/A'}\n"
        f"Scanner/Tool: {', '.join(found_by) or 'Unknown'}\n"
        f"Affected Endpoint(s): {', '.join(str(e) for e in endpoints[:3]) or 'N/A'}\n\n"
        f"Description:\n{(finding.get('description') or 'No description provided')[:1500]}\n"
    )

    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=512,
            system=TRIAGE_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        text = message.content[0].text.strip()
        return json.loads(text)
    except json.JSONDecodeError as e:
        return {
            "verdict": "true_positive",
            "confidence": 50,
            "reasoning": f"AI returned non-JSON response; defaulting to true_positive. Raw: {text[:200]}",
            "recommended_priority": "medium",
            "parse_error": str(e),
        }
    except Exception as e:
        return {
            "verdict": "true_positive",
            "confidence": 0,
            "reasoning": f"AI triage failed: {e}. Defaulting to true_positive.",
            "recommended_priority": "medium",
            "error": str(e),
        }


# ── Main triage loop ───────────────────────────────────────────────────────────

def run_triage(product_id, severity_filter, limit, apply, dry_run):
    print(f"[*] Fetching unverified findings from DefectDojo ({DD_URL})", file=sys.stderr)

    list_result = dd_list_findings(product_id, severity_filter, limit)
    if "error" in list_result:
        print(f"[!] DefectDojo error: {list_result}", file=sys.stderr)
        sys.exit(1)

    findings = list_result.get("results", [])
    total = list_result.get("count", 0)
    print(f"[*] {total} total unverified findings, fetched {len(findings)}", file=sys.stderr)

    if not findings:
        return {
            "product_id": product_id,
            "total_fetched": 0,
            "total_triaged": 0,
            "dry_run": dry_run or not apply,
            "summary": {"true_positives": 0, "false_positives": 0,
                        "risk_accepted": 0, "jira_tickets_created": 0, "errors": 0},
            "findings": [],
        }

    summary = {"true_positives": 0, "false_positives": 0,
               "risk_accepted": 0, "jira_tickets_created": 0, "errors": 0}
    results = []

    for f in findings:
        fid   = f["id"]
        title = f.get("title", f"Finding #{fid}")
        sev   = f.get("severity", "Unknown")
        print(f"  [{sev}] #{fid} {title[:60]}", file=sys.stderr)

        verdict_data = triage_finding_with_ai(f)
        verdict    = verdict_data.get("verdict", "true_positive")
        confidence = verdict_data.get("confidence", 50)
        reasoning  = verdict_data.get("reasoning", "")

        record = {
            "id":              fid,
            "title":           title,
            "severity":        sev,
            "verdict":         verdict,
            "confidence":      confidence,
            "reasoning":       reasoning,
            "recommended_priority": verdict_data.get("recommended_priority"),
            "jira_key":        None,
            "dd_note_added":   False,
            "dd_patched":      False,
        }

        if apply and not dry_run:
            note_text = (
                f"[AI Triage] Verdict: {verdict} (confidence: {confidence}%)\n"
                f"Reasoning: {reasoning}"
            )
            note_result = dd_add_note(fid, note_text)
            record["dd_note_added"] = "id" in note_result

            if verdict == "false_positive":
                patch = {"false_p": True, "active": False}
                summary["false_positives"] += 1
            elif verdict == "risk_accepted":
                patch = {"risk_accepted": True}
                summary["risk_accepted"] += 1
            else:
                patch = {"verified": True}
                summary["true_positives"] += 1

            patch_result = dd_patch_finding(fid, patch)
            record["dd_patched"] = "id" in patch_result or "error" not in patch_result

            if verdict == "true_positive":
                existing = jira_search_existing(title, fid)
                if existing:
                    record["jira_key"] = existing
                    record["jira_note"] = "existing ticket found"
                else:
                    full_finding = dd_get_finding(fid)
                    merged = {**f, **(full_finding if "error" not in full_finding else {})}
                    jira_key, jira_err = jira_create_issue(merged, reasoning)
                    if jira_key:
                        record["jira_key"] = jira_key
                        summary["jira_tickets_created"] += 1
                        dd_add_note(fid, f"[AI Triage] Jira ticket created: {jira_key}")
                    else:
                        record["jira_error"] = jira_err
        else:
            if verdict == "false_positive":
                summary["false_positives"] += 1
            elif verdict == "risk_accepted":
                summary["risk_accepted"] += 1
            else:
                summary["true_positives"] += 1

        if verdict_data.get("error"):
            summary["errors"] += 1

        results.append(record)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "product_id":   product_id,
        "total_fetched": len(findings),
        "total_triaged": len(results),
        "dry_run":       dry_run or not apply,
        "summary":       summary,
        "findings":      results,
    }


def main():
    parser = argparse.ArgumentParser(description="DefectDojo AI Triage Agent")
    parser.add_argument("--product-id",   type=int,   help="DefectDojo product ID to filter")
    parser.add_argument("--severity",     default=None,
                        help="Comma-separated severities: Critical,High,Medium,Low,Info")
    parser.add_argument("--limit",        type=int,   default=50, help="Max findings to triage")
    parser.add_argument("--apply",        action="store_true",
                        help="Write triage decisions back to DefectDojo and create Jira tickets")
    parser.add_argument("--no-dry-run",   dest="dry_run", action="store_false",
                        help="Actually apply changes (default: dry-run preview only)")
    parser.set_defaults(dry_run=True)
    parser.add_argument("--output",       default="triage_report.json")
    args = parser.parse_args()

    if not ANTHROPIC_KEY:
        print("[!] ANTHROPIC_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    report = run_triage(
        product_id=args.product_id,
        severity_filter=args.severity,
        limit=args.limit,
        apply=args.apply,
        dry_run=args.dry_run,
    )

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)

    s = report["summary"]
    mode = "DRY RUN" if report["dry_run"] else "APPLIED"
    print(f"\n[{mode}] Triaged {report['total_triaged']} findings: "
          f"{s['true_positives']} TP, {s['false_positives']} FP, "
          f"{s['risk_accepted']} risk-accepted, "
          f"{s['jira_tickets_created']} Jira tickets created",
          file=sys.stderr)
    print(f"[+] Report saved to {args.output}", file=sys.stderr)
    print(json.dumps(report, indent=2, default=str))

    if s["true_positives"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
