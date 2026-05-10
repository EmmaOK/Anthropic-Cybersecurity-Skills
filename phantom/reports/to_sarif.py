"""
to_sarif.py — Convert Phantom CI findings to SARIF 2.1.0.

SARIF is the format GitHub reads for the Security tab and PR annotations.
Upload the output with: github/codeql-action/upload-sarif@v3
"""

from datetime import datetime, timezone

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME = "Phantom CI"
TOOL_VERSION = "1.0.0"
TOOL_URI = "https://github.com/EmmaOK/Anthropic-Cybersecurity-Skills"

# Map Phantom severity → SARIF level
SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFO":     "none",
}

# Map category → CWE ID (best-effort)
CATEGORY_TO_CWE = {
    "injection":  "CWE-89",
    "auth":       "CWE-287",
    "config":     "CWE-16",
    "exposure":   "CWE-200",
    "crypto":     "CWE-327",
    "dos":        "CWE-400",
    "other":      "CWE-693",
}


def convert_to_sarif(findings: dict, config: dict | None = None) -> dict:
    """
    Convert Phantom findings dict to SARIF 2.1.0 document.

    Args:
        findings: Output from phantom_ci coordinator — {findings: [...], summary: {...}}
        config:   Optional pentest config for engagement metadata

    Returns:
        SARIF 2.1.0 dict ready to be serialised to JSON.
    """
    items = findings.get("findings", [])
    rules = _build_rules(items)
    results = _build_results(items)

    engagement = (config or {}).get("engagement", {})

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": "python phantom/phantom_ci.py",
                        "endTimeUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "properties": {
                            "targets": engagement.get("targets", []),
                            "scope": engagement.get("scope", []),
                            "risk_score": findings.get("summary", {}).get("risk_score", 0),
                        },
                    }
                ],
                "results": results,
                "properties": {
                    "phantom_summary": findings.get("summary", {}),
                },
            }
        ],
    }


def _build_rules(items: list[dict]) -> list[dict]:
    """One SARIF rule per unique finding title."""
    seen: dict[str, dict] = {}
    for f in items:
        rule_id = _rule_id(f)
        if rule_id not in seen:
            cwe = CATEGORY_TO_CWE.get(f.get("category", "other"), "CWE-693")
            seen[rule_id] = {
                "id": rule_id,
                "name": _pascal(f.get("title", "UnknownFinding")),
                "shortDescription": {"text": f.get("title", "")},
                "fullDescription": {"text": f.get("description", "")},
                "helpUri": (
                    f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"
                    if "-" in cwe else TOOL_URI
                ),
                "properties": {
                    "tags": [
                        f.get("category", "other"),
                        f"severity/{f.get('severity', 'INFO').lower()}",
                        cwe,
                    ]
                    + ([f.get("attack_technique")] if f.get("attack_technique") else [])
                    + ([f.get("cve")] if f.get("cve") else []),
                    "security-severity": _cvss_string(f.get("severity", "INFO")),
                },
                "defaultConfiguration": {
                    "level": SEVERITY_TO_LEVEL.get(f.get("severity", "INFO"), "note")
                },
            }
    return list(seen.values())


def _build_results(items: list[dict]) -> list[dict]:
    """One SARIF result per finding instance."""
    results = []
    for i, f in enumerate(items):
        target = f.get("target", "unknown")
        evidence = f.get("evidence", "")
        results.append({
            "ruleId": _rule_id(f),
            "level": SEVERITY_TO_LEVEL.get(f.get("severity", "INFO"), "note"),
            "message": {
                "text": (
                    f"{f.get('description', '')} "
                    f"| Target: {target} "
                    f"| Remediation: {f.get('remediation', '')}"
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _normalise_uri(target),
                            "uriBaseId": "%SRCROOT%",
                        }
                    }
                }
            ],
            "partialFingerprints": {
                "phantomFindingId": f.get("id", f"F{i+1:03d}"),
            },
            "properties": {
                "target": target,
                "evidence": evidence[:500],
                "cve": f.get("cve"),
                "attack_technique": f.get("attack_technique"),
                "confirmed": f.get("confirmed", False),
            },
        })
    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rule_id(f: dict) -> str:
    title = f.get("title", "unknown").lower()
    safe = "".join(c if c.isalnum() else "-" for c in title).strip("-")
    return f"phantom/{safe[:60]}"


def _pascal(s: str) -> str:
    return "".join(w.capitalize() for w in s.split())


def _normalise_uri(target: str) -> str:
    """Strip protocol for SARIF URI (best-effort)."""
    for prefix in ("https://", "http://", "ssh://"):
        if target.startswith(prefix):
            return target[len(prefix):]
    return target


def _cvss_string(severity: str) -> str:
    """Map severity to approximate CVSS score string (used by GitHub for colouring)."""
    return {
        "CRITICAL": "9.5",
        "HIGH":     "7.5",
        "MEDIUM":   "5.0",
        "LOW":      "2.5",
        "INFO":     "0.0",
    }.get(severity.upper(), "0.0")
