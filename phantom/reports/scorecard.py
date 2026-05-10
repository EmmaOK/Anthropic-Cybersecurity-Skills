#!/usr/bin/env python3
"""
phantom/reports/scorecard.py — Security scorecard generator for Phantom CI.

Produces per-category scores (0-100) with letter grades (A-F) mapped to
OWASP Web Top 10, LLM Top 10, MCP Top 10, and Agentic Top 10 frameworks.
Renders both a structured JSON scorecard and a self-contained HTML report.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from string import Template
from typing import Any

# ---------------------------------------------------------------------------
# OWASP category definitions
# ---------------------------------------------------------------------------

OWASP_WEB = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable & Outdated Components",
    "A07": "Identification & Authentication Failures",
    "A08": "Software & Data Integrity Failures",
    "A09": "Security Logging & Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Model Denial of Service",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Excessive Agency",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

OWASP_MCP = {
    "MCP01": "Tool Poisoning",
    "MCP02": "Authentication & Authorization",
    "MCP03": "Privilege Scope Enforcement",
    "MCP04": "Context Injection",
    "MCP05": "Shadow Server Exposure",
    "MCP06": "Command Injection",
    "MCP07": "Token & Secret Exposure",
    "MCP08": "Intent Flow Subversion",
    "MCP09": "Audit Logging Gaps",
    "MCP10": "Supply Chain Integrity",
}

OWASP_AGENTIC = {
    "ASI01": "Prompt Injection (Agentic)",
    "ASI02": "Sensitive Data Disclosure",
    "ASI03": "Memory Poisoning",
    "ASI04": "Tool Misuse",
    "ASI05": "Identity & Privilege Escalation",
    "ASI06": "Unsafe Code Execution",
    "ASI07": "Insufficient Human Oversight",
    "ASI08": "Supply Chain Compromise",
    "ASI09": "Cascading Failure",
    "ASI10": "Vector & Embedding Attacks",
}

# Maps `category` field values from findings → OWASP Web IDs
CATEGORY_TO_WEB = {
    "injection":        "A03",
    "sqli":             "A03",
    "xss":              "A03",
    "xxe":              "A03",
    "auth":             "A07",
    "authentication":   "A07",
    "broken-auth":      "A07",
    "access-control":   "A01",
    "idor":             "A01",
    "bola":             "A01",
    "crypto":           "A02",
    "tls":              "A02",
    "config":           "A05",
    "misconfiguration": "A05",
    "exposure":         "A06",
    "components":       "A06",
    "design":           "A04",
    "integrity":        "A08",
    "logging":          "A09",
    "monitoring":       "A09",
    "ssrf":             "A10",
}

SEVERITY_PENALTY = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
SEVERITY_ORDER   = {"CRITICAL": 4,  "HIGH": 3,  "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _grade(score: int) -> str:
    if score >= 85: return "A"
    if score >= 70: return "B"
    if score >= 55: return "C"
    if score >= 40: return "D"
    return "F"


def _grade_color(grade: str) -> str:
    return {"A": "#27ae60", "B": "#2ecc71", "C": "#f39c12", "D": "#e67e22", "F": "#e74c3c"}.get(grade, "#7f8c8d")


def _score_findings(findings: list[dict]) -> int:
    score = 100
    for f in findings:
        score -= SEVERITY_PENALTY.get(f.get("severity", "INFO"), 0)
    return max(0, score)


def _bucket_findings(all_findings: list[dict], owasp_map: dict, id_field: str = "owasp_id") -> dict[str, list]:
    """Group findings by OWASP ID using owasp_id field or category heuristic."""
    buckets: dict[str, list] = {k: [] for k in owasp_map}
    for f in all_findings:
        oid = f.get(id_field, "")
        if oid in owasp_map:
            buckets[oid].append(f)
    return buckets


def _bucket_web_findings(all_findings: list[dict]) -> dict[str, list]:
    """Map web findings to OWASP Web Top 10 IDs via category field."""
    buckets: dict[str, list] = {k: [] for k in OWASP_WEB}
    for f in all_findings:
        cat = f.get("category", "").lower().replace(" ", "-").replace("_", "-")
        oid = f.get("owasp_id", "")
        # Direct OWASP ID match
        if oid in OWASP_WEB:
            buckets[oid].append(f)
            continue
        # Category heuristic
        mapped = CATEGORY_TO_WEB.get(cat)
        if mapped:
            buckets[mapped].append(f)
        else:
            # Default uncategorised web findings to A05 (misconfiguration) as catch-all
            if f.get("category") not in ("ai-llm", "mcp", "agentic"):
                buckets["A05"].append(f)
    return buckets


def _framework_scorecard(title: str, owasp_map: dict, buckets: dict[str, list]) -> dict:
    cat_results = {}
    for oid, label in owasp_map.items():
        fs = buckets.get(oid, [])
        sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in fs:
            sev[f.get("severity", "INFO")] = sev.get(f.get("severity", "INFO"), 0) + 1
        score = _score_findings(fs)
        cat_results[oid] = {
            "title":    label,
            "score":    score,
            "grade":    _grade(score),
            "total":    len(fs),
            "critical": sev["CRITICAL"],
            "high":     sev["HIGH"],
            "medium":   sev["MEDIUM"],
            "low":      sev["LOW"],
        }

    scores = [v["score"] for v in cat_results.values()]
    fw_score = round(sum(scores) / len(scores)) if scores else 100
    return {
        "title":      title,
        "score":      fw_score,
        "grade":      _grade(fw_score),
        "categories": cat_results,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_scorecard(findings: dict, config: dict) -> dict:
    """
    Build a full security scorecard from Phantom findings.
    Returns a structured dict ready for JSON serialisation or HTML rendering.
    """
    all_f: list[dict] = findings.get("findings", [])
    summary = findings.get("summary", {})
    engagement = config.get("engagement", {})

    web_f    = [f for f in all_f if f.get("category") not in ("ai-llm", "mcp", "agentic")]
    llm_f    = [f for f in all_f if f.get("category") == "ai-llm"]
    mcp_f    = [f for f in all_f if f.get("category") == "mcp"]
    agent_f  = [f for f in all_f if f.get("category") == "agentic"]

    frameworks = {}

    if web_f or not any([llm_f, mcp_f, agent_f]):
        frameworks["web"] = _framework_scorecard(
            "OWASP Web Top 10 2021", OWASP_WEB, _bucket_web_findings(web_f or all_f)
        )
    if llm_f:
        frameworks["llm"] = _framework_scorecard(
            "OWASP LLM Top 10 2025", OWASP_LLM, _bucket_findings(llm_f, OWASP_LLM)
        )
    if mcp_f:
        frameworks["mcp"] = _framework_scorecard(
            "OWASP MCP Top 10 v0.1", OWASP_MCP, _bucket_findings(mcp_f, OWASP_MCP)
        )
    if agent_f:
        frameworks["agentic"] = _framework_scorecard(
            "OWASP Agentic Top 10 2026", OWASP_AGENTIC, _bucket_findings(agent_f, OWASP_AGENTIC)
        )

    # Overall score: average of framework scores (or summary risk_score fallback)
    fw_scores = [v["score"] for v in frameworks.values()]
    overall_score = round(sum(fw_scores) / len(fw_scores)) if fw_scores else max(0, 100 - summary.get("risk_score", 0))

    targets = engagement.get("targets", [])
    target_str = ", ".join(targets) if isinstance(targets, list) else str(targets)

    return {
        "tool":       "Phantom CI",
        "target":     target_str,
        "scan_date":  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "overall": {
            "score":          overall_score,
            "grade":          _grade(overall_score),
            "risk_score":     summary.get("risk_score", 0),
            "recommendation": summary.get("recommendation", "UNKNOWN"),
            "total_findings": summary.get("total", 0),
            "critical":       summary.get("critical", 0),
            "high":           summary.get("high", 0),
            "medium":         summary.get("medium", 0),
            "low":            summary.get("low", 0),
        },
        "frameworks": frameworks,
    }


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def render_markdown_scorecard(sc: dict) -> str:
    ov = sc["overall"]
    grade = ov["grade"]
    grade_emoji = {"A": "🟢", "B": "🟢", "C": "🟡", "D": "🟠", "F": "🔴"}.get(grade, "⚪")
    rec_icon = {"BLOCK_DEPLOY": "🚨", "PROCEED_WITH_CAUTION": "⚠️", "PROCEED": "✅"}.get(ov["recommendation"], "🔍")

    lines = [
        "## Security Scorecard",
        "",
        f"| | |",
        f"|---|---|",
        f"| **Target** | `{sc['target']}` |",
        f"| **Scan date** | {sc['scan_date']} |",
        f"| **Overall grade** | {grade_emoji} **{grade}** ({ov['score']}/100) |",
        f"| **Decision** | {rec_icon} {ov['recommendation']} |",
        f"| **Findings** | {ov['critical']} Critical / {ov['high']} High / {ov['medium']} Medium / {ov['low']} Low |",
        "",
    ]

    for fw_key, fw in sc.get("frameworks", {}).items():
        fw_grade = fw["grade"]
        fw_icon = {"A": "🟢", "B": "🟢", "C": "🟡", "D": "🟠", "F": "🔴"}.get(fw_grade, "⚪")
        lines += [
            f"### {fw['title']}",
            f"**Score:** {fw_icon} {fw_grade} ({fw['score']}/100)",
            "",
            "| ID | Category | Score | Grade | Crit | High | Med | Low |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for cat_id, cat in fw["categories"].items():
            bar = "█" * (cat["score"] // 10) + "░" * (10 - cat["score"] // 10)
            lines.append(
                f"| {cat_id} | {cat['title']} | `{bar}` {cat['score']} "
                f"| **{cat['grade']}** | {cat['critical']} | {cat['high']} | {cat['medium']} | {cat['low']} |"
            )
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phantom Security Scorecard — $target</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e;
    --grade-A: #27ae60; --grade-B: #2ecc71;
    --grade-C: #f39c12; --grade-D: #e67e22; --grade-F: #e74c3c;
    --critical: #e74c3c; --high: #e67e22; --medium: #f39c12;
    --low: #3498db; --info: #8b949e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif; font-size: 14px; line-height: 1.5; }
  a { color: #58a6ff; text-decoration: none; }
  .container { max-width: 960px; margin: 0 auto; padding: 32px 20px; }

  /* Header */
  .header { display: flex; align-items: center; gap: 32px; padding: 28px; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 24px; }
  .grade-circle { width: 100px; height: 100px; border-radius: 50%; display: flex; flex-direction: column; align-items: center; justify-content: center; flex-shrink: 0; font-weight: 800; }
  .grade-circle .letter { font-size: 40px; line-height: 1; }
  .grade-circle .pts { font-size: 12px; opacity: .8; }
  .header-info h1 { font-size: 22px; font-weight: 700; }
  .header-info .meta { color: var(--muted); font-size: 12px; margin-top: 4px; }
  .badges { display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap; }
  .badge { padding: 3px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; background: var(--border); }
  .badge.critical { background: #2d0e0e; color: var(--critical); border: 1px solid var(--critical); }
  .badge.high     { background: #2d1b0e; color: var(--high);     border: 1px solid var(--high);     }
  .badge.medium   { background: #2d260e; color: var(--medium);   border: 1px solid var(--medium);   }
  .badge.low      { background: #0e1e2d; color: var(--low);      border: 1px solid var(--low);      }
  .rec-banner { padding: 10px 16px; border-radius: 8px; font-size: 13px; font-weight: 600; margin-bottom: 24px; }
  .rec-BLOCK_DEPLOY        { background: #2d0e0e; border: 1px solid var(--critical); color: var(--critical); }
  .rec-PROCEED_WITH_CAUTION{ background: #2d260e; border: 1px solid var(--medium);   color: var(--medium);   }
  .rec-PROCEED             { background: #0e2d1e; border: 1px solid var(--grade-A);  color: var(--grade-A);  }

  /* Framework card */
  .fw-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 20px; overflow: hidden; }
  .fw-header { display: flex; align-items: center; gap: 16px; padding: 14px 20px; border-bottom: 1px solid var(--border); }
  .fw-badge { width: 44px; height: 44px; border-radius: 8px; display: flex; flex-direction: column; align-items: center; justify-content: center; font-weight: 800; flex-shrink: 0; }
  .fw-badge .ltr { font-size: 20px; line-height: 1; }
  .fw-badge .pts { font-size: 10px; }
  .fw-header h2 { font-size: 15px; font-weight: 700; }
  .fw-score-summary { margin-left: auto; text-align: right; font-size: 12px; color: var(--muted); }

  /* Category table */
  table { width: 100%; border-collapse: collapse; }
  th { padding: 8px 12px; text-align: left; font-size: 11px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; border-bottom: 1px solid var(--border); }
  td { padding: 8px 12px; border-bottom: 1px solid #21262d; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  .cat-id { font-family: monospace; font-size: 12px; color: var(--muted); }
  .cat-title { font-size: 13px; }
  .score-bar-wrap { width: 120px; }
  .score-bar-bg { background: #21262d; border-radius: 4px; height: 8px; overflow: hidden; }
  .score-bar-fill { height: 8px; border-radius: 4px; transition: width .3s; }
  .score-num { font-size: 12px; color: var(--muted); margin-top: 2px; }
  .grade-pill { display: inline-block; width: 28px; text-align: center; padding: 2px 0; border-radius: 4px; font-size: 12px; font-weight: 700; }
  .sev-counts { display: flex; gap: 6px; }
  .sev-dot { font-size: 11px; font-weight: 600; }
  .sev-dot.c { color: var(--critical); }
  .sev-dot.h { color: var(--high); }
  .sev-dot.m { color: var(--medium); }
  .sev-dot.l { color: var(--low); }

  .footer { text-align: center; color: var(--muted); font-size: 11px; margin-top: 28px; }
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <div class="grade-circle" style="background:$overall_color;color:#fff;">
      <span class="letter">$overall_grade</span>
      <span class="pts">$overall_score/100</span>
    </div>
    <div class="header-info">
      <h1>Security Scorecard</h1>
      <div class="meta">$target &nbsp;·&nbsp; $scan_date</div>
      <div class="badges">
        <span class="badge critical">$critical Critical</span>
        <span class="badge high">$high High</span>
        <span class="badge medium">$medium Medium</span>
        <span class="badge low">$low Low</span>
      </div>
    </div>
  </div>

  <div class="rec-banner rec-$rec_key">$rec_icon &nbsp; $recommendation</div>

  $framework_sections

  <div class="footer">Generated by <strong>Phantom CI</strong> &nbsp;·&nbsp; $scan_date</div>
</div>
</body>
</html>
"""

_FW_SECTION = """\
<div class="fw-card">
  <div class="fw-header">
    <div class="fw-badge" style="background:$fw_color;color:#fff;">
      <span class="ltr">$fw_grade</span>
      <span class="pts">$fw_score</span>
    </div>
    <div>
      <h2>$fw_title</h2>
    </div>
    <div class="fw-score-summary">Score $fw_score / 100</div>
  </div>
  <table>
    <thead><tr>
      <th>ID</th><th>Category</th><th style="width:160px">Score</th>
      <th>Grade</th><th>Findings</th>
    </tr></thead>
    <tbody>$rows</tbody>
  </table>
</div>
"""

_ROW = """\
<tr>
  <td class="cat-id">$cat_id</td>
  <td class="cat-title">$cat_title</td>
  <td class="score-bar-wrap">
    <div class="score-bar-bg"><div class="score-bar-fill" style="width:$score%;background:$color;"></div></div>
    <div class="score-num">$score / 100</div>
  </td>
  <td><span class="grade-pill" style="background:$color;color:#fff;">$grade</span></td>
  <td><div class="sev-counts">
    <span class="sev-dot c">$critical C</span>
    <span class="sev-dot h">$high H</span>
    <span class="sev-dot m">$medium M</span>
    <span class="sev-dot l">$low L</span>
  </div></td>
</tr>
"""


def render_html(sc: dict) -> str:
    ov = sc["overall"]
    overall_color = _grade_color(ov["grade"])
    rec = ov["recommendation"]
    rec_icon = {"BLOCK_DEPLOY": "🚨 DEPLOY BLOCKED", "PROCEED_WITH_CAUTION": "⚠️ PROCEED WITH CAUTION", "PROCEED": "✅ DEPLOY APPROVED"}.get(rec, rec)

    fw_sections = ""
    for fw in sc.get("frameworks", {}).values():
        rows = ""
        for cat_id, cat in fw["categories"].items():
            color = _grade_color(cat["grade"])
            rows += Template(_ROW).substitute(
                cat_id=cat_id, cat_title=cat["title"],
                score=cat["score"], grade=cat["grade"], color=color,
                critical=cat["critical"], high=cat["high"],
                medium=cat["medium"], low=cat["low"],
            )
        fw_color = _grade_color(fw["grade"])
        fw_sections += Template(_FW_SECTION).substitute(
            fw_title=fw["title"], fw_score=fw["score"],
            fw_grade=fw["grade"], fw_color=fw_color, rows=rows,
        )

    return Template(_HTML_TEMPLATE).substitute(
        target=sc["target"] or "Unknown target",
        scan_date=sc["scan_date"],
        overall_grade=ov["grade"],
        overall_score=ov["score"],
        overall_color=overall_color,
        critical=ov["critical"], high=ov["high"],
        medium=ov["medium"], low=ov["low"],
        rec_key=rec,
        rec_icon=rec_icon,
        recommendation=rec,
        framework_sections=fw_sections,
    )
