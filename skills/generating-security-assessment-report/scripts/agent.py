#!/usr/bin/env python3
"""Security Assessment Report Generator — HTML (always) + optional PDF (fpdf2)."""
import argparse
import html
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False

SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "PASS": 0}
SEVERITY_COLOR = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c",
    "MEDIUM":   "#d97706", "LOW":  "#2563eb",
    "INFO":     "#6b7280", "PASS": "#16a34a",
}
SEVERITY_BG = {
    "CRITICAL": "#fef2f2", "HIGH": "#fff7ed",
    "MEDIUM":   "#fffbeb", "LOW":  "#eff6ff",
    "INFO":     "#f9fafb", "PASS": "#f0fdf4",
}


# ── Normalise any Phantom JSON report into a flat findings list ────────────────

def normalise(data: dict, source_file: str) -> tuple[str, str, list[dict]]:
    """Return (target_url, methodology, [normalised_findings])."""
    target   = data.get("target_url", data.get("target", ""))
    method   = data.get("methodology", Path(source_file).stem)
    findings = []

    # OWASP API assessment  →  results[].findings[]
    if "results" in data and isinstance(data["results"], list):
        for result in data["results"]:
            owasp_id = result.get("owasp_id", "")
            risk     = result.get("risk", "")
            for fi in result.get("findings", []):
                sev = fi.get("severity", result.get("severity", "INFO"))
                if SEVERITY_ORDER.get(sev, 0) < 1:
                    continue
                findings.append(_make_finding(
                    title    = fi.get("detail", fi.get("description", risk or owasp_id)),
                    severity = sev,
                    owasp    = fi.get("owasp", owasp_id),
                    asvs     = fi.get("asvs", ""),
                    cwe      = fi.get("cwe", ""),
                    url      = fi.get("url", fi.get("endpoint", target)),
                    detail   = fi.get("detail", fi.get("description", "")),
                    evidence = fi.get("evidence", fi.get("param", "")),
                    remediation = fi.get("remediation", fi.get("solution", "")),
                    reproduction_steps = fi.get("reproduction_steps", fi.get("steps_to_reproduce", "")),
                    source   = method,
                ))

    # ASVS active verification  →  chapters[].failing_controls[]
    elif "chapters" in data and isinstance(data["chapters"], list):
        for ch in data["chapters"]:
            chapter = ch.get("chapter", "")
            title   = ch.get("title", "")
            for ctrl in ch.get("failing_controls", []):
                sev = ctrl.get("severity", "LOW")
                if SEVERITY_ORDER.get(sev, 0) < 1:
                    continue
                findings.append(_make_finding(
                    title    = f"[{ctrl.get('control_id', chapter)}] {ctrl.get('description', title)}",
                    severity = sev,
                    owasp    = "",
                    asvs     = f"{chapter} — {title}",
                    cwe      = "",
                    url      = target,
                    detail   = ctrl.get("description", ""),
                    evidence = "",
                    remediation = "",
                    reproduction_steps = ctrl.get("reproduction_steps", ctrl.get("steps_to_reproduce", "")),
                    source   = method,
                ))

    # ZAP / flat findings[]
    elif "findings" in data and isinstance(data["findings"], list):
        for fi in data["findings"]:
            sev = fi.get("severity", "INFO")
            if SEVERITY_ORDER.get(sev, 0) < 1:
                continue
            findings.append(_make_finding(
                title    = fi.get("alert", fi.get("test", fi.get("check", "Finding"))),
                severity = sev,
                owasp    = fi.get("owasp_top10", fi.get("owasp", "")),
                asvs     = fi.get("asvs_chapter", fi.get("asvs", "")),
                cwe      = fi.get("cwe_id", fi.get("cwe", "")),
                url      = fi.get("url", fi.get("endpoint", target)),
                detail   = fi.get("detail", fi.get("description", fi.get("alert", ""))),
                evidence = fi.get("evidence", fi.get("param", "")),
                remediation = fi.get("solution", fi.get("remediation", "")),
                reproduction_steps = fi.get("reproduction_steps", fi.get("steps_to_reproduce", "")),
                source   = method,
            ))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 0), reverse=True)
    return target, method, findings


def _make_finding(**kwargs) -> dict:
    return {
        "title":               kwargs.get("title", ""),
        "severity":            kwargs.get("severity", "INFO"),
        "owasp":               kwargs.get("owasp", ""),
        "asvs":                kwargs.get("asvs", ""),
        "cwe":                 kwargs.get("cwe", ""),
        "url":                 kwargs.get("url", ""),
        "detail":              kwargs.get("detail", ""),
        "evidence":            kwargs.get("evidence", ""),
        "remediation":         kwargs.get("remediation", ""),
        "reproduction_steps":  kwargs.get("reproduction_steps", ""),
        "source":              kwargs.get("source", ""),
    }


# ── HTML report ────────────────────────────────────────────────────────────────

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       font-size: 14px; color: #1e293b; background: #f8fafc; line-height: 1.6; }
a { color: #2563eb; }

/* Cover */
.cover { background: #0f172a; color: white; padding: 60px 64px; min-height: 100vh;
         display: flex; flex-direction: column; justify-content: center; }
.cover-logo { font-size: 11px; letter-spacing: 3px; text-transform: uppercase;
              color: #94a3b8; margin-bottom: 48px; }
.cover h1 { font-size: 42px; font-weight: 700; letter-spacing: -1px;
            line-height: 1.15; margin-bottom: 12px; }
.cover-subtitle { font-size: 16px; color: #94a3b8; margin-bottom: 48px; }
.cover-meta { border-collapse: collapse; width: 100%; max-width: 560px;
              margin-bottom: 48px; }
.cover-meta td { padding: 10px 0; border-bottom: 1px solid #1e3a5f;
                 vertical-align: top; }
.cover-meta td:first-child { width: 140px; color: #94a3b8; font-size: 12px;
                              text-transform: uppercase; letter-spacing: 1px; }
.cover-meta td:last-child { color: #e2e8f0; font-weight: 500; }
.risk-badge { display: inline-block; padding: 8px 20px; border-radius: 4px;
              font-weight: 700; font-size: 15px; letter-spacing: 1px;
              text-transform: uppercase; }
.risk-CRITICAL { background: #dc2626; color: white; }
.risk-HIGH     { background: #ea580c; color: white; }
.risk-MEDIUM   { background: #d97706; color: white; }
.risk-LOW      { background: #2563eb; color: white; }
.risk-PASS     { background: #16a34a; color: white; }
.risk-INFO     { background: #6b7280; color: white; }
.risk-UNKNOWN  { background: #6b7280; color: white; }

/* Page layout */
.page { max-width: 900px; margin: 48px auto; padding: 0 24px; }
h2 { font-size: 22px; font-weight: 700; color: #0f172a; margin-bottom: 20px;
     padding-bottom: 10px; border-bottom: 2px solid #e2e8f0; }
h3 { font-size: 16px; font-weight: 600; color: #0f172a; }

/* Summary cards */
.summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px;
                margin-bottom: 32px; }
.stat-card { background: white; border: 1px solid #e2e8f0; border-radius: 8px;
             padding: 16px; text-align: center; }
.stat-card .num { font-size: 32px; font-weight: 700; }
.stat-card .lbl { font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
                  color: #64748b; margin-top: 2px; }
.stat-CRITICAL .num { color: #dc2626; }
.stat-HIGH .num     { color: #ea580c; }
.stat-MEDIUM .num   { color: #d97706; }
.stat-LOW .num      { color: #2563eb; }
.stat-TOTAL .num    { color: #0f172a; }

/* Risk bar */
.risk-bar-wrap { background: white; border: 1px solid #e2e8f0; border-radius: 8px;
                 padding: 20px 24px; margin-bottom: 32px; }
.risk-bar-wrap h3 { margin-bottom: 12px; font-size: 13px; text-transform: uppercase;
                    letter-spacing: 1px; color: #64748b; }
.risk-bar { display: flex; height: 28px; border-radius: 6px; overflow: hidden;
            gap: 2px; }
.risk-seg { display: flex; align-items: center; justify-content: center;
            font-size: 11px; font-weight: 700; color: white;
            transition: flex 0.3s; min-width: 0; overflow: hidden; }
.risk-legend { display: flex; gap: 16px; margin-top: 10px; flex-wrap: wrap; }
.legend-item { display: flex; align-items: center; gap: 6px;
               font-size: 12px; color: #475569; }
.legend-dot { width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }

/* Source badges */
.sources { margin-bottom: 32px; }
.source-tag { display: inline-block; background: #f1f5f9; color: #475569;
              border: 1px solid #e2e8f0; border-radius: 4px;
              font-size: 11px; padding: 3px 8px; margin: 3px; }

/* Findings */
.severity-section { margin-bottom: 40px; }
.severity-header { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; }
.severity-label { display: inline-block; padding: 4px 12px; border-radius: 4px;
                  font-size: 12px; font-weight: 700; text-transform: uppercase;
                  letter-spacing: 1px; color: white; }
.severity-count { font-size: 13px; color: #64748b; }

.finding { background: white; border: 1px solid #e2e8f0; border-radius: 8px;
           margin-bottom: 12px; overflow: hidden; }
.finding-header { padding: 14px 20px; display: flex; align-items: flex-start;
                  gap: 12px; cursor: pointer; }
.finding-title { font-weight: 600; font-size: 14px; flex: 1; }
.finding-meta { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.meta-chip { font-size: 11px; color: #64748b; background: #f8fafc;
             border: 1px solid #e2e8f0; border-radius: 3px; padding: 2px 6px; }
.finding-body { padding: 0 20px 20px; border-top: 1px solid #f1f5f9; }
.finding-body table { width: 100%; border-collapse: collapse; margin: 14px 0; }
.finding-body td { padding: 7px 10px; border: 1px solid #f1f5f9; font-size: 13px;
                   vertical-align: top; }
.finding-body td:first-child { width: 120px; font-weight: 600; color: #475569;
                                background: #f8fafc; }
.finding-detail { margin-top: 12px; color: #374151; font-size: 13px; }
.finding-evidence { background: #f8fafc; border-left: 3px solid #e2e8f0;
                    padding: 10px 14px; margin: 10px 0; font-family: monospace;
                    font-size: 12px; overflow-x: auto; white-space: pre-wrap; }
.remediation-box { background: #f0fdf4; border: 1px solid #bbf7d0;
                   border-radius: 6px; padding: 12px 16px; margin-top: 12px; }
.remediation-box h4 { font-size: 12px; color: #166534; text-transform: uppercase;
                       letter-spacing: 1px; margin-bottom: 6px; }
.remediation-box p { font-size: 13px; color: #166534; }
.reproduction-box { background: #faf5ff; border: 1px solid #e9d5ff;
                    border-radius: 6px; padding: 12px 16px; margin-top: 12px; }
.reproduction-box h4 { font-size: 12px; color: #6b21a8; text-transform: uppercase;
                        letter-spacing: 1px; margin-bottom: 8px; }
.reproduction-box pre { font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', monospace;
                         font-size: 12px; color: #3b0764; background: #f3e8ff;
                         border-radius: 4px; padding: 10px 12px; overflow-x: auto;
                         white-space: pre-wrap; word-break: break-all; margin: 0; }

/* Methodology */
.methodology { background: white; border: 1px solid #e2e8f0; border-radius: 8px;
               padding: 24px; margin-bottom: 32px; }
.methodology table { width: 100%; border-collapse: collapse; }
.methodology td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; }
.methodology td:first-child { width: 180px; color: #64748b; font-weight: 500; }


/* Print */
@media print {
  body { background: white; font-size: 12px; }
  .cover { min-height: auto; padding: 40px; page-break-after: always; }
  .page { margin: 20px auto; }
  .finding { page-break-inside: avoid; }
  .severity-section { page-break-inside: avoid; }
  h2 { page-break-after: avoid; }
  .summary-grid { grid-template-columns: repeat(5, 1fr); }
}
"""


def _h(s: str) -> str:
    return html.escape(str(s) if s else "")


def render_html(title, target, author, date_str, overall_risk, findings,
                methodologies, sources) -> str:
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    total = len(findings)

    # Risk distribution bar
    bar_html = ""
    bar_legend = ""
    colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c",
              "MEDIUM": "#d97706", "LOW": "#2563eb", "INFO": "#6b7280"}
    for sev, color in colors.items():
        n = counts.get(sev, 0)
        if n > 0 and total > 0:
            pct = max(round(n / total * 100), 5)
            bar_html += (f'<div class="risk-seg" style="flex:{pct};background:{color}">'
                         f'{n}</div>')
            bar_legend += (f'<div class="legend-item">'
                           f'<div class="legend-dot" style="background:{color}"></div>'
                           f'{sev}: {n}</div>')

    # Source tags
    source_tags = "".join(
        f'<span class="source-tag">{_h(s)}</span>'
        for s in sorted(set(f["source"] for f in findings if f.get("source")))
    )

    # Stat cards
    stat_cards = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        n = counts.get(sev, 0)
        stat_cards += (f'<div class="stat-card stat-{sev}">'
                       f'<div class="num">{n}</div>'
                       f'<div class="lbl">{sev}</div></div>')
    stat_cards = (f'<div class="stat-card stat-TOTAL">'
                  f'<div class="num">{total}</div>'
                  f'<div class="lbl">Total</div></div>') + stat_cards

    # Findings sections
    findings_html = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        sev_finds = [f for f in findings if f["severity"] == sev]
        if not sev_finds:
            continue
        color = SEVERITY_COLOR[sev]
        cards = ""
        for i, f in enumerate(sev_finds):
            meta = ""
            if f.get("owasp"):
                meta += f'<span class="meta-chip">{_h(f["owasp"])}</span>'
            if f.get("asvs"):
                meta += f'<span class="meta-chip">ASVS {_h(f["asvs"])}</span>'
            if f.get("cwe") and f["cwe"] not in ("N/A", ""):
                meta += f'<span class="meta-chip">CWE-{_h(f["cwe"])}</span>'

            rows = ""
            for label, key in [("URL / Location", "url"), ("OWASP", "owasp"),
                                ("ASVS", "asvs"), ("CWE", "cwe"), ("Source", "source")]:
                val = f.get(key, "")
                if val and val != "N/A":
                    rows += f'<tr><td>{label}</td><td>{_h(val)}</td></tr>'

            evidence_block = ""
            if f.get("evidence"):
                evidence_block = (f'<div class="finding-evidence">{_h(f["evidence"])}</div>')

            remed_block = ""
            if f.get("remediation"):
                remed_block = (
                    f'<div class="remediation-box">'
                    f'<h4>Remediation</h4>'
                    f'<p>{_h(f["remediation"])}</p>'
                    f'</div>'
                )

            repro_block = ""
            if f.get("reproduction_steps"):
                repro_block = (
                    f'<div class="reproduction-box">'
                    f'<h4>How to Reproduce</h4>'
                    f'<pre>{_h(f["reproduction_steps"])}</pre>'
                    f'</div>'
                )

            cards += f"""
<div class="finding">
  <div class="finding-header">
    <div class="finding-title">{_h(f["title"])}</div>
    <div class="finding-meta">{meta}</div>
  </div>
  <div class="finding-body">
    <table>{rows}</table>
    <div class="finding-detail">{_h(f["detail"])}</div>
    {evidence_block}
    {repro_block}
    {remed_block}
  </div>
</div>"""

        findings_html += f"""
<div class="severity-section">
  <div class="severity-header">
    <span class="severity-label" style="background:{color}">{sev}</span>
    <span class="severity-count">{len(sev_finds)} finding{"s" if len(sev_finds) != 1 else ""}</span>
  </div>
  {cards}
</div>"""

    # Methodology table
    method_rows = "".join(
        f'<tr><td>Methodology</td><td>{_h(m)}</td></tr>'
        for m in methodologies
    )

    risk_badge_class = overall_risk if overall_risk in SEVERITY_COLOR else "UNKNOWN"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_h(title)}</title>
<style>{CSS}</style>
</head>
<body>

<!-- Cover -->
<div class="cover">
  <div class="cover-logo">Phantom · Cybersecurity Skills</div>
  <h1>{_h(title)}</h1>
  <div class="cover-subtitle">Automated Security Assessment Report</div>
  <table class="cover-meta">
    <tr><td>Target</td><td>{_h(target or "Multiple targets")}</td></tr>
    <tr><td>Date</td><td>{_h(date_str)}</td></tr>
    <tr><td>Prepared by</td><td>{_h(author or "Emmanuel Okonkwo (Phantom)")}</td></tr>
    <tr><td>Total Findings</td><td>{total}</td></tr>
    <tr><td>Overall Risk</td>
        <td><span class="risk-badge risk-{risk_badge_class}">{overall_risk}</span></td></tr>
  </table>
</div>

<!-- Executive Summary -->
<div class="page">
  <h2>Executive Summary</h2>

  <div class="summary-grid">{stat_cards}</div>

  <div class="risk-bar-wrap">
    <h3>Risk Distribution</h3>
    <div class="risk-bar">{bar_html or '<div style="flex:1;background:#e2e8f0;border-radius:6px;display:flex;align-items:center;justify-content:center;color:#94a3b8;font-size:12px">No findings</div>'}</div>
    <div class="risk-legend">{bar_legend}</div>
  </div>

  {"<div class='sources'><strong>Tools &amp; Methodologies:</strong> " + source_tags + "</div>" if source_tags else ""}

  <h2>Findings</h2>
  {findings_html or '<p style="color:#64748b;padding:20px 0">No findings above INFO severity.</p>'}

  <h2>Methodology</h2>
  <div class="methodology">
    <table>
      {method_rows}
      <tr><td>Assessment Date</td><td>{_h(date_str)}</td></tr>
      <tr><td>Report Generated</td><td>{_h(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))}</td></tr>
    </table>
  </div>

</div>

</body>
</html>"""


# ── PDF via fpdf2 ──────────────────────────────────────────────────────────────

def render_pdf(title, target, author, date_str, overall_risk, findings,
               methodologies, output_path):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(20, 20, 20)

    # Cover page
    pdf.add_page()
    pdf.set_fill_color(15, 23, 42)
    pdf.rect(0, 0, 210, 297, "F")

    pdf.set_text_color(148, 163, 184)
    pdf.set_font("Helvetica", size=9)
    pdf.set_y(40)
    pdf.cell(0, 6, "PHANTOM  ·  CYBERSECURITY SKILLS", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_y(70)
    pdf.multi_cell(0, 12, title, align="C")

    pdf.set_font("Helvetica", size=11)
    pdf.set_text_color(148, 163, 184)
    pdf.ln(6)
    pdf.cell(0, 8, "Automated Security Assessment Report", align="C", new_x="LMARGIN", new_y="NEXT")

    # Risk badge
    risk_colors = {
        "CRITICAL": (220, 38, 38), "HIGH": (234, 88, 12),
        "MEDIUM": (217, 119, 6), "LOW": (37, 99, 235), "PASS": (22, 163, 74),
    }
    rc = risk_colors.get(overall_risk, (107, 114, 128))
    pdf.set_y(130)
    pdf.set_fill_color(*rc)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 12, f"OVERALL RISK: {overall_risk}", align="C", fill=True,
             new_x="LMARGIN", new_y="NEXT")

    # Cover meta
    meta = [("Target", target or "Multiple targets"), ("Date", date_str),
            ("Prepared by", author or "Emmanuel Okonkwo (Phantom)"),
            ("Total Findings", str(len(findings)))]
    pdf.ln(20)
    for label, val in meta:
        pdf.set_text_color(148, 163, 184)
        pdf.set_font("Helvetica", size=9)
        pdf.cell(45, 7, label.upper(), new_x="RIGHT")
        pdf.set_text_color(226, 232, 240)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, str(val)[:80], new_x="LMARGIN", new_y="NEXT")

    # Executive Summary page
    pdf.add_page()
    pdf.set_fill_color(255, 255, 255)
    pdf.set_text_color(15, 23, 42)

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(226, 232, 240)
    pdf.line(20, pdf.get_y(), 190, pdf.get_y())
    pdf.ln(8)

    # Stats table
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    pdf.set_font("Helvetica", "B", 10)
    headers = ["Severity", "Count"]
    col_w = [80, 80]
    for h, w in zip(headers, col_w):
        pdf.set_fill_color(241, 245, 249)
        pdf.cell(w, 8, h, border=1, fill=True)
    pdf.ln()
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = counts.get(sev, 0)
        c = risk_colors.get(sev, (107, 114, 128))
        pdf.set_fill_color(*c)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(80, 7, sev, border=1, fill=True)
        pdf.set_fill_color(255, 255, 255)
        pdf.set_text_color(15, 23, 42)
        pdf.set_font("Helvetica", size=9)
        pdf.cell(80, 7, str(n), border=1)
        pdf.ln()
    pdf.ln(10)

    # Findings pages
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "Findings", new_x="LMARGIN", new_y="NEXT")
    pdf.line(20, pdf.get_y(), 190, pdf.get_y())
    pdf.ln(8)

    for i, f in enumerate(findings, 1):
        sev = f["severity"]
        c = risk_colors.get(sev, (107, 114, 128))

        pdf.set_fill_color(*c)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        title_text = f"{i}. [{sev}] {f['title']}"[:100]
        pdf.cell(0, 8, title_text, fill=True, new_x="LMARGIN", new_y="NEXT")

        pdf.set_fill_color(255, 255, 255)
        pdf.set_text_color(71, 85, 105)
        pdf.set_font("Helvetica", size=8)

        rows = []
        if f.get("url"):    rows.append(("URL", f["url"][:90]))
        if f.get("owasp"):  rows.append(("OWASP", f["owasp"]))
        if f.get("asvs"):   rows.append(("ASVS",  f["asvs"]))
        if f.get("cwe") and f["cwe"] not in ("N/A", ""):
            rows.append(("CWE", f"CWE-{f['cwe']}"))

        for label, val in rows:
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(30, 6, label + ":", border="B")
            pdf.set_font("Helvetica", size=8)
            pdf.cell(0, 6, str(val)[:120], border="B", new_x="LMARGIN", new_y="NEXT")

        if f.get("detail"):
            pdf.set_font("Helvetica", size=8)
            pdf.set_text_color(55, 65, 81)
            pdf.multi_cell(0, 5, str(f["detail"])[:400])

        if f.get("remediation"):
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(22, 101, 52)
            pdf.multi_cell(0, 5, "Remediation: " + str(f["remediation"])[:300])

        pdf.set_text_color(15, 23, 42)
        pdf.ln(6)

    # Footer
    pdf.set_y(-20)
    pdf.set_font("Helvetica", size=8)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 6, f"Generated by Phantom · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
             align="C")

    pdf.output(str(output_path))


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate HTML/PDF security report from Phantom JSON outputs"
    )
    parser.add_argument("--input", nargs="+", required=True,
                        help="One or more JSON report files from any Phantom skill")
    parser.add_argument("--title", default="Security Assessment Report",
                        help="Report title")
    parser.add_argument("--target", default="",
                        help="Target application URL (auto-detected from JSON if omitted)")
    parser.add_argument("--author", default="",
                        help="Author / team name for the cover page")
    parser.add_argument("--format", choices=["html", "pdf", "both"], default="html",
                        help="Output format (default: html; pdf requires: pip install fpdf2)")
    parser.add_argument("--output", default="security_report.html",
                        help="Output file path (extension determines format when --format=html)")
    args = parser.parse_args()

    all_findings   = []
    all_targets    = []
    methodologies  = []
    sources        = set()

    for path in args.input:
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception as e:
            print(f"Warning: could not read {path}: {e}", file=sys.stderr)
            continue

        target, method, findings = normalise(data, path)
        all_findings.extend(findings)
        if target and target not in all_targets:
            all_targets.append(target)
        if method and method not in methodologies:
            methodologies.append(method)
        for f in findings:
            if f.get("source"):
                sources.add(f["source"])

    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 0), reverse=True)

    target_str  = args.target or (all_targets[0] if len(all_targets) == 1 else ", ".join(all_targets[:3]))
    date_str    = datetime.now(timezone.utc).strftime("%B %d, %Y")

    sev_weights = {s: SEVERITY_ORDER.get(s, 0) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    max_sev     = max((sev_weights.get(f["severity"], 0) for f in all_findings), default=0)
    overall     = next((s for s, w in sorted(sev_weights.items(), key=lambda x: x[1], reverse=True)
                        if w == max_sev and max_sev > 0), "PASS")

    out_path = Path(args.output)

    # HTML
    if args.format in ("html", "both"):
        html_path = out_path if out_path.suffix == ".html" else out_path.with_suffix(".html")
        report_html = render_html(
            title        = args.title,
            target       = target_str,
            author       = args.author,
            date_str     = date_str,
            overall_risk = overall,
            findings     = all_findings,
            methodologies= methodologies,
            sources      = sources,
        )
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(report_html)
        print(f"HTML report: {html_path}", flush=True)
        if args.format == "html":
            print("  To save as PDF: open in Chrome/Safari → Cmd+P → Save as PDF", flush=True)

    # PDF
    if args.format in ("pdf", "both"):
        if not HAS_FPDF:
            print("PDF generation requires fpdf2: pip install fpdf2", file=sys.stderr)
            if args.format == "pdf":
                sys.exit(2)
        else:
            pdf_path = out_path.with_suffix(".pdf")
            render_pdf(
                title        = args.title,
                target       = target_str,
                author       = args.author,
                date_str     = date_str,
                overall_risk = overall,
                findings     = all_findings,
                methodologies= methodologies,
                output_path  = pdf_path,
            )
            print(f"PDF report:  {pdf_path}", flush=True)

    summary = {
        "title": args.title,
        "target": target_str,
        "overall_risk": overall,
        "total_findings": len(all_findings),
        "critical": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
        "high":     sum(1 for f in all_findings if f["severity"] == "HIGH"),
        "medium":   sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
        "low":      sum(1 for f in all_findings if f["severity"] == "LOW"),
        "inputs":   args.input,
        "format":   args.format,
        "output":   str(out_path),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
