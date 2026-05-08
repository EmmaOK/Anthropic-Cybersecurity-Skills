"""
phantom/notifier.py — Post-investigation email notifications

Sends two emails after a phishing investigation completes:

1. Reporter email — personal message to the person who forwarded the email:
   - Tells them the verdict (phishing / legitimate / suspicious)
   - Asks if they clicked any links or opened attachments
   - Gives clear, jargon-free next steps

2. Security team report — full investigation report in HTML with IOC table,
   verdict summary, and the complete Markdown report inline.

Sending strategy (tried in order):
  1. AWS SES via boto3 (preferred in Lambda / ECS)
  2. SMTP (for on-prem or non-AWS Phantom deployments)

Environment variables:
  PHANTOM_FROM_EMAIL      — "from" address, e.g. phantom@corp.com (required)
  SECURITY_TEAM_EMAIL     — security team distribution list (required for team report)
  AWS_DEFAULT_REGION      — used by boto3 SES automatically
  SMTP_HOST               — SMTP server host (fallback if boto3 unavailable)
  SMTP_PORT               — SMTP port (default 587)
  SMTP_USER               — SMTP username
  SMTP_PASSWORD           — SMTP password
  SMTP_USE_TLS            — "true" to use STARTTLS (default true)
"""

import html as _html
import os
import re
import smtplib
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

FROM_EMAIL  = os.environ.get("PHANTOM_FROM_EMAIL", "phantom@corp.com")
TEAM_EMAIL  = os.environ.get("SECURITY_TEAM_EMAIL", "")
PHANTOM_URL = os.environ.get("PHANTOM_URL", "").rstrip("/")

# Verdict display config
_VERDICT_META = {
    "PHISHING": {
        "color":    "#dc2626",
        "emoji":    "🚨",
        "label":    "CONFIRMED PHISHING",
        "urgency":  "high",
    },
    "SUSPICIOUS": {
        "color":    "#d97706",
        "emoji":    "⚠️",
        "label":    "SUSPICIOUS EMAIL",
        "urgency":  "medium",
    },
    "LEGITIMATE": {
        "color":    "#16a34a",
        "emoji":    "✅",
        "label":    "APPEARS LEGITIMATE",
        "urgency":  "low",
    },
    "UNKNOWN": {
        "color":    "#6b7280",
        "emoji":    "❓",
        "label":    "INCONCLUSIVE",
        "urgency":  "medium",
    },
}


# ── HTML email builder ─────────────────────────────────────────────────────────

_BASE_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
       background: #f8fafc; color: #1e293b; font-size: 15px; line-height: 1.6; }
.wrapper { max-width: 620px; margin: 32px auto; }
.header { border-radius: 8px 8px 0 0; padding: 28px 32px; }
.header h1 { font-size: 13px; letter-spacing: 2px; text-transform: uppercase;
             color: rgba(255,255,255,0.75); margin-bottom: 8px; }
.header h2 { font-size: 26px; font-weight: 700; color: white; }
.body { background: white; padding: 32px; }
.body p { margin-bottom: 16px; color: #374151; }
.verdict-box { border-radius: 8px; padding: 20px 24px; margin: 24px 0; }
.verdict-box .verdict-label { font-size: 12px; text-transform: uppercase;
                               letter-spacing: 1.5px; font-weight: 700;
                               margin-bottom: 6px; }
.verdict-box .verdict-main { font-size: 22px; font-weight: 800; }
.verdict-box .confidence { font-size: 13px; margin-top: 6px; opacity: 0.85; }
.checklist { background: #f8fafc; border-radius: 8px; padding: 20px 24px; margin: 20px 0; }
.checklist h3 { font-size: 14px; font-weight: 700; text-transform: uppercase;
                letter-spacing: 1px; margin-bottom: 14px; }
.checklist label { display: flex; align-items: flex-start; gap: 10px;
                   margin-bottom: 12px; cursor: pointer; }
.checklist .cb { width: 18px; height: 18px; border: 2px solid #d1d5db;
                 border-radius: 4px; flex-shrink: 0; margin-top: 2px; }
.steps { margin: 20px 0; }
.steps h3 { font-size: 14px; font-weight: 700; text-transform: uppercase;
            letter-spacing: 1px; margin-bottom: 14px; }
.step { display: flex; gap: 14px; margin-bottom: 14px; align-items: flex-start; }
.step-num { width: 28px; height: 28px; border-radius: 50%; display: flex;
            align-items: center; justify-content: center; font-size: 13px;
            font-weight: 700; color: white; flex-shrink: 0; }
.step-text { padding-top: 4px; font-size: 14px; color: #374151; }
.meta-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
.meta-table td { padding: 8px 0; border-bottom: 1px solid #f1f5f9;
                 font-size: 13px; vertical-align: top; }
.meta-table td:first-child { width: 130px; color: #6b7280; font-weight: 600; }
.footer { background: #f8fafc; border-radius: 0 0 8px 8px; padding: 20px 32px;
          font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }
.reply-box { background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px;
             padding: 18px 22px; margin: 20px 0; }
.reply-box h3 { font-size: 14px; font-weight: 700; color: #1d4ed8; margin-bottom: 8px; }
.reply-box p { color: #1e40af; font-size: 14px; margin: 0; }
"""

def _html_wrap(header_color: str, header_title: str, header_subtitle: str, body_html: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>{_BASE_CSS}</style></head>
<body>
<div class="wrapper">
  <div class="header" style="background:{header_color}">
    <h1>Phantom · Security Operations</h1>
    <h2>{_html.escape(header_subtitle)}</h2>
  </div>
  <div class="body">
    {body_html}
  </div>
  <div class="footer">
    This message was sent automatically by Phantom, your AI-powered security investigation platform.<br>
    Report ID: {header_title} · Do not forward this email.
  </div>
</div>
</body></html>"""


# ── Reporter email ─────────────────────────────────────────────────────────────

def _build_reporter_email(
    verdict: str,
    confidence: int,
    subject: str,
    from_email: str,
    summary: str,
    report_id: str,
    recommended_action: str,
) -> tuple[str, str, str]:
    """Returns (email_subject, html_body, plain_text)."""
    meta = _VERDICT_META.get(verdict, _VERDICT_META["UNKNOWN"])
    color = meta["color"]
    emoji = meta["emoji"]

    # ── Subject line ──
    if verdict == "PHISHING":
        email_subject = f"{emoji} Action Required: The email you reported is PHISHING"
    elif verdict == "SUSPICIOUS":
        email_subject = f"{emoji} Update: The email you reported looks suspicious"
    elif verdict == "LEGITIMATE":
        email_subject = f"{emoji} Update: The email you reported appears legitimate"
    else:
        email_subject = f"{emoji} Update: Phishing investigation complete"

    # ── Verdict box ──
    verdict_box = f"""
<div class="verdict-box" style="background:{color}18;border:2px solid {color}40;">
  <div class="verdict-label" style="color:{color}">Investigation Verdict</div>
  <div class="verdict-main" style="color:{color}">{emoji} {meta['label']}</div>
  <div class="confidence" style="color:{color}">Confidence: {confidence}%</div>
</div>"""

    # ── Email metadata table ──
    meta_table = f"""
<table class="meta-table">
  <tr><td>Email Subject</td><td>{_html.escape(subject)}</td></tr>
  <tr><td>Sender</td><td>{_html.escape(from_email)}</td></tr>
  <tr><td>Report ID</td><td><code>{_html.escape(report_id)}</code></td></tr>
</table>"""

    # ── Verdict-specific body ──
    if verdict == "PHISHING":
        checklist = """
<div class="checklist">
  <h3 style="color:#dc2626;">⚠️ Please answer these questions</h3>
  <p style="margin-bottom:14px;font-size:14px;color:#374151;">
    Reply to this email with your answers so our security team can assist you immediately.
  </p>
  <label><span class="cb"></span><span>Did you <strong>click any links</strong> in the email?</span></label>
  <label><span class="cb"></span><span>Did you <strong>open any attachments</strong>?</span></label>
  <label><span class="cb"></span><span>Did you <strong>enter your username, password, or any personal information</strong> on any website?</span></label>
  <label><span class="cb"></span><span>Did you <strong>download or run any files</strong>?</span></label>
</div>"""

        steps_color = "#dc2626"
        steps = f"""
<div class="steps">
  <h3 style="color:{steps_color};">If you interacted with the email, do this now:</h3>
  <div class="step">
    <div class="step-num" style="background:{steps_color};">1</div>
    <div class="step-text"><strong>Change your password immediately</strong> — especially if you entered credentials anywhere.</div>
  </div>
  <div class="step">
    <div class="step-num" style="background:{steps_color};">2</div>
    <div class="step-text"><strong>Do not click anything else</strong> in the email or any follow-up emails from the same sender.</div>
  </div>
  <div class="step">
    <div class="step-num" style="background:{steps_color};">3</div>
    <div class="step-text"><strong>Contact the security team</strong> by replying to this email — we will help you immediately.</div>
  </div>
  <div class="step">
    <div class="step-num" style="background:{steps_color};">4</div>
    <div class="step-text">If you ran any files or applications, <strong>disconnect your device from the network</strong> and contact us.</div>
  </div>
</div>"""

        reply_box = """
<div class="reply-box">
  <h3>📧 How to respond</h3>
  <p>Simply <strong>reply to this email</strong> with your answers to the questions above.
  Our security team will follow up with you within the hour.</p>
</div>"""

        body_html = f"""
<p>Thank you for reporting a suspicious email. Our security team investigated it immediately.</p>
{verdict_box}
{meta_table}
<p style="color:#dc2626;font-weight:600;">This email was confirmed as a phishing attempt.
{_html.escape(summary)}</p>
{checklist}
{steps}
{reply_box}
<p style="color:#6b7280;font-size:13px;">
  If you did <em>not</em> click any links or open any attachments, no immediate action is required —
  but please still reply to confirm. Thank you for keeping our organisation safe by reporting this.
</p>"""

        plain = f"""Thank you for reporting a suspicious email.

VERDICT: {verdict} ({confidence}% confidence)
Email From: {from_email}
Subject: {subject}

This email was confirmed as a phishing attempt. {summary}

PLEASE REPLY TO THIS EMAIL AND ANSWER:
1. Did you click any links in the email?
2. Did you open any attachments?
3. Did you enter your username, password, or any personal information?
4. Did you download or run any files?

IF YOU INTERACTED WITH THE EMAIL:
1. Change your password immediately
2. Do not click anything else in the email
3. Reply to this email — the security team will help you
4. If you ran any files, disconnect your device from the network

Report ID: {report_id}"""

    elif verdict == "SUSPICIOUS":
        checklist = """
<div class="checklist">
  <h3 style="color:#d97706;">Please confirm your actions</h3>
  <label><span class="cb"></span><span>Did you <strong>click any links</strong> in the email?</span></label>
  <label><span class="cb"></span><span>Did you <strong>open any attachments</strong>?</span></label>
  <label><span class="cb"></span><span>Did you <strong>enter any credentials or personal information</strong>?</span></label>
</div>"""

        body_html = f"""
<p>Thank you for reporting a suspicious email. Our security team has completed its investigation.</p>
{verdict_box}
{meta_table}
<p>{_html.escape(summary)}</p>
{checklist}
<p>Please <strong>reply to this email</strong> to let us know if you interacted with it.
Our security team will review your response and advise you on any next steps.</p>
<p style="color:#6b7280;font-size:13px;">
  In the meantime, <strong>do not click any links or open any attachments</strong> in that email.
  Thank you for your vigilance.
</p>"""

        plain = f"""Thank you for reporting a suspicious email.

VERDICT: SUSPICIOUS ({confidence}% confidence)
Email From: {from_email}
Subject: {subject}

{summary}

Please reply to this email and let us know:
1. Did you click any links in the email?
2. Did you open any attachments?
3. Did you enter any credentials or personal information?

Do not interact with that email further until we advise you.

Report ID: {report_id}"""

    else:  # LEGITIMATE or UNKNOWN
        body_html = f"""
<p>Thank you for reporting a suspicious email. Our security team has completed its investigation.</p>
{verdict_box}
{meta_table}
<p>{_html.escape(summary)}</p>
<p>No action is required on your part. The email does not appear to be malicious.</p>
<p style="color:#6b7280;font-size:13px;">
  Thank you for staying vigilant — reporting suspicious emails is exactly the right thing to do,
  even when they turn out to be legitimate. It helps keep everyone safe.
</p>"""

        plain = f"""Thank you for reporting a suspicious email.

VERDICT: {verdict} ({confidence}% confidence)
Email From: {from_email}
Subject: {subject}

{summary}

No action is required. The email appears to be legitimate.
Thank you for your vigilance.

Report ID: {report_id}"""

    html_out = _html_wrap(color, report_id, email_subject, body_html)
    return email_subject, html_out, plain


# ── Security team email ────────────────────────────────────────────────────────

def _md_to_html(md: str) -> str:
    """Very basic Markdown → HTML for embedding in emails (no external deps)."""
    lines = md.split("\n")
    out = []
    in_code = False
    in_list = False

    for line in lines:
        if line.startswith("```"):
            if in_code:
                out.append("</pre></div>")
                in_code = False
            else:
                if in_list:
                    out.append("</ul>")
                    in_list = False
                out.append('<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;'
                           'padding:12px 16px;margin:12px 0;overflow-x:auto;">'
                           '<pre style="font-family:monospace;font-size:12px;margin:0;white-space:pre-wrap;">')
                in_code = True
            continue

        if in_code:
            out.append(_html.escape(line))
            continue

        if line.startswith("### "):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f'<h3 style="font-size:15px;font-weight:700;margin:20px 0 8px;color:#0f172a;">'
                       f'{_html.escape(line[4:])}</h3>')
        elif line.startswith("## "):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f'<h2 style="font-size:18px;font-weight:700;margin:28px 0 10px;color:#0f172a;'
                       f'padding-bottom:8px;border-bottom:2px solid #e2e8f0;">'
                       f'{_html.escape(line[3:])}</h2>')
        elif line.startswith("# "):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f'<h1 style="font-size:22px;font-weight:800;margin:0 0 16px;color:#0f172a;">'
                       f'{_html.escape(line[2:])}</h1>')
        elif line.startswith("- ") or line.startswith("* "):
            if not in_list:
                out.append('<ul style="margin:8px 0 8px 20px;padding:0;">')
                in_list = True
            item = line[2:]
            item = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', item)
            out.append(f'<li style="margin-bottom:4px;font-size:14px;">{item}</li>')
        elif line.startswith("| "):
            if in_list: out.append("</ul>"); in_list = False
            # Table row
            if "---" in line:
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            is_header = not out or not out[-1].strip().startswith("<tr")
            tag = "th" if is_header else "td"
            style = ('style="padding:8px 12px;border:1px solid #e2e8f0;font-size:13px;'
                     + ('font-weight:700;background:#f8fafc;"' if is_header else '"'))
            if is_header and not any("<table" in o for o in out[-3:]):
                out.append('<table style="width:100%;border-collapse:collapse;margin:12px 0;">')
            row = "".join(f"<{tag} {style}>{_html.escape(c)}</{tag}>" for c in cells)
            out.append(f"<tr>{row}</tr>")
        else:
            if in_list: out.append("</ul>"); in_list = False
            if line.strip() == "":
                out.append("<br>")
            else:
                line = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', line)
                line = re.sub(r'`(.+?)`',
                              r'<code style="background:#f1f5f9;padding:1px 5px;'
                              r'border-radius:3px;font-size:12px;">\1</code>', line)
                out.append(f'<p style="margin:6px 0;font-size:14px;color:#374151;">{line}</p>')

    if in_list:
        out.append("</ul>")
    if in_code:
        out.append("</pre></div>")

    return "\n".join(out)


def _build_team_email(result: dict) -> tuple[str, str, str]:
    """Returns (subject, html_body, plain_text) for the security team."""
    verdict    = result.get("verdict", "UNKNOWN")
    confidence = result.get("confidence", 0)
    action     = result.get("recommended_action", "QUARANTINE")
    subject    = result.get("subject", "(no subject)")
    from_email = result.get("from_email", "unknown")
    reporter   = result.get("reported_by", "unknown")
    report_id  = result.get("report_id", "")
    summary    = result.get("summary", "")
    iocs       = result.get("iocs", {})
    report_md  = result.get("report_markdown", "")

    meta      = _VERDICT_META.get(verdict, _VERDICT_META["UNKNOWN"])
    color     = meta["color"]
    emoji     = meta["emoji"]
    report_url = f"{PHANTOM_URL}/api/investigate/phishing/{report_id}" if PHANTOM_URL else ""

    email_subject = f"[Phantom] {emoji} {verdict} — {subject[:60]}"

    # IOC table
    ioc_rows = ""
    for ioc_type, values in iocs.items():
        if values:
            for v in values:
                ioc_rows += f'<tr><td style="padding:6px 10px;border:1px solid #e2e8f0;font-size:12px;color:#6b7280;text-transform:capitalize;">{_html.escape(ioc_type.rstrip("s"))}</td><td style="padding:6px 10px;border:1px solid #e2e8f0;font-size:12px;font-family:monospace;">{_html.escape(str(v))}</td></tr>'

    ioc_table = ""
    if ioc_rows:
        ioc_table = f"""
<h2 style="font-size:16px;font-weight:700;margin:24px 0 10px;">Indicators of Compromise</h2>
<table style="width:100%;border-collapse:collapse;margin-bottom:24px;">
  <tr>
    <th style="padding:8px 10px;border:1px solid #e2e8f0;background:#f8fafc;font-size:12px;text-align:left;width:100px;">Type</th>
    <th style="padding:8px 10px;border:1px solid #e2e8f0;background:#f8fafc;font-size:12px;text-align:left;">Value</th>
  </tr>
  {ioc_rows}
</table>"""

    # Action badge
    action_colors = {
        "BLOCK_AND_DELETE": "#dc2626",
        "QUARANTINE":       "#d97706",
        "MONITOR":          "#2563eb",
        "WHITELIST":        "#16a34a",
    }
    action_color = action_colors.get(action, "#6b7280")

    report_link = (f'<p><a href="{_html.escape(report_url)}" '
                   f'style="color:#2563eb;">View full investigation in Phantom →</a></p>'
                   if report_url else "")

    report_html = _md_to_html(report_md) if report_md else "<p><em>Report not available.</em></p>"

    body_html = f"""
<div style="background:{color}18;border:2px solid {color}40;border-radius:8px;padding:20px 24px;margin-bottom:24px;">
  <div style="font-size:12px;text-transform:uppercase;letter-spacing:1.5px;font-weight:700;color:{color};margin-bottom:6px;">Investigation Verdict</div>
  <div style="font-size:28px;font-weight:800;color:{color};">{emoji} {verdict}</div>
  <div style="color:{color};font-size:13px;margin-top:4px;">Confidence: {confidence}%</div>
</div>

<table style="width:100%;border-collapse:collapse;margin-bottom:24px;">
  <tr><td style="padding:8px 0;border-bottom:1px solid #f1f5f9;width:150px;color:#6b7280;font-size:13px;font-weight:600;">Recommended Action</td>
      <td style="padding:8px 0;border-bottom:1px solid #f1f5f9;font-size:13px;"><span style="background:{action_color};color:white;padding:2px 10px;border-radius:4px;font-weight:700;font-size:12px;">{_html.escape(action)}</span></td></tr>
  <tr><td style="padding:8px 0;border-bottom:1px solid #f1f5f9;color:#6b7280;font-size:13px;font-weight:600;">Reporter</td>
      <td style="padding:8px 0;border-bottom:1px solid #f1f5f9;font-size:13px;">{_html.escape(reporter)}</td></tr>
  <tr><td style="padding:8px 0;border-bottom:1px solid #f1f5f9;color:#6b7280;font-size:13px;font-weight:600;">Email From</td>
      <td style="padding:8px 0;border-bottom:1px solid #f1f5f9;font-size:13px;font-family:monospace;">{_html.escape(from_email)}</td></tr>
  <tr><td style="padding:8px 0;border-bottom:1px solid #f1f5f9;color:#6b7280;font-size:13px;font-weight:600;">Subject</td>
      <td style="padding:8px 0;border-bottom:1px solid #f1f5f9;font-size:13px;">{_html.escape(subject)}</td></tr>
  <tr><td style="padding:8px 0;color:#6b7280;font-size:13px;font-weight:600;">Report ID</td>
      <td style="padding:8px 0;font-size:13px;font-family:monospace;">{_html.escape(report_id)}</td></tr>
</table>

<p style="color:#374151;font-size:14px;margin-bottom:24px;">{_html.escape(summary)}</p>

{report_link}

{ioc_table}

<hr style="border:none;border-top:2px solid #e2e8f0;margin:32px 0;">
<h2 style="font-size:18px;font-weight:700;margin-bottom:20px;">Full Investigation Report</h2>
{report_html}"""

    html_out = _html_wrap(color, report_id, f"Phishing Investigation: {verdict}", body_html)

    plain = f"""[Phantom] Phishing Investigation Complete

VERDICT:  {verdict} ({confidence}% confidence)
ACTION:   {action}
Reporter: {reporter}
From:     {from_email}
Subject:  {subject}
ID:       {report_id}

{summary}

IOCs:
{json_iocs(iocs)}

Full report: {report_url}
"""
    return email_subject, html_out, plain


def json_iocs(iocs: dict) -> str:
    lines = []
    for ioc_type, values in iocs.items():
        if values:
            for v in values:
                lines.append(f"  {ioc_type}: {v}")
    return "\n".join(lines) if lines else "  (none extracted)"


# ── Email sending ──────────────────────────────────────────────────────────────

def _send_via_ses(to: str, subject: str, html_body: str, plain_body: str) -> bool:
    """Send via AWS SES using boto3."""
    try:
        import boto3
        client = boto3.client("ses")
        client.send_email(
            Source=FROM_EMAIL,
            Destination={"ToAddresses": [to]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {
                    "Text": {"Data": plain_body, "Charset": "UTF-8"},
                    "Html": {"Data": html_body, "Charset": "UTF-8"},
                },
            },
        )
        print(f"  [notifier] SES sent → {to}: {subject[:60]}", flush=True)
        return True
    except Exception as e:
        print(f"  [notifier] SES failed: {e}", flush=True)
        return False


def _send_via_smtp(to: str, subject: str, html_body: str, plain_body: str) -> bool:
    """Send via SMTP (fallback for non-AWS deployments)."""
    host     = os.environ.get("SMTP_HOST", "")
    port     = int(os.environ.get("SMTP_PORT", "587"))
    user     = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASSWORD", "")
    use_tls  = os.environ.get("SMTP_USE_TLS", "true").lower() != "false"

    if not host:
        print("  [notifier] No SMTP_HOST configured — cannot send email", flush=True)
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = FROM_EMAIL
    msg["To"]      = to
    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            if use_tls:
                smtp.starttls()
            if user and password:
                smtp.login(user, password)
            smtp.sendmail(FROM_EMAIL, [to], msg.as_string())
        print(f"  [notifier] SMTP sent → {to}: {subject[:60]}", flush=True)
        return True
    except Exception as e:
        print(f"  [notifier] SMTP failed: {e}", flush=True)
        return False


def _send(to: str, subject: str, html_body: str, plain_body: str) -> bool:
    """Try SES first, then SMTP."""
    if not to or "@" not in to:
        print(f"  [notifier] Invalid recipient address: {to!r}", flush=True)
        return False
    return _send_via_ses(to, subject, html_body, plain_body) or \
           _send_via_smtp(to, subject, html_body, plain_body)


# ── Public API ─────────────────────────────────────────────────────────────────

def notify_reporter(result: dict) -> bool:
    """
    Send a personalised verdict email to the person who reported the phishing email.
    Returns True if sent successfully.
    """
    reporter = result.get("reported_by", "")
    if not reporter or "@" not in reporter:
        print("  [notifier] No valid reporter email — skipping reporter notification", flush=True)
        return False

    subject_line, html_body, plain_body = _build_reporter_email(
        verdict=result.get("verdict", "UNKNOWN"),
        confidence=result.get("confidence", 0),
        subject=result.get("subject", ""),
        from_email=result.get("from_email", ""),
        summary=result.get("summary", ""),
        report_id=result.get("report_id", ""),
        recommended_action=result.get("recommended_action", "QUARANTINE"),
    )
    return _send(reporter, subject_line, html_body, plain_body)


def notify_security_team(result: dict) -> bool:
    """
    Send the full investigation report to the security team.
    Uses SECURITY_TEAM_EMAIL env var.
    Returns True if sent successfully.
    """
    team = TEAM_EMAIL
    if not team or "@" not in team:
        print("  [notifier] SECURITY_TEAM_EMAIL not configured — skipping team notification", flush=True)
        return False

    subject_line, html_body, plain_body = _build_team_email(result)
    return _send(team, subject_line, html_body, plain_body)


def notify_all(result: dict) -> dict:
    """Send both reporter and team notifications. Returns status dict."""
    reporter_sent = notify_reporter(result)
    team_sent     = notify_security_team(result)
    return {
        "reporter_notified": reporter_sent,
        "team_notified":     team_sent,
        "reporter":          result.get("reported_by", ""),
        "team":              TEAM_EMAIL,
    }
