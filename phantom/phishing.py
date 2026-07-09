#!/usr/bin/env python3
"""
phantom/phishing.py — Autonomous Phishing Email Investigator

Accepts a raw .eml email string, parses it completely, then runs a fully
autonomous Claude-powered investigation using phishing-specific tools:
  - DNS-over-HTTPS lookups (SPF, DMARC, MX)
  - URL extraction and reputation checks (VirusTotal optional)
  - Sending IP reverse DNS + reputation
  - Attachment hashing and type detection
  - Email authentication header analysis
  - Skill library search for investigation procedures
  - Structured Markdown report generation

Public API:
    result = investigate_phishing(raw_email, reported_by="user@corp.com", report_id="abc123")
    # result: {report_id, verdict, confidence, recommended_action, iocs, report_markdown, ...}

Environment variables (all optional except ANTHROPIC_API_KEY):
    ANTHROPIC_API_KEY    — required for Claude investigation
    VIRUSTOTAL_API_KEY   — URL/IP/hash reputation via VirusTotal v3
    Threat-intel fan-out (each source is skipped if its key is unset):
      SHODAN_API_KEY     — attacker-infra profiling (open ports, CVEs, DNS) on IPs/domains
      ABUSEIPDB_API_KEY  — IP abuse-confidence score
      GREYNOISE_API_KEY  — IP scanner/mass-exploit classification (community API)
      URLSCAN_API_KEY    — urlscan.io lookups (optional; raises rate limits)
      THREATFOX_API_KEY  — abuse.ch ThreatFox IOC matches (a.k.a. ABUSECH_API_KEY)
      MISP_URL + MISP_API_KEY — correlate IOCs against your own MISP instance
      SKIP_TLS_VERIFY=1  — only for a self-signed MISP in a lab (repo convention)
"""

import email
import email.policy
import hashlib
import html
import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.header import decode_header
from pathlib import Path

try:
    import anthropic
except ImportError:
    raise ImportError("pip install anthropic")

from skill_loader import search_skills as _search_skills, load_skill as _load_skill
from notifier import notify_all

ROOT         = Path(__file__).parent.parent
REPORTS_DIR  = ROOT / "reports" / "phishing"
MODEL        = "claude-opus-4-8"
MAX_TOKENS   = 8096
VT_KEY       = os.environ.get("VIRUSTOTAL_API_KEY", "")

# Threat-intel fan-out source keys (each optional; unset sources are skipped)
SHODAN_KEY    = os.environ.get("SHODAN_API_KEY", "")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
GREYNOISE_KEY = os.environ.get("GREYNOISE_API_KEY", "")
URLSCAN_KEY   = os.environ.get("URLSCAN_API_KEY", "")
THREATFOX_KEY = os.environ.get("THREATFOX_API_KEY", os.environ.get("ABUSECH_API_KEY", ""))
MISP_URL      = os.environ.get("MISP_URL", "").rstrip("/")
MISP_KEY      = os.environ.get("MISP_API_KEY", os.environ.get("MISP_KEY", ""))
VERIFY_TLS    = os.environ.get("SKIP_TLS_VERIFY", "").lower() not in ("1", "true", "yes")

# In-memory store for completed investigations (report_id → result)
_RESULTS: dict[str, dict] = {}


# ── Email parsing ──────────────────────────────────────────────────────────────

def _decode_header_value(value: str) -> str:
    if not value:
        return ""
    parts = decode_header(value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return " ".join(decoded)


def _extract_urls(text: str) -> list[str]:
    pattern = re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE,
    )
    seen = set()
    urls = []
    for m in pattern.finditer(text):
        url = m.group(0).rstrip(".,;:!?)")
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def _get_body(msg) -> tuple[str, str]:
    """Returns (plain_text, html_text)."""
    plain, html_body = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cte = part.get("Content-Transfer-Encoding", "")
            charset = part.get_content_charset() or "utf-8"
            if ct == "text/plain" and not plain:
                try:
                    plain = part.get_payload(decode=True).decode(charset, errors="replace")
                except Exception:
                    plain = str(part.get_payload())
            elif ct == "text/html" and not html_body:
                try:
                    html_body = part.get_payload(decode=True).decode(charset, errors="replace")
                except Exception:
                    html_body = str(part.get_payload())
    else:
        charset = msg.get_content_charset() or "utf-8"
        try:
            body = msg.get_payload(decode=True)
            if body:
                text = body.decode(charset, errors="replace")
                if msg.get_content_type() == "text/html":
                    html_body = text
                else:
                    plain = text
        except Exception:
            plain = str(msg.get_payload())
    return plain, html_body


def _get_attachments(msg) -> list[dict]:
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() not in ("attachment", "inline"):
            continue
        filename = _decode_header_value(part.get_filename() or "")
        if not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        sha256 = hashlib.sha256(payload).hexdigest()
        attachments.append({
            "filename":   filename,
            "content_type": part.get_content_type(),
            "size_bytes": len(payload),
            "sha256":     sha256,
        })
    return attachments


def _parse_received_chain(msg) -> list[str]:
    """Extract all Received headers in order (oldest first)."""
    received = msg.get_all("Received") or []
    return [r.strip().replace("\n", " ").replace("\t", " ") for r in reversed(received)]


def _extract_sending_ip(received_chain: list[str]) -> str:
    """Try to extract the original sending IP from the first Received header."""
    if not received_chain:
        return ""
    first = received_chain[0] if received_chain else ""
    ip_pattern = re.compile(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]')
    m = ip_pattern.search(first)
    return m.group(1) if m else ""


def parse_email(raw_email: str) -> dict:
    """Full email parse — returns a structured dict with everything needed for investigation."""
    msg = email.message_from_string(raw_email, policy=email.policy.compat32)

    from_raw    = _decode_header_value(msg.get("From", ""))
    reply_to    = _decode_header_value(msg.get("Reply-To", ""))
    return_path = _decode_header_value(msg.get("Return-Path", ""))
    to_raw      = _decode_header_value(msg.get("To", ""))
    subject     = _decode_header_value(msg.get("Subject", ""))
    date        = msg.get("Date", "")
    message_id  = msg.get("Message-ID", "")
    auth_results = msg.get("Authentication-Results", "")
    dkim_sig    = msg.get("DKIM-Signature", "")
    x_mailer    = msg.get("X-Mailer", "")
    x_originating_ip = msg.get("X-Originating-IP", "")

    # Extract sender domain
    from_match = re.search(r'@([\w.\-]+)', from_raw)
    sender_domain = from_match.group(1).lower() if from_match else ""

    # Extract display name vs actual email
    display_match = re.match(r'^(.+?)\s*<(.+?)>', from_raw)
    display_name = display_match.group(1).strip().strip('"') if display_match else ""
    from_email   = display_match.group(2).strip() if display_match else from_raw.strip()

    received_chain = _parse_received_chain(msg)
    sending_ip     = x_originating_ip.strip() or _extract_sending_ip(received_chain)

    plain_body, html_body = _get_body(msg)
    all_text = plain_body or re.sub(r'<[^>]+>', ' ', html_body)
    urls = _extract_urls(all_text) + _extract_urls(html_body)
    # Deduplicate while preserving order
    seen_urls = set()
    unique_urls = []
    for u in urls:
        if u not in seen_urls:
            seen_urls.add(u)
            unique_urls.append(u)

    attachments = _get_attachments(msg)

    # Urgency / credential-harvesting language heuristics
    urgency_words = ["urgent", "immediately", "verify", "suspended", "unusual activity",
                     "confirm your", "click here", "account locked", "expires", "action required",
                     "update your", "password", "login", "sign in", "invoice", "payment"]
    text_lower = all_text.lower()
    urgency_hits = [w for w in urgency_words if w in text_lower]

    return {
        "from_raw":        from_raw,
        "from_email":      from_email,
        "display_name":    display_name,
        "sender_domain":   sender_domain,
        "reply_to":        reply_to,
        "return_path":     return_path,
        "to":              to_raw,
        "subject":         subject,
        "date":            date,
        "message_id":      message_id,
        "x_mailer":        x_mailer,
        "auth_results":    auth_results,
        "dkim_signature":  bool(dkim_sig),
        "x_originating_ip": x_originating_ip,
        "received_chain":  received_chain[-5:],  # last 5 hops
        "sending_ip":      sending_ip,
        "body_plain":      plain_body[:3000],
        "body_length":     len(plain_body),
        "urls":            unique_urls[:30],
        "attachments":     attachments,
        "urgency_indicators": urgency_hits,
    }


# ── DNS-over-HTTPS utilities ───────────────────────────────────────────────────

def _doh_query(name: str, record_type: str) -> list[str]:
    """Query Cloudflare DNS-over-HTTPS. Returns list of record data strings."""
    try:
        url = f"https://1.1.1.1/dns-query?name={urllib.parse.quote(name)}&type={record_type}"
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        type_map = {"A": 1, "AAAA": 28, "MX": 15, "TXT": 16, "NS": 2}
        rtype = type_map.get(record_type.upper(), 0)
        return [str(a.get("data", "")) for a in data.get("Answer", []) if a.get("type") == rtype]
    except Exception:
        return []


def _get_spf(domain: str) -> str:
    """Fetch SPF TXT record for domain."""
    txt_records = _doh_query(domain, "TXT")
    for r in txt_records:
        clean = r.strip('"')
        if clean.startswith("v=spf1"):
            return clean
    return ""


def _get_dmarc(domain: str) -> str:
    """Fetch DMARC policy for domain."""
    txt_records = _doh_query(f"_dmarc.{domain}", "TXT")
    for r in txt_records:
        clean = r.strip('"')
        if clean.startswith("v=DMARC1"):
            return clean
    return ""


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ── VirusTotal helpers (optional) ──────────────────────────────────────────────

def _vt_get(path: str) -> dict:
    if not VT_KEY:
        return {"skipped": "VIRUSTOTAL_API_KEY not set"}
    try:
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/{path}",
            headers={"x-apikey": VT_KEY, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}


def _vt_url_report(url: str) -> dict:
    url_id = urllib.parse.quote(
        __import__("base64").urlsafe_b64encode(url.encode()).decode().rstrip("="), safe=""
    )
    data = _vt_get(f"urls/{url_id}")
    if "error" in data:
        return data
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "url":       url,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":  stats.get("harmless", 0),
        "verdict":   "malicious" if stats.get("malicious", 0) > 0 else
                     "suspicious" if stats.get("suspicious", 0) > 2 else "clean",
    }


def _vt_ip_report(ip: str) -> dict:
    data = _vt_get(f"ip_addresses/{ip}")
    if "error" in data:
        return data
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "ip":        ip,
        "country":   attrs.get("country", ""),
        "asn":       attrs.get("asn", ""),
        "as_owner":  attrs.get("as_owner", ""),
        "malicious": stats.get("malicious", 0),
        "verdict":   "malicious" if stats.get("malicious", 0) > 0 else "clean",
    }


# ── Threat-intel fan-out sources (each optional, keyed by env var) ──────────────

def _http_json(url: str, headers: dict | None = None, method: str = "GET",
               data: dict | None = None, timeout: int = 12, verify: bool = True) -> dict:
    """Minimal JSON HTTP helper. Returns {'_http_error': code} or {'_error': msg} on failure."""
    hdrs = {"Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    ctx = None
    if url.startswith("https") and not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code}
    except Exception as e:
        return {"_error": str(e)}


def _shodan_host(ip: str) -> dict:
    if not SHODAN_KEY:
        return {"available": False, "reason": "SHODAN_API_KEY not set"}
    r = _http_json(f"https://api.shodan.io/shodan/host/{urllib.parse.quote(ip)}?key={SHODAN_KEY}")
    if r.get("_http_error") == 404:
        return {"available": True, "not_found": True}
    if "_http_error" in r or "_error" in r:
        return {"available": True, "error": r}
    return {
        "available": True,
        "ports":     r.get("ports", [])[:20],
        "org":       r.get("org", ""),
        "isp":       r.get("isp", ""),
        "hostnames": r.get("hostnames", [])[:5],
        "os":        r.get("os"),
        "vulns":     list(r.get("vulns", []))[:10],
        "country":   r.get("country_name", ""),
        "tags":      r.get("tags", []),
    }


def _shodan_domain(domain: str) -> dict:
    """Passive-DNS-style view of a domain via Shodan's DNS database."""
    if not SHODAN_KEY:
        return {"available": False, "reason": "SHODAN_API_KEY not set"}
    r = _http_json(f"https://api.shodan.io/dns/domain/{urllib.parse.quote(domain)}?key={SHODAN_KEY}")
    if "_http_error" in r or "_error" in r:
        return {"available": True, "error": r}
    recs = r.get("data", [])
    return {
        "available":   True,
        "subdomains":  r.get("subdomains", [])[:15],
        "record_count": len(recs),
        "recent":      [{"type": d.get("type"), "value": d.get("value"),
                         "last_seen": d.get("last_seen")} for d in recs[:8]],
    }


def _abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {"available": False, "reason": "ABUSEIPDB_API_KEY not set"}
    r = _http_json(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90",
        headers={"Key": ABUSEIPDB_KEY})
    d = r.get("data", {})
    if not d:
        return {"available": True, "error": r}
    return {
        "available":        True,
        "abuse_confidence": d.get("abuseConfidenceScore"),
        "total_reports":    d.get("totalReports"),
        "country":          d.get("countryCode"),
        "isp":              d.get("isp"),
        "usage_type":       d.get("usageType"),
        "is_tor":           d.get("isTor"),
    }


def _greynoise(ip: str) -> dict:
    if not GREYNOISE_KEY:
        return {"available": False, "reason": "GREYNOISE_API_KEY not set"}
    r = _http_json(f"https://api.greynoise.io/v3/community/{urllib.parse.quote(ip)}",
                   headers={"key": GREYNOISE_KEY})
    if r.get("_http_error") == 404:
        return {"available": True, "seen": False}
    if "_http_error" in r or "_error" in r:
        return {"available": True, "error": r}
    return {
        "available":      True,
        "noise":          r.get("noise"),
        "riot":           r.get("riot"),
        "classification": r.get("classification"),
        "name":           r.get("name"),
        "last_seen":      r.get("last_seen"),
    }


def _urlscan(domain: str) -> dict:
    if not domain:
        return {"available": False, "reason": "no domain"}
    hdrs = {"API-Key": URLSCAN_KEY} if URLSCAN_KEY else {}
    q = urllib.parse.quote(f'page.domain:"{domain}"')
    search = _http_json(f"https://urlscan.io/api/v1/search/?q={q}&size=5", headers=hdrs)
    if "_http_error" in search or "_error" in search:
        return {"available": True, "error": search}
    results = search.get("results", [])
    out = {"available": True, "scans_found": len(results)}
    if results:
        newest = results[0]
        out["latest_scan"] = newest.get("result", "")
        out["latest_url"] = newest.get("page", {}).get("url", "")
        uid = newest.get("_id", "")
        if uid:
            detail = _http_json(f"https://urlscan.io/api/v1/result/{uid}/", headers=hdrs)
            v = detail.get("verdicts", {}).get("overall", {})
            out["malicious"] = bool(v.get("malicious"))
            out["score"] = v.get("score")
            out["categories"] = v.get("categories", [])
    return out


def _threatfox(ioc: str) -> dict:
    hdrs = {"Auth-Key": THREATFOX_KEY} if THREATFOX_KEY else {}
    r = _http_json("https://threatfox-api.abuse.ch/api/v1/", headers=hdrs, method="POST",
                   data={"query": "search_ioc", "search_term": ioc})
    status = r.get("query_status")
    if status == "ok":
        data = r.get("data", [])
        return {
            "available":    True,
            "matches":      len(data),
            "malware":      [m for m in {d.get("malware_printable", "") for d in data} if m][:5],
            "threat_types": [t for t in {d.get("threat_type", "") for d in data} if t][:5],
        }
    if status == "no_result":
        return {"available": True, "matches": 0}
    # missing Auth-Key or other error
    return {"available": bool(THREATFOX_KEY), "error": status or r}


def _misp(ioc: str) -> dict:
    if not (MISP_URL and MISP_KEY):
        return {"available": False, "reason": "MISP_URL / MISP_API_KEY not set"}
    r = _http_json(f"{MISP_URL}/attributes/restSearch",
                   headers={"Authorization": MISP_KEY},
                   method="POST",
                   data={"value": ioc, "limit": 10, "returnFormat": "json"},
                   verify=VERIFY_TLS)
    resp = r.get("response")
    attrs = resp.get("Attribute", []) if isinstance(resp, dict) else (resp or [])
    if "_error" in r or "_http_error" in r:
        return {"available": True, "error": r}
    return {
        "available": True,
        "matches":   len(attrs),
        "events":    [e for e in {a.get("event_id", "") for a in attrs} if e][:5],
        "to_ids":    any(a.get("to_ids") for a in attrs),
    }


# ── Tool implementations ───────────────────────────────────────────────────────

def _tool_check_urls(urls: list[str]) -> dict:
    """Check URL reputation. Uses VirusTotal if key is set, else basic domain checks."""
    if not urls:
        return {"message": "No URLs provided"}

    results = []
    for url in urls[:10]:  # cap at 10 to avoid timeout
        if VT_KEY:
            r = _vt_url_report(url)
        else:
            # Basic: extract domain, check DNS resolution
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.split(":")[0]
            try:
                ip = socket.gethostbyname(domain)
                r = {"url": url, "domain": domain, "resolves_to": ip, "verdict": "resolves"}
            except Exception:
                r = {"url": url, "domain": domain, "verdict": "does_not_resolve"}
        results.append(r)

    return {"checked": len(results), "results": results, "vt_enabled": bool(VT_KEY)}


def _tool_check_sender_ip(ip: str) -> dict:
    """Reverse DNS + optional VirusTotal for sending IP."""
    if not ip:
        return {"error": "No IP provided"}

    rdns = _reverse_dns(ip)
    result = {"ip": ip, "reverse_dns": rdns}

    if VT_KEY:
        vt = _vt_ip_report(ip)
        result.update(vt)

    # Check if IP is in a cloud/hosting ASN (common for phishing)
    hosting_indicators = ["amazonaws", "googlecloud", "azure", "digitalocean",
                          "linode", "vultr", "ovh", "hetzner", "contabo"]
    result["hosting_provider_indicator"] = any(h in rdns.lower() for h in hosting_indicators)

    return result


def _tool_verify_email_auth(sender_domain: str, auth_results_header: str) -> dict:
    """Check SPF and DMARC records for sender domain. Parse Authentication-Results header."""
    spf_record  = _get_spf(sender_domain)
    dmarc_record = _get_dmarc(sender_domain)
    mx_records  = _doh_query(sender_domain, "MX")

    # Parse Authentication-Results header
    auth_parsed = {}
    if auth_results_header:
        for proto in ["spf", "dkim", "dmarc"]:
            m = re.search(rf'{proto}=(\w+)', auth_results_header, re.IGNORECASE)
            if m:
                auth_parsed[proto] = m.group(1).lower()

    # Derive SPF policy strength
    spf_policy = "none"
    if spf_record:
        if "-all" in spf_record:
            spf_policy = "fail"
        elif "~all" in spf_record:
            spf_policy = "softfail"
        elif "?all" in spf_record:
            spf_policy = "neutral"
        elif "+all" in spf_record:
            spf_policy = "pass_all (dangerous)"

    # Derive DMARC policy
    dmarc_policy = "none"
    if dmarc_record:
        m = re.search(r'p=(\w+)', dmarc_record)
        if m:
            dmarc_policy = m.group(1).lower()

    return {
        "sender_domain":   sender_domain,
        "spf_record":      spf_record or "NOT FOUND",
        "spf_policy":      spf_policy,
        "dmarc_record":    dmarc_record or "NOT FOUND",
        "dmarc_policy":    dmarc_policy,
        "mx_records":      mx_records[:5],
        "has_mx":          bool(mx_records),
        "auth_results_parsed": auth_parsed,
        "assessment": (
            "FAIL — no SPF or DMARC configured (easy to spoof)" if not spf_record and not dmarc_record
            else "WEAK — SPF softfail, no reject policy" if spf_policy == "softfail" and dmarc_policy != "reject"
            else "PASS — SPF and DMARC configured" if spf_record and dmarc_record
            else "PARTIAL"
        ),
    }


def _tool_check_domain(domain: str) -> dict:
    """Basic domain checks: resolution, MX, NS, TXT records."""
    result = {"domain": domain}
    try:
        result["a_record"] = socket.gethostbyname(domain)
    except Exception:
        result["a_record"] = None
        result["resolves"] = False
        return result

    result["resolves"] = True
    result["mx"] = _doh_query(domain, "MX")[:3]
    result["ns"] = _doh_query(domain, "NS")[:3]

    # Check for lookalike indicators
    lookalike_patterns = [
        r'\d{4,}',              # lots of numbers
        r'[-]{2,}',             # double dashes
        r'(paypa|paypа|micros0ft|arnazon|g00gle)',  # common brand lookalikes
        r'(secure|login|update|verify|account|signin)',  # phishing keywords in domain
    ]
    result["lookalike_indicators"] = [
        p for p in lookalike_patterns
        if re.search(p, domain, re.IGNORECASE)
    ]

    return result


def _tool_analyze_attachment(sha256: str, filename: str) -> dict:
    """VirusTotal file hash lookup. Falls back to extension-based risk assessment."""
    high_risk_extensions = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf",
        ".hta", ".scr", ".pif", ".com", ".lnk", ".iso", ".img",
        ".docm", ".xlsm", ".pptm",  # macro-enabled Office
    }
    ext = Path(filename).suffix.lower()
    is_high_risk = ext in high_risk_extensions

    result = {
        "sha256":    sha256,
        "filename":  filename,
        "extension": ext,
        "high_risk_extension": is_high_risk,
    }

    if VT_KEY and sha256:
        data = _vt_get(f"files/{sha256}")
        if "data" in data:
            attrs = data["data"].get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            result["vt_malicious"]  = stats.get("malicious", 0)
            result["vt_suspicious"] = stats.get("suspicious", 0)
            result["vt_verdict"]    = "malicious" if stats.get("malicious", 0) > 0 else "clean"

    return result


def _tool_threat_intel(indicator: str, indicator_type: str) -> dict:
    """Fan an indicator out across every configured external threat-intel source
    and roll the results up into a short list of malicious signals."""
    indicator = (indicator or "").strip()
    t = (indicator_type or "").lower().strip()
    if not indicator:
        return {"error": "no indicator provided"}

    sources: dict[str, dict] = {}
    if t == "ip":
        sources["shodan"]    = _shodan_host(indicator)
        sources["abuseipdb"] = _abuseipdb(indicator)
        sources["greynoise"] = _greynoise(indicator)
        sources["threatfox"] = _threatfox(indicator)
        sources["misp"]      = _misp(indicator)
    elif t == "domain":
        sources["shodan_dns"] = _shodan_domain(indicator)
        sources["urlscan"]    = _urlscan(indicator)
        sources["threatfox"]  = _threatfox(indicator)
        sources["misp"]       = _misp(indicator)
    elif t == "url":
        domain = urllib.parse.urlparse(indicator).netloc.split(":")[0] or indicator
        sources["urlscan"]   = _urlscan(domain)
        sources["threatfox"] = _threatfox(indicator)
        sources["misp"]      = _misp(indicator)
    elif t == "hash":
        sources["threatfox"] = _threatfox(indicator)
        sources["misp"]      = _misp(indicator)
    else:
        return {"error": f"unknown indicator_type '{indicator_type}' (use ip/domain/url/hash)"}

    # Roll up the signals that actually indicate maliciousness.
    signals: list[str] = []
    ab = sources.get("abuseipdb", {})
    if isinstance(ab.get("abuse_confidence"), (int, float)) and ab["abuse_confidence"] >= 50:
        signals.append(f"AbuseIPDB abuse-confidence {ab['abuse_confidence']}%")
    if sources.get("greynoise", {}).get("classification") == "malicious":
        signals.append("GreyNoise classification: malicious")
    if sources.get("urlscan", {}).get("malicious"):
        signals.append("urlscan.io overall verdict: malicious")
    tf = sources.get("threatfox", {})
    if tf.get("matches"):
        mal = ", ".join(tf.get("malware", [])) or "known IOC"
        signals.append(f"ThreatFox: {tf['matches']} match(es) ({mal})")
    mi = sources.get("misp", {})
    if mi.get("matches"):
        signals.append(f"MISP: {mi['matches']} attribute match(es) across events {mi.get('events', [])}")
    if sources.get("shodan", {}).get("vulns"):
        signals.append(f"Shodan: host exposes CVEs {sources['shodan']['vulns'][:3]}")

    return {
        "indicator":            indicator,
        "type":                 t,
        "malicious_signals":    signals,
        "sources_queried":      [k for k, v in sources.items() if v.get("available")],
        "sources_unconfigured": [k for k, v in sources.items() if not v.get("available")],
        "detail":               sources,
    }


# ── Claude tool schemas ────────────────────────────────────────────────────────

PHISHING_TOOLS = [
    {
        "name": "check_urls",
        "description": (
            "Check the reputation of URLs found in the email. "
            "Uses VirusTotal if VIRUSTOTAL_API_KEY is set, otherwise checks DNS resolution. "
            "Pass all suspicious or shortened URLs for analysis."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of URLs to check (max 10)",
                },
            },
            "required": ["urls"],
        },
    },
    {
        "name": "check_sender_ip",
        "description": "Perform reverse DNS lookup and optional VirusTotal reputation check on the sending IP address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IPv4 address of the sending mail server"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "verify_email_auth",
        "description": (
            "Look up SPF and DMARC DNS records for the sender domain and parse the Authentication-Results header. "
            "Use this to determine if the email was spoofed or passed authentication."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "sender_domain":       {"type": "string", "description": "Domain from the From: address"},
                "auth_results_header": {"type": "string", "description": "Raw Authentication-Results header value (empty string if absent)"},
            },
            "required": ["sender_domain", "auth_results_header"],
        },
    },
    {
        "name": "check_domain",
        "description": (
            "Check a domain's DNS resolution, MX records, NS records, and scan for lookalike/typosquatting patterns. "
            "Use for sender domains and domains found in URLs."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain name to check"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "analyze_attachment",
        "description": "Check an attachment's SHA256 hash against VirusTotal and assess risk by file extension.",
        "input_schema": {
            "type": "object",
            "properties": {
                "sha256":   {"type": "string", "description": "SHA256 hash of the attachment"},
                "filename": {"type": "string", "description": "Attachment filename"},
            },
            "required": ["sha256", "filename"],
        },
    },
    {
        "name": "check_threat_intel",
        "description": (
            "Fan an indicator out across external threat-intel sources — Shodan (attacker-infra "
            "ports/CVEs/DNS), AbuseIPDB (IP abuse score), GreyNoise (scanner/mass-exploit "
            "classification), urlscan.io (URL/domain scans + verdict), ThreatFox (known malware/C2 "
            "IOC matches), and your MISP instance (org sightings) — and return correlated reputation "
            "plus a rolled-up list of malicious signals. Call it for the sending IP, the sender domain, "
            "each URL's domain, and any attachment hash. Sources without an API key are skipped and "
            "listed under 'sources_unconfigured' — don't treat a skipped source as clean."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator":      {"type": "string", "description": "the IP, domain, URL, or file hash to look up"},
                "indicator_type": {"type": "string", "enum": ["ip", "domain", "url", "hash"]},
            },
            "required": ["indicator", "indicator_type"],
        },
    },
    {
        "name": "search_skills",
        "description": "Search the cybersecurity skill library for phishing investigation and analysis procedures.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "e.g. 'phishing email investigation', 'email header analysis'"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "load_skill",
        "description": "Load the full workflow for a specific skill by its kebab-case name.",
        "input_schema": {
            "type": "object",
            "properties": {
                "skill_name": {"type": "string"},
            },
            "required": ["skill_name"],
        },
    },
    {
        "name": "write_report",
        "description": (
            "Write the final phishing investigation report. Call this LAST after all enrichment steps. "
            "The verdict must be one of: PHISHING, SUSPICIOUS, LEGITIMATE, UNKNOWN."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["PHISHING", "SUSPICIOUS", "LEGITIMATE", "UNKNOWN"],
                },
                "confidence": {
                    "type": "integer",
                    "description": "0–100 confidence in verdict",
                },
                "recommended_action": {
                    "type": "string",
                    "enum": ["BLOCK_AND_DELETE", "QUARANTINE", "MONITOR", "WHITELIST"],
                },
                "iocs": {
                    "type": "object",
                    "description": "Extracted indicators of compromise",
                    "properties": {
                        "ips":     {"type": "array", "items": {"type": "string"}},
                        "domains": {"type": "array", "items": {"type": "string"}},
                        "urls":    {"type": "array", "items": {"type": "string"}},
                        "hashes":  {"type": "array", "items": {"type": "string"}},
                        "emails":  {"type": "array", "items": {"type": "string"}},
                    },
                },
                "summary": {
                    "type": "string",
                    "description": "2–3 sentence executive summary of findings",
                },
                "report_markdown": {
                    "type": "string",
                    "description": "Full Markdown investigation report",
                },
            },
            "required": ["verdict", "confidence", "recommended_action", "iocs", "summary", "report_markdown"],
        },
    },
]


# ── Tool dispatcher ────────────────────────────────────────────────────────────

def _dispatch(tool_name: str, tool_input: dict, parsed_email: dict) -> tuple[str, dict | None]:
    """Execute a tool call. Returns (result_json, final_result_if_write_report)."""
    print(f"  [phishing:{tool_name}]", flush=True)

    if tool_name == "check_urls":
        return json.dumps(_tool_check_urls(tool_input.get("urls", []))), None

    elif tool_name == "check_sender_ip":
        return json.dumps(_tool_check_sender_ip(tool_input.get("ip", ""))), None

    elif tool_name == "verify_email_auth":
        return json.dumps(_tool_verify_email_auth(
            tool_input.get("sender_domain", ""),
            tool_input.get("auth_results_header", ""),
        )), None

    elif tool_name == "check_domain":
        return json.dumps(_tool_check_domain(tool_input.get("domain", ""))), None

    elif tool_name == "analyze_attachment":
        return json.dumps(_tool_analyze_attachment(
            tool_input.get("sha256", ""),
            tool_input.get("filename", ""),
        )), None

    elif tool_name == "check_threat_intel":
        return json.dumps(_tool_threat_intel(
            tool_input.get("indicator", ""),
            tool_input.get("indicator_type", ""),
        )), None

    elif tool_name == "search_skills":
        results = _search_skills(tool_input.get("query", ""))
        return json.dumps({"results": [{"name": r["name"], "description": r.get("description", "")} for r in results]}), None

    elif tool_name == "load_skill":
        content = _load_skill(tool_input.get("skill_name", ""))
        if len(content) > 6000:
            content = content[:6000] + "\n\n[... truncated ...]"
        return content, None

    elif tool_name == "write_report":
        return json.dumps({"written": True}), {
            "verdict":            tool_input.get("verdict", "UNKNOWN"),
            "confidence":         tool_input.get("confidence", 50),
            "recommended_action": tool_input.get("recommended_action", "QUARANTINE"),
            "iocs":               tool_input.get("iocs", {}),
            "summary":            tool_input.get("summary", ""),
            "report_markdown":    tool_input.get("report_markdown", ""),
        }

    return json.dumps({"error": f"Unknown tool: {tool_name}"}), None


# ── System prompt ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are Phantom, an autonomous phishing email investigator. You have received a suspicious email
reported by an employee. Your job is to investigate it completely and determine whether it is a
phishing attempt, suspicious, or legitimate.

Follow this investigation sequence:
1. Search for the most relevant phishing investigation skill and load it
2. Analyse the email metadata provided: sender, headers, URLs, attachments, urgency indicators
3. verify_email_auth — check SPF/DMARC for the sender domain
4. check_sender_ip — check the sending IP reputation
5. check_domain — check sender domain and any domains in URLs
6. check_urls — check URL reputation (check ALL URLs in the email)
7. analyze_attachment — for each attachment, check hash and extension risk
8. check_threat_intel — correlate the campaign's indicators against external threat intel:
   the sending IP (type=ip), the sender domain (type=domain), each URL's domain (type=url),
   and every attachment hash (type=hash). This adds Shodan/AbuseIPDB/GreyNoise/urlscan/
   ThreatFox/MISP context beyond VirusTotal. Treat any entry in 'malicious_signals' as
   strong evidence; a source listed in 'sources_unconfigured' was skipped, not cleared.
9. Reach a verdict: PHISHING / SUSPICIOUS / LEGITIMATE / UNKNOWN
10. write_report — this MUST be your final action

Verdict guidance:
- PHISHING: clear indicators of malicious intent (failed auth + suspicious URLs, known bad IP, malicious attachment, impersonation)
- SUSPICIOUS: multiple soft indicators but no definitive proof
- LEGITIMATE: passes authentication, no suspicious URLs, no urgency manipulation
- UNKNOWN: insufficient data to determine

The report MUST include:
- Executive Summary (verdict, confidence, recommended action)
- Email Authentication Analysis (SPF, DKIM, DMARC results)
- Sender Analysis (From vs Reply-To mismatch, domain age, IP reputation)
- URL Analysis (all URLs checked with verdict per URL)
- Attachment Analysis (if present)
- Threat Intelligence Correlation (Shodan/AbuseIPDB/GreyNoise/urlscan/ThreatFox/MISP signals;
  note which sources were unconfigured/skipped)
- Content Analysis (urgency language, credential harvesting patterns)
- IOCs (all extracted indicators)
- Recommended Actions for the security team

Be thorough. Do not ask the user anything. Call write_report as your FINAL action."""


# ── Main investigation function ────────────────────────────────────────────────

def investigate_phishing(
    raw_email: str,
    reported_by: str = "",
    report_id: str = "",
) -> dict:
    """
    Investigate a raw email string. Stores result in _RESULTS[report_id].
    Returns the result dict immediately on completion.
    """
    from datetime import datetime, timezone
    import uuid

    if not report_id:
        report_id = f"phi-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        error = {"error": "ANTHROPIC_API_KEY not set", "report_id": report_id}
        _RESULTS[report_id] = error
        return error

    # Parse email upfront
    parsed = parse_email(raw_email)
    ts = datetime.now(timezone.utc).isoformat()

    print(f"\n[phishing] Investigation {report_id} started", flush=True)
    print(f"[phishing] From: {parsed['from_email']} | Subject: {parsed['subject'][:60]}", flush=True)
    print(f"[phishing] URLs: {len(parsed['urls'])} | Attachments: {len(parsed['attachments'])}", flush=True)

    # Build initial message with all pre-parsed data
    initial_msg = f"""Investigate this reported phishing email.

REPORTER: {reported_by or "anonymous"}
REPORT ID: {report_id}

=== EMAIL METADATA ===
From:          {parsed['from_raw']}
From Email:    {parsed['from_email']}
Display Name:  {parsed['display_name']}
Sender Domain: {parsed['sender_domain']}
Reply-To:      {parsed['reply_to'] or 'same as From'}
Return-Path:   {parsed['return_path'] or 'not set'}
To:            {parsed['to']}
Subject:       {parsed['subject']}
Date:          {parsed['date']}
Message-ID:    {parsed['message_id']}
X-Mailer:      {parsed['x_mailer'] or 'not set'}

=== AUTHENTICATION HEADERS ===
Authentication-Results: {parsed['auth_results'] or 'NOT PRESENT'}
DKIM-Signature present: {parsed['dkim_signature']}

=== ROUTING ===
X-Originating-IP: {parsed['x_originating_ip'] or 'not set'}
Sending IP (from Received chain): {parsed['sending_ip'] or 'could not extract'}
Received chain (oldest first, max 5):
{chr(10).join(f'  {i+1}. {r[:120]}' for i, r in enumerate(parsed['received_chain']))}

=== URLS FOUND ({len(parsed['urls'])}) ===
{chr(10).join(f'  - {u}' for u in parsed['urls'][:20]) or '  (none)'}

=== ATTACHMENTS ({len(parsed['attachments'])}) ===
{chr(10).join(f"  - {a['filename']} ({a['content_type']}, {a['size_bytes']} bytes, sha256: {a['sha256']})" for a in parsed['attachments']) or '  (none)'}

=== URGENCY / PHISHING LANGUAGE DETECTED ===
{', '.join(parsed['urgency_indicators']) or 'none detected'}

=== BODY PREVIEW (first 1500 chars) ===
{parsed['body_plain'][:1500] or '[HTML-only email — check URLs above]'}

Begin the investigation now. Start by searching for the phishing investigation skill."""

    client   = anthropic.Anthropic(api_key=api_key)
    messages = [{"role": "user", "content": initial_msg}]
    final_result: dict | None = None
    step = 0
    max_steps = 20

    while step < max_steps:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            tools=PHISHING_TOOLS,
            messages=messages,
        )

        text_parts = [b.text for b in response.content if b.type == "text"]
        if text_parts:
            print(f"  [claude] {' '.join(text_parts)[:200]}", flush=True)

        if response.stop_reason == "end_turn":
            break

        if response.stop_reason != "tool_use":
            break

        assistant_blocks = []
        for b in response.content:
            if b.type == "tool_use":
                assistant_blocks.append({"type": "tool_use", "id": b.id, "name": b.name, "input": b.input})
            else:
                assistant_blocks.append({"type": "text", "text": getattr(b, "text", "")})
        messages.append({"role": "assistant", "content": assistant_blocks})

        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            result_str, report_data = _dispatch(block.name, block.input, parsed)
            tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": result_str})
            step += 1
            if report_data:
                final_result = report_data

        messages.append({"role": "user", "content": tool_results})

        if final_result:
            break

    # Save report via the shared blob store (local FS by default, S3 in prod)
    report_path = f"phishing/{report_id}.md"
    if final_result and final_result.get("report_markdown"):
        import store
        report_path = store.save_blob("phishing", f"{report_id}.md",
                                      final_result["report_markdown"])

    result = {
        "report_id":         report_id,
        "reported_by":       reported_by,
        "investigated_at":   ts,
        "subject":           parsed["subject"],
        "from_email":        parsed["from_email"],
        "sender_domain":     parsed["sender_domain"],
        "verdict":           final_result.get("verdict", "UNKNOWN") if final_result else "UNKNOWN",
        "confidence":        final_result.get("confidence", 0) if final_result else 0,
        "recommended_action": final_result.get("recommended_action", "QUARANTINE") if final_result else "QUARANTINE",
        "summary":           final_result.get("summary", "") if final_result else "",
        "iocs":              final_result.get("iocs", {}) if final_result else {},
        "report_path":       str(report_path),
        "report_markdown":   final_result.get("report_markdown", "") if final_result else "",
    }

    _RESULTS[report_id] = result
    print(f"\n[phishing] {report_id} complete — verdict: {result['verdict']} ({result['confidence']}%)", flush=True)

    # Optional: pivot from a confirmed phish to a tenant-wide victim hunt.
    # Opt-in (PHANTOM_AUTO_VICTIM_HUNT) and always report-only — containment
    # (mailbox purge / forwarding removal) stays a human-authorized action.
    # Best-effort: a missing Google client or config never breaks triage.
    if (final_result and result["verdict"] == "PHISHING"
            and os.environ.get("PHANTOM_AUTO_VICTIM_HUNT", "").lower() in ("1", "true", "yes")):
        try:
            from gworkspace_hunt import hunt_from_phishing_result
            hunt = hunt_from_phishing_result(result, remediate=False)
            result["victim_hunt"] = {
                "hunt_id": hunt.get("hunt_id"),
                "scanned_users": hunt.get("scanned_users"),
                "affected_count": hunt.get("affected_count"),
                "forwarding_findings": len(hunt.get("forwarding_findings", [])),
                "error": hunt.get("error"),
            }
            print(f"[phishing] victim hunt: {result['victim_hunt']}", flush=True)
        except Exception as e:  # noqa: BLE001 — never let hunting break triage
            result["victim_hunt"] = {"error": str(e)}

    # Send notifications — reporter confirmation email + team report
    notification_status = notify_all(result)
    result["notifications"] = notification_status
    _RESULTS[report_id] = result

    return result


def get_result(report_id: str) -> dict | None:
    return _RESULTS.get(report_id)


def list_results(limit: int = 50) -> list[dict]:
    """Return recent results without the full report_markdown (for listing)."""
    results = []
    for r in list(_RESULTS.values())[-limit:]:
        slim = {k: v for k, v in r.items() if k != "report_markdown"}
        results.append(slim)
    return list(reversed(results))
