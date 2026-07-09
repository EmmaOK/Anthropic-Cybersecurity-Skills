#!/usr/bin/env python3
"""
phantom/phishingbox_intake.py — reported-phish intake + full IR pipeline.

Closes the last gap in Phantom's phishing coverage: getting a user-reported
phish *into* the investigator, then driving the whole incident end-to-end.

Intake sources (use whichever fits your environment):
  1. PhishingBox webhook  — normalize_webhook(payload): PhishingBox POSTs a
     reported email to Phantom's /webhook/phishingbox route (see server.py).
  2. PhishingBox API poll — poll_phishingbox(): pull reported items on a timer.
  3. Abuse mailbox        — poll_abuse_mailbox(): read a shared reporting inbox
     (e.g. phishing@corp.com) via the same Google Workspace delegation the
     victim-hunt module uses, and extract the forwarded original message.

Pipeline (run_pipeline) chains the pieces already built:
    raw .eml
      -> investigate_phishing()        (verdict + IOCs + report + notify)
      -> correlate()                   (cluster into a campaign, dedupe)
      -> sync_campaign()               (TheHive case + MISP event + Jira ticket)
      -> hunt_from_phishing_result()   (Google Workspace victim hunt, report-only)

Every stage is guarded: a missing dependency or unconfigured integration is
skipped and reported, never fatal. Only a confirmed PHISHING verdict triggers
case-sync and victim-hunt; SUSPICIOUS is correlated but not escalated.

Environment (all optional):
  PhishingBox API : PHISHINGBOX_API_URL, PHISHINGBOX_API_KEY
  Abuse mailbox   : ABUSE_MAILBOX (+ the GOOGLE_* vars from gworkspace_hunt)
  Pipeline switches: PHANTOM_PIPELINE_CASE_SYNC (default on),
                     PHANTOM_PIPELINE_VICTIM_HUNT (default off; report-only)
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path

from http_util import http_json, ok


def _truthy(name: str, default: bool) -> bool:
    v = os.environ.get(name, "").lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")


# ── Intake normalizers ───────────────────────────────────────────────────────

_RAW_KEYS = ("raw_email", "rfc822", "eml", "message", "email", "raw", "content")
_REPORTER_KEYS = ("reported_by", "reporter", "reporter_email", "user", "email_address", "from")


def _maybe_b64(s: str) -> str:
    """Return decoded text if `s` looks base64-encoded, else `s` unchanged."""
    if not s or ("@" in s and " " in s) or "\n" in s.strip():
        return s  # already looks like a raw email
    try:
        import binascii
        pad = s + "=" * (-len(s) % 4)
        decoded = base64.b64decode(pad, validate=True).decode("utf-8", "replace")
        return decoded if ("@" in decoded or "Received:" in decoded) else s
    except (binascii.Error, ValueError, Exception):
        return s


def normalize_webhook(payload: dict) -> dict | None:
    """Normalize a PhishingBox (or generic) webhook payload into an intake item.

    Returns {raw_email, reporter, source, external_id} or None if no email found.
    """
    if not isinstance(payload, dict):
        return None
    # unwrap a common single-level envelope
    body = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    raw = ""
    for k in _RAW_KEYS:
        if body.get(k):
            raw = _maybe_b64(str(body[k]))
            break
    if not raw:
        return None
    reporter = ""
    for k in _REPORTER_KEYS:
        if body.get(k):
            reporter = str(body[k])
            break
    return {
        "raw_email": raw,
        "reporter": reporter,
        "source": "phishingbox-webhook",
        "external_id": str(body.get("id") or body.get("report_id") or ""),
    }


def poll_phishingbox() -> list[dict]:
    """Pull reported items from the PhishingBox API. Best-effort/defensive:
    endpoint + auth vary by tenant, so the URL is fully configurable and the
    response is parsed leniently. Returns a list of normalized intake items."""
    url = os.environ.get("PHISHINGBOX_API_URL", "").rstrip("/")
    key = os.environ.get("PHISHINGBOX_API_KEY", "")
    if not (url and key):
        print("[intake] PHISHINGBOX_API_URL / PHISHINGBOX_API_KEY not set — skipping", flush=True)
        return []
    resp = http_json(url, headers={"Authorization": f"Bearer {key}"})
    if not ok(resp):
        print(f"[intake] PhishingBox API error: {resp}", flush=True)
        return []
    # accept {"data":[...]}, {"results":[...]}, or a bare list
    items = resp.get("data") or resp.get("results") or resp.get("reports") or resp
    if not isinstance(items, list):
        return []
    out = []
    for it in items:
        norm = normalize_webhook(it if isinstance(it, dict) else {})
        if norm:
            norm["source"] = "phishingbox-api"
            out.append(norm)
    print(f"[intake] PhishingBox API: {len(out)} report(s)", flush=True)
    return out


def poll_abuse_mailbox(max_messages: int = 25, mark_read: bool = True) -> list[dict]:
    """Read a shared reporting mailbox via Google Workspace delegation and
    extract the original message users forwarded/attached. Returns intake items."""
    mailbox = os.environ.get("ABUSE_MAILBOX", "")
    if not mailbox:
        print("[intake] ABUSE_MAILBOX not set — skipping", flush=True)
        return []
    try:
        import gworkspace_hunt as g
    except Exception as e:  # noqa: BLE001
        print(f"[intake] abuse-mailbox needs gworkspace_hunt/google libs: {e}", flush=True)
        return []
    if not g._GOOGLE_OK:
        print("[intake] google-api-python-client not installed — skipping abuse mailbox", flush=True)
        return []
    cfg = g._config()
    if not cfg["key_file"]:
        print("[intake] GOOGLE_SERVICE_ACCOUNT_FILE not set — skipping abuse mailbox", flush=True)
        return []
    scopes = ["https://www.googleapis.com/auth/gmail.modify"]
    try:
        gmail = g._service("gmail", "v1", mailbox, scopes, cfg["key_file"])
        listing = gmail.users().messages().list(
            userId="me", q="is:unread", maxResults=max_messages).execute()
        items = []
        for ref in listing.get("messages", []):
            full = gmail.users().messages().get(
                userId="me", id=ref["id"], format="raw").execute()
            raw_bytes = base64.urlsafe_b64decode(full["raw"] + "===")
            raw_text = raw_bytes.decode("utf-8", "replace")
            original = _extract_forwarded_original(raw_text) or raw_text
            items.append({"raw_email": original, "reporter": mailbox,
                          "source": "abuse-mailbox", "external_id": ref["id"]})
            if mark_read:
                gmail.users().messages().modify(
                    userId="me", id=ref["id"],
                    body={"removeLabelIds": ["UNREAD"]}).execute()
        print(f"[intake] abuse mailbox {mailbox}: {len(items)} report(s)", flush=True)
        return items
    except Exception as e:  # noqa: BLE001
        print(f"[intake] abuse-mailbox read failed: {e}", flush=True)
        return []


def _extract_forwarded_original(raw_text: str) -> str | None:
    """If the report carries the phish as a message/rfc822 attachment, return it."""
    import email
    import email.policy
    try:
        msg = email.message_from_string(raw_text, policy=email.policy.compat32)
        for part in msg.walk():
            if part.get_content_type() == "message/rfc822":
                payload = part.get_payload()
                if isinstance(payload, list) and payload:
                    return payload[0].as_string()
                if isinstance(payload, str):
                    return payload
    except Exception:
        pass
    return None


# ── The pipeline ─────────────────────────────────────────────────────────────

def run_pipeline(raw_email: str, reporter: str = "", source: str = "manual",
                 case_sync: bool | None = None, victim_hunt: bool | None = None) -> dict:
    """Investigate → correlate → case-sync → victim-hunt. Returns a summary dict."""
    do_case = _truthy("PHANTOM_PIPELINE_CASE_SYNC", True) if case_sync is None else case_sync
    do_hunt = _truthy("PHANTOM_PIPELINE_VICTIM_HUNT", False) if victim_hunt is None else victim_hunt

    from phishing import investigate_phishing  # lazy: pulls anthropic
    result = investigate_phishing(raw_email, reported_by=reporter)
    summary = {
        "report_id": result.get("report_id"),
        "source": source,
        "verdict": result.get("verdict"),
        "confidence": result.get("confidence"),
        "correlation": None, "case_refs": None, "victim_hunt": None,
    }
    if result.get("error"):
        summary["error"] = result["error"]
        return summary

    escalate = result.get("verdict") in ("PHISHING", "SUSPICIOUS")
    if not escalate:
        return summary

    # 1) Campaign correlation (dedupe + cluster)
    campaign = None
    try:
        import phishing_campaigns as pc
        corr = pc.correlate(result)
        summary["correlation"] = corr
        campaign = pc.get_campaign(corr["campaign_id"]) or {"campaign_id": corr["campaign_id"],
                                                            "report_count": corr["report_count"]}
        if corr.get("is_duplicate"):
            print(f"[pipeline] duplicate of {corr['campaign_id']} — skipping escalation", flush=True)
            return summary
    except Exception as e:  # noqa: BLE001
        summary["correlation"] = {"error": str(e)}

    # Only fully escalate confirmed phishing.
    if result.get("verdict") != "PHISHING":
        return summary

    # 2) Case management + IOC push
    if do_case and campaign:
        try:
            import case_sync as cs
            refs = cs.sync_campaign(result, campaign)
            summary["case_refs"] = refs
            try:
                import phishing_campaigns as pc
                pc.record_case_refs(
                    campaign["campaign_id"],
                    thehive=(refs.get("thehive") or {}).get("case_id"),
                    misp=(refs.get("misp") or {}).get("event_id"),
                    jira=(refs.get("jira") or {}).get("key"))
            except Exception:
                pass
        except Exception as e:  # noqa: BLE001
            summary["case_refs"] = {"error": str(e)}

    # 3) Google Workspace victim hunt (report-only)
    if do_hunt:
        try:
            from gworkspace_hunt import hunt_from_phishing_result
            hunt = hunt_from_phishing_result(result, remediate=False)
            summary["victim_hunt"] = {
                "hunt_id": hunt.get("hunt_id"), "scanned_users": hunt.get("scanned_users"),
                "affected_count": hunt.get("affected_count"),
                "forwarding_findings": len(hunt.get("forwarding_findings", [])),
                "error": hunt.get("error"),
            }
        except Exception as e:  # noqa: BLE001
            summary["victim_hunt"] = {"error": str(e)}

    return summary


def process_intake(items: list[dict]) -> list[dict]:
    out = []
    for it in items:
        print(f"[intake] processing report from {it.get('reporter') or 'unknown'} "
              f"(source={it.get('source')})", flush=True)
        out.append(run_pipeline(it["raw_email"], it.get("reporter", ""), it.get("source", "intake")))
    return out


# ── CLI ──────────────────────────────────────────────────────────────────────

def _main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Reported-phish intake + IR pipeline")
    p.add_argument("--eml", help="run the pipeline on a raw .eml file")
    p.add_argument("--reporter", default="", help="who reported it")
    p.add_argument("--webhook-file", help="normalize + process a saved webhook JSON payload")
    p.add_argument("--poll-phishingbox", action="store_true", help="poll the PhishingBox API")
    p.add_argument("--poll-abuse-mailbox", action="store_true", help="poll the abuse mailbox")
    p.add_argument("--no-case-sync", action="store_true", help="skip TheHive/MISP/Jira push")
    p.add_argument("--victim-hunt", action="store_true", help="run the Google Workspace victim hunt")
    args = p.parse_args(argv)

    case_sync = False if args.no_case_sync else None
    hunt = True if args.victim_hunt else None
    results = []
    if args.eml:
        raw = Path(args.eml).read_text(encoding="utf-8", errors="replace")
        results = [run_pipeline(raw, args.reporter, "manual", case_sync, hunt)]
    elif args.webhook_file:
        payload = json.loads(Path(args.webhook_file).read_text())
        item = normalize_webhook(payload)
        if not item:
            print("ERROR: no email found in webhook payload", file=sys.stderr)
            return 2
        results = [run_pipeline(item["raw_email"], item["reporter"], item["source"], case_sync, hunt)]
    elif args.poll_phishingbox:
        results = process_intake(poll_phishingbox())
    elif args.poll_abuse_mailbox:
        results = process_intake(poll_abuse_mailbox())
    else:
        p.print_help()
        return 0

    print(json.dumps(results, indent=2, default=str))
    # exit 1 if any confirmed phishing was processed (HIGH-finding contract)
    return 1 if any(r.get("verdict") == "PHISHING" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
