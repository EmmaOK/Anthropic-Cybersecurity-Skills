#!/usr/bin/env python3
"""
phantom/phishing_campaigns.py — cluster phishing reports into campaigns.

Gives the pipeline memory: records each investigated report, links it to a
*campaign* (so "47 people got the same phish" is one incident), and dedupes
re-reports of an already-seen message.

Clustering rule (conservative, to avoid over-merging):
  Two reports are the same campaign if they share ANY strong indicator — a URL
  domain or an attachment hash — OR they share BOTH the sender domain and a
  normalized subject. A bare shared sender domain is NOT enough.

State lives in the shared store (phantom/store.py): a local SQLite file by
default, or Postgres when PHANTOM_DB_URL is set — no code change either way.

Public API:
    corr = correlate(phishing_result)   # -> {campaign_id, is_new_campaign,
                                        #     is_duplicate, report_count, matched_on}
    camp = get_campaign(campaign_id)
    all_ = list_campaigns(status="open")
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import store
from store import Campaign, CampaignReport


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── Normalization & fingerprinting (pure functions) ─────────────────────────

_SUBJ_PREFIX = re.compile(r'^\s*(re|fw|fwd|aw|wg)\s*:\s*', re.IGNORECASE)


def normalize_subject(subject: str) -> str:
    s = subject or ""
    while _SUBJ_PREFIX.match(s):
        s = _SUBJ_PREFIX.sub("", s, count=1)
    s = s.lower()
    s = re.sub(r'\b\d[\d,.\-/]*\b', '', s)
    s = re.sub(r'[^a-z\s]', ' ', s)
    return re.sub(r'\s+', ' ', s).strip()


def _url_domain(url: str) -> str:
    try:
        net = urlparse(url if "://" in url else "http://" + url).netloc
        return net.split("@")[-1].split(":")[0].lower().strip(".")
    except Exception:
        return ""


def strong_tokens(iocs: dict) -> set[str]:
    toks: set[str] = set()
    for u in iocs.get("urls", []) or []:
        d = _url_domain(u)
        if d:
            toks.add(f"urldom:{d}")
    for d in iocs.get("domains", []) or []:
        d = (d or "").lower().strip(".")
        if d:
            toks.add(f"urldom:{d}")
    for h in iocs.get("hashes", []) or []:
        h = (h or "").lower().strip()
        if h:
            toks.add(f"hash:{h}")
    return toks


def _result_fields(result: dict) -> dict:
    iocs = result.get("iocs", {}) or {}
    return {
        "report_id": result.get("report_id", ""),
        "message_id": (result.get("message_id", "") or "").strip().strip("<>"),
        "verdict": result.get("verdict", "UNKNOWN"),
        "confidence": int(result.get("confidence", 0) or 0),
        "reported_by": result.get("reported_by", ""),
        "subject": result.get("subject", ""),
        "subject_norm": normalize_subject(result.get("subject", "")),
        "sender_domain": (result.get("sender_domain", "") or "").lower(),
        "iocs": iocs,
        "tokens": strong_tokens(iocs),
    }


def _merge_iocs(a: dict, b: dict) -> dict:
    out = {}
    for k in set(a) | set(b):
        out[k] = sorted(set(a.get(k, []) or []) | set(b.get(k, []) or []))
    return out


# ── Correlation ─────────────────────────────────────────────────────────────

def correlate(result: dict) -> dict:
    """Link a phishing.py result to a campaign (creating one if needed)."""
    f = _result_fields(result)
    now = _now()
    s = store.session()
    try:
        # 1) Exact dedupe on Message-ID
        if f["message_id"]:
            row = (s.query(CampaignReport)
                   .filter(CampaignReport.message_id == f["message_id"]).first())
            if row and row.report_id != f["report_id"]:
                return {"campaign_id": row.campaign_id, "is_new_campaign": False,
                        "is_duplicate": True, "matched_on": "message-id",
                        "report_count": _count(s, row.campaign_id)}

        # 2) Find an open campaign sharing a strong token, or (sender + subject)
        match_id, matched_on = None, None
        for camp in s.query(Campaign).filter(Campaign.status == "open").all():
            ctoks = set(store.loads(camp.tokens, []))
            if f["tokens"] & ctoks:
                match_id, matched_on = camp.campaign_id, "shared-ioc"
                break
            if (f["sender_domain"] and f["subject_norm"]
                    and camp.sender_domain == f["sender_domain"]
                    and camp.subject == f["subject_norm"]):
                match_id, matched_on = camp.campaign_id, "sender+subject"
                break

        is_new = match_id is None
        if is_new:
            match_id = f"camp-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
            s.add(Campaign(campaign_id=match_id, created_at=now, last_seen=now, status="open",
                           report_count=0, subject=f["subject_norm"],
                           sender_domain=f["sender_domain"],
                           tokens=store.dumps(sorted(f["tokens"])), iocs=store.dumps(f["iocs"])))
            matched_on = "new"
        else:
            camp = s.get(Campaign, match_id)
            merged_tokens = sorted(set(store.loads(camp.tokens, [])) | f["tokens"])
            merged_iocs = _merge_iocs(store.loads(camp.iocs, {}), f["iocs"])
            camp.last_seen = now
            camp.tokens = store.dumps(merged_tokens)
            camp.iocs = store.dumps(merged_iocs)

        # 3) Upsert the report and bump the campaign count
        rep = s.get(CampaignReport, f["report_id"])
        if rep is None:
            rep = CampaignReport(report_id=f["report_id"])
            s.add(rep)
        rep.message_id = f["message_id"]
        rep.campaign_id = match_id
        rep.investigated_at = now
        rep.verdict = f["verdict"]
        rep.confidence = f["confidence"]
        rep.reported_by = f["reported_by"]
        rep.subject = f["subject"]
        rep.sender_domain = f["sender_domain"]
        rep.iocs = store.dumps(f["iocs"])
        s.flush()

        count = _count(s, match_id)
        s.get(Campaign, match_id).report_count = count
        s.commit()
        return {"campaign_id": match_id, "is_new_campaign": is_new, "is_duplicate": False,
                "matched_on": matched_on, "report_count": count}
    finally:
        s.close()


def _count(s, campaign_id: str) -> int:
    return s.query(CampaignReport).filter(CampaignReport.campaign_id == campaign_id).count()


def record_case_refs(campaign_id: str, thehive=None, misp=None, jira=None) -> None:
    s = store.session()
    try:
        camp = s.get(Campaign, campaign_id)
        if camp:
            if thehive:
                camp.thehive_case = str(thehive)
            if misp:
                camp.misp_event = str(misp)
            if jira:
                camp.jira_issue = str(jira)
            s.commit()
    finally:
        s.close()


def get_campaign(campaign_id: str) -> dict | None:
    s = store.session()
    try:
        camp = s.get(Campaign, campaign_id)
        if not camp:
            return None
        d = {"campaign_id": camp.campaign_id, "status": camp.status,
             "report_count": camp.report_count, "subject": camp.subject,
             "sender_domain": camp.sender_domain,
             "created_at": camp.created_at, "last_seen": camp.last_seen,
             "tokens": store.loads(camp.tokens, []), "iocs": store.loads(camp.iocs, {}),
             "thehive_case": camp.thehive_case, "misp_event": camp.misp_event,
             "jira_issue": camp.jira_issue}
        d["reports"] = [{"report_id": r.report_id, "message_id": r.message_id,
                         "verdict": r.verdict, "confidence": r.confidence,
                         "reported_by": r.reported_by, "investigated_at": r.investigated_at}
                        for r in s.query(CampaignReport)
                        .filter(CampaignReport.campaign_id == campaign_id)
                        .order_by(CampaignReport.investigated_at).all()]
        return d
    finally:
        s.close()


def list_campaigns(status: str | None = None, limit: int = 100) -> list[dict]:
    s = store.session()
    try:
        q = s.query(Campaign)
        if status:
            q = q.filter(Campaign.status == status)
        rows = q.order_by(Campaign.last_seen.desc()).limit(limit).all()
        return [{"campaign_id": c.campaign_id, "created_at": c.created_at,
                 "last_seen": c.last_seen, "status": c.status,
                 "report_count": c.report_count, "subject": c.subject,
                 "sender_domain": c.sender_domain} for c in rows]
    finally:
        s.close()
