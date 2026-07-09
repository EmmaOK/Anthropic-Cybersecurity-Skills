#!/usr/bin/env python3
"""
phantom/gworkspace_hunt.py — Google Workspace Campaign Victim-Hunt

Given the IOCs of a confirmed phishing campaign (sender addresses, subjects,
URLs, attachment hashes, or the original RFC822 Message-ID), this module hunts
across *every* mailbox in a Google Workspace tenant to answer the questions the
single-email investigator (phishing.py) cannot:

    - WHO ELSE received a message from this campaign?
    - Did they open / reply to it? (read state + SENT-label heuristics)
    - Did the attacker plant auto-forwarding rules or external forwarding
      addresses in any affected mailbox? (a classic BEC persistence move)

and then — only when explicitly authorized — contains it:

    - Move the campaign message to Trash across all affected mailboxes
      (recoverable; the default), or permanently batch-delete it.
    - Delete attacker-created forwarding filters and disable auto-forwarding.

Public API:
    result = hunt_campaign(
        iocs={"senders": [...], "subjects": [...], "urls": [...],
              "hashes": [...], "message_ids": [...]},
        days=14, remediate=False,
    )
    # result: {campaign_query, scanned_users, affected, forwarding_findings,
    #          actions, report_markdown, ...}

    # convenience: drive a hunt straight from a phishing.py result dict
    result = hunt_from_phishing_result(phishing_result, remediate=False)

Authentication — a service account with DOMAIN-WIDE DELEGATION (the same trust
model the implementing-google-workspace-admin-security skill uses). Configure the
service account's client-id with the OAuth scopes below in the Admin console
(Security > API controls > Domain-wide delegation), then:

    export GOOGLE_SERVICE_ACCOUNT_FILE=/path/to/sa-key.json   # or GOOGLE_APPLICATION_CREDENTIALS
    export GOOGLE_WORKSPACE_ADMIN=admin@corp.com              # super-admin to impersonate for the directory
    export GOOGLE_WORKSPACE_CUSTOMER=my_customer              # optional (default: my_customer)

Read-only scopes needed for the hunt:
    admin.directory.user.readonly, gmail.readonly, gmail.settings.basic
Remediation adds (only requested when --confirm-remediate is passed):
    gmail.modify (trash), gmail.settings.sharing (forwarding removal)
Permanent deletion adds:
    https://mail.google.com/

Safety: destructive actions are OFF by default. The module reports first; it only
trashes/deletes when hunt_campaign(remediate=True) (CLI: --confirm-remediate) and
never permanently deletes unless --permanent is *also* given. Credentials come
only from env vars / the SA key file (repo convention: no hard-coded secrets).

CLI:
    python phantom/gworkspace_hunt.py \
        --sender attacker@evil.com --subject "Urgent: verify your account" \
        --url https://evil.example/login --days 14
    python phantom/gworkspace_hunt.py --message-id '<abc123@evil.com>' \
        --confirm-remediate            # trash across all affected mailboxes
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
    _GOOGLE_OK = True
except ImportError:  # keep the module importable even without the libs
    _GOOGLE_OK = False

ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT / "reports" / "victim-hunt"

# --- OAuth scopes ------------------------------------------------------------
READ_SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.settings.basic",
]
REMEDIATE_SCOPES = READ_SCOPES + [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.settings.sharing",
]
PERMANENT_SCOPES = REMEDIATE_SCOPES + ["https://mail.google.com/"]

_META_HEADERS = ["From", "Subject", "Date", "To", "Reply-To", "Message-ID"]


# ── Configuration & credentials ─────────────────────────────────────────────

def _config() -> dict:
    key_file = (os.environ.get("GOOGLE_SERVICE_ACCOUNT_FILE")
                or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", ""))
    return {
        "key_file": key_file,
        "admin": os.environ.get("GOOGLE_WORKSPACE_ADMIN", ""),
        "customer": os.environ.get("GOOGLE_WORKSPACE_CUSTOMER", "my_customer"),
        "domain": os.environ.get("GOOGLE_WORKSPACE_DOMAIN", ""),
    }


def _service(api: str, version: str, subject: str, scopes: list[str], key_file: str):
    """Build a delegated Google API client impersonating `subject`."""
    creds = service_account.Credentials.from_service_account_file(
        key_file, scopes=scopes, subject=subject)
    # cache_discovery=False avoids noisy warnings / filesystem writes in servers
    return build(api, version, credentials=creds, cache_discovery=False)


# ── Query construction ──────────────────────────────────────────────────────

def build_gmail_query(iocs: dict, days: int = 14) -> str:
    """Turn campaign IOCs into a single Gmail search query.

    The strongest selector is the RFC822 Message-ID (rfc822msgid:) — it pins the
    *exact* message across mailboxes. Sender / subject / URL widen the net for
    re-sent or slightly-mutated variants of the same campaign.
    """
    def esc(v: str) -> str:
        return v.replace('"', '').strip()

    clauses: list[str] = []
    for mid in iocs.get("message_ids", []) or []:
        mid = mid.strip().strip("<>")
        if mid:
            clauses.append(f"rfc822msgid:{mid}")
    senders = [esc(s) for s in (iocs.get("senders") or []) if esc(s)]
    if senders:
        clauses.append("from:(" + " OR ".join(senders) + ")")
    subjects = [esc(s) for s in (iocs.get("subjects") or []) if esc(s)]
    for subj in subjects:
        clauses.append(f'subject:"{subj}"')
    # URLs and hashes match as literal body text
    for term in (iocs.get("urls") or []) + (iocs.get("hashes") or []):
        term = esc(term)
        if term:
            clauses.append(f'"{term}"')

    if not clauses:
        raise ValueError("No usable IOCs: provide at least one of "
                         "message_ids / senders / subjects / urls / hashes")

    query = "(" + " OR ".join(clauses) + ")"
    if days and days > 0:
        after = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y/%m/%d")
        query += f" after:{after}"
    return query


# ── Directory: enumerate mailboxes ──────────────────────────────────────────

def list_users(cfg: dict, scopes: list[str], max_users: int | None = None) -> list[str]:
    """List all active, non-suspended user emails in the tenant."""
    svc = _service("admin", "directory_v1", cfg["admin"], scopes, cfg["key_file"])
    emails: list[str] = []
    params = {"customer": cfg["customer"], "maxResults": 500,
              "orderBy": "email", "projection": "basic", "query": "isSuspended=false"}
    request = svc.users().list(**params)
    while request is not None:
        resp = request.execute()
        for u in resp.get("users", []):
            if not u.get("suspended", False):
                emails.append(u["primaryEmail"])
                if max_users and len(emails) >= max_users:
                    return emails
        request = svc.users().list_next(request, resp)
    return emails


# ── Per-mailbox hunt ────────────────────────────────────────────────────────

def _parse_headers(msg: dict) -> dict:
    headers = {h["name"].lower(): h["value"]
               for h in msg.get("payload", {}).get("headers", [])}
    label_ids = msg.get("labelIds", []) or []
    return {
        "from": headers.get("from", ""),
        "subject": headers.get("subject", ""),
        "date": headers.get("date", ""),
        "message_id": headers.get("message-id", ""),
        "read": "UNREAD" not in label_ids,
        "trashed": "TRASH" in label_ids,
        "replied_or_sent": "SENT" in label_ids,
        "labels": label_ids,
    }


def _external_domain(addr_or_domain: str, own_domains: set[str]) -> bool:
    at = addr_or_domain.rsplit("@", 1)
    dom = (at[1] if len(at) == 2 else at[0]).strip("<> ").lower()
    return bool(dom) and dom not in own_domains


def hunt_mailbox(user: str, query: str, cfg: dict, scopes: list[str],
                 own_domains: set[str], max_hits: int = 25) -> dict:
    """Search one mailbox for the campaign and inspect its forwarding config."""
    out = {"user": user, "hits": [], "forwarding": [], "error": None}
    try:
        gmail = _service("gmail", "v1", user, scopes, cfg["key_file"])

        listing = gmail.users().messages().list(
            userId="me", q=query, maxResults=max_hits).execute()
        for ref in listing.get("messages", []):
            msg = gmail.users().messages().get(
                userId="me", id=ref["id"], format="metadata",
                metadataHeaders=_META_HEADERS).execute()
            meta = _parse_headers(msg)
            meta["id"] = ref["id"]
            meta["thread_id"] = ref.get("threadId", "")
            out["hits"].append(meta)

        # Forwarding persistence — only worth inspecting mailboxes that got hit,
        # but we check every scanned mailbox cheaply for filters that forward out.
        try:
            filters = gmail.users().settings().filters().list(userId="me").execute()
            for f in filters.get("filter", []):
                fwd = f.get("action", {}).get("forward", "")
                if fwd and _external_domain(fwd, own_domains):
                    out["forwarding"].append({
                        "type": "filter", "id": f.get("id", ""),
                        "forward_to": fwd, "criteria": f.get("criteria", {}),
                        "external": True,
                    })
        except HttpError:
            pass  # settings scope may be absent; not fatal for the hunt
    except HttpError as e:
        out["error"] = f"HTTP {getattr(e, 'status_code', '')} {e}"
    except Exception as e:  # per-user isolation — one bad mailbox never aborts the hunt
        out["error"] = str(e)
    return out


# ── Remediation (approval-gated) ────────────────────────────────────────────

def remediate_mailbox(user: str, message_ids: list[str], filter_ids: list[str],
                      cfg: dict, scopes: list[str], permanent: bool = False) -> dict:
    """Trash (or permanently delete) the campaign messages and remove attacker
    forwarding filters in one mailbox. Caller must have confirmed authorization."""
    res = {"user": user, "messages_removed": [], "filters_removed": [], "errors": []}
    try:
        gmail = _service("gmail", "v1", user, scopes, cfg["key_file"])
        if permanent and message_ids:
            try:
                gmail.users().messages().batchDelete(
                    userId="me", body={"ids": message_ids}).execute()
                res["messages_removed"] = list(message_ids)
            except HttpError as e:
                res["errors"].append(f"batchDelete: {e}")
        else:
            for mid in message_ids:
                try:
                    gmail.users().messages().trash(userId="me", id=mid).execute()
                    res["messages_removed"].append(mid)
                except HttpError as e:
                    res["errors"].append(f"trash {mid}: {e}")
        for fid in filter_ids:
            try:
                gmail.users().settings().filters().delete(userId="me", id=fid).execute()
                res["filters_removed"].append(fid)
            except HttpError as e:
                res["errors"].append(f"filter {fid}: {e}")
    except Exception as e:
        res["errors"].append(str(e))
    return res


# ── Orchestration ───────────────────────────────────────────────────────────

def hunt_campaign(iocs: dict, days: int = 14, users: list[str] | None = None,
                  max_users: int | None = None, workers: int = 8,
                  remediate: bool = False, permanent: bool = False,
                  hunt_id: str = "") -> dict:
    """Run a full-tenant campaign victim-hunt. Returns a structured result dict."""
    if not _GOOGLE_OK:
        return {"error": "google-api-python-client not installed "
                         "(pip install google-api-python-client google-auth)"}
    cfg = _config()
    if not cfg["key_file"] or not cfg["admin"]:
        return {"error": "Set GOOGLE_SERVICE_ACCOUNT_FILE and GOOGLE_WORKSPACE_ADMIN"}

    hunt_id = hunt_id or f"vh-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    started = datetime.now(timezone.utc).isoformat()
    scopes = (PERMANENT_SCOPES if permanent else REMEDIATE_SCOPES) if remediate else READ_SCOPES

    try:
        query = build_gmail_query(iocs, days)
    except ValueError as e:
        return {"error": str(e), "hunt_id": hunt_id}

    own_domains = set()
    if cfg["domain"]:
        own_domains.add(cfg["domain"].lower())

    print(f"[gws-hunt] {hunt_id} query: {query}", flush=True)
    try:
        targets = users or list_users(cfg, scopes, max_users)
    except Exception as e:
        return {"error": f"directory listing failed: {e}", "hunt_id": hunt_id}
    # derive own domains from the mailbox list if not configured
    for addr in targets:
        if "@" in addr:
            own_domains.add(addr.rsplit("@", 1)[1].lower())
    print(f"[gws-hunt] scanning {len(targets)} mailboxes with {workers} workers", flush=True)

    affected, forwarding_findings, scan_errors = [], [], []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = {pool.submit(hunt_mailbox, u, query, cfg, scopes, own_domains): u
                for u in targets}
        for fut in as_completed(futs):
            r = fut.result()
            if r["error"]:
                scan_errors.append({"user": r["user"], "error": r["error"]})
            if r["hits"]:
                affected.append({
                    "user": r["user"],
                    "message_count": len(r["hits"]),
                    "read": any(h["read"] for h in r["hits"]),
                    "replied": any(h["replied_or_sent"] for h in r["hits"]),
                    "message_ids": [h["id"] for h in r["hits"]],
                    "messages": r["hits"],
                })
            for f in r["forwarding"]:
                forwarding_findings.append({"user": r["user"], **f})

    affected.sort(key=lambda a: (not a["replied"], not a["read"], a["user"]))

    # Remediation pass — only when explicitly authorized.
    actions = []
    if remediate and (affected or forwarding_findings):
        print(f"[gws-hunt] REMEDIATING (permanent={permanent})", flush=True)
        fwd_by_user: dict[str, list[str]] = {}
        for f in forwarding_findings:
            fwd_by_user.setdefault(f["user"], []).append(f["id"])
        users_to_fix = {a["user"] for a in affected} | set(fwd_by_user)
        msg_by_user = {a["user"]: a["message_ids"] for a in affected}
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futs = {pool.submit(remediate_mailbox, u, msg_by_user.get(u, []),
                                fwd_by_user.get(u, []), cfg, scopes, permanent): u
                    for u in users_to_fix}
            for fut in as_completed(futs):
                actions.append(fut.result())

    result = {
        "hunt_id": hunt_id,
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "campaign_query": query,
        "iocs": iocs,
        "scanned_users": len(targets),
        "affected_count": len(affected),
        "affected": affected,
        "forwarding_findings": forwarding_findings,
        "scan_errors": scan_errors,
        "remediated": remediate,
        "actions": actions,
    }
    result["report_markdown"] = render_report(result)

    import store
    store.save_blob("victim-hunt", f"{hunt_id}.md", result["report_markdown"])
    store.save_blob("victim-hunt", f"{hunt_id}.json",
                    json.dumps({k: v for k, v in result.items() if k != "report_markdown"},
                               indent=2, default=str))
    print(f"[gws-hunt] {hunt_id} complete — {len(affected)} affected / "
          f"{len(targets)} scanned", flush=True)
    return result


def hunt_from_phishing_result(phishing_result: dict, **kwargs) -> dict:
    """Map a phishing.py investigation result into a campaign hunt."""
    iocs_in = phishing_result.get("iocs", {}) or {}
    iocs = {
        "senders": list(filter(None, [phishing_result.get("from_email", "")]
                               + iocs_in.get("emails", []))),
        "subjects": list(filter(None, [phishing_result.get("subject", "")])),
        "urls": iocs_in.get("urls", []),
        "hashes": iocs_in.get("hashes", []),
        "message_ids": list(filter(None, [phishing_result.get("message_id", "")])),
    }
    return hunt_campaign(iocs, **kwargs)


# ── Reporting ────────────────────────────────────────────────────────────────

def render_report(r: dict) -> str:
    lines = [
        f"# Google Workspace Campaign Victim-Hunt — {r['hunt_id']}",
        "",
        f"- **Started:** {r['started_at']}",
        f"- **Mailboxes scanned:** {r['scanned_users']}",
        f"- **Affected mailboxes:** {r['affected_count']}",
        f"- **Attacker forwarding rules found:** {len(r['forwarding_findings'])}",
        f"- **Remediation performed:** {'YES' if r['remediated'] else 'no (report-only)'}",
        "",
        "## Campaign search query",
        "```",
        r["campaign_query"],
        "```",
        "",
        "## Affected users",
    ]
    if r["affected"]:
        lines += ["| User | Msgs | Opened | Replied/Sent |",
                  "|---|---|---|---|"]
        for a in r["affected"]:
            lines.append(f"| {a['user']} | {a['message_count']} | "
                         f"{'yes' if a['read'] else 'no'} | "
                         f"{'⚠️ YES' if a['replied'] else 'no'} |")
    else:
        lines.append("_No other recipients found for this campaign._")

    if r["forwarding_findings"]:
        lines += ["", "## ⚠️ Attacker-created forwarding (persistence)",
                  "| User | Forwards to | Filter id |", "|---|---|---|"]
        for f in r["forwarding_findings"]:
            lines.append(f"| {f['user']} | {f.get('forward_to', '')} | {f.get('id', '')} |")

    if r["remediated"] and r["actions"]:
        removed = sum(len(a["messages_removed"]) for a in r["actions"])
        fdel = sum(len(a["filters_removed"]) for a in r["actions"])
        lines += ["", "## Remediation actions",
                  f"- Messages removed: **{removed}**",
                  f"- Forwarding filters deleted: **{fdel}**"]
        errs = [e for a in r["actions"] for e in a["errors"]]
        if errs:
            lines.append(f"- Errors: {len(errs)} (see JSON artifact)")
    elif not r["remediated"] and (r["affected"] or r["forwarding_findings"]):
        lines += ["", "## Recommended actions",
                  "- Purge the campaign message from affected mailboxes "
                  "(re-run with `--confirm-remediate`).",
                  "- Reset credentials + revoke sessions/OAuth tokens for any user "
                  "who **replied** or entered credentials.",
                  "- Remove attacker forwarding rules and re-verify MFA.",
                  "- Block the sender domain / URL at the email gateway."]

    if r["scan_errors"]:
        lines += ["", f"> {len(r['scan_errors'])} mailbox(es) could not be scanned "
                  "(see JSON artifact for details)."]
    return "\n".join(lines)


# ── CLI ──────────────────────────────────────────────────────────────────────

def _main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Google Workspace campaign victim-hunt")
    p.add_argument("--sender", action="append", default=[], help="campaign sender (repeatable)")
    p.add_argument("--subject", action="append", default=[], help="campaign subject (repeatable)")
    p.add_argument("--url", action="append", default=[], help="malicious URL (repeatable)")
    p.add_argument("--hash", action="append", default=[], dest="hashes", help="attachment hash (repeatable)")
    p.add_argument("--message-id", action="append", default=[], dest="message_ids",
                   help="original RFC822 Message-ID — the most precise selector (repeatable)")
    p.add_argument("--days", type=int, default=14, help="look-back window in days (default 14)")
    p.add_argument("--user", action="append", default=[], dest="users",
                   help="restrict hunt to these mailboxes (repeatable; default = whole tenant)")
    p.add_argument("--max-users", type=int, default=None, help="cap mailboxes scanned")
    p.add_argument("--workers", type=int, default=8, help="concurrent mailbox scans (default 8)")
    p.add_argument("--from-phishing-report", help="path to a phishing.py result JSON to seed IOCs")
    p.add_argument("--confirm-remediate", action="store_true",
                   help="AUTHORIZE containment: trash campaign messages + delete forwarding rules")
    p.add_argument("--permanent", action="store_true",
                   help="with --confirm-remediate, permanently delete instead of trashing")
    p.add_argument("--json", action="store_true", help="print full result JSON to stdout")
    args = p.parse_args(argv)

    if not _GOOGLE_OK:
        print("Install: pip install google-api-python-client google-auth", file=sys.stderr)
        return 2

    if args.from_phishing_report:
        pr = json.loads(Path(args.from_phishing_report).read_text())
        result = hunt_from_phishing_result(
            pr, days=args.days, users=args.users or None, max_users=args.max_users,
            workers=args.workers, remediate=args.confirm_remediate, permanent=args.permanent)
    else:
        iocs = {"senders": args.sender, "subjects": args.subject, "urls": args.url,
                "hashes": args.hashes, "message_ids": args.message_ids}
        result = hunt_campaign(
            iocs, days=args.days, users=args.users or None, max_users=args.max_users,
            workers=args.workers, remediate=args.confirm_remediate, permanent=args.permanent)

    if result.get("error"):
        print(f"ERROR: {result['error']}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({k: v for k, v in result.items() if k != "report_markdown"},
                         indent=2, default=str))
    else:
        print("\n" + result["report_markdown"])
    # Exit 1 signals a HIGH finding (campaign spread beyond the reporter) —
    # preserves the repo's script exit-code contract for CI/automation gating.
    return 1 if (result["affected_count"] or result["forwarding_findings"]) else 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
