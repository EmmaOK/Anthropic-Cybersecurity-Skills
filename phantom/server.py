#!/usr/bin/env python3
"""
Phantom Web Server

Setup:
  pip install fastapi "uvicorn[standard]" jinja2 python-multipart aiofiles httpx

Run:
  cd /path/to/project
  uvicorn phantom.server:app --host 0.0.0.0 --port 8080
"""
import asyncio
import json
import os
import sys
import uuid
from pathlib import Path
from typing import AsyncGenerator

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

try:
    from anthropic import AsyncAnthropic
except ImportError:
    print("pip install anthropic")
    sys.exit(1)

_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

from skill_loader import search_skills, load_skill
from executor import run_agent
from tools import TOOLS
from approvals import (
    create_approval, decide_approval, list_approvals,
    pending_count, verify_token, send_google_chat_notification,
)
from main import (
    PERSONAS, ROOT, MODEL, MAX_TOKENS,
    save_session, load_session, list_sessions, _serialize_messages,
)
from phishing import investigate_phishing, get_result, list_results
from phishingbox_intake import normalize_webhook, run_pipeline
from guardduty_intake import normalize_eventbridge, run_pipeline as run_guardduty_pipeline
from task_agent import list_task_types, run_task
import auth
import jobs

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="Phantom", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=_HERE / "static"), name="static")
templates = Jinja2Templates(directory=_HERE / "templates")

_client = AsyncAnthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
_sessions: dict[str, dict] = {}  # session_id → {messages, mode}


def _get_session(session_id: str, mode: str = "general") -> dict:
    if session_id not in _sessions:
        _sessions[session_id] = {"messages": [], "mode": mode}
    return _sessions[session_id]


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------
def _dispatch(name: str, inp: dict, session_id: str = "") -> str:
    if name == "request_approval":
        a = create_approval(
            session_id=session_id,
            action_type=inp.get("action_type", "unknown"),
            resources=inp.get("resources", []),
            justification=inp.get("justification", ""),
            impact=inp.get("impact", ""),
            impact_level=inp.get("impact_level", "HIGH"),
        )
        send_google_chat_notification(a)
        return json.dumps({
            "approval_id": a["id"],
            "status": "pending",
            "expires_at": a["expires_at"],
            "note": f"Approval {a['id']} submitted. Approver notified via Google Chat and /approvals.",
        })

    if name == "search_skills":
        results = search_skills(inp.get("query", ""))
        if not results:
            return json.dumps({"results": [], "message": "No skills found."})
        return json.dumps({"results": [
            {"name": r["name"], "description": r.get("description", ""), "path": r["path"]}
            for r in results], "count": len(results)})

    if name == "load_skill":
        content = load_skill(inp.get("skill_name", ""))
        return content[:8000] + "\n\n[truncated]" if len(content) > 8000 else content

    if name == "run_skill_agent":
        return run_agent(inp.get("skill_name", ""), inp.get("args", []))

    if name == "write_file":
        target = ROOT / inp.get("path", "")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(inp.get("content", ""), encoding="utf-8")
        return f"Written: {target}"

    if name == "generate_diagram":
        import subprocess
        title = inp.get("title", "diagram")
        src   = inp.get("mermaid_source", "")
        out   = ROOT / inp.get("output_path", f"diagrams/{title.lower().replace(' ','_')}")
        out.parent.mkdir(parents=True, exist_ok=True)
        mmd = out.with_suffix(".mmd")
        mmd.write_text(src, encoding="utf-8")
        png = out.with_suffix(".png")
        try:
            r = subprocess.run(["mmdc", "-i", str(mmd), "-o", str(png), "--quiet"],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                return f"Diagram saved.\n  Mermaid: {mmd}\n  PNG: {png}"
            return f"Mermaid saved to {mmd}. PNG failed: {r.stderr[:100]}"
        except FileNotFoundError:
            return f"Mermaid saved to {mmd}. Install mmdc: npm i -g @mermaid-js/mermaid-cli"
        except subprocess.TimeoutExpired:
            return f"Mermaid saved to {mmd}. PNG timed out."

    return f"[Error] Unknown tool: {name}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _block_to_dict(b) -> dict:
    """Serialize a content block to only the fields the API accepts."""
    block_type = getattr(b, "type", None)
    if block_type == "tool_use":
        return {"type": "tool_use", "id": b.id, "name": b.name, "input": b.input}
    if block_type == "text" or hasattr(b, "text"):
        return {"type": "text", "text": b.text}
    if hasattr(b, "model_dump"):
        d = b.model_dump()
        return {k: v for k, v in d.items() if k in ("type", "id", "name", "input", "text", "content")}
    return {"type": "text", "text": str(b)}


# ---------------------------------------------------------------------------
# Streaming turn
# ---------------------------------------------------------------------------
async def _stream(messages: list, system: str, session_id: str) -> AsyncGenerator[str, None]:
    while True:
        async with _client.messages.stream(
            model=MODEL, max_tokens=MAX_TOKENS,
            system=system, tools=TOOLS, messages=messages,
        ) as stream:
            async for chunk in stream.text_stream:
                yield f"data: {json.dumps({'type':'text','delta':chunk})}\n\n"
            msg = await stream.get_final_message()

        if msg.stop_reason == "end_turn":
            content = [_block_to_dict(b) for b in msg.content]
            messages.append({"role": "assistant", "content": content or [{"type":"text","text":""}]})
            yield f"data: {json.dumps({'type':'done'})}\n\n"
            return

        if msg.stop_reason == "tool_use":
            assistant_blocks = [_block_to_dict(b) for b in msg.content]
            messages.append({"role": "assistant", "content": assistant_blocks})

            tool_results = []
            for b in msg.content:
                if getattr(b, "type", None) != "tool_use":
                    continue
                yield f"data: {json.dumps({'type':'tool_call','name':b.name,'input':b.input})}\n\n"
                result = await asyncio.to_thread(_dispatch, b.name, b.input, session_id)
                yield f"data: {json.dumps({'type':'tool_result','name':b.name})}\n\n"
                tool_results.append({"type":"tool_result","tool_use_id":b.id,"content":result})

            messages.append({"role": "user", "content": tool_results})
        else:
            yield f"data: {json.dumps({'type':'done'})}\n\n"
            return


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------
class ChatRequest(BaseModel):
    session_id: str
    message: str
    mode: str = "general"
    image_base64: str | None = None
    image_media_type: str | None = None


# ---------------------------------------------------------------------------
# UI routes
# ---------------------------------------------------------------------------
@app.get("/", response_class=RedirectResponse)
async def root():
    return RedirectResponse(url="/chat")


@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    return templates.TemplateResponse(request, "chat.html", {
        "modes": list(PERSONAS.keys()),
        "pending_approvals": pending_count(),
    })


@app.get("/approvals", response_class=HTMLResponse)
async def approvals_page(request: Request):
    pending = list_approvals(status="pending")
    history = [a for a in list_approvals() if a["status"] != "pending"][:20]
    return templates.TemplateResponse(request, "approvals.html", {
        "pending": pending, "history": history,
        "pending_count": len(pending), "modes": list(PERSONAS.keys()),
        "pending_approvals": len(pending),
    })


# ---------------------------------------------------------------------------
# Auth dependency (used by every gated route below)
# ---------------------------------------------------------------------------
def _request_token(request: Request, authorization: str | None) -> str | None:
    """Resolve a bearer token from the header, an add-in header, a cookie, or a
    query param — so webhooks (Authorization), browser JS (cookie/X-Phantom-Token),
    and email add-ins all have a path. Returns an 'authorization'-style string."""
    if authorization:
        return authorization
    xt = request.headers.get("x-phantom-token")
    if xt:
        return f"Bearer {xt}"
    ck = request.cookies.get("phantom_token")
    if ck:
        return f"Bearer {ck}"
    qp = request.query_params.get("token")
    if qp:
        return f"Bearer {qp}"
    return None


def get_principal(request: Request,
                  authorization: str | None = Header(default=None)) -> auth.Principal:
    """FastAPI dependency: resolve the caller, or 401/403/503 via HTTPException."""
    try:
        return auth.authenticate(_request_token(request, authorization))
    except auth.AuthError as e:
        auth.audit("auth_failure", None, status=e.status, detail=e.detail,
                   source_ip=(request.client.host if request.client else None),
                   path=request.url.path)
        raise HTTPException(status_code=e.status, detail=e.detail)


def require_perm(principal: auth.Principal, action: str, request: Request) -> None:
    """Enforce a non-task permission (chat, phishing:report, ...), audit denials."""
    try:
        auth.require(principal, action)
    except auth.AuthError as e:
        auth.audit("perm_denied", principal, permission=action, detail=e.detail,
                   source_ip=(request.client.host if request.client else None),
                   path=request.url.path)
        raise HTTPException(status_code=e.status, detail=e.detail)


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------
@app.post("/api/chat")
async def api_chat(req: ChatRequest, request: Request,
                   principal: auth.Principal = Depends(get_principal)):
    require_perm(principal, "chat", request)
    session = _get_session(req.session_id, req.mode)
    session["mode"] = req.mode

    if req.image_base64 and req.image_media_type:
        content = [
            {"type": "image", "source": {"type": "base64",
             "media_type": req.image_media_type, "data": req.image_base64}},
            {"type": "text", "text": req.message},
        ]
    else:
        content = req.message

    session["messages"].append({"role": "user", "content": content})

    return StreamingResponse(
        _stream(session["messages"], PERSONAS.get(req.mode, PERSONAS["general"]), req.session_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/sessions")
async def api_sessions(request: Request, principal: auth.Principal = Depends(get_principal)):
    require_perm(principal, "chat", request)
    return JSONResponse({"sessions": list_sessions()})


@app.post("/api/sessions/{name}/save")
async def api_save(name: str, request: Request,
                   principal: auth.Principal = Depends(get_principal)):
    require_perm(principal, "chat", request)
    body = await request.json()
    s = _sessions.get(body.get("session_id",""), {})
    path = save_session(s.get("messages",[]), s.get("mode","general"), name)
    return JSONResponse({"saved": True, "path": str(path)})


@app.post("/api/sessions/{name}/load")
async def api_load(name: str, request: Request,
                   principal: auth.Principal = Depends(get_principal)):
    require_perm(principal, "chat", request)
    result = load_session(name)
    if result is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    messages, mode = result
    sid = str(uuid.uuid4())
    _sessions[sid] = {"messages": messages, "mode": mode}
    return JSONResponse({"session_id": sid, "mode": mode, "message_count": len(messages)})


@app.get("/api/approvals")
async def api_approvals(request: Request, status: str | None = Query(None),
                        principal: auth.Principal = Depends(get_principal)):
    require_perm(principal, "approvals:read", request)
    return JSONResponse({"approvals": list_approvals(status=status), "pending_count": pending_count()})


@app.post("/api/approvals/{aid}/decide")
async def api_decide(aid: str, request: Request,
                     principal: auth.Principal = Depends(get_principal)):
    require_perm(principal, "approvals:decide", request)
    body = await request.json()
    decision   = body.get("decision")
    decided_by = body.get("decided_by") or principal.username
    if decision not in ("approved", "denied"):
        return JSONResponse({"error": "decision must be approved or denied"}, status_code=400)
    a = decide_approval(aid, decision, decided_by)
    if a is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"approval": a})


# Google Chat link flow — token-validated GET endpoints
@app.get("/approvals/{aid}/approve", response_class=HTMLResponse)
async def approve_link(request: Request, aid: str, token: str = Query(...)):
    if not verify_token(aid, "approved", token):
        return HTMLResponse("<h2 style='font-family:sans-serif;color:#da3633'>Invalid or expired link.</h2>", 403)
    a = decide_approval(aid, "approved", "google-chat")
    if not a:
        return HTMLResponse("<h2 style='font-family:sans-serif'>Approval not found.</h2>", 404)
    return templates.TemplateResponse(request, "approval_result.html",
        {"decision": "approved", "approval": a,
         "modes": list(PERSONAS.keys()), "pending_approvals": pending_count()})


@app.get("/approvals/{aid}/deny", response_class=HTMLResponse)
async def deny_link(request: Request, aid: str, token: str = Query(...)):
    if not verify_token(aid, "denied", token):
        return HTMLResponse("<h2 style='font-family:sans-serif;color:#da3633'>Invalid or expired link.</h2>", 403)
    a = decide_approval(aid, "denied", "google-chat")
    if not a:
        return HTMLResponse("<h2 style='font-family:sans-serif'>Approval not found.</h2>", 404)
    return templates.TemplateResponse(request, "approval_result.html",
        {"decision": "denied", "approval": a,
         "modes": list(PERSONAS.keys()), "pending_approvals": pending_count()})


# ---------------------------------------------------------------------------
# Phishing Investigation
# ---------------------------------------------------------------------------

class PhishingRequest(BaseModel):
    raw_email: str           # raw .eml content (full RFC 2822 email)
    reported_by: str = ""    # reporter email address
    report_id: str = ""      # optional — generated if not provided


@app.post("/api/investigate/phishing")
async def api_investigate_phishing(req: PhishingRequest, request: Request,
                                   principal: auth.Principal = Depends(get_principal)):
    """
    Accept a raw email and run autonomous phishing investigation.
    Blocks until investigation completes (typically 30–90 seconds).
    Called by the AWS Lambda function after SES delivers an email to S3.
    """
    require_perm(principal, "phishing:report", request)
    auth.audit("phishing_investigate", principal, reported_by=req.reported_by,
               source_ip=(request.client.host if request.client else None))
    result = await asyncio.to_thread(
        investigate_phishing,
        req.raw_email,
        req.reported_by,
        req.report_id,
    )
    # Return full result except the lengthy report_markdown to keep response small.
    # Retrieve full report via GET /api/investigate/phishing/{report_id}
    slim = {k: v for k, v in result.items() if k != "report_markdown"}
    slim["report_url"] = f"/api/investigate/phishing/{result['report_id']}"
    return JSONResponse(slim)


@app.get("/api/investigate/phishing")
async def api_list_investigations(request: Request, limit: int = Query(default=50, le=200),
                                  principal: auth.Principal = Depends(get_principal)):
    """List recent phishing investigations (no report bodies)."""
    require_perm(principal, "phishing:read", request)
    return JSONResponse({"investigations": list_results(limit)})


@app.get("/api/investigate/phishing/{report_id}")
async def api_get_investigation(report_id: str, request: Request,
                                principal: auth.Principal = Depends(get_principal)):
    """Get full investigation result including the Markdown report."""
    require_perm(principal, "phishing:read", request)
    result = get_result(report_id)
    if result is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(result)


@app.get("/api/investigate/phishing/{report_id}/report")
async def api_get_report_markdown(report_id: str, request: Request,
                                  principal: auth.Principal = Depends(get_principal)):
    """Return the raw Markdown investigation report."""
    require_perm(principal, "phishing:read", request)
    result = get_result(report_id)
    if result is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    md = result.get("report_markdown", "")
    if not md:
        report_path = Path(result.get("report_path", ""))
        if report_path.exists():
            md = report_path.read_text(encoding="utf-8")
    return JSONResponse({"report_id": report_id, "report_markdown": md})


# ---------------------------------------------------------------------------
# Universal Kill Phish Webhook
# Accepts reports from any email client (Gmail add-on, Outlook add-in,
# Proofpoint, Mimecast, manual API call, etc.)
# Returns immediately — investigation runs in background, results emailed.
# ---------------------------------------------------------------------------

import base64 as _base64
import hashlib as _hashlib

# Deduplication: dedup key → job_id (best-effort; avoids re-investigating the
# same email submitted from multiple clients at once). Per-process — for strict
# cross-container dedup, back this with Redis.
_SEEN_HASHES: dict[str, str] = {}


class KillPhishRequest(BaseModel):
    # Email content — provide exactly one of these three
    raw_email:    str | None = None   # full RFC 2822 string (Gmail getRawContent())
    email_base64: str | None = None   # base64-encoded RFC 2822 (Outlook getAsFileAsync())
    # Structured fallback — used when client cannot obtain raw EML
    subject:      str | None = None
    from_address: str | None = None
    to_address:   str | None = None
    date:         str | None = None
    body_html:    str | None = None
    body_text:    str | None = None
    headers:      dict | None = None  # extra headers as key→value dict

    # Metadata
    reported_by:     str = ""         # reporter's email address
    source:          str = "unknown"  # "gmail-addon", "outlook-addin", "api", etc.
    report_id:       str = ""         # optional — generated if omitted
    message_id:      str = ""         # email Message-ID for deduplication
    gmail_message_id: str = ""        # Gmail thread/message ID for deduplication


def _normalise_email(req: KillPhishRequest) -> str:
    """Produce a raw RFC 2822 string from whichever fields were provided."""
    if req.raw_email:
        return req.raw_email

    if req.email_base64:
        try:
            return _base64.b64decode(req.email_base64).decode("utf-8", errors="replace")
        except Exception:
            pass

    # Structured fallback — reconstruct minimal RFC 2822
    lines = []
    if req.from_address:
        lines.append(f"From: {req.from_address}")
    if req.to_address:
        lines.append(f"To: {req.to_address}")
    if req.subject:
        lines.append(f"Subject: {req.subject}")
    if req.date:
        lines.append(f"Date: {req.date}")
    if req.message_id:
        lines.append(f"Message-ID: {req.message_id}")
    if req.headers:
        for k, v in req.headers.items():
            lines.append(f"{k}: {v}")
    lines.append("Content-Type: text/html; charset=utf-8")
    lines.append("")
    lines.append(req.body_html or req.body_text or "(no body)")
    return "\r\n".join(lines)


@app.post("/api/webhook/phishing-report")
async def api_killphish_webhook(req: KillPhishRequest, request: Request,
                                principal: auth.Principal = Depends(get_principal)):
    """
    Universal Kill Phish webhook — called by Gmail add-on, Outlook add-in,
    or any email security tool. Returns immediately; investigation runs async.

    Accepts raw EML, base64-encoded EML, or structured JSON fields.
    Deduplicates by Message-ID and content hash to avoid re-investigating
    the same email submitted from multiple clients simultaneously.

    Auth: caller needs the 'phishing:report' permission (e.g. a service token
    with role 'service-phishing'). Add-ins send it via Authorization/X-Phantom-Token.
    """
    require_perm(principal, "phishing:report", request)
    raw_email = _normalise_email(req)
    if not raw_email.strip():
        return JSONResponse({"error": "No email content provided."}, status_code=400)

    # Deduplicate by Message-ID header
    dedup_key = req.message_id or req.gmail_message_id or ""
    if not dedup_key:
        dedup_key = _hashlib.sha256(raw_email[:2000].encode()).hexdigest()[:16]

    if dedup_key in _SEEN_HASHES:
        existing_id = _SEEN_HASHES[dedup_key]
        existing = jobs.get_job(existing_id)
        return JSONResponse({
            "report_id":    existing_id,
            "status":       existing["status"] if existing else "queued",
            "deduplicated": True,
            "message":      "This email was already reported. Check your inbox for results.",
            "status_url":   f"/api/webhook/phishing-report/{existing_id}",
        })

    # Enqueue triage (worker runs investigate_phishing) — do not run in-process.
    job_id = jobs.enqueue("phishing_investigate",
                          {"raw_email": raw_email, "reported_by": req.reported_by},
                          owner=principal.username)
    _SEEN_HASHES[dedup_key] = job_id
    auth.audit("phishing_report", principal, job_id=job_id, source=req.source,
               reported_by=req.reported_by,
               source_ip=(request.client.host if request.client else None))
    return JSONResponse({
        "report_id":  job_id,
        "status":     "queued",
        "source":     req.source,
        "message":    "Received. Phantom is investigating — we'll email you the verdict.",
        "status_url": f"/api/webhook/phishing-report/{job_id}",
    })


@app.get("/api/webhook/phishing-report/{report_id}")
async def api_killphish_status(report_id: str, request: Request,
                               principal: auth.Principal = Depends(get_principal)):
    """Poll investigation status. Used by add-ins that want to show live results."""
    require_perm(principal, "phishing:read", request)
    job = jobs.get_job(report_id)
    if not job or job.get("kind") != "phishing_investigate":
        return JSONResponse({"error": "not found"}, status_code=404)
    result = job.get("result")
    if job["status"] in ("complete", "error") and isinstance(result, dict):
        slim = {k: v for k, v in result.items() if k != "report_markdown"}
        return JSONResponse({"status": job["status"], "result": slim})
    return JSONResponse({"status": job["status"], "report_id": report_id})


# ---------------------------------------------------------------------------
# PhishingBox intake — full IR pipeline (investigate → correlate → case → hunt).
# Enqueued to a worker (jobs.py), not run in the API process.
# ---------------------------------------------------------------------------
@app.post("/api/webhook/phishingbox")
async def api_phishingbox_webhook(request: Request,
                                  principal: auth.Principal = Depends(get_principal)):
    """PhishingBox report-a-phish webhook. Accepts PhishingBox's (or any) JSON
    payload, extracts the reported email, and enqueues the full IR pipeline —
    investigate, campaign-correlate, open a TheHive/MISP/Jira case, and (if
    enabled) hunt Google Workspace for other victims. Returns immediately.

    Auth: requires 'phishing:report' (configure PhishingBox to send a service
    token in the Authorization header)."""
    require_perm(principal, "phishing:report", request)
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON body"}, status_code=400)

    item = normalize_webhook(payload)
    if not item:
        return JSONResponse(
            {"error": "no reported email found in payload",
             "hint": "expected one of: raw_email/rfc822/eml/message/email (base64 ok)"},
            status_code=422)

    job_id = jobs.enqueue("phishing_pipeline",
                          {"raw_email": item["raw_email"], "reporter": item["reporter"],
                           "source": item["source"]},
                          owner=principal.username)
    auth.audit("phishingbox_report", principal, job_id=job_id, source=item["source"],
               source_ip=(request.client.host if request.client else None))
    return JSONResponse({
        "report_id": job_id, "status": "queued", "source": item["source"],
        "message": "Received. Phantom is running the phishing IR pipeline.",
        "status_url": f"/api/webhook/phishingbox/{job_id}",
    })


@app.get("/api/webhook/phishingbox/{report_id}")
async def api_phishingbox_status(report_id: str, request: Request,
                                 principal: auth.Principal = Depends(get_principal)):
    """Poll the pipeline result (verdict, campaign, case refs, victim-hunt)."""
    require_perm(principal, "phishing:read", request)
    job = jobs.get_job(report_id)
    if not job or job.get("kind") != "phishing_pipeline":
        return JSONResponse({"error": "not found"}, status_code=404)
    if job["status"] in ("complete", "error"):
        return JSONResponse({"status": job["status"], "result": job.get("result")})
    return JSONResponse({"status": job["status"], "report_id": report_id})


# ---------------------------------------------------------------------------
# GuardDuty intake — EventBridge posts a finding; Phantom runs the cloud IR
# pipeline (investigate → enrich → CloudTrail → case → approval-gated containment).
# The work is ENQUEUED (jobs.py) and executed by a worker, not run in-process.
# ---------------------------------------------------------------------------
@app.post("/api/webhook/guardduty")
async def api_guardduty_webhook(request: Request,
                                principal: auth.Principal = Depends(get_principal)):
    """AWS GuardDuty webhook (EventBridge → API Destination / Lambda). Accepts the
    EventBridge event (finding under 'detail') or a bare finding, enqueues the
    cloud IR pipeline, and returns immediately. Requires 'guardduty:report'."""
    require_perm(principal, "guardduty:report", request)
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON body"}, status_code=400)
    norm = normalize_eventbridge(payload)
    if not norm:
        return JSONResponse({"error": "no GuardDuty finding in payload",
                             "hint": "expected an EventBridge event with a 'detail' finding"},
                            status_code=422)
    raw_finding = payload.get("detail", payload)  # pass the raw finding to the pipeline
    job_id = jobs.enqueue("guardduty", {"finding": raw_finding, "source": "eventbridge"},
                          owner=principal.username)
    auth.audit("guardduty_submit", principal, job_id=job_id,
               finding_type=norm.get("type"), severity=norm.get("severity"),
               source_ip=(request.client.host if request.client else None))
    return JSONResponse({"report_id": job_id, "status": "queued",
                         "finding_type": norm.get("type"),
                         "status_url": f"/api/webhook/guardduty/{job_id}"})


@app.get("/api/webhook/guardduty/{report_id}")
async def api_guardduty_status(report_id: str, request: Request,
                               principal: auth.Principal = Depends(get_principal)):
    """Poll the GuardDuty pipeline result (verdict, case refs, containment approvals)."""
    require_perm(principal, "guardduty:read", request)
    job = jobs.get_job(report_id)
    if not job or job.get("kind") != "guardduty":
        return JSONResponse({"error": "not found"}, status_code=404)
    if job["status"] in ("complete", "error"):
        return JSONResponse({"status": job["status"], "result": job.get("result")})
    return JSONResponse({"status": job["status"], "report_id": report_id})


# ---------------------------------------------------------------------------
# Task control plane — assign any registered task type (detection engineering,
# threat intel, DFIR, cloud posture, ...) and poll for the result.
# Access is gated by phantom/auth.py: callers present `Authorization: Bearer
# <token>`, roles grant task types, reads are scoped to the caller's own tasks
# unless their role has can_read_all, and every action is written to the audit
# log. Secure by default — unconfigured auth refuses these routes (503) unless
# PHANTOM_AUTH_ALLOW_ANONYMOUS=1 (read-only). See auth.py for setup.
# ---------------------------------------------------------------------------
class TaskRequest(BaseModel):
    task_type: str                       # e.g. "detection-engineering", "threat-intelligence", "dfir-forensics"
    objective: str                       # what to do, in plain language
    technique: str = ""                  # detection-engineering: ATT&CK id (optional)
    indicators: list | None = None       # threat-intelligence: [["ip","1.2.3.4"], ...] (optional)
    context: str = ""                    # any extra context for the agent


def _task_job(task_id: str, principal: auth.Principal):
    """Fetch a 'task'-kind job and enforce ownership; returns (job, error_response)."""
    job = jobs.get_job(task_id)
    if not job or job.get("kind") != "task":
        return None, JSONResponse({"error": "not found"}, status_code=404)
    if not (auth.can_read_all(principal) or job.get("owner") == principal.username):
        raise HTTPException(status_code=403, detail="not your task")
    return job, None


@app.get("/api/tasks/types")
async def api_task_types(principal: auth.Principal = Depends(get_principal)):
    """List task types, annotated with whether THIS caller may submit each."""
    types = list_task_types()
    for t in types:
        t["allowed"] = auth.can_submit(principal, t["name"])
    return JSONResponse({"task_types": types, "you": {"username": principal.username,
                         "roles": principal.roles, "can_read_all": auth.can_read_all(principal)}})


@app.post("/api/tasks")
async def api_submit_task(req: TaskRequest, request: Request,
                          principal: auth.Principal = Depends(get_principal)):
    """Assign a task. Requires a role that grants this task type. Enqueued to a worker."""
    known = {t["name"] for t in list_task_types()}
    if req.task_type not in known:
        return JSONResponse({"error": f"unknown task_type '{req.task_type}'",
                             "available": sorted(known)}, status_code=422)
    if not req.objective.strip():
        return JSONResponse({"error": "objective is required"}, status_code=400)
    try:
        auth.require_submit(principal, req.task_type)
    except auth.AuthError as e:
        auth.audit("task_denied", principal, task_type=req.task_type, detail=e.detail,
                   source_ip=(request.client.host if request.client else None))
        raise HTTPException(status_code=e.status, detail=e.detail)

    kwargs = {"context": req.context}
    if req.technique:
        kwargs["technique"] = req.technique
    if req.indicators:
        kwargs["indicators"] = req.indicators
    job_id = jobs.enqueue("task",
                          {"task_type": req.task_type, "objective": req.objective, "kwargs": kwargs},
                          owner=principal.username)
    auth.audit("task_submit", principal, job_id=job_id, task_type=req.task_type,
               objective=req.objective[:200],
               source_ip=(request.client.host if request.client else None))
    return JSONResponse({"task_id": job_id, "task_type": req.task_type, "status": "queued",
                         "assigned_by": principal.username, "status_url": f"/api/tasks/{job_id}"})


@app.get("/api/tasks")
async def api_list_tasks(principal: auth.Principal = Depends(get_principal)):
    """List assigned tasks — all of them for can_read_all roles, else only your own."""
    owner = None if auth.can_read_all(principal) else principal.username
    tasks = [{"task_id": j["job_id"], "status": j["status"], "owner": j.get("owner"),
              "task_type": (j.get("payload") or {}).get("task_type")}
             for j in jobs.list_jobs(owner=owner) if j.get("kind") == "task"]
    return JSONResponse({"tasks": tasks[:100]})


@app.get("/api/tasks/{task_id}")
async def api_task_status(task_id: str, principal: auth.Principal = Depends(get_principal)):
    """Poll a task's status/result. You can only read your own tasks unless can_read_all."""
    job, err = _task_job(task_id, principal)
    if err:
        return err
    result = job.get("result")
    if job["status"] in ("complete", "error") and isinstance(result, dict):
        slim = {k: v for k, v in result.items() if k != "report_markdown"}
        return JSONResponse({"status": job["status"], "result": slim})
    return JSONResponse({"status": job["status"], "task_id": task_id})


@app.get("/api/tasks/{task_id}/report")
async def api_task_report(task_id: str, principal: auth.Principal = Depends(get_principal)):
    """Fetch the full Markdown report. Ownership-scoped like the status route."""
    job, err = _task_job(task_id, principal)
    if err:
        return err
    result = job.get("result")
    if not isinstance(result, dict):
        return JSONResponse({"error": "still running"}, status_code=409)
    md = result.get("report_markdown", "")
    if not md:
        return JSONResponse({"error": "no report produced", "result": {
            k: v for k, v in result.items() if k != "report_markdown"}}, status_code=200)
    return HTMLResponse(f"<pre>{_html_escape(md)}</pre>")


@app.get("/api/queue/health")
async def api_queue_health(principal: auth.Principal = Depends(get_principal)):
    """Report the active queue backend (local vs redis) — useful post-deploy."""
    return JSONResponse({"backend": jobs.backend_kind()})


def _html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
