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

from fastapi import FastAPI, Query, Request
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
# API routes
# ---------------------------------------------------------------------------
@app.post("/api/chat")
async def api_chat(req: ChatRequest):
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
async def api_sessions():
    return JSONResponse({"sessions": list_sessions()})


@app.post("/api/sessions/{name}/save")
async def api_save(name: str, request: Request):
    body = await request.json()
    s = _sessions.get(body.get("session_id",""), {})
    path = save_session(s.get("messages",[]), s.get("mode","general"), name)
    return JSONResponse({"saved": True, "path": str(path)})


@app.post("/api/sessions/{name}/load")
async def api_load(name: str):
    result = load_session(name)
    if result is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    messages, mode = result
    sid = str(uuid.uuid4())
    _sessions[sid] = {"messages": messages, "mode": mode}
    return JSONResponse({"session_id": sid, "mode": mode, "message_count": len(messages)})


@app.get("/api/approvals")
async def api_approvals(status: str | None = Query(None)):
    return JSONResponse({"approvals": list_approvals(status=status), "pending_count": pending_count()})


@app.post("/api/approvals/{aid}/decide")
async def api_decide(aid: str, request: Request):
    body = await request.json()
    decision   = body.get("decision")
    decided_by = body.get("decided_by", "web-ui")
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
async def api_investigate_phishing(req: PhishingRequest):
    """
    Accept a raw email and run autonomous phishing investigation.
    Blocks until investigation completes (typically 30–90 seconds).
    Called by the AWS Lambda function after SES delivers an email to S3.
    """
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
async def api_list_investigations(limit: int = Query(default=50, le=200)):
    """List recent phishing investigations (no report bodies)."""
    return JSONResponse({"investigations": list_results(limit)})


@app.get("/api/investigate/phishing/{report_id}")
async def api_get_investigation(report_id: str):
    """Get full investigation result including the Markdown report."""
    result = get_result(report_id)
    if result is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(result)


@app.get("/api/investigate/phishing/{report_id}/report")
async def api_get_report_markdown(report_id: str):
    """Return the raw Markdown investigation report."""
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

# Background investigation status store (report_id → "investigating" | verdict)
_WEBHOOK_STATUS: dict[str, str] = {}
# Deduplication: content hash → report_id (prevents re-investigating same email)
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


async def _investigate_in_background(raw_email: str, reported_by: str, report_id: str):
    """Run investigation in a background thread; update status when done."""
    try:
        result = await asyncio.to_thread(investigate_phishing, raw_email, reported_by, report_id)
        _WEBHOOK_STATUS[report_id] = result.get("verdict", "complete")
    except Exception as e:
        _WEBHOOK_STATUS[report_id] = f"error: {e}"


@app.post("/api/webhook/phishing-report")
async def api_killphish_webhook(req: KillPhishRequest):
    """
    Universal Kill Phish webhook — called by Gmail add-on, Outlook add-in,
    or any email security tool. Returns immediately; investigation runs async.

    Accepts raw EML, base64-encoded EML, or structured JSON fields.
    Deduplicates by Message-ID and content hash to avoid re-investigating
    the same email submitted from multiple clients simultaneously.
    """
    raw_email = _normalise_email(req)
    if not raw_email.strip():
        return JSONResponse({"error": "No email content provided."}, status_code=400)

    # Deduplicate by Message-ID header
    dedup_key = req.message_id or req.gmail_message_id or ""
    if not dedup_key:
        dedup_key = _hashlib.sha256(raw_email[:2000].encode()).hexdigest()[:16]

    if dedup_key in _SEEN_HASHES:
        existing_id = _SEEN_HASHES[dedup_key]
        return JSONResponse({
            "report_id":   existing_id,
            "status":      _WEBHOOK_STATUS.get(existing_id, "investigating"),
            "deduplicated": True,
            "message":     "This email was already reported. Check your inbox for results.",
            "status_url":  f"/api/webhook/phishing-report/{existing_id}",
        })

    # Generate report ID
    report_id = req.report_id or f"phi-{uuid.uuid4().hex[:10]}"
    _SEEN_HASHES[dedup_key] = report_id
    _WEBHOOK_STATUS[report_id] = "investigating"

    # Fire investigation in background — do not await
    asyncio.create_task(
        _investigate_in_background(raw_email, req.reported_by, report_id)
    )

    return JSONResponse({
        "report_id":  report_id,
        "status":     "investigating",
        "source":     req.source,
        "message":    "Received. Phantom is investigating — we'll email you the verdict.",
        "status_url": f"/api/webhook/phishing-report/{report_id}",
    })


@app.get("/api/webhook/phishing-report/{report_id}")
async def api_killphish_status(report_id: str):
    """Poll investigation status. Used by add-ins that want to show live results."""
    status = _WEBHOOK_STATUS.get(report_id)
    if status is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    result = get_result(report_id)
    if result:
        slim = {k: v for k, v in result.items() if k != "report_markdown"}
        return JSONResponse({"status": "complete", "result": slim})
    return JSONResponse({"status": status, "report_id": report_id})
