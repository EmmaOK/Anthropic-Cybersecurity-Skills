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
    return templates.TemplateResponse("chat.html", {
        "request": request,
        "modes": list(PERSONAS.keys()),
        "pending_approvals": pending_count(),
    })


@app.get("/approvals", response_class=HTMLResponse)
async def approvals_page(request: Request):
    pending = list_approvals(status="pending")
    history = [a for a in list_approvals() if a["status"] != "pending"][:20]
    return templates.TemplateResponse("approvals.html", {
        "request": request, "pending": pending, "history": history,
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
    return templates.TemplateResponse("approval_result.html",
        {"request": request, "decision": "approved", "approval": a,
         "modes": list(PERSONAS.keys()), "pending_approvals": pending_count()})


@app.get("/approvals/{aid}/deny", response_class=HTMLResponse)
async def deny_link(request: Request, aid: str, token: str = Query(...)):
    if not verify_token(aid, "denied", token):
        return HTMLResponse("<h2 style='font-family:sans-serif;color:#da3633'>Invalid or expired link.</h2>", 403)
    a = decide_approval(aid, "denied", "google-chat")
    if not a:
        return HTMLResponse("<h2 style='font-family:sans-serif'>Approval not found.</h2>", 404)
    return templates.TemplateResponse("approval_result.html",
        {"request": request, "decision": "denied", "approval": a,
         "modes": list(PERSONAS.keys()), "pending_approvals": pending_count()})
