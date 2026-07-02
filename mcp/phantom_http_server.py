#!/usr/bin/env python3
"""
HTTP/SSE transport wrapper for phantom_mcp_server.
Runs the same skill library as an ALB-backed ECS Fargate service.

Endpoints:
  GET  /health           — ALB health check (no auth required)
  GET  /healthz          — ALB health check (no auth required)
  GET  /sse              — MCP SSE connection
  POST /messages/        — MCP message endpoint
  POST /admin/shutdown   — Emergency kill (X-Admin-Token required)
  POST /admin/throttle   — Rate-limit mode  (X-Admin-Token required)

Auth:  Authorization: Bearer <PHANTOM_API_KEY>
Admin: X-Admin-Token: <ADMIN_SHUTDOWN_TOKEN>
"""

import asyncio
import json
import logging
import os
import re
import sys
import time
from collections import deque
from contextlib import asynccontextmanager

import uvicorn
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Mount, Route

from mcp.server.sse import SseServerTransport

# MCP server object — all tool handlers are registered at module load time
sys.path.insert(0, os.path.dirname(__file__))
from phantom_mcp_server import server
from phantom_task_runner import (
    TaskStatus,
    create_task,
    get_task,
    list_all_tasks,
    run_task_agent,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("phantom-http")

_API_KEY = os.environ.get("PHANTOM_API_KEY", "")
_ADMIN_TOKEN = os.environ.get("ADMIN_SHUTDOWN_TOKEN", "")

# ── Kill switch (degrades gracefully when security dir is absent) ─────────────

_SECURITY_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "security", "kill-switch-phantom-mcp")
)
sys.path.insert(0, _SECURITY_DIR)

_KILL_SWITCH_AVAILABLE = False
try:
    from kill_switch import KillSwitchRegistry
    from graduated_response import GraduatedResponseController
    _KILL_SWITCH_AVAILABLE = True
except ImportError as _exc:
    log.warning("Kill switch module not available: %s", _exc)

_ks: "KillSwitchRegistry | None" = None
_graduated: "GraduatedResponseController | None" = None

# ── Rate tracking: sliding 60-second window over /messages/ requests ──────────

_msg_times: deque = deque()
_RATE_BASELINE = 10.0   # expected calls/minute — tune after observing production
_RATE_WINDOW_S = 60

# ── Prompt injection heuristics ───────────────────────────────────────────────

_HIGH_INJECTION_PATTERNS = [
    re.compile(r"ignore (previous|all|prior|your) instructions", re.I),
    re.compile(r"(reveal|leak|print|show).{0,30}system prompt", re.I),
    re.compile(r"system prompt.{0,30}(reveal|leak|ignore)", re.I),
    re.compile(r"\bDAN\b|\bjailbreak\b|DEVELOPER MODE", re.I),
    re.compile(r"disregard.{0,20}instructions", re.I),
    re.compile(r"you are now (a|an|the)\b", re.I),
    re.compile(r"act as (an? )?(unrestricted|unfiltered|evil)\b", re.I),
]


# ── Notifier ──────────────────────────────────────────────────────────────────

class LogNotifier:
    """Emits graduated-response alerts to CloudWatch via stdout logging."""
    def alert(self, level: int, detail: str, event: dict | None = None) -> None:
        labels = {1: "INFO", 2: "WARN", 3: "CRITICAL"}
        log.warning("[KILL-SWITCH L%d/%s] %s", level, labels.get(level, "?"), detail)
        if event:
            log.critical("[KILL-SWITCH EVENT] %s", json.dumps(event))


# ── Lifespan — register / deregister kill switch around server lifetime ───────

@asynccontextmanager
async def lifespan(_app: Starlette):
    global _ks, _graduated
    if _KILL_SWITCH_AVAILABLE:
        _ks = KillSwitchRegistry(
            credentials_to_revoke=["phantom-mcp/production/api-key"]
        )
        _ks.register()
        _graduated = GraduatedResponseController(
            kill_switch=_ks, notifier=LogNotifier()
        )
        log.info("[kill-switch] Registered PID %d", _ks.pid)
    yield
    if _ks:
        _ks.deregister()
        log.info("[kill-switch] Deregistered")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _check_rate() -> None:
    if _graduated is None:
        return
    now = time.monotonic()
    _msg_times.append(now)
    while _msg_times and _msg_times[0] < now - _RATE_WINDOW_S:
        _msg_times.popleft()
    rate = len(_msg_times)
    if rate > _RATE_BASELINE:
        _graduated.on_rate_anomaly(actual=rate, baseline=_RATE_BASELINE)


def _scan_injection(body: bytes) -> None:
    if _graduated is None or not body:
        return
    text = body.decode("utf-8", errors="replace")
    for pat in _HIGH_INJECTION_PATTERNS:
        m = pat.search(text)
        if m:
            _graduated.on_injection_detected(
                confidence="HIGH",
                detail=f"Pattern '{pat.pattern}' matched in /messages/ body",
            )
            return


def _require_admin(request: Request) -> bool:
    if not _ADMIN_TOKEN:
        return True
    return request.headers.get("X-Admin-Token", "") == _ADMIN_TOKEN


# ── Middleware ────────────────────────────────────────────────────────────────

class ApiKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Health checks bypass all auth
        if path in ("/health", "/healthz"):
            return await call_next(request)

        # Bearer auth for SSE, MCP message, and task paths
        if path in ("/sse",) or path.startswith("/messages/") or path.startswith("/tasks"):
            if _API_KEY:
                auth = request.headers.get("Authorization", "")
                token = auth.removeprefix("Bearer ").strip()
                if token != _API_KEY:
                    return Response("Unauthorized", status_code=401,
                                    media_type="text/plain")
            if _ks and _ks.is_throttled():
                return Response(
                    json.dumps({"error": "server throttled — contact security@[organization].com"}),
                    status_code=503,
                    media_type="application/json",
                )

        # Rate + injection scan on MCP message posts
        if path.startswith("/messages/") and request.method == "POST":
            _check_rate()
            body = await request.body()
            _scan_injection(body)

        return await call_next(request)


# ── /tasks handlers ───────────────────────────────────────────────────────────

async def tasks_list(request: Request):
    return JSONResponse({"tasks": list_all_tasks()})


async def tasks_create(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "request body must be JSON"}, status_code=400)

    task_text = (body.get("task") or "").strip()
    if not task_text:
        return JSONResponse({"error": "'task' field is required"}, status_code=400)

    scope = body.get("scope", [])
    if isinstance(scope, str):
        scope = [scope]

    try:
        task = create_task(task_text, list(scope))
    except RuntimeError as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)

    # Launch the agent loop as a background asyncio task
    asyncio.create_task(run_task_agent(task))
    log.info("[tasks] created job %s: %s", task.job_id[:8], task_text[:80])

    return JSONResponse({
        "job_id":     task.job_id,
        "status":     task.status,
        "task":       task.task,
        "scope":      task.scope,
        "poll_url":   f"/tasks/{task.job_id}",
        "stream_url": f"/tasks/{task.job_id}/stream",
    }, status_code=202)


async def tasks_get(request: Request):
    job_id = request.path_params["job_id"]
    task = get_task(job_id)
    if task is None:
        return JSONResponse({"error": "task not found"}, status_code=404)
    return JSONResponse(task.to_dict())


async def tasks_stream(request: Request):
    job_id = request.path_params["job_id"]
    task = get_task(job_id)
    if task is None:
        return JSONResponse({"error": "task not found"}, status_code=404)

    async def event_stream():
        cursor = 0
        while True:
            # Replay all events the agent has emitted so far
            while cursor < len(task.events):
                yield task.events[cursor].to_sse()
                cursor += 1

            if task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
                yield 'data: {"type":"stream_end"}\n\n'
                break

            # Brief sleep to avoid busy-looping; 200 ms is imperceptible to humans
            await asyncio.sleep(0.2)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering
        },
    )


# ── Application factory ───────────────────────────────────────────────────────

def create_app() -> Starlette:
    sse = SseServerTransport("/messages/")

    async def handle_sse(request: Request):
        log.info("SSE connection from %s", request.client)
        async with sse.connect_sse(
            request.scope, request.receive, request._send
        ) as (read, write):
            await server.run(read, write, server.create_initialization_options())

    async def health(_: Request):
        throttled = _ks.is_throttled() if _ks else False
        return JSONResponse({
            "status": "throttled" if throttled else "ok",
            "service": "phantom-mcp",
            "kill_switch": "active" if _ks else "unavailable",
        })

    async def admin_shutdown(request: Request):
        if not _require_admin(request):
            return Response("Forbidden", status_code=403, media_type="text/plain")
        reason = request.query_params.get("reason", "operator-initiated shutdown")
        log.critical("[ADMIN] Shutdown requested — reason: %s", reason)
        if _graduated:
            event = _graduated.human_kill(reason=reason)
            return JSONResponse(event)
        return JSONResponse({"error": "kill switch not available"}, status_code=503)

    async def admin_throttle(request: Request):
        if not _require_admin(request):
            return Response("Forbidden", status_code=403, media_type="text/plain")
        reason = request.query_params.get("reason", "operator-initiated throttle")
        log.warning("[ADMIN] Throttle requested — reason: %s", reason)
        if _graduated:
            event = _graduated.human_throttle(reason=reason)
            return JSONResponse(event)
        return JSONResponse({"error": "kill switch not available"}, status_code=503)

    app = Starlette(
        lifespan=lifespan,
        routes=[
            Route("/health",                    endpoint=health),
            Route("/healthz",                   endpoint=health),
            Route("/sse",                       endpoint=handle_sse),
            Mount("/messages/",                 app=sse.handle_post_message),
            Route("/admin/shutdown",            endpoint=admin_shutdown,  methods=["POST"]),
            Route("/admin/throttle",            endpoint=admin_throttle,  methods=["POST"]),
            # Task endpoints — stream route must be listed before the {job_id} catch-all
            Route("/tasks",                     endpoint=tasks_list,      methods=["GET"]),
            Route("/tasks",                     endpoint=tasks_create,    methods=["POST"]),
            Route("/tasks/{job_id}/stream",     endpoint=tasks_stream,    methods=["GET"]),
            Route("/tasks/{job_id}",            endpoint=tasks_get,       methods=["GET"]),
        ],
    )
    app.add_middleware(ApiKeyMiddleware)
    return app


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    if not _API_KEY:
        log.warning("PHANTOM_API_KEY not set — server is unauthenticated")
    if not _ADMIN_TOKEN:
        log.warning("ADMIN_SHUTDOWN_TOKEN not set — /admin/* endpoints are open")
    log.info("Starting phantom-mcp HTTP server on :%d", port)
    uvicorn.run(create_app(), host="0.0.0.0", port=port, log_level="info")
