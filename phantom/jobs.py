#!/usr/bin/env python3
"""
phantom/jobs.py — job queue + result store for the API/worker split.

The API (server.py) enqueues long-running work (agent tasks, IR pipelines) and
returns immediately; workers execute it. Two interchangeable backends, chosen at
runtime so the same code runs on a laptop and in a cluster:

  LOCAL  (default) — an in-process queue.Queue + dict store, with worker THREADS
                     started lazily inside the API process. Zero dependencies;
                     behaves like the old asyncio.create_task path, just decoupled.
  REDIS            — jobs + results live in Redis; the API only enqueues and the
                     worker(s) run as separate processes (`python phantom/worker.py`).
                     Enables horizontal scaling and survives an API restart.

Selection (env):
  PHANTOM_QUEUE_BACKEND = auto | local | redis      (default: auto)
  REDIS_URL             = redis://host:6379/0        (auto ⇒ redis when set)
  PHANTOM_LOCAL_WORKERS = N in-process worker threads (default: 2)

A job:  {job_id, kind, payload, owner, status, result, created_at, updated_at}
        status ∈ queued | running | complete | error
Job kinds are executed by worker.execute_job (task | phishing_pipeline | guardduty | echo).

Public API:
  enqueue(kind, payload, owner="") -> job_id
  get_job(job_id) -> dict | None
  list_jobs(owner=None, limit=200) -> list
  fetch(timeout=5) -> job | None      # workers only (redis mode)
  set_status(job_id, status) / set_result(job_id, status, result)   # workers only
  backend_kind() -> "local" | "redis"
"""
from __future__ import annotations

import json
import os
import queue
import threading
import uuid
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_job(kind: str, payload: dict, owner: str) -> dict:
    return {"job_id": f"job-{uuid.uuid4().hex[:12]}", "kind": kind, "payload": payload,
            "owner": owner, "status": "queued", "result": None,
            "created_at": _now(), "updated_at": _now()}


# ── Local (in-process) backend ───────────────────────────────────────────────

class LocalBackend:
    kind = "local"

    def __init__(self):
        self._q: queue.Queue = queue.Queue()
        self._store: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._started = False
        self._n = max(1, int(os.environ.get("PHANTOM_LOCAL_WORKERS", "2") or 2))

    def enqueue(self, job: dict) -> None:
        with self._lock:
            self._store[job["job_id"]] = job
        self._q.put(job["job_id"])
        self._ensure_workers()

    def _ensure_workers(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
        for i in range(self._n):
            threading.Thread(target=self._loop, name=f"phantom-worker-{i}", daemon=True).start()

    def _loop(self) -> None:
        while True:
            job_id = self._q.get()
            self.set_status(job_id, "running")
            try:
                import worker  # lazy — avoids import cycle (worker imports jobs)
                result = worker.execute_job(self.get(job_id))
                status = "error" if isinstance(result, dict) and result.get("error") else "complete"
                self.set_result(job_id, status, result)
            except Exception as e:  # noqa: BLE001
                self.set_result(job_id, "error", {"error": str(e)})
            finally:
                self._q.task_done()

    def fetch(self, timeout: int = 5):
        try:
            return self.get(self._q.get(timeout=timeout))
        except queue.Empty:
            return None

    def get(self, job_id: str):
        with self._lock:
            j = self._store.get(job_id)
            return dict(j) if j else None

    def set_status(self, job_id: str, status: str) -> None:
        with self._lock:
            if job_id in self._store:
                self._store[job_id]["status"] = status
                self._store[job_id]["updated_at"] = _now()

    def set_result(self, job_id: str, status: str, result) -> None:
        with self._lock:
            if job_id in self._store:
                self._store[job_id].update(status=status, result=result, updated_at=_now())

    def list(self, owner=None, limit: int = 200):
        with self._lock:
            js = [dict(j) for j in self._store.values()]
        js.sort(key=lambda j: j["created_at"], reverse=True)
        if owner is not None:
            js = [j for j in js if j.get("owner") == owner]
        return js[:limit]


# ── Redis backend ────────────────────────────────────────────────────────────

class RedisBackend:
    kind = "redis"
    QUEUE = "phantom:jobs:queue"
    INDEX = "phantom:jobs:index"

    def __init__(self, url: str):
        import redis  # optional dependency
        self._r = redis.Redis.from_url(url, decode_responses=True)
        self._r.ping()

    def _k(self, job_id: str) -> str:
        return f"phantom:job:{job_id}"

    def _save(self, job: dict) -> None:
        self._r.set(self._k(job["job_id"]), json.dumps(job))

    def enqueue(self, job: dict) -> None:
        self._save(job)
        self._r.lpush(self.INDEX, job["job_id"])
        self._r.ltrim(self.INDEX, 0, 999)
        self._r.lpush(self.QUEUE, job["job_id"])

    def fetch(self, timeout: int = 5):
        res = self._r.brpop(self.QUEUE, timeout=timeout)
        return self.get(res[1]) if res else None

    def get(self, job_id: str):
        raw = self._r.get(self._k(job_id))
        return json.loads(raw) if raw else None

    def set_status(self, job_id: str, status: str) -> None:
        j = self.get(job_id)
        if j:
            j["status"] = status
            j["updated_at"] = _now()
            self._save(j)

    def set_result(self, job_id: str, status: str, result) -> None:
        j = self.get(job_id)
        if j:
            j.update(status=status, result=result, updated_at=_now())
            self._save(j)

    def list(self, owner=None, limit: int = 200):
        ids = self._r.lrange(self.INDEX, 0, limit - 1)
        js = [j for j in (self.get(i) for i in ids) if j]
        if owner is not None:
            js = [j for j in js if j.get("owner") == owner]
        return js


# ── Backend selection + public API ───────────────────────────────────────────

_BACKEND = None
_BACKEND_LOCK = threading.Lock()


def _backend():
    global _BACKEND
    if _BACKEND is None:
        with _BACKEND_LOCK:
            if _BACKEND is None:
                url = os.environ.get("REDIS_URL", "")
                want = os.environ.get("PHANTOM_QUEUE_BACKEND", "auto").lower()
                if want == "redis" or (want == "auto" and url):
                    try:
                        _BACKEND = RedisBackend(url or "redis://localhost:6379/0")
                        print("[jobs] backend=redis", flush=True)
                    except Exception as e:  # noqa: BLE001 — fall back rather than fail startup
                        print(f"[jobs] redis unavailable ({e}); backend=local", flush=True)
                        _BACKEND = LocalBackend()
                else:
                    _BACKEND = LocalBackend()
    return _BACKEND


def _reset():  # test hook — force re-selection after changing env
    global _BACKEND
    _BACKEND = None


def backend_kind() -> str:
    return _backend().kind


def enqueue(kind: str, payload: dict, owner: str = "") -> str:
    job = _new_job(kind, payload, owner)
    _backend().enqueue(job)
    return job["job_id"]


def get_job(job_id: str):
    return _backend().get(job_id)


def list_jobs(owner=None, limit: int = 200):
    return _backend().list(owner, limit)


def fetch(timeout: int = 5):
    return _backend().fetch(timeout)


def set_status(job_id: str, status: str) -> None:
    _backend().set_status(job_id, status)


def set_result(job_id: str, status: str, result) -> None:
    _backend().set_result(job_id, status, result)
