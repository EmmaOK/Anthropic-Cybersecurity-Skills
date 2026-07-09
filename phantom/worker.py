#!/usr/bin/env python3
"""
phantom/worker.py — executes queued Phantom jobs (the "execution plane").

`execute_job(job)` maps a job kind to the real work and returns its result.
The same function is used by:
  - the LOCAL backend's in-process worker threads (jobs.py), and
  - this module's `run_worker()` blocking loop for the REDIS backend.

Run standalone workers only when the queue is Redis-backed:
    REDIS_URL=redis://redis:6379/0 python phantom/worker.py
In local mode the API auto-runs in-process workers, so this is a no-op there.

Handlers import their target modules lazily so the worker starts fast and a
missing optional dependency only affects the job kind that needs it.
"""
from __future__ import annotations

import sys

import jobs

# Job kinds this worker can execute. Keep in sync with what server.py enqueues.
KINDS = ("task", "phishing_investigate", "phishing_pipeline", "guardduty", "echo")


def execute_job(job: dict) -> dict:
    """Dispatch a job to its handler. Returns the handler's result dict."""
    kind = job.get("kind")
    p = job.get("payload") or {}

    if kind == "echo":                                   # health / smoke test
        return {"echo": p}

    if kind == "task":
        from task_agent import run_task
        return run_task(p["task_type"], p["objective"], **(p.get("kwargs") or {}))

    if kind == "phishing_investigate":            # Kill-Phish add-in: triage only
        from phishing import investigate_phishing
        return investigate_phishing(p["raw_email"], p.get("reported_by", ""))

    if kind == "phishing_pipeline":
        from phishingbox_intake import run_pipeline
        return run_pipeline(p["raw_email"], p.get("reporter", ""), p.get("source", "intake"))

    if kind == "guardduty":
        from guardduty_intake import run_pipeline as run_gd
        return run_gd(p["finding"], p.get("source", "eventbridge"))

    return {"error": f"unknown job kind '{kind}'"}


def run_worker(poll_timeout: int = 5) -> None:
    """Blocking dequeue→execute loop for the Redis backend."""
    if jobs.backend_kind() == "local":
        print("[worker] local backend auto-runs in-process workers — a standalone "
              "worker is only needed with REDIS_URL set. Nothing to do.", flush=True)
        return
    print(f"[worker] started (backend={jobs.backend_kind()}); kinds={KINDS}", flush=True)
    while True:
        job = jobs.fetch(timeout=poll_timeout)
        if not job:
            continue
        jobs.set_status(job["job_id"], "running")
        print(f"[worker] {job['job_id']} kind={job.get('kind')} owner={job.get('owner')}", flush=True)
        try:
            result = execute_job(job)
            status = "error" if isinstance(result, dict) and result.get("error") else "complete"
            jobs.set_result(job["job_id"], status, result)
        except Exception as e:  # noqa: BLE001 — one bad job must not kill the worker
            jobs.set_result(job["job_id"], "error", {"error": str(e)})
            print(f"[worker] {job['job_id']} failed: {e}", flush=True)


if __name__ == "__main__":
    try:
        run_worker()
    except KeyboardInterrupt:
        sys.exit(0)
