#!/usr/bin/env python3
"""
Emergency kill script for phantom-mcp.
Pre-written for runbook use — do NOT modify during an incident.

Usage:
    # Throttle (reversible — returns 503 to MCP clients)
    ADMIN_SHUTDOWN_TOKEN=<token> python kill_agent.py --throttle --reason "..."

    # Full kill (rotates API key + SIGTERM — requires redeploy to recover)
    ADMIN_SHUTDOWN_TOKEN=<token> python kill_agent.py --reason "..."

    # Fleet-wide halt (scales ECS service to 0 — fastest way to stop all tasks)
    python kill_agent.py --fleet --reason "..."

    # Dry-run (prints what would happen, no action taken)
    python kill_agent.py [--throttle] [--fleet] --reason "..." --dry-run

Environment:
    ADMIN_SHUTDOWN_TOKEN  — required for --throttle / kill actions
    KILL_REGISTRY_PATH    — override registry path (default: /tmp/phantom-mcp-kill-registry.json)
    AWS_PROFILE           — AWS profile for --fleet (default: AdministratorAccess-[AWS-ACCOUNT-ID])
"""
import argparse
import datetime
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REGISTRY_PATH = Path(os.environ.get("KILL_REGISTRY_PATH",
                                    "/tmp/phantom-mcp-kill-registry.json"))
ECS_CLUSTER  = os.environ.get("ECS_CLUSTER",  "phantom-mcp-production")
ECS_SERVICE  = os.environ.get("ECS_SERVICE",  "phantom-mcp-production")
AWS_REGION   = os.environ.get("AWS_REGION",   "us-east-1")
AWS_PROFILE  = os.environ.get("AWS_PROFILE",  "AdministratorAccess-[AWS-ACCOUNT-ID]")


def _ts() -> str:
    return datetime.datetime.utcnow().isoformat()


def fleet_halt(reason: str, dry_run: bool) -> None:
    """Scale the ECS service to 0 tasks — halts the entire fleet immediately."""
    print(f"[{_ts()}] FLEET HALT — scaling {ECS_CLUSTER}/{ECS_SERVICE} to 0")
    print(f"Reason : {reason}")
    if dry_run:
        print("[DRY RUN] No action taken.")
        return

    t0 = time.monotonic()
    try:
        import boto3
        ecs = boto3.client("ecs", region_name=AWS_REGION)
        ecs.update_service(
            cluster=ECS_CLUSTER,
            service=ECS_SERVICE,
            desiredCount=0,
        )
    except ImportError:
        # boto3 not available — fall back to AWS CLI
        cmd = [
            "aws", "ecs", "update-service",
            "--cluster", ECS_CLUSTER,
            "--service", ECS_SERVICE,
            "--desired-count", "0",
            "--region", AWS_REGION,
            "--profile", AWS_PROFILE,
            "--output", "text",
            "--query", "service.desiredCount",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"ERROR: AWS CLI fleet halt failed: {result.stderr}", file=sys.stderr)
            sys.exit(1)

    elapsed = time.monotonic() - t0
    print(f"Fleet halt issued in {elapsed:.2f}s")
    print(f"\nVerify: aws ecs list-tasks --cluster {ECS_CLUSTER} --desired-status RUNNING "
          f"--region {AWS_REGION}  # should return empty task list after ~60s")
    print(f"Restore: aws ecs update-service --cluster {ECS_CLUSTER} --service {ECS_SERVICE} "
          f"--desired-count 2 --force-new-deployment --region {AWS_REGION}")


def main():
    parser = argparse.ArgumentParser(
        description="Emergency kill / throttle / fleet-halt for phantom-mcp"
    )
    parser.add_argument("--reason", required=True, help="Human-readable reason for the action")
    parser.add_argument("--throttle", action="store_true",
                        help="Throttle only (reversible) — does not rotate credentials")
    parser.add_argument("--fleet", action="store_true",
                        help="Fleet-wide halt: scale ECS service to 0 tasks")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would happen without taking any action")
    args = parser.parse_args()

    # --fleet is independent of registry — acts on the ECS service directly
    if args.fleet:
        fleet_halt(args.reason, args.dry_run)
        return

    # Per-agent kill/throttle — requires the registry file (written by the running agent)
    if not REGISTRY_PATH.exists():
        print(f"ERROR: Registry not found at {REGISTRY_PATH}", file=sys.stderr)
        print("       Is the agent running? Has KILL_REGISTRY_PATH been set correctly?",
              file=sys.stderr)
        sys.exit(1)

    registry = json.loads(REGISTRY_PATH.read_text())
    pid      = registry["pid"]
    endpoint = registry.get("shutdown_endpoint", "http://localhost:8080/admin/shutdown")
    token    = os.environ.get("ADMIN_SHUTDOWN_TOKEN", "")

    action_label = "THROTTLE" if args.throttle else "KILL"
    print(f"[{_ts()}] Targeting phantom-mcp (PID {pid})")
    print(f"Reason : {args.reason}")
    print(f"Action : {action_label}")

    if args.dry_run:
        print("[DRY RUN] No action taken.")
        return

    t0 = time.monotonic()
    action = "throttle" if args.throttle else "shutdown"
    url = endpoint.replace("/shutdown", f"/{action}") + f"?reason={args.reason}"
    req = urllib.request.Request(url, method="POST", headers={"X-Admin-Token": token})
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        body = json.loads(resp.read().decode())
        elapsed = time.monotonic() - t0
        print(f"HTTP {action} completed in {elapsed:.3f}s")
        print(f"Response: {json.dumps(body, indent=2)}")
    except Exception as exc:
        elapsed = time.monotonic() - t0
        print(f"HTTP endpoint failed after {elapsed:.3f}s ({exc}), falling back to SIGTERM",
              file=sys.stderr)
        if not args.throttle:
            try:
                os.kill(pid, signal.SIGTERM)
                print(f"SIGTERM sent to PID {pid}")
            except ProcessLookupError:
                print(f"PID {pid} not found — agent may have already exited")

    print(f"\nVerify: ps aux | grep {pid}")
    print(f"Verify: ls {REGISTRY_PATH}  # should be absent after kill")


if __name__ == "__main__":
    main()
