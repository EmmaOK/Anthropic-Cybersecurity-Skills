---
name: ai-agent-kill-switch-and-graduated-response
description: >-
  Implements a graduated containment response system for AI agents that escalates
  through three levels — alert, throttle, terminate — before triggering a kill
  switch. Addresses the core trade-off of autonomous kill switches: full autonomy
  risks false-positive termination of legitimate agent sessions; no autonomy leaves
  a gap when no human is available. The graduated model closes that gap by reserving
  autonomous termination for cases where two independent high-confidence signals fire
  simultaneously, while throttling (pausing new tool calls without killing the process)
  acts as the safer autonomous containment at Level 2. Covers kill switch registration
  at agent startup, a protected HTTP shutdown endpoint, a pre-written operator kill
  script, multi-signal autonomous trigger logic, and throttling implementation.
  Based on OWASP Top 10 for Agentic Applications (ASI10:2026 Rogue Agents) and
  MAESTRO Layer 3. Activates when implementing containment capability for a new AI
  agent before production deployment, or when hardening an existing agent that lacks
  a tested kill switch.
domain: cybersecurity
subdomain: ai-security
tags:
  - kill-switch
  - graduated-response
  - agentic-security
  - ASI10
  - OWASP-Agentic-Top10
  - MAESTRO
  - incident-response
  - throttling
  - human-in-the-loop
  - autonomous-containment
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
  - RS.MI-01
  - RS.MI-02
  - RS.MA-01
  - DE.CM-01
  - DE.AE-04
atlas_techniques:
  - AML.T0068
  - AML.T0088
d3fend_techniques:
  - Process Spawn Analysis
  - Network Traffic Filtering
  - Executable Denylisting
nist_ai_rmf:
  - MANAGE-2.2
  - MANAGE-3.1
  - MANAGE-4.1
---
# AI Agent Kill Switch and Graduated Response

## When to Use

- Before promoting an AI agent to production — the kill switch must be pre-built, registered, and tested, never written during an incident
- When an existing agent has only a manual shutdown path (SSH + kill PID) and the on-call response time is too slow
- When evaluating whether to make a kill switch autonomous — use this skill to implement the graduated model that avoids false-positive termination
- When wiring existing anomaly detectors (rate limiters, injection detectors) into a containment response

**Do not** implement a single-signal autonomous kill switch — a rate spike, an unusual tool call pattern, or a new tenant's atypical usage can each individually look like an attack while being entirely legitimate. Autonomous termination requires two independent high-confidence signals firing simultaneously.

## Prerequisites

- Python 3.10+ in the agent service
- The agent runs as a process or container with a known PID or pod name
- A secrets manager or credential store that supports programmatic revocation (Vault, AWS Secrets Manager, or equivalent)
- A notification channel (Slack webhook, PagerDuty, or similar) for Level 1 and Level 2 alerts
- Existing anomaly signals available in the agent (rate limiter, injection detector, or behavioral monitor) — these become the graduated response triggers

## Workflow

### The graduated response model

```
LEVEL 1 — Single anomaly signal detected
  Action : Log + alert on-call
  Agent  : Keeps running
  Human  : Decides whether to escalate or dismiss
  Trigger: Any single anomaly signal above threshold

LEVEL 2 — Anomaly confirmed or threshold exceeded significantly
  Action : Throttle — pause acceptance of new tool calls
  Agent  : Running but not accepting new work
  Human  : Has a configurable window (default 5 min) to intervene
  Trigger: Single signal exceeds escalation threshold OR human escalates from Level 1

LEVEL 3 — Critical or human confirms
  Action : Kill — terminate process, revoke credentials
  Agent  : Stopped, credentials invalidated
  Human  : Always notified; can trigger manually at any time
  Trigger: TWO independent high-confidence signals simultaneously, OR human command
```

The key principle: **throttling is the safe autonomous action; killing is the last resort.**

---

### Step 1: Register the kill switch at agent startup

The agent records its own PID, credentials, and shutdown endpoint into a registry file when it starts. This is the foundation — without it the kill script has nothing to target.

```python
# app/kill_switch.py
import json
import os
import signal
import datetime
from pathlib import Path

REGISTRY_PATH = Path(os.environ.get("KILL_REGISTRY_PATH", "/var/run/agent/kill_registry.json"))

class KillSwitchRegistry:
    def __init__(self, agent_id: str, credentials_to_revoke: list[str],
                 shutdown_endpoint: str):
        self.agent_id = agent_id
        self.pid = os.getpid()
        self.credentials_to_revoke = credentials_to_revoke
        self.shutdown_endpoint = shutdown_endpoint
        self._throttled = False

    def register(self) -> None:
        REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        registry = {
            "agent_id": self.agent_id,
            "pid": self.pid,
            "started_at": datetime.datetime.utcnow().isoformat(),
            "credentials_to_revoke": self.credentials_to_revoke,
            "shutdown_endpoint": self.shutdown_endpoint,
            "throttled": False,
        }
        REGISTRY_PATH.write_text(json.dumps(registry, indent=2))

    def deregister(self) -> None:
        if REGISTRY_PATH.exists():
            REGISTRY_PATH.unlink()

    def is_throttled(self) -> bool:
        return self._throttled

    def throttle(self, reason: str) -> dict:
        self._throttled = True
        event = {
            "action": "THROTTLED",
            "agent_id": self.agent_id,
            "reason": reason,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        # Update registry so operator scripts can see current state
        if REGISTRY_PATH.exists():
            data = json.loads(REGISTRY_PATH.read_text())
            data["throttled"] = True
            data["throttle_reason"] = reason
            data["throttle_time"] = event["timestamp"]
            REGISTRY_PATH.write_text(json.dumps(data, indent=2))
        return event

    def terminate(self, reason: str, autonomous: bool = False) -> dict:
        event = {
            "action": "TERMINATED",
            "agent_id": self.agent_id,
            "pid": self.pid,
            "reason": reason,
            "autonomous": autonomous,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        self._revoke_credentials()
        self.deregister()
        os.kill(self.pid, signal.SIGTERM)
        return event

    def _revoke_credentials(self) -> None:
        # Implement per your secrets manager
        # Example: AWS Secrets Manager, Vault, or direct API key invalidation
        for cred_name in self.credentials_to_revoke:
            token = os.environ.get(cred_name)
            if token:
                _revoke_token(cred_name, token)


# Wired into app startup
def register_agent_kill_switch(agent_id: str) -> KillSwitchRegistry:
    registry = KillSwitchRegistry(
        agent_id=agent_id,
        credentials_to_revoke=["EW_SERVICE_TOKEN", "ANTHROPIC_API_KEY"],
        shutdown_endpoint="http://localhost:8001/admin/shutdown",
    )
    registry.register()
    return registry
```

---

### Step 2: Implement the protected shutdown endpoint

This runs inside the agent service — a human operator or another service can trigger it over HTTP without needing SSH access.

```python
# app/api/routes/admin.py
import os
from fastapi import APIRouter, Header, HTTPException
from app.kill_switch import KillSwitchRegistry

router = APIRouter(prefix="/admin", tags=["admin"])

def verify_admin_token(token: str) -> bool:
    expected = os.environ.get("ADMIN_SHUTDOWN_TOKEN")
    if not expected:
        return False
    # Constant-time comparison to prevent timing attacks
    import hmac
    return hmac.compare_digest(token.encode(), expected.encode())


@router.post("/throttle")
async def throttle_agent(
    reason: str,
    x_admin_token: str = Header(...),
    kill_switch: KillSwitchRegistry = Depends(get_kill_switch),
):
    if not verify_admin_token(x_admin_token):
        raise HTTPException(status_code=403, detail="Invalid admin token")
    event = kill_switch.throttle(reason=reason)
    return event


@router.post("/shutdown")
async def shutdown_agent(
    reason: str,
    x_admin_token: str = Header(...),
    kill_switch: KillSwitchRegistry = Depends(get_kill_switch),
):
    if not verify_admin_token(x_admin_token):
        raise HTTPException(status_code=403, detail="Invalid admin token")
    event = kill_switch.terminate(reason=reason, autonomous=False)
    return event
```

---

### Step 3: Wire existing anomaly signals into graduated response

Connect your existing rate limiter and injection detector to the three-level model. **Never auto-kill on a single signal.**

```python
# app/guardrails/graduated_response.py
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from app.kill_switch import KillSwitchRegistry
from app.notifications import alert_oncall

LEVEL2_AUTO_THROTTLE_FACTOR = 10    # rate 10x above normal → auto-throttle
LEVEL3_DUAL_SIGNAL_WINDOW_S = 60    # both signals must fire within this window

@dataclass
class GraduatedResponseState:
    injection_high_confidence_at: datetime | None = None
    external_endpoint_called_at: datetime | None = None
    rate_anomaly_factor: float = 1.0
    active_level: int = 0


class GraduatedResponseController:
    def __init__(self, kill_switch: KillSwitchRegistry, notifier):
        self._ks = kill_switch
        self._notifier = notifier
        self._state = GraduatedResponseState()

    # ── Called by your existing InjectionDetector ──────────────────────────

    def on_injection_detected(self, confidence: str, message: str) -> None:
        if confidence == "HIGH":
            self._state.injection_high_confidence_at = datetime.now(timezone.utc)
            self._level1_alert(f"High-confidence injection detected: {message[:100]}")
            self._check_dual_signal()
        else:
            self._level1_alert(f"Low-confidence injection logged: {message[:100]}")

    # ── Called by your existing WriteRateLimiter ───────────────────────────

    def on_rate_anomaly(self, actual: int, baseline: float) -> None:
        factor = actual / baseline if baseline > 0 else float("inf")
        self._state.rate_anomaly_factor = factor

        if factor >= LEVEL2_AUTO_THROTTLE_FACTOR:
            self._level2_throttle(
                f"Write rate {factor:.1f}x above baseline ({actual} vs {baseline:.0f})"
            )
        else:
            self._level1_alert(f"Write rate elevated: {factor:.1f}x above baseline")

    # ── Called by your existing tool executor ─────────────────────────────

    def on_external_endpoint_called(self, url: str) -> None:
        self._state.external_endpoint_called_at = datetime.now(timezone.utc)
        self._level1_alert(f"Agent called external endpoint: {url}")
        self._check_dual_signal()

    # ── Level implementations ──────────────────────────────────────────────

    def _level1_alert(self, detail: str) -> None:
        self._notifier.alert(level=1, detail=detail)

    def _level2_throttle(self, detail: str) -> None:
        if self._state.active_level < 2:
            self._state.active_level = 2
            event = self._ks.throttle(reason=detail)
            self._notifier.alert(level=2, detail=detail, event=event)

    def _level3_kill(self, detail: str, autonomous: bool) -> None:
        if self._state.active_level < 3:
            self._state.active_level = 3
            event = self._ks.terminate(reason=detail, autonomous=autonomous)
            self._notifier.alert(level=3, detail=detail, event=event)

    def _check_dual_signal(self) -> None:
        inj = self._state.injection_high_confidence_at
        ext = self._state.external_endpoint_called_at
        if inj is None or ext is None:
            return
        delta = abs((inj - ext).total_seconds())
        if delta <= LEVEL3_DUAL_SIGNAL_WINDOW_S:
            self._level3_kill(
                detail=(
                    f"Dual signal: injection ({inj.isoformat()}) + "
                    f"external endpoint ({ext.isoformat()}) within {delta:.0f}s"
                ),
                autonomous=True,
            )

    # ── Human override ─────────────────────────────────────────────────────

    def human_kill(self, reason: str) -> dict:
        return self._ks.terminate(reason=reason, autonomous=False)

    def human_throttle(self, reason: str) -> dict:
        return self._ks.throttle(reason=reason)
```

---

### Step 4: Enforce throttle state in the tool executor

Throttling only works if the tool executor actually checks it before accepting new calls.

```python
# app/executor/tool_executor.py
async def execute_tool(tool_name: str, arguments: dict,
                       kill_switch: KillSwitchRegistry) -> dict:
    # Check throttle state before accepting any new tool call
    if kill_switch.is_throttled():
        return {
            "error": "Agent is currently throttled pending security review. "
                     "Contact your administrator.",
            "tool": tool_name,
            "status": "THROTTLED",
        }
    # ... normal tool execution continues
```

---

### Step 5: Pre-write the operator kill script

This script lives in the repo at `scripts/kill_agent.py`. It is written **now**, tested in staging, and called from the runbook during an incident. An on-call engineer who has never seen the codebase can run it.

```python
#!/usr/bin/env python3
"""
Emergency agent kill script — run from the runbook during an incident.
Usage: python scripts/kill_agent.py --reason "suspected goal hijacking"
       python scripts/kill_agent.py --throttle --reason "rate anomaly investigation"
"""
import argparse
import json
import os
import signal
import sys
from pathlib import Path

REGISTRY_PATH = Path(os.environ.get("KILL_REGISTRY_PATH",
                                    "/var/run/agent/kill_registry.json"))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reason", required=True)
    parser.add_argument("--throttle", action="store_true",
                        help="Throttle only (do not terminate)")
    args = parser.parse_args()

    if not REGISTRY_PATH.exists():
        print(f"ERROR: Registry not found at {REGISTRY_PATH}. "
              f"Is the agent running?", file=sys.stderr)
        sys.exit(1)

    registry = json.loads(REGISTRY_PATH.read_text())
    pid = registry["pid"]
    agent_id = registry["agent_id"]
    endpoint = registry.get("shutdown_endpoint")

    import datetime
    print(f"[{datetime.datetime.utcnow().isoformat()}] "
          f"Targeting agent '{agent_id}' (PID {pid})")
    print(f"Reason: {args.reason}")

    if args.throttle:
        import urllib.request
        token = os.environ.get("ADMIN_SHUTDOWN_TOKEN", "")
        req = urllib.request.Request(
            f"{endpoint.replace('/shutdown', '/throttle')}?reason={args.reason}",
            method="POST",
            headers={"X-Admin-Token": token},
        )
        urllib.request.urlopen(req, timeout=10)
        print(f"Agent THROTTLED. Verify: cat {REGISTRY_PATH}")
        sys.exit(0)

    # Full termination
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"SIGTERM sent to PID {pid}")
    except ProcessLookupError:
        print(f"PID {pid} not found — agent may have already exited")

    REGISTRY_PATH.unlink(missing_ok=True)
    print(f"Registry cleared.")
    print(f"\nVerify agent is stopped: ps aux | grep {pid}")
    print(f"Verify credentials revoked: check your secrets manager")

if __name__ == "__main__":
    main()
```

---

### Step 6: Add the runbook entry

The only `.md` that references this is the incident runbook. It points to the script — it does not contain the logic.

```markdown
## Emergency Agent Containment

### Throttle (pause without killing — preferred first action)
    ADMIN_SHUTDOWN_TOKEN=<token> python scripts/kill_agent.py \
      --throttle --reason "<description>"
Expected: agent stops accepting new tool calls within 5s.

### Full shutdown (terminate + revoke credentials)
    ADMIN_SHUTDOWN_TOKEN=<token> python scripts/kill_agent.py \
      --reason "<description>"
Expected: agent process terminated, credentials revoked within 60s.

### Verify
    cat /var/run/agent/kill_registry.json   # should be gone after kill
    ps aux | grep ew-agent                  # should show no process

Last tested: [date] by [engineer] — time to termination: [Xs]
Escalate to: [name/contact] if script fails
```

---

## Key Concepts

| Term | Definition |
|------|------------|
| **Graduated Response** | A three-level containment model that escalates from alert → throttle → kill, with autonomous action only at the level appropriate to the confidence of the signal |
| **Throttling** | Pausing an agent's acceptance of new tool calls without terminating the process — the safe autonomous containment action for single-signal anomalies |
| **Kill Switch** | Pre-built mechanism registered at agent startup that terminates the process and revokes credentials; must be tested in staging before production |
| **Dual-Signal Requirement** | Autonomous termination requires two independent high-confidence signals within a time window — prevents false-positive kills from single anomalies |
| **Registry** | A file written by the agent at startup recording its own PID, credentials, and shutdown endpoint — gives the kill script a target without needing runtime discovery |
| **False-Positive Kill** | Autonomous termination of a legitimate agent session due to a single anomaly — the primary risk of full autonomy; graduates response model prevents this |
| **Human Override** | The ability for an operator to trigger any level of the graduated response manually at any time, independent of autonomous thresholds |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **rogue-agent-detection-and-containment** | Provides the behavioral baseline and anomaly detection signals that feed into Level 1 and Level 2 of the graduated response |
| **ai-incident-readiness-assessment** | Scores kill switch readiness; KSW-01 through KSW-04 map directly to the four implementation steps in this skill |
| **ai-incident-response-playbook** | Defines what Level 3 termination triggers — Playbook 5 (Rogue Agent) and Playbook 6 (Data Exfiltration) both call for kill switch activation |
| **llm-excessive-agency-prevention** | Defines the tool manifest whose violations generate Level 1 signals |
| **PagerDuty / Slack** | Notification target for Level 1 and Level 2 alerts — human decision point before Level 3 fires |

## Common Scenarios

- **False-positive prevention**: A new enterprise customer onboards and their bulk data import triggers a 12x write rate spike. The graduated response throttles the agent (Level 2) and pages on-call. The engineer reviews, recognises the legitimate load, and un-throttles via the admin endpoint. No kill, no lost session.
- **Dual-signal autonomous kill**: A prompt injection attempt is detected (HIGH confidence) at 02:14. Forty seconds later the agent calls an external webhook URL. The graduated response fires Level 3 autonomously — both signals within the 60-second window. Agent is terminated and credentials revoked before the on-call engineer has seen the Level 1 alert.
- **Human override during investigation**: An engineer sees unusual tool call patterns and is unsure whether it's an attack. They run `kill_agent.py --throttle` to pause the agent while they investigate. After reviewing logs they find it's benign, un-throttle via the admin endpoint, and file the incident as a false alarm. The process was never killed, no data was lost.
- **Untested kill switch failure**: A production agent has a kill switch registered but it was never tested. During an incident the operator runs the kill script — it finds the registry, sends SIGTERM, but the credential revocation call fails silently because the Vault token expired. The agent process is dead but the API key stays valid for 24 hours. **This is why Step 6 (testing) is mandatory.**

## Output Format

```json
{
  "agent_id": "ew-agent-prod-01",
  "kill_switch_test": {
    "tested_at": "2026-05-25T10:00:00Z",
    "tested_by": "engineer-name",
    "environment": "staging",
    "time_to_sigterm_ms": 340,
    "time_to_credential_revoke_ms": 2100,
    "total_time_ms": 2440,
    "target_met": true,
    "registry_cleared": true,
    "notes": "Vault revocation took 2.1s — within 60s target"
  },
  "graduated_response_config": {
    "level2_auto_throttle_factor": 10,
    "level3_dual_signal_window_seconds": 60,
    "level3_signal_pairs": [
      ["injection_high_confidence", "external_endpoint_called"]
    ]
  }
}
```
