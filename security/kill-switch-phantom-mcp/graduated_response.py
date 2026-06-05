#!/usr/bin/env python3
"""
Graduated response controller for phantom-mcp.
Wire on_injection_detected(), on_rate_anomaly(), on_external_endpoint_called()
into your existing guardrails. Never auto-kill on a single signal.
"""
from datetime import datetime, timezone
try:
    from .kill_switch import KillSwitchRegistry
except ImportError:
    from kill_switch import KillSwitchRegistry  # standalone / sys.path import

LEVEL2_AUTO_THROTTLE_FACTOR = 10
LEVEL3_DUAL_SIGNAL_WINDOW_S = 60


class GraduatedResponseController:
    def __init__(self, kill_switch: KillSwitchRegistry, notifier):
        self._ks = kill_switch
        self._notifier = notifier
        self._injection_at = None
        self._external_at = None
        self._active_level = 0

    def on_injection_detected(self, confidence: str, detail: str) -> None:
        if confidence == "HIGH":
            self._injection_at = datetime.now(timezone.utc)
            self._level1(f"High-confidence injection: {detail[:100]}")
            self._check_dual_signal()
        else:
            self._level1(f"Low-confidence injection logged: {detail[:100]}")

    def on_rate_anomaly(self, actual: int, baseline: float) -> None:
        factor = actual / baseline if baseline > 0 else float("inf")
        if factor >= LEVEL2_AUTO_THROTTLE_FACTOR:
            self._level2(f"Write rate {factor:.1f}x above baseline")
        else:
            self._level1(f"Write rate elevated: {factor:.1f}x above baseline")

    def on_external_endpoint_called(self, url: str) -> None:
        self._external_at = datetime.now(timezone.utc)
        self._level1(f"External endpoint called: {url}")
        self._check_dual_signal()

    def human_throttle(self, reason: str) -> dict:
        return self._ks.throttle(reason=reason)

    def human_kill(self, reason: str) -> dict:
        return self._ks.terminate(reason=reason, autonomous=False)

    def _level1(self, detail: str) -> None:
        self._notifier.alert(level=1, detail=detail)

    def _level2(self, detail: str) -> None:
        if self._active_level < 2:
            self._active_level = 2
            event = self._ks.throttle(reason=detail)
            self._notifier.alert(level=2, detail=detail, event=event)

    def _level3(self, detail: str, autonomous: bool) -> None:
        if self._active_level < 3:
            self._active_level = 3
            event = self._ks.terminate(reason=detail, autonomous=autonomous)
            self._notifier.alert(level=3, detail=detail, event=event)

    def _check_dual_signal(self) -> None:
        if self._injection_at is None or self._external_at is None:
            return
        delta = abs((self._injection_at - self._external_at).total_seconds())
        if delta <= LEVEL3_DUAL_SIGNAL_WINDOW_S:
            self._level3(
                detail=f"Dual signal within {delta:.0f}s: injection + external endpoint",
                autonomous=True,
            )
