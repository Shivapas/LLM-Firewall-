"""SP-335: Canary leakage metrics store for admin dashboard badge.

Tracks canary leakage detection events within a 30-day rolling window
for the admin dashboard badge.

SP-335 acceptance criteria:
  - Dashboard badge updates within 30s of new detection
  - 30-day rolling leakage event count displayed
"""

from __future__ import annotations

import logging
import time
from collections import deque
from threading import Lock

logger = logging.getLogger("sphinx.canary.metrics")


class CanaryMetricsStore:
    """Thread-safe rolling metrics store for canary leakage detections.

    Tracks leakage events within a configurable rolling window (default 30 days)
    for the admin dashboard badge.
    """

    _DEFAULT_WINDOW_SECONDS = 30 * 86400  # 30 days

    def __init__(self, window_seconds: int = _DEFAULT_WINDOW_SECONDS) -> None:
        self._window_seconds = window_seconds
        self._lock = Lock()
        self._detections: deque[dict] = deque()
        self._total_scans: int = 0
        self._total_detections: int = 0
        self._total_sessions_protected: int = 0

    def record_scan(self, detected: bool, session_id: str = "") -> None:
        """Record a canary scan result."""
        now = time.time()
        with self._lock:
            self._total_scans += 1
            if detected:
                self._total_detections += 1
                self._detections.append({
                    "ts": now,
                    "session_id": session_id,
                })
            self._prune(now)

    def record_session_protected(self) -> None:
        """Record that a session had a canary token injected."""
        with self._lock:
            self._total_sessions_protected += 1

    def get_rolling_stats(self) -> dict:
        """Return rolling window detection statistics for the dashboard badge."""
        now = time.time()
        with self._lock:
            self._prune(now)
            return {
                "rolling_leakage_count": len(self._detections),
                "total_scans": self._total_scans,
                "total_detections": self._total_detections,
                "total_sessions_protected": self._total_sessions_protected,
                "window_days": self._window_seconds // 86400,
                "detection_rate": (
                    round(self._total_detections / self._total_scans, 6)
                    if self._total_scans > 0
                    else 0.0
                ),
            }

    def _prune(self, now: float) -> None:
        """Remove detections outside the rolling window."""
        cutoff = now - self._window_seconds
        while self._detections and self._detections[0]["ts"] < cutoff:
            self._detections.popleft()
