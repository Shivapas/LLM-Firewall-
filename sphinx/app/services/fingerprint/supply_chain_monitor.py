"""SP-350: SupplyChainMonitor -- consecutive-response deviation alerting.

Tracks per-response deviation scores and raises a HIGH alert when N
consecutive responses exceed the configured alert threshold (default N=5).

A single outlier response does not trigger an alert; only sustained
deviation across multiple consecutive responses indicates a potential
model substitution in the inference supply chain.

SP-350 acceptance criteria:
  - Monitor alerts correctly when 5 consecutive synthetic high-deviation
    responses are sent
  - Single outlier does not trigger alert
  - N is configurable (default 5)
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

from app.services.fingerprint.deviation_scorer import DeviationResult

logger = logging.getLogger("sphinx.fingerprint.supply_chain_monitor")

# Default consecutive breach count before alert
DEFAULT_CONSECUTIVE_THRESHOLD = 5

# Model alignment status labels (SP-353 dashboard badge)
STATUS_ALIGNED = "ALIGNED"
STATUS_DRIFTING = "DRIFTING"
STATUS_SWAPPED = "SWAPPED"


@dataclass
class SupplyChainAlert:
    """Alert emitted when consecutive deviation threshold is breached.

    Contains all fields required by the TrustDetect HIGH event schema (SP-352).
    """

    alert_id: str = ""
    timestamp: float = field(default_factory=time.time)
    severity: str = "HIGH"
    category: str = "SUPPLY_CHAIN_SWAP"
    model_id: str = ""
    baseline_version: str = ""
    deviation_scores: list[float] = field(default_factory=list)
    feature_delta: dict[str, float] = field(default_factory=dict)
    consecutive_count: int = 0
    alignment_status: str = STATUS_SWAPPED

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "category": self.category,
            "model_id": self.model_id,
            "baseline_version": self.baseline_version,
            "deviation_scores": self.deviation_scores,
            "feature_delta": self.feature_delta,
            "consecutive_count": self.consecutive_count,
            "alignment_status": self.alignment_status,
        }


@dataclass
class DeviationRecord:
    """A single deviation score record with metadata."""

    timestamp: float
    aggregate_deviation: float
    alert_triggered: bool
    feature_deltas: dict[str, float]
    max_z_feature: str
    max_z_score: float
    scoring_time_ms: float


class SupplyChainMonitor:
    """Monitors consecutive per-response deviation scores for model swap detection.

    Tracks a sliding window of deviation results and raises a HIGH alert
    when ``consecutive_threshold`` consecutive responses all exceed the
    deviation scorer's alert threshold.

    Thread-safe: all mutable state is protected by a lock.
    """

    def __init__(
        self,
        consecutive_threshold: int = DEFAULT_CONSECUTIVE_THRESHOLD,
        model_id: str = "",
        baseline_version: str = "",
        history_size: int = 1000,
    ) -> None:
        self._consecutive_threshold = consecutive_threshold
        self._model_id = model_id
        self._baseline_version = baseline_version
        self._lock = Lock()

        # Consecutive breach counter
        self._consecutive_breaches: int = 0

        # Recent deviation history for dashboard (SP-353)
        self._history: deque[DeviationRecord] = deque(maxlen=history_size)

        # Alert state
        self._alert_active: bool = False
        self._last_alert: Optional[SupplyChainAlert] = None
        self._total_alerts: int = 0
        self._total_responses_scored: int = 0

        # Rolling 24h window for dashboard (SP-353)
        self._rolling_24h: deque[DeviationRecord] = deque()

    @property
    def consecutive_threshold(self) -> int:
        return self._consecutive_threshold

    @consecutive_threshold.setter
    def consecutive_threshold(self, value: int) -> None:
        if value < 1:
            raise ValueError("Consecutive threshold must be >= 1")
        with self._lock:
            self._consecutive_threshold = value

    @property
    def consecutive_breaches(self) -> int:
        with self._lock:
            return self._consecutive_breaches

    @property
    def alert_active(self) -> bool:
        with self._lock:
            return self._alert_active

    @property
    def last_alert(self) -> Optional[SupplyChainAlert]:
        with self._lock:
            return self._last_alert

    @property
    def total_alerts(self) -> int:
        with self._lock:
            return self._total_alerts

    @property
    def total_responses_scored(self) -> int:
        with self._lock:
            return self._total_responses_scored

    @property
    def model_id(self) -> str:
        return self._model_id

    @model_id.setter
    def model_id(self, value: str) -> None:
        self._model_id = value

    @property
    def baseline_version(self) -> str:
        return self._baseline_version

    @baseline_version.setter
    def baseline_version(self, value: str) -> None:
        self._baseline_version = value

    def record_deviation(self, result: DeviationResult) -> Optional[SupplyChainAlert]:
        """Record a deviation result and check for consecutive breach alert.

        Args:
            result: The deviation scoring result from DeviationScorer.

        Returns:
            A SupplyChainAlert if the consecutive threshold was just breached,
            otherwise None.
        """
        import uuid

        now = time.time()
        record = DeviationRecord(
            timestamp=now,
            aggregate_deviation=result.aggregate_deviation,
            alert_triggered=result.alert_triggered,
            feature_deltas=result.feature_deltas(),
            max_z_feature=result.max_z_feature,
            max_z_score=result.max_z_score,
            scoring_time_ms=result.scoring_time_ms,
        )

        with self._lock:
            self._total_responses_scored += 1
            self._history.append(record)
            self._rolling_24h.append(record)
            self._prune_24h(now)

            if result.alert_triggered:
                self._consecutive_breaches += 1
                logger.debug(
                    "Consecutive breach %d/%d: deviation=%.3f max_z=%.3f (%s)",
                    self._consecutive_breaches,
                    self._consecutive_threshold,
                    result.aggregate_deviation,
                    result.max_z_score,
                    result.max_z_feature,
                )

                if self._consecutive_breaches >= self._consecutive_threshold:
                    # Collect deviation scores from the last N breaching responses
                    recent_scores = [
                        r.aggregate_deviation
                        for r in list(self._history)[-self._consecutive_threshold:]
                    ]
                    # Use the most recent result's feature deltas
                    alert = SupplyChainAlert(
                        alert_id=str(uuid.uuid4()),
                        timestamp=now,
                        severity="HIGH",
                        category="SUPPLY_CHAIN_SWAP",
                        model_id=self._model_id,
                        baseline_version=self._baseline_version,
                        deviation_scores=recent_scores,
                        feature_delta=result.feature_deltas(),
                        consecutive_count=self._consecutive_breaches,
                        alignment_status=STATUS_SWAPPED,
                    )
                    self._alert_active = True
                    self._last_alert = alert
                    self._total_alerts += 1
                    logger.warning(
                        "SUPPLY CHAIN ALERT: %d consecutive high-deviation "
                        "responses detected. model=%s scores=%s",
                        self._consecutive_breaches,
                        self._model_id,
                        [f"{s:.3f}" for s in recent_scores],
                    )
                    return alert
            else:
                # Reset consecutive counter on a non-breaching response
                if self._consecutive_breaches > 0:
                    logger.debug(
                        "Consecutive breach counter reset (was %d)",
                        self._consecutive_breaches,
                    )
                self._consecutive_breaches = 0
                self._alert_active = False

            return None

    def get_alignment_status(self) -> str:
        """Return the current model alignment status for the dashboard badge.

        SP-353: ALIGNED / DRIFTING / SWAPPED
        """
        with self._lock:
            if self._alert_active:
                return STATUS_SWAPPED
            if self._consecutive_breaches >= max(1, self._consecutive_threshold // 2):
                return STATUS_DRIFTING
            return STATUS_ALIGNED

    def get_rolling_24h_stats(self) -> dict:
        """Return rolling 24h deviation statistics for the dashboard.

        SP-353: rolling 24h deviation score chart data.
        """
        now = time.time()
        with self._lock:
            self._prune_24h(now)
            records = list(self._rolling_24h)

        if not records:
            return {
                "total_scored": 0,
                "avg_deviation": 0.0,
                "max_deviation": 0.0,
                "alerts_triggered": 0,
                "deviation_scores": [],
                "timestamps": [],
            }

        deviations = [r.aggregate_deviation for r in records]
        return {
            "total_scored": len(records),
            "avg_deviation": round(sum(deviations) / len(deviations), 6),
            "max_deviation": round(max(deviations), 6),
            "alerts_triggered": sum(1 for r in records if r.alert_triggered),
            "deviation_scores": [round(d, 4) for d in deviations],
            "timestamps": [r.timestamp for r in records],
        }

    def get_per_feature_drift(self) -> dict[str, list[float]]:
        """Return per-feature drift data from the most recent scored responses.

        SP-353: per-feature drift chart data.
        """
        with self._lock:
            records = list(self._history)[-50:]  # Last 50 responses

        if not records:
            return {}

        # Collect feature deltas across recent records
        drift: dict[str, list[float]] = {}
        for record in records:
            for feature_name, z_score in record.feature_deltas.items():
                drift.setdefault(feature_name, []).append(round(z_score, 4))

        return drift

    def get_summary(self) -> dict:
        """Return a summary of the monitor's state for API/dashboard use."""
        with self._lock:
            return {
                "alignment_status": self.get_alignment_status(),
                "consecutive_breaches": self._consecutive_breaches,
                "consecutive_threshold": self._consecutive_threshold,
                "alert_active": self._alert_active,
                "total_alerts": self._total_alerts,
                "total_responses_scored": self._total_responses_scored,
                "model_id": self._model_id,
                "baseline_version": self._baseline_version,
                "last_alert": self._last_alert.to_dict() if self._last_alert else None,
            }

    def reset(self) -> None:
        """Reset all monitor state."""
        with self._lock:
            self._consecutive_breaches = 0
            self._alert_active = False
            self._last_alert = None
            self._total_alerts = 0
            self._total_responses_scored = 0
            self._history.clear()
            self._rolling_24h.clear()
            logger.info("SupplyChainMonitor reset")

    def _prune_24h(self, now: float) -> None:
        """Remove records older than 24 hours from the rolling window."""
        cutoff = now - 86400
        while self._rolling_24h and self._rolling_24h[0].timestamp < cutoff:
            self._rolling_24h.popleft()


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_monitor: Optional[SupplyChainMonitor] = None


def get_supply_chain_monitor(
    consecutive_threshold: int = DEFAULT_CONSECUTIVE_THRESHOLD,
    model_id: str = "",
    baseline_version: str = "",
) -> SupplyChainMonitor:
    """Get or create the singleton SupplyChainMonitor."""
    global _monitor
    if _monitor is None:
        _monitor = SupplyChainMonitor(
            consecutive_threshold=consecutive_threshold,
            model_id=model_id,
            baseline_version=baseline_version,
        )
    return _monitor


def reset_supply_chain_monitor() -> None:
    """Reset the singleton (for testing)."""
    global _monitor
    _monitor = None
