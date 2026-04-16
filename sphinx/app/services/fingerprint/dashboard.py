"""SP-353: Inference endpoint health dashboard data provider.

Provides data for the inference endpoint health dashboard:
  - Rolling 24h deviation score chart
  - Per-feature drift chart
  - Current model alignment status badge (ALIGNED / DRIFTING / SWAPPED)

SP-353 acceptance criteria:
  - Dashboard visible in admin UI
  - Status badge transitions correctly in staging
  - Simulate by importing a different baseline
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from app.services.fingerprint.baseline_profiler import (
    BaselineProfiler,
    get_baseline_profiler,
)
from app.services.fingerprint.deviation_scorer import (
    DeviationScorer,
    get_deviation_scorer,
)
from app.services.fingerprint.supply_chain_monitor import (
    STATUS_ALIGNED,
    STATUS_DRIFTING,
    STATUS_SWAPPED,
    SupplyChainMonitor,
    get_supply_chain_monitor,
)

logger = logging.getLogger("sphinx.fingerprint.dashboard")


class InferenceHealthDashboard:
    """Aggregates data from the fingerprint module for the admin dashboard.

    Provides three main views:
    1. Rolling 24h deviation score chart
    2. Per-feature drift chart (last 50 responses)
    3. Model alignment status badge
    """

    def __init__(
        self,
        monitor: Optional[SupplyChainMonitor] = None,
        profiler: Optional[BaselineProfiler] = None,
        scorer: Optional[DeviationScorer] = None,
    ) -> None:
        self._monitor = monitor or get_supply_chain_monitor()
        self._profiler = profiler or get_baseline_profiler()
        self._scorer = scorer or get_deviation_scorer()

    def get_status_badge(self) -> dict:
        """Return the current alignment status badge for the dashboard.

        Returns:
            {
                "status": "ALIGNED" | "DRIFTING" | "SWAPPED",
                "color": "green" | "yellow" | "red",
                "consecutive_breaches": int,
                "threshold": int,
                "model_id": str,
                "profile_loaded": bool,
            }
        """
        status = self._monitor.get_alignment_status()
        profile = self._profiler.profile

        color_map = {
            STATUS_ALIGNED: "green",
            STATUS_DRIFTING: "yellow",
            STATUS_SWAPPED: "red",
        }

        return {
            "status": status,
            "color": color_map.get(status, "grey"),
            "consecutive_breaches": self._monitor.consecutive_breaches,
            "threshold": self._monitor.consecutive_threshold,
            "model_id": self._monitor.model_id,
            "profile_loaded": profile is not None,
            "warm_up_complete": self._profiler.is_warm_up_complete,
            "alert_threshold_sigma": self._scorer.alert_threshold,
        }

    def get_deviation_chart(self) -> dict:
        """Return rolling 24h deviation score chart data.

        Returns:
            {
                "chart_type": "time_series",
                "title": "Inference Deviation (24h)",
                "data": {
                    "timestamps": [...],
                    "deviation_scores": [...],
                    "threshold_line": float,
                },
                "stats": {
                    "total_scored": int,
                    "avg_deviation": float,
                    "max_deviation": float,
                    "alerts_triggered": int,
                },
            }
        """
        stats = self._monitor.get_rolling_24h_stats()
        return {
            "chart_type": "time_series",
            "title": "Inference Deviation (24h)",
            "data": {
                "timestamps": stats["timestamps"],
                "deviation_scores": stats["deviation_scores"],
                "threshold_line": self._scorer.alert_threshold,
            },
            "stats": {
                "total_scored": stats["total_scored"],
                "avg_deviation": stats["avg_deviation"],
                "max_deviation": stats["max_deviation"],
                "alerts_triggered": stats["alerts_triggered"],
            },
        }

    def get_drift_chart(self) -> dict:
        """Return per-feature drift chart data.

        Returns:
            {
                "chart_type": "multi_line",
                "title": "Per-Feature Drift",
                "data": {
                    "feature_name_1": [z_scores...],
                    "feature_name_2": [z_scores...],
                    ...
                },
                "sample_count": int,
            }
        """
        drift = self._monitor.get_per_feature_drift()
        sample_count = max((len(v) for v in drift.values()), default=0)
        return {
            "chart_type": "multi_line",
            "title": "Per-Feature Drift",
            "data": drift,
            "sample_count": sample_count,
        }

    def get_full_dashboard(self) -> dict:
        """Return the complete dashboard payload.

        Combines status badge, deviation chart, drift chart, and monitor
        summary into a single response.
        """
        return {
            "timestamp": time.time(),
            "status_badge": self.get_status_badge(),
            "deviation_chart": self.get_deviation_chart(),
            "drift_chart": self.get_drift_chart(),
            "monitor_summary": self._monitor.get_summary(),
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_dashboard: Optional[InferenceHealthDashboard] = None


def get_inference_health_dashboard() -> InferenceHealthDashboard:
    """Get or create the singleton InferenceHealthDashboard."""
    global _dashboard
    if _dashboard is None:
        _dashboard = InferenceHealthDashboard()
    return _dashboard


def reset_inference_health_dashboard() -> None:
    """Reset the singleton (for testing)."""
    global _dashboard
    _dashboard = None
