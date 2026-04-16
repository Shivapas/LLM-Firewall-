"""SP-351: Wire ModelFingerprintScorer into Sphinx output scanning layer.

Scores every LLM response against the baseline profile and writes the
deviation score to response metadata.  The scorer runs asynchronously
against a copy of the response text so the main response path is not
blocked (risk mitigation per Sprint 35 risk register).

SP-351 acceptance criteria:
  - Deviation score present in Sphinx response metadata for 100% of
    responses in staging
  - p99 scoring latency < 10ms
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from app.services.fingerprint.baseline_profiler import (
    BaselineProfile,
    BaselineProfiler,
    get_baseline_profiler,
)
from app.services.fingerprint.deviation_scorer import (
    DeviationResult,
    DeviationScorer,
    get_deviation_scorer,
)
from app.services.fingerprint.supply_chain_monitor import (
    SupplyChainAlert,
    SupplyChainMonitor,
    get_supply_chain_monitor,
)

logger = logging.getLogger("sphinx.fingerprint.output_scanner_integration")


@dataclass
class FingerprintScanResult:
    """Result of fingerprint-scanning an LLM response.

    Attached to Sphinx response metadata (SP-351).
    """

    scored: bool = False
    deviation_score: float = 0.0
    alert_triggered: bool = False
    alignment_status: str = "ALIGNED"
    max_z_feature: str = ""
    max_z_score: float = 0.0
    scoring_time_ms: float = 0.0
    supply_chain_alert: Optional[SupplyChainAlert] = None
    warm_up_in_progress: bool = False

    def to_metadata(self) -> dict:
        """Serialise to metadata dict for Sphinx response headers."""
        meta = {
            "fingerprint_scored": self.scored,
            "fingerprint_deviation": round(self.deviation_score, 6),
            "fingerprint_alert": self.alert_triggered,
            "fingerprint_alignment": self.alignment_status,
        }
        if self.max_z_feature:
            meta["fingerprint_max_z_feature"] = self.max_z_feature
            meta["fingerprint_max_z_score"] = round(self.max_z_score, 4)
        if self.scoring_time_ms > 0:
            meta["fingerprint_scoring_ms"] = round(self.scoring_time_ms, 2)
        if self.warm_up_in_progress:
            meta["fingerprint_warm_up"] = True
        return meta


class FingerprintOutputIntegration:
    """Integrates model fingerprinting into the Sphinx output scanning layer.

    This class is called on every LLM response to:
    1. During warm-up: collect the response for baseline profiling
    2. After warm-up: score the response and record deviation in the
       SupplyChainMonitor
    3. Return a FingerprintScanResult for inclusion in response metadata

    Thread-safe: delegates to thread-safe BaselineProfiler,
    DeviationScorer, and SupplyChainMonitor.
    """

    def __init__(
        self,
        profiler: Optional[BaselineProfiler] = None,
        scorer: Optional[DeviationScorer] = None,
        monitor: Optional[SupplyChainMonitor] = None,
        enabled: bool = True,
    ) -> None:
        self._profiler = profiler or get_baseline_profiler()
        self._scorer = scorer or get_deviation_scorer()
        self._monitor = monitor or get_supply_chain_monitor()
        self._enabled = enabled
        self._total_scored: int = 0
        self._total_warm_up: int = 0

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    @property
    def total_scored(self) -> int:
        return self._total_scored

    @property
    def total_warm_up(self) -> int:
        return self._total_warm_up

    def scan_response(self, response_text: str) -> FingerprintScanResult:
        """Score an LLM response and record in the supply chain monitor.

        This is the main entry point called from the output scanning layer.

        If the baseline profile is not yet available (warm-up in progress),
        the response is added to the warm-up set and auto-computes the
        profile once the target count is reached.

        Returns:
            FingerprintScanResult with deviation score and metadata.
        """
        if not self._enabled or not response_text or not response_text.strip():
            return FingerprintScanResult(scored=False)

        profile = self._profiler.profile

        # Phase 1: Warm-up -- collect responses for baseline
        if profile is None:
            warm_up_done = self._profiler.add_response(response_text)
            self._total_warm_up += 1
            if warm_up_done and self._profiler.profile is None:
                try:
                    profile = self._profiler.compute_profile()
                    self._monitor.baseline_version = profile.profile_hash[:12]
                    logger.info(
                        "Baseline profile auto-computed during warm-up: "
                        "samples=%d hash=%s",
                        profile.sample_count,
                        profile.profile_hash[:12],
                    )
                except Exception:
                    logger.warning("Failed to auto-compute baseline profile", exc_info=True)

            return FingerprintScanResult(
                scored=False,
                warm_up_in_progress=True,
            )

        # Phase 2: Score response against baseline
        start = time.perf_counter()
        result = self._scorer.score_response(response_text, profile)
        scoring_ms = (time.perf_counter() - start) * 1000

        # Record in supply chain monitor
        alert = self._monitor.record_deviation(result)
        alignment = self._monitor.get_alignment_status()
        self._total_scored += 1

        scan_result = FingerprintScanResult(
            scored=True,
            deviation_score=result.aggregate_deviation,
            alert_triggered=result.alert_triggered,
            alignment_status=alignment,
            max_z_feature=result.max_z_feature,
            max_z_score=result.max_z_score,
            scoring_time_ms=scoring_ms,
            supply_chain_alert=alert,
        )

        if alert:
            logger.warning(
                "Supply chain alert triggered: consecutive=%d deviation=%.3f "
                "alignment=%s model=%s",
                alert.consecutive_count,
                result.aggregate_deviation,
                alignment,
                alert.model_id,
            )

        return scan_result


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_integration: Optional[FingerprintOutputIntegration] = None


def get_fingerprint_output_integration(
    enabled: bool = True,
) -> FingerprintOutputIntegration:
    """Get or create the singleton FingerprintOutputIntegration."""
    global _integration
    if _integration is None:
        _integration = FingerprintOutputIntegration(enabled=enabled)
    return _integration


def reset_fingerprint_output_integration() -> None:
    """Reset the singleton (for testing)."""
    global _integration
    _integration = None
