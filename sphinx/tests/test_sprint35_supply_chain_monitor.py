"""Sprint 35 — SP-350: SupplyChainMonitor Test Suite.

Tests for consecutive-response deviation alerting:
  - Monitor alerts correctly when 5 consecutive high-deviation responses sent
  - Single outlier does not trigger alert
  - 4 consecutive breaches do not trigger alert (threshold is 5)
  - N is configurable
  - Monitor reset clears state
  - Alignment status badge transitions: ALIGNED -> DRIFTING -> SWAPPED
"""

import pytest

from app.services.fingerprint.deviation_scorer import DeviationResult
from app.services.fingerprint.supply_chain_monitor import (
    DEFAULT_CONSECUTIVE_THRESHOLD,
    STATUS_ALIGNED,
    STATUS_DRIFTING,
    STATUS_SWAPPED,
    SupplyChainMonitor,
    reset_supply_chain_monitor,
)


def _make_result(aggregate: float, triggered: bool) -> DeviationResult:
    """Create a synthetic DeviationResult."""
    return DeviationResult(
        z_scores=[aggregate] * 16,
        feature_names=[f"f{i}" for i in range(16)],
        aggregate_deviation=aggregate,
        alert_triggered=triggered,
        threshold=2.5,
        max_z_score=aggregate,
        max_z_feature="f0",
        scoring_time_ms=1.0,
    )


@pytest.fixture
def monitor():
    reset_supply_chain_monitor()
    m = SupplyChainMonitor(
        consecutive_threshold=5,
        model_id="test-model",
        baseline_version="abc123",
    )
    yield m
    reset_supply_chain_monitor()


class TestSP350ConsecutiveAlerting:
    """SP-350: consecutive deviation alerting tests."""

    def test_5_consecutive_breaches_trigger_alert(self, monitor):
        """5 consecutive high-deviation responses trigger a HIGH alert."""
        for i in range(4):
            alert = monitor.record_deviation(_make_result(3.0, True))
            assert alert is None, f"Alert should not trigger at breach {i + 1}"

        alert = monitor.record_deviation(_make_result(3.0, True))
        assert alert is not None
        assert alert.severity == "HIGH"
        assert alert.category == "SUPPLY_CHAIN_SWAP"
        assert alert.consecutive_count == 5
        assert alert.model_id == "test-model"
        assert alert.baseline_version == "abc123"
        assert len(alert.deviation_scores) == 5

    def test_single_outlier_does_not_trigger(self, monitor):
        """A single high-deviation response does not trigger alert."""
        alert = monitor.record_deviation(_make_result(5.0, True))
        assert alert is None
        assert monitor.consecutive_breaches == 1

    def test_4_consecutive_do_not_trigger(self, monitor):
        """4 consecutive breaches do not trigger alert (threshold is 5)."""
        for _ in range(4):
            alert = monitor.record_deviation(_make_result(3.0, True))
            assert alert is None
        assert monitor.consecutive_breaches == 4
        assert not monitor.alert_active

    def test_reset_on_non_breach(self, monitor):
        """Consecutive counter resets when a non-breaching response arrives."""
        for _ in range(3):
            monitor.record_deviation(_make_result(3.0, True))
        assert monitor.consecutive_breaches == 3

        # Non-breaching response resets the counter
        monitor.record_deviation(_make_result(0.5, False))
        assert monitor.consecutive_breaches == 0

        # Need 5 more breaches now
        for i in range(4):
            alert = monitor.record_deviation(_make_result(3.0, True))
            assert alert is None
        alert = monitor.record_deviation(_make_result(3.0, True))
        assert alert is not None

    def test_configurable_threshold(self):
        """Consecutive threshold is configurable."""
        m = SupplyChainMonitor(consecutive_threshold=3)
        for _ in range(2):
            alert = m.record_deviation(_make_result(3.0, True))
            assert alert is None
        alert = m.record_deviation(_make_result(3.0, True))
        assert alert is not None
        assert alert.consecutive_count == 3

    def test_continued_breaches_emit_more_alerts(self, monitor):
        """After first alert, continued breaches emit additional alerts."""
        # First 5 breaches -> first alert
        for _ in range(5):
            monitor.record_deviation(_make_result(3.0, True))

        # 6th breach -> another alert (consecutive_count = 6)
        alert = monitor.record_deviation(_make_result(3.0, True))
        assert alert is not None
        assert alert.consecutive_count == 6

    def test_alert_contains_feature_delta(self, monitor):
        """Alert includes feature_delta mapping."""
        for _ in range(5):
            monitor.record_deviation(_make_result(3.0, True))
        alert = monitor.last_alert
        assert alert is not None
        assert isinstance(alert.feature_delta, dict)
        assert len(alert.feature_delta) > 0

    def test_alert_to_dict(self, monitor):
        """Alert serialises to dict with all required fields."""
        for _ in range(5):
            monitor.record_deviation(_make_result(3.0, True))
        alert = monitor.last_alert
        d = alert.to_dict()
        assert "alert_id" in d
        assert "severity" in d
        assert "model_id" in d
        assert "baseline_version" in d
        assert "deviation_scores" in d
        assert "feature_delta" in d
        assert "consecutive_count" in d
        assert "alignment_status" in d


class TestSP350AlignmentStatus:
    """SP-353: alignment status badge transitions."""

    def test_initial_status_is_aligned(self, monitor):
        assert monitor.get_alignment_status() == STATUS_ALIGNED

    def test_drifting_at_half_threshold(self, monitor):
        """Status transitions to DRIFTING at ceil(threshold/2) breaches."""
        # threshold=5, so drifting at 3
        for _ in range(3):
            monitor.record_deviation(_make_result(3.0, True))
        assert monitor.get_alignment_status() == STATUS_DRIFTING

    def test_swapped_at_threshold(self, monitor):
        """Status transitions to SWAPPED when alert is active."""
        for _ in range(5):
            monitor.record_deviation(_make_result(3.0, True))
        assert monitor.get_alignment_status() == STATUS_SWAPPED

    def test_returns_to_aligned_after_reset(self, monitor):
        """Status returns to ALIGNED when non-breaching response arrives."""
        for _ in range(5):
            monitor.record_deviation(_make_result(3.0, True))
        assert monitor.get_alignment_status() == STATUS_SWAPPED

        monitor.record_deviation(_make_result(0.5, False))
        assert monitor.get_alignment_status() == STATUS_ALIGNED


class TestSP350MonitorReset:
    """SupplyChainMonitor reset behavior."""

    def test_reset_clears_all_state(self, monitor):
        for _ in range(5):
            monitor.record_deviation(_make_result(3.0, True))
        assert monitor.alert_active

        monitor.reset()
        assert not monitor.alert_active
        assert monitor.consecutive_breaches == 0
        assert monitor.total_alerts == 0
        assert monitor.total_responses_scored == 0
        assert monitor.last_alert is None

    def test_get_summary(self, monitor):
        for _ in range(3):
            monitor.record_deviation(_make_result(3.0, True))
        summary = monitor.get_summary()
        assert summary["consecutive_breaches"] == 3
        assert summary["total_responses_scored"] == 3
        assert summary["model_id"] == "test-model"


class TestSP350Rolling24h:
    """Rolling 24h statistics for dashboard."""

    def test_rolling_stats_empty(self, monitor):
        stats = monitor.get_rolling_24h_stats()
        assert stats["total_scored"] == 0
        assert stats["avg_deviation"] == 0.0

    def test_rolling_stats_populated(self, monitor):
        for _ in range(10):
            monitor.record_deviation(_make_result(1.5, False))
        stats = monitor.get_rolling_24h_stats()
        assert stats["total_scored"] == 10
        assert stats["avg_deviation"] == pytest.approx(1.5, abs=0.01)

    def test_per_feature_drift(self, monitor):
        for _ in range(5):
            monitor.record_deviation(_make_result(1.0, False))
        drift = monitor.get_per_feature_drift()
        assert len(drift) > 0
        for feature_name, values in drift.items():
            assert len(values) == 5
