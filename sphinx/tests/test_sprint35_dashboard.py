"""Sprint 35 — SP-353: Inference Endpoint Health Dashboard Test Suite.

Tests for the inference endpoint health dashboard:
  - Status badge shows ALIGNED / DRIFTING / SWAPPED correctly
  - Deviation chart contains rolling 24h data
  - Drift chart contains per-feature z-scores
  - Full dashboard combines all components
  - Dashboard responds when baseline is not yet loaded
"""

import pytest

from app.services.fingerprint.feature_extractor import (
    StylemetricFeatureExtractor,
    reset_feature_extractor,
)
from app.services.fingerprint.baseline_profiler import (
    BaselineProfiler,
    reset_baseline_profiler,
)
from app.services.fingerprint.deviation_scorer import (
    DeviationResult,
    DeviationScorer,
    reset_deviation_scorer,
)
from app.services.fingerprint.supply_chain_monitor import (
    STATUS_ALIGNED,
    STATUS_DRIFTING,
    STATUS_SWAPPED,
    SupplyChainMonitor,
    reset_supply_chain_monitor,
)
from app.services.fingerprint.dashboard import (
    InferenceHealthDashboard,
    reset_inference_health_dashboard,
)


def _make_result(aggregate: float, triggered: bool) -> DeviationResult:
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
def dashboard():
    reset_feature_extractor()
    reset_baseline_profiler()
    reset_deviation_scorer()
    reset_supply_chain_monitor()
    reset_inference_health_dashboard()

    extractor = StylemetricFeatureExtractor()
    profiler = BaselineProfiler(extractor=extractor, warm_up_count=10, model_id="test")
    scorer = DeviationScorer(extractor=extractor, alert_threshold=2.5)
    monitor = SupplyChainMonitor(consecutive_threshold=5, model_id="test-model")
    dashboard = InferenceHealthDashboard(
        monitor=monitor,
        profiler=profiler,
        scorer=scorer,
    )
    yield dashboard, monitor, profiler

    reset_feature_extractor()
    reset_baseline_profiler()
    reset_deviation_scorer()
    reset_supply_chain_monitor()
    reset_inference_health_dashboard()


class TestSP353StatusBadge:
    """Status badge transitions correctly."""

    def test_initial_badge_aligned(self, dashboard):
        dash, monitor, _ = dashboard
        badge = dash.get_status_badge()
        assert badge["status"] == STATUS_ALIGNED
        assert badge["color"] == "green"

    def test_badge_drifting(self, dashboard):
        dash, monitor, _ = dashboard
        for _ in range(3):
            monitor.record_deviation(_make_result(3.0, True))
        badge = dash.get_status_badge()
        assert badge["status"] == STATUS_DRIFTING
        assert badge["color"] == "yellow"

    def test_badge_swapped(self, dashboard):
        dash, monitor, _ = dashboard
        for _ in range(5):
            monitor.record_deviation(_make_result(3.0, True))
        badge = dash.get_status_badge()
        assert badge["status"] == STATUS_SWAPPED
        assert badge["color"] == "red"

    def test_badge_returns_to_aligned(self, dashboard):
        dash, monitor, _ = dashboard
        for _ in range(5):
            monitor.record_deviation(_make_result(3.0, True))
        assert dash.get_status_badge()["status"] == STATUS_SWAPPED

        monitor.record_deviation(_make_result(0.5, False))
        assert dash.get_status_badge()["status"] == STATUS_ALIGNED

    def test_badge_contains_model_id(self, dashboard):
        dash, _, _ = dashboard
        badge = dash.get_status_badge()
        assert badge["model_id"] == "test-model"

    def test_badge_profile_loaded_flag(self, dashboard):
        dash, _, profiler = dashboard
        badge = dash.get_status_badge()
        assert badge["profile_loaded"] is False

        # Warm up and compute profile
        responses = [
            "Test response one.", "Test response two.",
            "Test response three.", "Test response four.",
            "Test response five.", "Test response six.",
            "Test response seven.", "Test response eight.",
            "Test response nine.", "Test response ten.",
        ]
        for r in responses:
            profiler.add_response(r)
        profiler.compute_profile()

        badge = dash.get_status_badge()
        assert badge["profile_loaded"] is True


class TestSP353DeviationChart:
    """Rolling 24h deviation chart."""

    def test_empty_chart(self, dashboard):
        dash, _, _ = dashboard
        chart = dash.get_deviation_chart()
        assert chart["chart_type"] == "time_series"
        assert chart["stats"]["total_scored"] == 0

    def test_chart_with_data(self, dashboard):
        dash, monitor, _ = dashboard
        for _ in range(10):
            monitor.record_deviation(_make_result(1.5, False))

        chart = dash.get_deviation_chart()
        assert chart["stats"]["total_scored"] == 10
        assert len(chart["data"]["deviation_scores"]) == 10
        assert len(chart["data"]["timestamps"]) == 10
        assert chart["data"]["threshold_line"] == 2.5

    def test_chart_stats_correct(self, dashboard):
        dash, monitor, _ = dashboard
        monitor.record_deviation(_make_result(1.0, False))
        monitor.record_deviation(_make_result(3.0, True))

        chart = dash.get_deviation_chart()
        assert chart["stats"]["total_scored"] == 2
        assert chart["stats"]["alerts_triggered"] == 1


class TestSP353DriftChart:
    """Per-feature drift chart."""

    def test_empty_drift(self, dashboard):
        dash, _, _ = dashboard
        chart = dash.get_drift_chart()
        assert chart["chart_type"] == "multi_line"
        assert chart["sample_count"] == 0

    def test_drift_with_data(self, dashboard):
        dash, monitor, _ = dashboard
        for _ in range(5):
            monitor.record_deviation(_make_result(1.0, False))

        chart = dash.get_drift_chart()
        assert chart["sample_count"] == 5
        assert len(chart["data"]) > 0


class TestSP353FullDashboard:
    """Full dashboard combines all components."""

    def test_full_dashboard_structure(self, dashboard):
        dash, monitor, _ = dashboard
        for _ in range(3):
            monitor.record_deviation(_make_result(1.0, False))

        full = dash.get_full_dashboard()
        assert "timestamp" in full
        assert "status_badge" in full
        assert "deviation_chart" in full
        assert "drift_chart" in full
        assert "monitor_summary" in full

    def test_dashboard_status_badge_transitions_on_import(self, dashboard):
        """SP-353 acceptance: simulate different baseline by importing mismatch."""
        dash, monitor, profiler = dashboard

        # Start with ALIGNED
        assert dash.get_status_badge()["status"] == STATUS_ALIGNED

        # Simulate high-deviation responses (as if model was swapped)
        for _ in range(5):
            monitor.record_deviation(_make_result(4.0, True))

        # Should show SWAPPED
        assert dash.get_status_badge()["status"] == STATUS_SWAPPED
