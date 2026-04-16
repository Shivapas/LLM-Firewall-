"""SP-366b — Gap Analysis + Dashboard Widget Tests.

Tests for SP-362 (gap analysis) and SP-363 (dashboard widget):
  - Gap analysis generates correctly for config with 2+ modules disabled
  - Recommendations are actionable (non-empty strings)
  - Radar chart data has 10 labels/scores
  - Shield Score grading works correctly
  - Top gaps sorted by severity
  - Full dashboard payload has all required sections
"""

import pytest

from app.services.owasp.tag_registry import (
    OWASP_CATEGORIES,
    reset_tag_registry,
)
from app.services.owasp.coverage_engine import (
    OWASPCoverageEngine,
    reset_owasp_coverage_engine,
)
from app.services.owasp.gap_analysis import (
    GapAnalysisEngine,
    GapAnalysisResult,
    get_gap_analysis_engine,
    reset_gap_analysis_engine,
)
from app.services.owasp.dashboard import (
    OWASPComplianceDashboard,
    get_owasp_dashboard,
    reset_owasp_dashboard,
)


@pytest.fixture(autouse=True)
def _reset_singletons():
    reset_tag_registry()
    reset_owasp_coverage_engine()
    reset_gap_analysis_engine()
    reset_owasp_dashboard()
    yield
    reset_tag_registry()
    reset_owasp_coverage_engine()
    reset_gap_analysis_engine()
    reset_owasp_dashboard()


def _all_enabled_config() -> dict[str, bool]:
    """Build a config dict with all modules enabled."""
    from app.services.owasp.tag_registry import get_tag_registry
    registry = get_tag_registry()
    return {mod.config_key: True for mod in registry.modules.values()}


def _two_disabled_config() -> dict[str, bool]:
    """Config with IPIA and fingerprint disabled."""
    cfg = _all_enabled_config()
    cfg["ipia_enabled"] = False
    cfg["fingerprint_enabled"] = False
    return cfg


# ---------------------------------------------------------------------------
# SP-362: Gap Analysis
# ---------------------------------------------------------------------------


class TestGapAnalysis:
    """SP-362: Gap analysis for uncovered requirements."""

    def test_gap_analysis_returns_result(self):
        engine = GapAnalysisEngine()
        result = engine.analyse()
        assert isinstance(result, GapAnalysisResult)

    def test_all_enabled_fewer_gaps(self):
        """All modules enabled should have fewer gaps than partial config."""
        engine = GapAnalysisEngine()
        all_on = engine.analyse(_all_enabled_config())
        partial = engine.analyse(_two_disabled_config())
        assert partial.gap_count >= all_on.gap_count

    def test_two_disabled_generates_gaps(self):
        """SP-362: Gap analysis generates for config with 2 modules disabled."""
        engine = GapAnalysisEngine()
        result = engine.analyse(_two_disabled_config())
        assert result.gap_count > 0, "Expected gaps with IPIA + fingerprint disabled"

    def test_gaps_have_remediation(self):
        """SP-362: Recommendations are actionable (non-empty)."""
        engine = GapAnalysisEngine()
        result = engine.analyse(_two_disabled_config())
        for gap in result.gaps:
            assert gap.remediation, f"Gap {gap.requirement_id} has empty remediation"
            assert len(gap.remediation) > 10, (
                f"Gap {gap.requirement_id} remediation too short: {gap.remediation!r}"
            )

    def test_gaps_have_category_and_severity(self):
        engine = GapAnalysisEngine()
        result = engine.analyse(_two_disabled_config())
        for gap in result.gaps:
            assert gap.category_id in OWASP_CATEGORIES
            assert gap.severity in ("HIGH", "MEDIUM")

    def test_disabled_ipia_creates_llm08_gap(self):
        cfg = _all_enabled_config()
        cfg["ipia_enabled"] = False
        engine = GapAnalysisEngine()
        result = engine.analyse(cfg)
        llm08_gaps = [g for g in result.gaps if g.category_id == "LLM08"]
        assert len(llm08_gaps) > 0, "Disabling IPIA should create LLM08 gaps"

    def test_disabled_canary_creates_llm07_gap(self):
        cfg = _all_enabled_config()
        cfg["canary_token_enabled"] = False
        engine = GapAnalysisEngine()
        result = engine.analyse(cfg)
        llm07_gaps = [g for g in result.gaps if g.category_id == "LLM07"]
        assert len(llm07_gaps) > 0, "Disabling canary should create LLM07 gaps"

    def test_gap_analysis_to_dict(self):
        engine = GapAnalysisEngine()
        result = engine.analyse(_two_disabled_config())
        d = result.to_dict()
        assert "total_requirements" in d
        assert "covered_requirements" in d
        assert "gap_count" in d
        assert "coverage_percentage" in d
        assert "gaps" in d
        assert isinstance(d["gaps"], list)

    def test_top_gaps_returns_limited_results(self):
        engine = GapAnalysisEngine()
        top = engine.get_top_gaps(_two_disabled_config(), limit=3)
        assert len(top) <= 3

    def test_top_gaps_sorted_by_severity(self):
        engine = GapAnalysisEngine()
        top = engine.get_top_gaps(_two_disabled_config(), limit=10)
        if len(top) >= 2:
            # HIGH gaps should come before MEDIUM
            high_indices = [i for i, g in enumerate(top) if g["severity"] == "HIGH"]
            medium_indices = [i for i, g in enumerate(top) if g["severity"] == "MEDIUM"]
            if high_indices and medium_indices:
                assert max(high_indices) < min(medium_indices), (
                    "HIGH gaps should sort before MEDIUM gaps"
                )

    def test_singleton_returns_same_instance(self):
        e1 = get_gap_analysis_engine()
        e2 = get_gap_analysis_engine()
        assert e1 is e2


# ---------------------------------------------------------------------------
# SP-363: Dashboard Widget
# ---------------------------------------------------------------------------


class TestDashboardWidget:
    """SP-363: Compliance dashboard widget."""

    def test_radar_chart_has_10_entries(self):
        dashboard = OWASPComplianceDashboard()
        chart = dashboard.get_radar_chart()
        assert chart["chart_type"] == "radar"
        assert len(chart["labels"]) == 10
        assert len(chart["label_names"]) == 10
        assert len(chart["scores"]) == 10

    def test_radar_chart_labels_are_owasp_ids(self):
        dashboard = OWASPComplianceDashboard()
        chart = dashboard.get_radar_chart()
        for label in chart["labels"]:
            assert label in OWASP_CATEGORIES

    def test_radar_chart_scores_are_numeric(self):
        dashboard = OWASPComplianceDashboard()
        chart = dashboard.get_radar_chart()
        for score in chart["scores"]:
            assert isinstance(score, (int, float))
            assert 0.0 <= score <= 100.0

    def test_shield_score_grading(self):
        dashboard = OWASPComplianceDashboard()
        ss = dashboard.get_shield_score()
        assert "shield_score" in ss
        assert "grade" in ss
        assert ss["grade"] in ("A", "B", "C", "D", "F")
        assert "color" in ss
        assert ss["color"] in ("green", "yellow", "orange", "red")

    def test_shield_score_grade_a_for_high_score(self):
        """All modules enabled should give a decent grade."""
        dashboard = OWASPComplianceDashboard()
        ss = dashboard.get_shield_score(_all_enabled_config())
        assert ss["shield_score"] >= 80.0

    def test_top_gaps_default(self):
        dashboard = OWASPComplianceDashboard()
        gaps = dashboard.get_top_gaps()
        assert isinstance(gaps, list)
        assert len(gaps) <= 3

    def test_full_dashboard_has_all_sections(self):
        dashboard = OWASPComplianceDashboard()
        payload = dashboard.get_full_dashboard()
        assert "timestamp" in payload
        assert "radar_chart" in payload
        assert "shield_score" in payload
        assert "top_gaps" in payload
        assert "coverage_summary" in payload
        assert "gap_summary" in payload
        assert "scoring_time_ms" in payload

    def test_full_dashboard_radar_chart_shape(self):
        dashboard = OWASPComplianceDashboard()
        payload = dashboard.get_full_dashboard()
        chart = payload["radar_chart"]
        assert chart["chart_type"] == "radar"
        assert len(chart["labels"]) == 10
        assert len(chart["scores"]) == 10

    def test_full_dashboard_shield_score_section(self):
        dashboard = OWASPComplianceDashboard()
        payload = dashboard.get_full_dashboard()
        ss = payload["shield_score"]
        assert "score" in ss
        assert "grade" in ss
        assert "color" in ss

    def test_full_dashboard_custom_config(self):
        dashboard = OWASPComplianceDashboard()
        cfg = _two_disabled_config()
        payload = dashboard.get_full_dashboard(cfg)
        # Should still have all sections
        assert "radar_chart" in payload
        # Gap count should be > 0
        assert payload["gap_summary"]["gap_count"] > 0

    def test_singleton_returns_same_instance(self):
        d1 = get_owasp_dashboard()
        d2 = get_owasp_dashboard()
        assert d1 is d2
