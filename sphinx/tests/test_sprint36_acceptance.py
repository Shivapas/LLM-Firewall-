"""SP-366e — Sprint 36 Acceptance Criteria Validation.

Tests each sprint-level acceptance criterion from Sphinx_Sprint_Plan_Roadmap_v1.md:

  1. OWASPCoverageEngine returns correct scores: LLM08 score drops when IPIA
     disabled, recovers when re-enabled
  2. LLM07 score >= 90 with canary token enabled; <= 50 with canary disabled
  3. LLM03 score >= 85 with model fingerprinting enabled
  4. Overall Shield Score >= 85 for default Roadmap v1 configuration
  5. PDF export renders all 10 categories with scores and gap analysis on
     3-module-disabled test config
  6. Phase 9 E2E: IPIA blocks 5/5 injected chunks; canary alerts on extraction;
     model swap detected within 5 responses; OWASP re-score < 500ms
"""

import json
import time

import pytest

from app.services.owasp.tag_registry import (
    OWASP_CATEGORIES,
    get_tag_registry,
    reset_tag_registry,
)
from app.services.owasp.coverage_engine import (
    OWASPCoverageEngine,
    reset_owasp_coverage_engine,
)
from app.services.owasp.gap_analysis import (
    GapAnalysisEngine,
    reset_gap_analysis_engine,
)
from app.services.owasp.dashboard import (
    OWASPComplianceDashboard,
    reset_owasp_dashboard,
)
from app.services.owasp.compliance_export import (
    ComplianceExportEngine,
    reset_compliance_export_engine,
)


@pytest.fixture(autouse=True)
def _reset_singletons():
    reset_tag_registry()
    reset_owasp_coverage_engine()
    reset_gap_analysis_engine()
    reset_owasp_dashboard()
    reset_compliance_export_engine()
    yield
    reset_tag_registry()
    reset_owasp_coverage_engine()
    reset_gap_analysis_engine()
    reset_owasp_dashboard()
    reset_compliance_export_engine()


def _all_enabled_config() -> dict[str, bool]:
    """Roadmap v1 default: all modules enabled (including E15-E17)."""
    registry = get_tag_registry()
    return {mod.config_key: True for mod in registry.modules.values()}


def _three_disabled_config() -> dict[str, bool]:
    """Config with 3 modules disabled for PDF gap analysis test."""
    cfg = _all_enabled_config()
    cfg["ipia_enabled"] = False
    cfg["fingerprint_enabled"] = False
    cfg["canary_token_enabled"] = False
    return cfg


# ---------------------------------------------------------------------------
# Acceptance Criterion 1: LLM08 score drops/recovers with IPIA toggle
# ---------------------------------------------------------------------------


class TestAC1_LLM08_IPIA_Toggle:
    """OWASPCoverageEngine: LLM08 drops when IPIA disabled, recovers when re-enabled."""

    def test_llm08_drops_when_ipia_disabled(self):
        engine = OWASPCoverageEngine()
        cfg_on = _all_enabled_config()
        cfg_off = dict(cfg_on)
        cfg_off["ipia_enabled"] = False

        score_on = engine.compute_coverage(cfg_on).category_scores["LLM08"].score
        score_off = engine.compute_coverage(cfg_off).category_scores["LLM08"].score

        assert score_off < score_on, (
            f"LLM08 did not drop: on={score_on:.1f}, off={score_off:.1f}"
        )

    def test_llm08_recovers_when_ipia_re_enabled(self):
        engine = OWASPCoverageEngine()
        cfg = _all_enabled_config()

        score_initial = engine.compute_coverage(cfg).category_scores["LLM08"].score

        cfg["ipia_enabled"] = False
        score_disabled = engine.compute_coverage(cfg).category_scores["LLM08"].score

        cfg["ipia_enabled"] = True
        score_recovered = engine.compute_coverage(cfg).category_scores["LLM08"].score

        assert score_disabled < score_initial
        assert score_recovered == score_initial, (
            f"LLM08 did not recover: initial={score_initial:.1f}, "
            f"recovered={score_recovered:.1f}"
        )


# ---------------------------------------------------------------------------
# Acceptance Criterion 2: LLM07 >= 90 with canary; <= 50 without
# ---------------------------------------------------------------------------


class TestAC2_LLM07_Canary:
    """LLM07 score >= 90 with canary enabled; <= 50 with canary disabled."""

    def test_llm07_ge_90_with_canary_enabled(self):
        engine = OWASPCoverageEngine()
        cfg = _all_enabled_config()
        score = engine.compute_coverage(cfg).category_scores["LLM07"].score
        assert score >= 90.0, f"LLM07 score {score:.1f} < 90 with canary enabled"

    def test_llm07_le_50_with_canary_disabled(self):
        engine = OWASPCoverageEngine()
        cfg = _all_enabled_config()
        cfg["canary_token_enabled"] = False
        score = engine.compute_coverage(cfg).category_scores["LLM07"].score
        assert score <= 50.0, f"LLM07 score {score:.1f} > 50 with canary disabled"


# ---------------------------------------------------------------------------
# Acceptance Criterion 3: LLM03 >= 85 with fingerprinting enabled
# ---------------------------------------------------------------------------


class TestAC3_LLM03_Fingerprint:
    """LLM03 score >= 85 with model fingerprinting enabled."""

    def test_llm03_ge_85_with_fingerprint_enabled(self):
        engine = OWASPCoverageEngine()
        cfg = _all_enabled_config()
        score = engine.compute_coverage(cfg).category_scores["LLM03"].score
        assert score >= 85.0, f"LLM03 score {score:.1f} < 85 with fingerprint enabled"


# ---------------------------------------------------------------------------
# Acceptance Criterion 4: Shield Score >= 85 for default Roadmap v1 config
# ---------------------------------------------------------------------------


class TestAC4_ShieldScore:
    """Overall Shield Score >= 85 for default Roadmap v1 configuration."""

    def test_shield_score_ge_85(self):
        engine = OWASPCoverageEngine()
        cfg = _all_enabled_config()
        result = engine.compute_coverage(cfg)
        assert result.shield_score >= 85.0, (
            f"Shield Score {result.shield_score:.1f} < 85 for Roadmap v1 config"
        )

    def test_shield_score_grade_a_or_b(self):
        dashboard = OWASPComplianceDashboard()
        ss = dashboard.get_shield_score(_all_enabled_config())
        assert ss["grade"] in ("A", "B"), f"Grade {ss['grade']} not A or B"


# ---------------------------------------------------------------------------
# Acceptance Criterion 5: PDF export renders all 10 categories on 3-disabled
# ---------------------------------------------------------------------------


class TestAC5_PDFExport:
    """PDF export: all 10 categories, scores, gap analysis on 3-disabled config."""

    def test_pdf_has_all_10_categories(self):
        engine = ComplianceExportEngine()
        report = engine.export_pdf(_three_disabled_config())

        # Find score table section
        score_section = None
        for s in report.sections:
            if "Category Scores" in s.title:
                score_section = s
                break
        assert score_section is not None

        # Check all 10 categories present in table (header + 10 rows)
        assert score_section.table is not None
        cat_ids = [row[0] for row in score_section.table[1:]]
        for cat_id in OWASP_CATEGORIES:
            assert cat_id in cat_ids, f"Category {cat_id} missing from PDF"

    def test_pdf_has_gap_analysis_for_disabled_modules(self):
        engine = ComplianceExportEngine()
        report = engine.export_pdf(_three_disabled_config())

        gap_section = None
        for s in report.sections:
            if "Gap Analysis" in s.title and "Uncovered" in s.title:
                gap_section = s
                break
        assert gap_section is not None, "Gap analysis section missing"
        assert gap_section.table is not None
        # Should have at least header + some gap rows
        assert len(gap_section.table) > 1

    def test_pdf_has_config_snapshot(self):
        engine = ComplianceExportEngine()
        report = engine.export_pdf(_three_disabled_config())
        assert isinstance(report.config_snapshot, dict)
        assert report.config_snapshot.get("ipia_enabled") is False
        assert report.config_snapshot.get("fingerprint_enabled") is False
        assert report.config_snapshot.get("canary_token_enabled") is False

    def test_pdf_text_render_contains_all_categories(self):
        engine = ComplianceExportEngine()
        report = engine.export_pdf(_three_disabled_config())
        text = report.render_text()
        for cat_id in OWASP_CATEGORIES:
            assert cat_id in text, f"{cat_id} missing from PDF text"


# ---------------------------------------------------------------------------
# Acceptance Criterion 6: Phase 9 E2E (OWASP re-score < 500ms specifically)
# ---------------------------------------------------------------------------


class TestAC6_OWASPRescore:
    """OWASP re-score completes < 500ms on config change."""

    def test_rescore_under_500ms_100_iterations(self):
        """Run 100 re-scores with config changes, all < 500ms."""
        engine = OWASPCoverageEngine()
        cfg = _all_enabled_config()

        times = []
        for i in range(100):
            # Toggle a module each iteration
            key = list(cfg.keys())[i % len(cfg)]
            cfg[key] = not cfg[key]

            start = time.perf_counter()
            engine.compute_coverage(cfg)
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

            # Restore
            cfg[key] = not cfg[key]

        max_time = max(times)
        avg_time = sum(times) / len(times)
        assert max_time < 500.0, f"Max re-score time {max_time:.2f}ms > 500ms"
        assert avg_time < 50.0, f"Avg re-score time {avg_time:.2f}ms > 50ms"


# ---------------------------------------------------------------------------
# JSON Export Schema Validation
# ---------------------------------------------------------------------------


class TestJSONSchemaValidation:
    """SP-365: JSON export validates against schema spec."""

    def test_json_schema_structure(self):
        engine = ComplianceExportEngine()
        export = engine.export_json(_all_enabled_config())
        d = export.to_dict()

        # Top-level fields
        assert "export_version" in d
        assert "sphinx_version" in d
        assert "owasp_version" in d
        assert "generated_at" in d
        assert "shield_score" in d
        assert "categories" in d
        assert "config_snapshot" in d

        # Each category has required fields
        for cat in d["categories"]:
            assert "category" in cat
            assert "category_name" in cat
            assert "score" in cat
            assert "modules" in cat
            assert "gaps" in cat
            assert "recommendations" in cat

            assert isinstance(cat["score"], (int, float))
            assert isinstance(cat["modules"], list)
            assert isinstance(cat["gaps"], list)
            assert isinstance(cat["recommendations"], list)

            # Each module has required fields
            for mod in cat["modules"]:
                assert "name" in mod
                assert "config_key" in mod
                assert "enabled" in mod

    def test_json_importable_into_siem(self):
        """JSON export should be parseable and contain event-like structure."""
        engine = ComplianceExportEngine()
        export = engine.export_json(_all_enabled_config())
        json_str = export.to_json()

        # Should be valid JSON
        parsed = json.loads(json_str)

        # Should have enough data for SIEM import
        assert len(parsed["categories"]) == 10
        assert parsed["shield_score"] > 0
        assert len(parsed["config_snapshot"]) > 0


# ---------------------------------------------------------------------------
# Roadmap v1 Release Checklist Validation (relevant items)
# ---------------------------------------------------------------------------


class TestRoadmapV1Checklist:
    """Validate Roadmap v1 release checklist items for OWASP (E18)."""

    def test_tag_registry_reviewed(self):
        """OWASP: Tag registry covers all Sphinx modules."""
        registry = get_tag_registry()
        assert registry.module_count >= 33

    def test_shield_score_ge_85(self):
        """OWASP: Shield Score >= 85 for default Roadmap v1 config."""
        engine = OWASPCoverageEngine()
        result = engine.compute_coverage(_all_enabled_config())
        assert result.shield_score >= 85.0

    def test_json_export_validates(self):
        """OWASP: JSON export validates against schema spec."""
        engine = ComplianceExportEngine()
        export = engine.export_json()
        json_str = export.to_json()
        parsed = json.loads(json_str)
        assert len(parsed["categories"]) == 10

    def test_rescore_latency(self):
        """OWASP: Re-score latency < 500ms confirmed."""
        engine = OWASPCoverageEngine()
        start = time.perf_counter()
        engine.compute_coverage(_all_enabled_config())
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 500.0

    def test_phase9_e2e_owasp_rescore(self):
        """QA: Phase 9 E2E — OWASP re-score on config change."""
        engine = OWASPCoverageEngine()
        cfg = _all_enabled_config()

        r1 = engine.compute_coverage(cfg)
        cfg["ipia_enabled"] = False
        r2 = engine.compute_coverage(cfg)

        assert r2.category_scores["LLM08"].score < r1.category_scores["LLM08"].score
        assert r2.scoring_time_ms < 500.0
