"""SP-366c — PDF + JSON Compliance Export Tests.

Tests for SP-364 (PDF export) and SP-365 (JSON export):
  - PDF renders correctly with all 10 categories
  - PDF contains scores and gap analysis
  - PDF has config snapshot
  - JSON export validates against expected schema
  - JSON export importable (round-trip parse)
  - JSON has all 10 categories with scores, modules, gaps, recommendations
"""

import json

import pytest

from app.services.owasp.tag_registry import (
    OWASP_CATEGORIES,
    reset_tag_registry,
)
from app.services.owasp.coverage_engine import reset_owasp_coverage_engine
from app.services.owasp.gap_analysis import reset_gap_analysis_engine
from app.services.owasp.compliance_export import (
    ComplianceExportEngine,
    JSONComplianceExport,
    PDFComplianceReport,
    SPHINX_VERSION,
    get_compliance_export_engine,
    reset_compliance_export_engine,
)


@pytest.fixture(autouse=True)
def _reset_singletons():
    reset_tag_registry()
    reset_owasp_coverage_engine()
    reset_gap_analysis_engine()
    reset_compliance_export_engine()
    yield
    reset_tag_registry()
    reset_owasp_coverage_engine()
    reset_gap_analysis_engine()
    reset_compliance_export_engine()


def _all_enabled_config() -> dict[str, bool]:
    from app.services.owasp.tag_registry import get_tag_registry
    registry = get_tag_registry()
    return {mod.config_key: True for mod in registry.modules.values()}


def _three_disabled_config() -> dict[str, bool]:
    """Config with 3 modules disabled for gap analysis testing."""
    cfg = _all_enabled_config()
    cfg["ipia_enabled"] = False
    cfg["fingerprint_enabled"] = False
    cfg["canary_token_enabled"] = False
    return cfg


# ---------------------------------------------------------------------------
# SP-365: JSON Export
# ---------------------------------------------------------------------------


class TestJSONExport:
    """SP-365: Machine-readable JSON compliance export."""

    def test_json_export_returns_object(self):
        engine = ComplianceExportEngine()
        export = engine.export_json()
        assert isinstance(export, JSONComplianceExport)

    def test_json_export_has_10_categories(self):
        engine = ComplianceExportEngine()
        export = engine.export_json()
        assert len(export.categories) == 10

    def test_json_export_category_ids_match(self):
        engine = ComplianceExportEngine()
        export = engine.export_json()
        cat_ids = [c.category for c in export.categories]
        for cat_id in OWASP_CATEGORIES:
            assert cat_id in cat_ids, f"Missing category {cat_id}"

    def test_json_export_category_has_score(self):
        engine = ComplianceExportEngine()
        export = engine.export_json()
        for cat in export.categories:
            assert isinstance(cat.score, (int, float))
            assert 0.0 <= cat.score <= 100.0

    def test_json_export_category_has_modules(self):
        engine = ComplianceExportEngine()
        export = engine.export_json(_all_enabled_config())
        for cat in export.categories:
            assert isinstance(cat.modules, list)
            assert len(cat.modules) >= 1, (
                f"Category {cat.category} has no modules"
            )

    def test_json_export_modules_have_enabled_field(self):
        engine = ComplianceExportEngine()
        export = engine.export_json(_all_enabled_config())
        for cat in export.categories:
            for mod in cat.modules:
                assert "enabled" in mod
                assert "name" in mod
                assert "config_key" in mod

    def test_json_export_has_gaps_for_disabled_config(self):
        engine = ComplianceExportEngine()
        export = engine.export_json(_three_disabled_config())
        total_gaps = sum(len(c.gaps) for c in export.categories)
        assert total_gaps > 0, "Expected gaps with 3 modules disabled"

    def test_json_export_has_recommendations_for_gaps(self):
        engine = ComplianceExportEngine()
        export = engine.export_json(_three_disabled_config())
        total_recs = sum(len(c.recommendations) for c in export.categories)
        assert total_recs > 0, "Expected recommendations for gaps"

    def test_json_export_has_shield_score(self):
        engine = ComplianceExportEngine()
        export = engine.export_json()
        assert 0.0 <= export.shield_score <= 100.0

    def test_json_export_has_config_snapshot(self):
        engine = ComplianceExportEngine()
        export = engine.export_json()
        assert isinstance(export.config_snapshot, dict)
        assert len(export.config_snapshot) >= 10  # At least 10 config keys

    def test_json_export_has_version_info(self):
        engine = ComplianceExportEngine()
        export = engine.export_json()
        assert export.sphinx_version == SPHINX_VERSION
        assert export.owasp_version == "2025"
        assert export.export_version == "1.0.0"

    def test_json_export_to_dict_serializable(self):
        engine = ComplianceExportEngine()
        export = engine.export_json()
        d = export.to_dict()
        # Should be JSON-serializable
        json_str = json.dumps(d)
        assert len(json_str) > 100

    def test_json_export_round_trip(self):
        """SP-365: JSON export importable — round-trip parse."""
        engine = ComplianceExportEngine()
        export = engine.export_json()
        json_str = export.to_json()
        parsed = json.loads(json_str)
        assert parsed["sphinx_version"] == SPHINX_VERSION
        assert len(parsed["categories"]) == 10
        assert "shield_score" in parsed

    def test_json_export_to_json_method(self):
        engine = ComplianceExportEngine()
        export = engine.export_json()
        json_str = export.to_json(indent=2)
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert "categories" in parsed

    def test_json_export_generated_at_timestamp(self):
        engine = ComplianceExportEngine()
        export = engine.export_json()
        assert export.generated_at > 0

    def test_singleton_returns_same_instance(self):
        e1 = get_compliance_export_engine()
        e2 = get_compliance_export_engine()
        assert e1 is e2


# ---------------------------------------------------------------------------
# SP-364: PDF Export
# ---------------------------------------------------------------------------


class TestPDFExport:
    """SP-364: PDF compliance report export."""

    def test_pdf_export_returns_report(self):
        engine = ComplianceExportEngine()
        report = engine.export_pdf()
        assert isinstance(report, PDFComplianceReport)

    def test_pdf_report_has_title(self):
        engine = ComplianceExportEngine()
        report = engine.export_pdf()
        assert "TrustFabric" in report.title
        assert "OWASP" in report.title

    def test_pdf_report_has_version(self):
        engine = ComplianceExportEngine()
        report = engine.export_pdf()
        assert report.sphinx_version == SPHINX_VERSION

    def test_pdf_report_has_shield_score(self):
        engine = ComplianceExportEngine()
        report = engine.export_pdf()
        assert 0.0 <= report.shield_score <= 100.0

    def test_pdf_report_has_grade(self):
        engine = ComplianceExportEngine()
        report = engine.export_pdf()
        assert report.grade in ("A", "B", "C", "D", "F")

    def test_pdf_report_has_sections(self):
        engine = ComplianceExportEngine()
        report = engine.export_pdf()
        assert len(report.sections) >= 3  # Summary, scores, config at minimum

    def test_pdf_report_score_table_has_all_10_categories(self):
        """SP-364: All 10 categories present in the score table."""
        engine = ComplianceExportEngine()
        report = engine.export_pdf()
        # Find the score table section
        score_section = None
        for s in report.sections:
            if "Category Scores" in s.title:
                score_section = s
                break
        assert score_section is not None, "Score table section not found"
        assert score_section.table is not None
        # Table has header + 10 data rows
        assert len(score_section.table) == 11, (
            f"Expected 11 rows (header + 10), got {len(score_section.table)}"
        )

    def test_pdf_report_gap_analysis_section_with_disabled(self):
        """SP-364: Gap analysis on 3-module-disabled config."""
        engine = ComplianceExportEngine()
        report = engine.export_pdf(_three_disabled_config())
        gap_section = None
        for s in report.sections:
            if "Gap Analysis" in s.title:
                gap_section = s
                break
        assert gap_section is not None, "Gap analysis section not found"
        # Should have a table with gaps
        assert gap_section.table is not None
        assert len(gap_section.table) > 1, "Gap table should have data rows"

    def test_pdf_report_remediation_section(self):
        engine = ComplianceExportEngine()
        report = engine.export_pdf(_three_disabled_config())
        remediation_section = None
        for s in report.sections:
            if "Remediation" in s.title:
                remediation_section = s
                break
        assert remediation_section is not None, "Remediation section not found"
        assert len(remediation_section.content) > 20

    def test_pdf_report_config_snapshot_section(self):
        """SP-364: Config snapshot matches environment."""
        engine = ComplianceExportEngine()
        report = engine.export_pdf()
        config_section = None
        for s in report.sections:
            if "Configuration" in s.title:
                config_section = s
                break
        assert config_section is not None, "Config snapshot section not found"
        assert config_section.table is not None
        assert len(config_section.table) > 1

    def test_pdf_report_config_snapshot_dict(self):
        engine = ComplianceExportEngine()
        report = engine.export_pdf()
        assert isinstance(report.config_snapshot, dict)
        assert len(report.config_snapshot) >= 10

    def test_pdf_report_to_dict(self):
        engine = ComplianceExportEngine()
        report = engine.export_pdf()
        d = report.to_dict()
        assert "title" in d
        assert "brand" in d
        assert "sections" in d
        assert len(d["sections"]) >= 3

    def test_pdf_report_render_text(self):
        """SP-364: Text rendering works for testing."""
        engine = ComplianceExportEngine()
        report = engine.export_pdf()
        text = report.render_text()
        assert isinstance(text, str)
        assert "TrustFabric" in text
        assert "Shield Score" in text
        assert "LLM01" in text
        assert "LLM10" in text

    def test_pdf_render_text_with_gaps(self):
        engine = ComplianceExportEngine()
        report = engine.export_pdf(_three_disabled_config())
        text = report.render_text()
        assert "Gap Analysis" in text
        assert "Remediation" in text

    def test_pdf_report_generated_at_iso_format(self):
        engine = ComplianceExportEngine()
        report = engine.export_pdf()
        # Should be ISO 8601 format
        assert "T" in report.generated_at
        assert len(report.generated_at) > 10
