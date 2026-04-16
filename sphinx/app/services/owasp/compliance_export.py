"""SP-364 / SP-365: Compliance report export (PDF + JSON).

SP-364: PDF compliance report export
  - Branded TrustFabric report
  - Per-category score table
  - Gap analysis
  - Remediation guidance
  - Sphinx version + config snapshot

SP-365: JSON compliance export
  - Machine-readable {category, score, modules[], gaps[], recommendations[]}
  - Validates against schema spec
  - Importable into SIEM test environment
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from app.services.owasp.coverage_engine import (
    CoverageResult,
    OWASPCoverageEngine,
    get_owasp_coverage_engine,
)
from app.services.owasp.gap_analysis import (
    GapAnalysisEngine,
    GapAnalysisResult,
    get_gap_analysis_engine,
)
from app.services.owasp.tag_registry import OWASP_CATEGORIES, get_tag_registry

logger = logging.getLogger("sphinx.owasp.compliance_export")

# Sphinx version for the report
SPHINX_VERSION = "2.1.0"
REPORT_BRAND = "TrustFabric"


# ---------------------------------------------------------------------------
# JSON Export (SP-365)
# ---------------------------------------------------------------------------


@dataclass
class CategoryExport:
    """JSON export for a single OWASP category."""

    category: str
    category_name: str
    score: float
    modules: list[dict] = field(default_factory=list)
    gaps: list[dict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "category_name": self.category_name,
            "score": round(self.score, 1),
            "modules": self.modules,
            "gaps": self.gaps,
            "recommendations": self.recommendations,
        }


@dataclass
class JSONComplianceExport:
    """Full JSON compliance export."""

    export_version: str = "1.0.0"
    sphinx_version: str = SPHINX_VERSION
    owasp_version: str = "2025"
    generated_at: float = 0.0
    shield_score: float = 0.0
    categories: list[CategoryExport] = field(default_factory=list)
    config_snapshot: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "export_version": self.export_version,
            "sphinx_version": self.sphinx_version,
            "owasp_version": self.owasp_version,
            "generated_at": self.generated_at,
            "shield_score": round(self.shield_score, 1),
            "categories": [c.to_dict() for c in self.categories],
            "config_snapshot": self.config_snapshot,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# PDF Export (SP-364)
# ---------------------------------------------------------------------------


@dataclass
class PDFSection:
    """A section in the PDF compliance report."""

    title: str
    content: str
    table: list[list[str]] | None = None


@dataclass
class PDFComplianceReport:
    """Structured PDF compliance report data.

    The actual PDF rendering can be done by any PDF library (ReportLab,
    WeasyPrint, etc.).  This class provides the structured data that
    the renderer needs.

    SP-364 acceptance criteria:
      - Branded TrustFabric report
      - Per-category score table
      - Gap analysis
      - Remediation guidance
      - Sphinx version + config snapshot
    """

    title: str = ""
    brand: str = REPORT_BRAND
    sphinx_version: str = SPHINX_VERSION
    generated_at: str = ""
    shield_score: float = 0.0
    grade: str = ""
    sections: list[PDFSection] = field(default_factory=list)
    config_snapshot: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "brand": self.brand,
            "sphinx_version": self.sphinx_version,
            "generated_at": self.generated_at,
            "shield_score": round(self.shield_score, 1),
            "grade": self.grade,
            "sections": [
                {
                    "title": s.title,
                    "content": s.content,
                    "table": s.table,
                }
                for s in self.sections
            ],
            "config_snapshot": self.config_snapshot,
        }

    def render_text(self) -> str:
        """Render the report as formatted text (for testing / plain export).

        Production deployments should use a proper PDF library.
        """
        lines: list[str] = []
        lines.append("=" * 72)
        lines.append(f"  {self.brand} — OWASP LLM Top 10 v2025 Compliance Report")
        lines.append(f"  Sphinx AI Mesh Firewall v{self.sphinx_version}")
        lines.append(f"  Generated: {self.generated_at}")
        lines.append("=" * 72)
        lines.append("")
        lines.append(f"  Overall Shield Score: {self.shield_score:.1f} / 100  ({self.grade})")
        lines.append("")

        for section in self.sections:
            lines.append("-" * 72)
            lines.append(f"  {section.title}")
            lines.append("-" * 72)
            if section.content:
                lines.append(section.content)
            if section.table:
                # Simple table rendering
                col_widths = []
                for col_idx in range(len(section.table[0])):
                    max_w = max(len(row[col_idx]) for row in section.table)
                    col_widths.append(max_w)
                for row_idx, row in enumerate(section.table):
                    line = "  ".join(
                        cell.ljust(col_widths[i]) for i, cell in enumerate(row)
                    )
                    lines.append(f"  {line}")
                    if row_idx == 0:
                        lines.append("  " + "  ".join(
                            "-" * w for w in col_widths
                        ))
            lines.append("")

        lines.append("=" * 72)
        lines.append(f"  End of Report — {self.brand}")
        lines.append("=" * 72)

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Export Engine
# ---------------------------------------------------------------------------


class ComplianceExportEngine:
    """Generates PDF and JSON compliance exports."""

    def __init__(
        self,
        coverage_engine: OWASPCoverageEngine | None = None,
        gap_engine: GapAnalysisEngine | None = None,
    ) -> None:
        self._coverage = coverage_engine or get_owasp_coverage_engine()
        self._gap = gap_engine or get_gap_analysis_engine()

    def _build_config_snapshot(
        self, active_config: dict[str, bool] | None,
    ) -> dict:
        """Build a config snapshot showing module enabled states."""
        registry = self._coverage.registry
        snapshot: dict[str, bool] = {}
        for mod_key, mod in registry.modules.items():
            if active_config is not None and mod.config_key in active_config:
                snapshot[mod.config_key] = active_config[mod.config_key]
            else:
                snapshot[mod.config_key] = mod.default_enabled
        return snapshot

    # ── JSON Export (SP-365) ──────────────────────────────────────────

    def export_json(
        self,
        active_config: dict[str, bool] | None = None,
    ) -> JSONComplianceExport:
        """Generate machine-readable JSON compliance export.

        SP-365: {category, score, modules[], gaps[], recommendations[]}
        for each LLM01-LLM10.
        """
        coverage = self._coverage.compute_coverage(active_config)
        gap_result = self._gap.analyse(active_config, coverage_result=coverage)
        registry = self._coverage.registry

        categories: list[CategoryExport] = []
        for cat_id in OWASP_CATEGORIES:
            cat_score = coverage.category_scores.get(cat_id)
            if cat_score is None:
                continue

            # Modules for this category
            modules = []
            for mod in registry.get_modules_for_category(cat_id):
                is_enabled = (
                    active_config.get(mod.config_key, mod.default_enabled)
                    if active_config
                    else mod.default_enabled
                )
                modules.append({
                    "name": mod.name,
                    "config_key": mod.config_key,
                    "enabled": is_enabled,
                    "version": mod.version,
                })

            # Gaps for this category
            cat_gaps = [
                g.to_dict() for g in gap_result.gaps
                if g.category_id == cat_id
            ]

            # Recommendations
            recommendations = [g.remediation for g in gap_result.gaps if g.category_id == cat_id]

            categories.append(CategoryExport(
                category=cat_id,
                category_name=cat_score.category_name,
                score=cat_score.score,
                modules=modules,
                gaps=cat_gaps,
                recommendations=recommendations,
            ))

        return JSONComplianceExport(
            generated_at=time.time(),
            shield_score=coverage.shield_score,
            categories=categories,
            config_snapshot=self._build_config_snapshot(active_config),
        )

    # ── PDF Export (SP-364) ───────────────────────────────────────────

    def export_pdf(
        self,
        active_config: dict[str, bool] | None = None,
    ) -> PDFComplianceReport:
        """Generate structured PDF compliance report data.

        SP-364 acceptance criteria:
          - Branded TrustFabric report
          - Per-category score table
          - Gap analysis
          - Remediation guidance
          - Sphinx version + config snapshot
        """
        coverage = self._coverage.compute_coverage(active_config)
        gap_result = self._gap.analyse(active_config, coverage_result=coverage)

        shield = coverage.shield_score
        if shield >= 90:
            grade = "A"
        elif shield >= 80:
            grade = "B"
        elif shield >= 70:
            grade = "C"
        elif shield >= 60:
            grade = "D"
        else:
            grade = "F"

        sections: list[PDFSection] = []

        # Section 1: Executive Summary
        sections.append(PDFSection(
            title="Executive Summary",
            content=(
                f"This report presents the OWASP LLM Top 10 v2025 compliance "
                f"assessment for Sphinx AI Mesh Firewall v{SPHINX_VERSION}.\n\n"
                f"Overall Shield Score: {shield:.1f}/100 (Grade: {grade})\n"
                f"Coverage: {gap_result.covered_requirements}/{gap_result.total_requirements} "
                f"requirements fully addressed ({gap_result.coverage_percentage:.1f}%)\n"
                f"Gaps identified: {gap_result.gap_count}"
            ),
        ))

        # Section 2: Per-category score table
        score_table = [["Category", "Name", "Score", "Enabled Modules", "Disabled Modules"]]
        for cat_id in OWASP_CATEGORIES:
            cat_score = coverage.category_scores.get(cat_id)
            if cat_score:
                score_table.append([
                    cat_id,
                    cat_score.category_name,
                    f"{cat_score.score:.1f}%",
                    str(len(cat_score.enabled_modules)),
                    str(len(cat_score.disabled_modules)),
                ])
        sections.append(PDFSection(
            title="OWASP LLM Top 10 v2025 — Category Scores",
            content="",
            table=score_table,
        ))

        # Section 3: Gap analysis
        if gap_result.gaps:
            gap_table = [["Req ID", "Category", "Severity", "Description", "Remediation"]]
            for gap in gap_result.gaps:
                gap_table.append([
                    gap.requirement_id,
                    gap.category_id,
                    gap.severity,
                    gap.description[:60],
                    gap.remediation[:60],
                ])
            sections.append(PDFSection(
                title="Gap Analysis — Uncovered Requirements",
                content=f"{gap_result.gap_count} gaps identified across {len(set(g.category_id for g in gap_result.gaps))} categories.",
                table=gap_table,
            ))
        else:
            sections.append(PDFSection(
                title="Gap Analysis",
                content="No gaps identified. All OWASP LLM Top 10 v2025 requirements are fully addressed.",
            ))

        # Section 4: Remediation Guidance
        if gap_result.gaps:
            remediation_lines = []
            for gap in gap_result.gaps:
                remediation_lines.append(
                    f"  [{gap.severity}] {gap.requirement_id} ({gap.category_id}): {gap.remediation}"
                )
            sections.append(PDFSection(
                title="Remediation Guidance",
                content="\n".join(remediation_lines),
            ))

        # Section 5: Config snapshot
        config_snapshot = self._build_config_snapshot(active_config)
        config_table = [["Config Key", "Enabled"]]
        for k, v in sorted(config_snapshot.items()):
            config_table.append([k, "Yes" if v else "No"])
        sections.append(PDFSection(
            title="Sphinx Configuration Snapshot",
            content=f"Sphinx version: {SPHINX_VERSION}",
            table=config_table,
        ))

        from datetime import datetime, timezone

        return PDFComplianceReport(
            title=f"{REPORT_BRAND} — OWASP LLM Top 10 v2025 Compliance Report",
            shield_score=shield,
            grade=grade,
            generated_at=datetime.now(timezone.utc).isoformat(),
            sections=sections,
            config_snapshot=config_snapshot,
        )


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_export_engine: Optional[ComplianceExportEngine] = None


def get_compliance_export_engine() -> ComplianceExportEngine:
    """Get or create the singleton ComplianceExportEngine."""
    global _export_engine
    if _export_engine is None:
        _export_engine = ComplianceExportEngine()
    return _export_engine


def reset_compliance_export_engine() -> None:
    """Reset the singleton (for testing)."""
    global _export_engine
    _export_engine = None
