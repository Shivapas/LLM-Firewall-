"""SP-363: OWASP compliance dashboard widget.

Provides data for the admin dashboard:
  - Radar chart (LLM01-LLM10 scores)
  - Overall Shield Score (weighted average)
  - Top 3 gaps

SP-363 acceptance criteria:
  - Radar chart renders in admin dashboard
  - Shield Score >= 85 for default Sphinx Roadmap v1 configuration
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from app.services.owasp.coverage_engine import (
    CoverageResult,
    OWASPCoverageEngine,
    get_owasp_coverage_engine,
)
from app.services.owasp.gap_analysis import (
    GapAnalysisEngine,
    get_gap_analysis_engine,
)
from app.services.owasp.tag_registry import OWASP_CATEGORIES

logger = logging.getLogger("sphinx.owasp.dashboard")


class OWASPComplianceDashboard:
    """Dashboard data provider for OWASP LLM Top 10 v2025 compliance.

    Combines coverage scoring and gap analysis into a single dashboard
    payload suitable for rendering in the admin UI.
    """

    def __init__(
        self,
        coverage_engine: OWASPCoverageEngine | None = None,
        gap_engine: GapAnalysisEngine | None = None,
    ) -> None:
        self._coverage = coverage_engine or get_owasp_coverage_engine()
        self._gap = gap_engine or get_gap_analysis_engine()

    def get_radar_chart(
        self,
        active_config: dict[str, bool] | None = None,
    ) -> dict:
        """Return radar chart data for LLM01-LLM10 scores.

        Returns:
            {
                "chart_type": "radar",
                "title": "OWASP LLM Top 10 v2025 Coverage",
                "labels": ["LLM01", ..., "LLM10"],
                "label_names": ["Prompt Injection", ..., "Unbounded Consumption"],
                "scores": [score1, ..., score10],
                "shield_score": float,
            }
        """
        result = self._coverage.compute_coverage(active_config)

        labels = []
        label_names = []
        scores = []
        for cat_id in OWASP_CATEGORIES:
            cat_score = result.category_scores.get(cat_id)
            labels.append(cat_id)
            label_names.append(cat_score.category_name if cat_score else cat_id)
            scores.append(round(cat_score.score, 1) if cat_score else 0.0)

        return {
            "chart_type": "radar",
            "title": "OWASP LLM Top 10 v2025 Coverage",
            "labels": labels,
            "label_names": label_names,
            "scores": scores,
            "shield_score": round(result.shield_score, 1),
        }

    def get_shield_score(
        self,
        active_config: dict[str, bool] | None = None,
    ) -> dict:
        """Return the overall Shield Score.

        Returns:
            {
                "shield_score": float,
                "grade": "A" | "B" | "C" | "D" | "F",
                "color": "green" | "yellow" | "orange" | "red",
            }
        """
        result = self._coverage.compute_coverage(active_config)
        score = result.shield_score

        if score >= 90:
            grade, color = "A", "green"
        elif score >= 80:
            grade, color = "B", "green"
        elif score >= 70:
            grade, color = "C", "yellow"
        elif score >= 60:
            grade, color = "D", "orange"
        else:
            grade, color = "F", "red"

        return {
            "shield_score": round(score, 1),
            "grade": grade,
            "color": color,
        }

    def get_top_gaps(
        self,
        active_config: dict[str, bool] | None = None,
        limit: int = 3,
    ) -> list[dict]:
        """Return top N coverage gaps."""
        return self._gap.get_top_gaps(active_config, limit=limit)

    def get_full_dashboard(
        self,
        active_config: dict[str, bool] | None = None,
    ) -> dict:
        """Return the complete OWASP compliance dashboard payload.

        Combines radar chart, Shield Score, top gaps, and full coverage
        into a single response.
        """
        result = self._coverage.compute_coverage(active_config)
        gap_result = self._gap.analyse(active_config, coverage_result=result)

        # Radar chart data
        labels = []
        label_names = []
        scores = []
        for cat_id in OWASP_CATEGORIES:
            cat_score = result.category_scores.get(cat_id)
            labels.append(cat_id)
            label_names.append(cat_score.category_name if cat_score else cat_id)
            scores.append(round(cat_score.score, 1) if cat_score else 0.0)

        # Shield Score grading
        shield = result.shield_score
        if shield >= 90:
            grade, color = "A", "green"
        elif shield >= 80:
            grade, color = "B", "green"
        elif shield >= 70:
            grade, color = "C", "yellow"
        elif shield >= 60:
            grade, color = "D", "orange"
        else:
            grade, color = "F", "red"

        # Top 3 gaps
        sorted_gaps = sorted(
            gap_result.gaps,
            key=lambda g: (0 if g.severity == "HIGH" else 1, g.category_id),
        )
        top_gaps = [g.to_dict() for g in sorted_gaps[:3]]

        return {
            "timestamp": time.time(),
            "radar_chart": {
                "chart_type": "radar",
                "title": "OWASP LLM Top 10 v2025 Coverage",
                "labels": labels,
                "label_names": label_names,
                "scores": scores,
            },
            "shield_score": {
                "score": round(shield, 1),
                "grade": grade,
                "color": color,
            },
            "top_gaps": top_gaps,
            "coverage_summary": result.to_dict(),
            "gap_summary": {
                "total_requirements": gap_result.total_requirements,
                "covered_requirements": gap_result.covered_requirements,
                "gap_count": gap_result.gap_count,
                "coverage_percentage": round(gap_result.coverage_percentage, 1),
            },
            "scoring_time_ms": round(result.scoring_time_ms, 3),
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_dashboard: Optional[OWASPComplianceDashboard] = None


def get_owasp_dashboard() -> OWASPComplianceDashboard:
    """Get or create the singleton OWASPComplianceDashboard."""
    global _dashboard
    if _dashboard is None:
        _dashboard = OWASPComplianceDashboard()
    return _dashboard


def reset_owasp_dashboard() -> None:
    """Reset the singleton (for testing)."""
    global _dashboard
    _dashboard = None
