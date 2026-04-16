"""SP-361: OWASPCoverageEngine -- per-category coverage scoring.

Computes per-category coverage scores (0-100%) from the active Sphinx
configuration.  Re-scores on config change in < 500ms.

SP-361 acceptance criteria:
  - Coverage scores computed correctly for LLM01-LLM10
  - Disabling IPIA reduces LLM08 score
  - Re-score completes in < 500ms
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from app.services.owasp.tag_registry import (
    OWASP_CATEGORIES,
    TagRegistry,
    get_tag_registry,
)

logger = logging.getLogger("sphinx.owasp.coverage_engine")


# ---------------------------------------------------------------------------
# Per-module weight overrides for more accurate scoring
# ---------------------------------------------------------------------------
# Modules that are considered "primary" for a category get a higher weight.
# This ensures that specialised modules (e.g. canary for LLM07, IPIA for
# LLM08) have a larger impact on their primary category.

_PRIMARY_WEIGHTS: dict[str, dict[str, float]] = {
    # LLM01 - Prompt Injection: threat_detection and IPIA are primary
    "LLM01": {
        "threat_detection": 2.0,
        "ipia_engine": 1.5,
        "multilingual_detector": 1.5,
        "memory_firewall": 1.0,
        "rag_pipeline": 1.0,
    },
    # LLM02 - Sensitive Information Disclosure: DataShield is primary
    "LLM02": {
        "data_shield": 2.5,
        "output_scanner": 1.5,
    },
    # LLM03 - Supply Chain: model_fingerprint and model_scanner are primary
    "LLM03": {
        "model_fingerprint": 2.5,
        "model_scanner": 2.0,
    },
    # LLM04 - Data/Model Poisoning: vectordb and model_scanner are primary
    "LLM04": {
        "vectordb_proxy": 2.0,
        "model_scanner": 2.0,
        "model_fingerprint": 1.5,
    },
    # LLM05 - Improper Output Handling: output_scanner is primary
    "LLM05": {
        "output_scanner": 2.5,
        "threat_detection": 1.5,
    },
    # LLM06 - Excessive Agency: mcp_guardrails and agent_scope are primary
    "LLM06": {
        "mcp_guardrails": 2.0,
        "agent_scope": 2.0,
        "hitl": 1.5,
    },
    # LLM07 - System Prompt Leakage: canary_token is the primary module
    "LLM07": {
        "canary_token": 3.0,
    },
    # LLM08 - Vector/Embedding Weaknesses: IPIA and RAG firewall are primary
    "LLM08": {
        "ipia_engine": 2.5,
        "rag_pipeline": 2.0,
        "vectordb_proxy": 1.5,
    },
    # LLM09 - Misinformation: thoth_classifier is primary
    "LLM09": {
        "thoth_classifier": 2.5,
    },
    # LLM10 - Unbounded Consumption: rate_limiter and token_budget are primary
    "LLM10": {
        "rate_limiter": 2.0,
        "token_budget": 2.0,
        "cost_tracker": 1.5,
    },
}

# Base score: even modules that are present (but disabled) contribute a
# small "awareness" score because they exist in the codebase and can be
# turned on.  Enabled modules get full weight.
_DISABLED_WEIGHT_FACTOR = 0.15
_ENABLED_WEIGHT_FACTOR = 1.0


@dataclass
class CategoryScore:
    """Coverage score for a single OWASP category."""

    category_id: str
    category_name: str
    score: float  # 0.0-100.0
    enabled_modules: list[str] = field(default_factory=list)
    disabled_modules: list[str] = field(default_factory=list)
    total_modules: int = 0


@dataclass
class CoverageResult:
    """Full coverage result across all 10 OWASP categories."""

    category_scores: dict[str, CategoryScore] = field(default_factory=dict)
    shield_score: float = 0.0  # Weighted average (0-100)
    scoring_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "shield_score": round(self.shield_score, 1),
            "scoring_time_ms": round(self.scoring_time_ms, 3),
            "categories": {
                k: {
                    "category_id": v.category_id,
                    "category_name": v.category_name,
                    "score": round(v.score, 1),
                    "enabled_modules": v.enabled_modules,
                    "disabled_modules": v.disabled_modules,
                    "total_modules": v.total_modules,
                }
                for k, v in self.category_scores.items()
            },
        }


# ---------------------------------------------------------------------------
# Shield Score category weights (for weighted average)
# ---------------------------------------------------------------------------
# All categories are equally weighted by default. Adjust these to
# prioritise certain categories in the overall Shield Score.

_SHIELD_WEIGHTS: dict[str, float] = {
    "LLM01": 1.2,   # Prompt injection — highest risk
    "LLM02": 1.0,
    "LLM03": 1.1,   # Supply chain — critical
    "LLM04": 1.0,
    "LLM05": 1.0,
    "LLM06": 1.0,
    "LLM07": 0.9,
    "LLM08": 1.0,
    "LLM09": 0.8,
    "LLM10": 0.9,
}


class OWASPCoverageEngine:
    """Computes OWASP LLM Top 10 v2025 coverage scores.

    Takes the active Sphinx configuration (which modules are enabled) and
    the tag registry to compute per-category coverage scores and an overall
    Shield Score.

    SP-361 acceptance criteria:
      - Scores correct for LLM01-LLM10
      - Disabling IPIA reduces LLM08 score
      - Re-score < 500ms
    """

    def __init__(
        self,
        registry: TagRegistry | None = None,
    ) -> None:
        self._registry = registry or get_tag_registry()

    @property
    def registry(self) -> TagRegistry:
        return self._registry

    def compute_coverage(
        self,
        active_config: dict[str, bool] | None = None,
    ) -> CoverageResult:
        """Compute per-category coverage from the active configuration.

        Args:
            active_config: Dict mapping config_key -> enabled (True/False).
                If None, uses default_enabled from the tag registry.

        Returns:
            CoverageResult with per-category scores and overall Shield Score.
        """
        start = time.perf_counter()

        # Resolve active modules
        module_enabled: dict[str, bool] = {}
        for mod_key, mod in self._registry.modules.items():
            if active_config is not None and mod.config_key in active_config:
                module_enabled[mod_key] = active_config[mod.config_key]
            else:
                module_enabled[mod_key] = mod.default_enabled

        # Score each category
        category_scores: dict[str, CategoryScore] = {}
        for cat_id in OWASP_CATEGORIES:
            cat_info = self._registry.categories.get(cat_id)
            cat_name = cat_info.name if cat_info else cat_id

            # Get modules that cover this category
            covering_modules = self._registry.get_modules_for_category(cat_id)

            if not covering_modules:
                category_scores[cat_id] = CategoryScore(
                    category_id=cat_id,
                    category_name=cat_name,
                    score=0.0,
                    total_modules=0,
                )
                continue

            # Compute weighted score
            weight_map = _PRIMARY_WEIGHTS.get(cat_id, {})
            total_weight = 0.0
            achieved_weight = 0.0
            enabled_mods = []
            disabled_mods = []

            for mod in covering_modules:
                mod_weight = weight_map.get(mod.module_key, 1.0)
                total_weight += mod_weight

                is_enabled = module_enabled.get(mod.module_key, mod.default_enabled)
                if is_enabled:
                    achieved_weight += mod_weight * _ENABLED_WEIGHT_FACTOR
                    enabled_mods.append(mod.name)
                else:
                    achieved_weight += mod_weight * _DISABLED_WEIGHT_FACTOR
                    disabled_mods.append(mod.name)

            score = (achieved_weight / total_weight) * 100.0 if total_weight > 0 else 0.0
            score = min(score, 100.0)

            category_scores[cat_id] = CategoryScore(
                category_id=cat_id,
                category_name=cat_name,
                score=score,
                enabled_modules=enabled_mods,
                disabled_modules=disabled_mods,
                total_modules=len(covering_modules),
            )

        # Compute Shield Score (weighted average)
        total_shield_weight = sum(_SHIELD_WEIGHTS.get(c, 1.0) for c in OWASP_CATEGORIES)
        shield_score = sum(
            category_scores[c].score * _SHIELD_WEIGHTS.get(c, 1.0)
            for c in OWASP_CATEGORIES
        ) / total_shield_weight if total_shield_weight > 0 else 0.0

        elapsed_ms = (time.perf_counter() - start) * 1000

        return CoverageResult(
            category_scores=category_scores,
            shield_score=shield_score,
            scoring_time_ms=elapsed_ms,
        )


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine: Optional[OWASPCoverageEngine] = None


def get_owasp_coverage_engine() -> OWASPCoverageEngine:
    """Get or create the singleton OWASPCoverageEngine."""
    global _engine
    if _engine is None:
        _engine = OWASPCoverageEngine()
    return _engine


def reset_owasp_coverage_engine() -> None:
    """Reset the singleton (for testing)."""
    global _engine
    _engine = None
