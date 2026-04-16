"""SP-366a — OWASP Tag Registry + Coverage Engine Tests.

Tests for SP-360 (tag registry) and SP-361 (coverage engine):
  - Tag registry loads and covers all 33 modules (30 v2.0 + 3 Roadmap v1)
  - Each module tagged with 1-N OWASP categories
  - Coverage scores computed correctly for LLM01-LLM10
  - Disabling IPIA reduces LLM08 score
  - Disabling canary reduces LLM07 score
  - Disabling fingerprint reduces LLM03 score
  - Re-score completes in < 500ms
"""

import time

import pytest

from app.services.owasp.tag_registry import (
    OWASP_CATEGORIES,
    TagRegistry,
    load_tag_registry,
    get_tag_registry,
    reset_tag_registry,
)
from app.services.owasp.coverage_engine import (
    CoverageResult,
    OWASPCoverageEngine,
    get_owasp_coverage_engine,
    reset_owasp_coverage_engine,
)


@pytest.fixture(autouse=True)
def _reset_singletons():
    reset_tag_registry()
    reset_owasp_coverage_engine()
    yield
    reset_tag_registry()
    reset_owasp_coverage_engine()


# ---------------------------------------------------------------------------
# SP-360: Tag Registry
# ---------------------------------------------------------------------------


class TestTagRegistry:
    """SP-360: OWASP tag registry covers all Sphinx modules."""

    def test_registry_loads(self):
        registry = load_tag_registry()
        assert isinstance(registry, TagRegistry)

    def test_registry_has_10_categories(self):
        registry = load_tag_registry()
        assert registry.category_count == 10
        for cat_id in OWASP_CATEGORIES:
            assert cat_id in registry.categories, f"Missing category {cat_id}"

    def test_registry_has_at_least_33_modules(self):
        """30 v2.0 modules + 3 Roadmap v1 (E15-E17) = 33."""
        registry = load_tag_registry()
        assert registry.module_count >= 33, (
            f"Expected >= 33 modules, got {registry.module_count}"
        )

    def test_every_module_has_at_least_one_owasp_tag(self):
        registry = load_tag_registry()
        for mod_key, mod in registry.modules.items():
            assert len(mod.owasp_tags) >= 1, (
                f"Module {mod_key} has no OWASP tags"
            )

    def test_every_module_has_config_key(self):
        registry = load_tag_registry()
        for mod_key, mod in registry.modules.items():
            assert mod.config_key, f"Module {mod_key} has no config_key"

    def test_owasp_tags_are_valid(self):
        registry = load_tag_registry()
        for mod_key, mod in registry.modules.items():
            for tag in mod.owasp_tags:
                assert tag in OWASP_CATEGORIES, (
                    f"Module {mod_key} has invalid tag {tag}"
                )

    def test_roadmap_v1_modules_present(self):
        """E15 (ipia_engine), E16 (canary_token), E17 (model_fingerprint)."""
        registry = load_tag_registry()
        assert "ipia_engine" in registry.modules
        assert "canary_token" in registry.modules
        assert "model_fingerprint" in registry.modules

    def test_ipia_tagged_with_llm01_llm08(self):
        registry = load_tag_registry()
        ipia = registry.modules["ipia_engine"]
        assert "LLM01" in ipia.owasp_tags
        assert "LLM08" in ipia.owasp_tags

    def test_canary_tagged_with_llm07(self):
        registry = load_tag_registry()
        canary = registry.modules["canary_token"]
        assert "LLM07" in canary.owasp_tags

    def test_fingerprint_tagged_with_llm03(self):
        registry = load_tag_registry()
        fp = registry.modules["model_fingerprint"]
        assert "LLM03" in fp.owasp_tags

    def test_get_modules_for_category(self):
        registry = load_tag_registry()
        # LLM07 should include canary_token
        llm07_mods = registry.get_modules_for_category("LLM07")
        mod_keys = [m.module_key for m in llm07_mods]
        assert "canary_token" in mod_keys

    def test_get_categories_for_module(self):
        registry = load_tag_registry()
        cats = registry.get_categories_for_module("threat_detection")
        assert "LLM01" in cats

    def test_registry_to_dict(self):
        registry = load_tag_registry()
        d = registry.to_dict()
        assert "modules" in d
        assert "categories" in d
        assert d["module_count"] >= 33

    def test_singleton_returns_same_instance(self):
        r1 = get_tag_registry()
        r2 = get_tag_registry()
        assert r1 is r2

    def test_all_categories_have_at_least_one_module(self):
        """Every OWASP category should be addressed by at least one module."""
        registry = load_tag_registry()
        for cat_id in OWASP_CATEGORIES:
            mods = registry.get_modules_for_category(cat_id)
            assert len(mods) >= 1, f"Category {cat_id} has no covering modules"


# ---------------------------------------------------------------------------
# SP-361: Coverage Engine
# ---------------------------------------------------------------------------


class TestCoverageEngine:
    """SP-361: OWASPCoverageEngine per-category scoring."""

    def test_default_coverage_returns_all_10_categories(self):
        engine = OWASPCoverageEngine()
        result = engine.compute_coverage()
        assert isinstance(result, CoverageResult)
        assert len(result.category_scores) == 10
        for cat_id in OWASP_CATEGORIES:
            assert cat_id in result.category_scores

    def test_default_coverage_has_shield_score(self):
        engine = OWASPCoverageEngine()
        result = engine.compute_coverage()
        assert 0.0 <= result.shield_score <= 100.0

    def test_all_enabled_config_high_scores(self):
        """With all modules enabled, every category should score > 50."""
        engine = OWASPCoverageEngine()
        all_enabled = {}
        for mod in engine.registry.modules.values():
            all_enabled[mod.config_key] = True
        result = engine.compute_coverage(all_enabled)
        for cat_id, cat_score in result.category_scores.items():
            assert cat_score.score > 50.0, (
                f"{cat_id} score {cat_score.score} <= 50 with all enabled"
            )

    def test_disabling_ipia_reduces_llm08(self):
        """SP-361: Disabling IPIA reduces LLM08 score."""
        engine = OWASPCoverageEngine()
        all_enabled = {}
        for mod in engine.registry.modules.values():
            all_enabled[mod.config_key] = True

        result_on = engine.compute_coverage(all_enabled)

        all_enabled["ipia_enabled"] = False
        result_off = engine.compute_coverage(all_enabled)

        assert result_off.category_scores["LLM08"].score < result_on.category_scores["LLM08"].score, (
            f"LLM08 score did not decrease when IPIA disabled: "
            f"{result_on.category_scores['LLM08'].score} -> {result_off.category_scores['LLM08'].score}"
        )

    def test_disabling_canary_reduces_llm07(self):
        """Disabling canary token reduces LLM07 score."""
        engine = OWASPCoverageEngine()
        all_enabled = {}
        for mod in engine.registry.modules.values():
            all_enabled[mod.config_key] = True

        result_on = engine.compute_coverage(all_enabled)

        all_enabled["canary_token_enabled"] = False
        result_off = engine.compute_coverage(all_enabled)

        assert result_off.category_scores["LLM07"].score < result_on.category_scores["LLM07"].score

    def test_disabling_fingerprint_reduces_llm03(self):
        """Disabling model fingerprint reduces LLM03 score."""
        engine = OWASPCoverageEngine()
        all_enabled = {}
        for mod in engine.registry.modules.values():
            all_enabled[mod.config_key] = True

        result_on = engine.compute_coverage(all_enabled)

        all_enabled["fingerprint_enabled"] = False
        result_off = engine.compute_coverage(all_enabled)

        assert result_off.category_scores["LLM03"].score < result_on.category_scores["LLM03"].score

    def test_rescoring_under_500ms(self):
        """SP-361: Re-score completes in < 500ms."""
        engine = OWASPCoverageEngine()
        # Warm up
        engine.compute_coverage()

        # Timed re-score
        start = time.perf_counter()
        for _ in range(10):
            engine.compute_coverage()
        elapsed_ms = (time.perf_counter() - start) * 1000 / 10

        assert elapsed_ms < 500.0, f"Re-score took {elapsed_ms:.2f}ms (> 500ms)"

    def test_coverage_result_to_dict(self):
        engine = OWASPCoverageEngine()
        result = engine.compute_coverage()
        d = result.to_dict()
        assert "shield_score" in d
        assert "scoring_time_ms" in d
        assert "categories" in d
        assert len(d["categories"]) == 10

    def test_category_score_has_modules(self):
        engine = OWASPCoverageEngine()
        result = engine.compute_coverage()
        for cat_id, cs in result.category_scores.items():
            assert cs.total_modules >= 1, f"{cat_id} has no modules"

    def test_threshold_0_config_all_disabled(self):
        """All modules disabled should result in low but non-zero scores
        (disabled modules contribute a small awareness weight)."""
        engine = OWASPCoverageEngine()
        all_disabled = {}
        for mod in engine.registry.modules.values():
            all_disabled[mod.config_key] = False
        result = engine.compute_coverage(all_disabled)
        # Shield score should be low
        assert result.shield_score < 30.0, (
            f"Shield score {result.shield_score} too high with all disabled"
        )

    def test_singleton_returns_same_instance(self):
        e1 = get_owasp_coverage_engine()
        e2 = get_owasp_coverage_engine()
        assert e1 is e2
