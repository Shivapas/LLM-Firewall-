"""Sprint 34 — Model Fingerprinting — Unit Tests: DeviationScorer.

Validates SP-342:
  - Scorer returns correct z-score for synthetic feature vectors
  - Threshold alert triggers correctly at 2.5 sigma default
  - z-score > 2.5 for synthetic model-swap vector
  - z-score < 1.0 for baseline-consistent vector
"""

import pytest

from app.services.fingerprint.feature_extractor import (
    FEATURE_COUNT,
    FEATURE_NAMES,
    StylemetricFeatureExtractor,
    reset_feature_extractor,
)
from app.services.fingerprint.baseline_profiler import (
    BaselineProfile,
    BaselineProfiler,
    reset_baseline_profiler,
)
from app.services.fingerprint.deviation_scorer import (
    DEFAULT_ALERT_THRESHOLD,
    DeviationResult,
    DeviationScorer,
    get_deviation_scorer,
    reset_deviation_scorer,
)


# ── Fixtures ───────────────────────────────────────────────────────────


@pytest.fixture
def extractor():
    reset_feature_extractor()
    ext = StylemetricFeatureExtractor()
    yield ext
    reset_feature_extractor()


@pytest.fixture
def baseline_profile():
    """A synthetic baseline profile with known means and stds."""
    return BaselineProfile(
        means=[1.0] * FEATURE_COUNT,
        stds=[0.5] * FEATURE_COUNT,
        sample_count=50,
        created_at=1700000000.0,
        model_id="test-baseline",
    )


@pytest.fixture
def scorer(extractor):
    reset_deviation_scorer()
    sc = DeviationScorer(extractor=extractor)
    yield sc
    reset_deviation_scorer()


# ── SP-342: Basic z-score computation ──────────────────────────────────


class TestZScoreComputation:

    def test_returns_deviation_result(self, scorer, baseline_profile):
        vec = [1.0] * FEATURE_COUNT  # Exactly at baseline means
        result = scorer.score_vector(vec, baseline_profile)
        assert isinstance(result, DeviationResult)

    def test_exact_match_gives_zero_deviation(self, scorer, baseline_profile):
        vec = [1.0] * FEATURE_COUNT
        result = scorer.score_vector(vec, baseline_profile)
        assert result.aggregate_deviation == pytest.approx(0.0, abs=0.001)
        assert not result.alert_triggered

    def test_one_sigma_deviation(self, scorer, baseline_profile):
        # 1 std above mean on all features → z = 1.0 each → RMS = 1.0
        vec = [1.5] * FEATURE_COUNT  # mean + 1 * std
        result = scorer.score_vector(vec, baseline_profile)
        assert result.aggregate_deviation == pytest.approx(1.0, abs=0.01)
        assert not result.alert_triggered  # Below 2.5σ threshold

    def test_three_sigma_triggers_alert(self, scorer, baseline_profile):
        # 3 std above mean → z = 3.0 each → RMS = 3.0 → above 2.5
        vec = [2.5] * FEATURE_COUNT  # mean + 3 * std
        result = scorer.score_vector(vec, baseline_profile)
        assert result.aggregate_deviation == pytest.approx(3.0, abs=0.01)
        assert result.alert_triggered

    def test_z_scores_count_matches_feature_count(self, scorer, baseline_profile):
        vec = [1.0] * FEATURE_COUNT
        result = scorer.score_vector(vec, baseline_profile)
        assert len(result.z_scores) == FEATURE_COUNT

    def test_feature_names_in_result(self, scorer, baseline_profile):
        vec = [1.0] * FEATURE_COUNT
        result = scorer.score_vector(vec, baseline_profile)
        assert result.feature_names == list(FEATURE_NAMES)


# ── SP-342: Threshold configuration ───────────────────────────────────


class TestThresholdConfiguration:

    def test_default_threshold(self, scorer):
        assert scorer.alert_threshold == DEFAULT_ALERT_THRESHOLD
        assert scorer.alert_threshold == 2.5

    def test_custom_threshold(self, extractor):
        custom = DeviationScorer(extractor=extractor, alert_threshold=1.5)
        assert custom.alert_threshold == 1.5

    def test_lower_threshold_more_sensitive(self, extractor, baseline_profile):
        sensitive = DeviationScorer(extractor=extractor, alert_threshold=0.5)
        vec = [1.5] * FEATURE_COUNT  # 1σ deviation
        result = sensitive.score_vector(vec, baseline_profile)
        assert result.alert_triggered  # 1.0 > 0.5

    def test_threshold_setter(self, scorer):
        scorer.alert_threshold = 3.0
        assert scorer.alert_threshold == 3.0

    def test_negative_threshold_raises(self, scorer):
        with pytest.raises(ValueError, match="positive"):
            scorer.alert_threshold = -1.0

    def test_zero_threshold_raises(self, scorer):
        with pytest.raises(ValueError, match="positive"):
            scorer.alert_threshold = 0.0


# ── SP-342: Model swap detection ──────────────────────────────────────


class TestModelSwapDetection:

    def test_high_deviation_for_swapped_model(self, scorer, baseline_profile):
        """z-score > 2.5 for a synthetic model-swap feature vector."""
        # Simulate a completely different model: all features far from baseline
        swap_vec = [5.0] * FEATURE_COUNT  # 8σ away from mean
        result = scorer.score_vector(swap_vec, baseline_profile)
        assert result.aggregate_deviation > 2.5
        assert result.alert_triggered

    def test_low_deviation_for_consistent_model(self, scorer, baseline_profile):
        """z-score < 1.0 for a baseline-consistent vector."""
        # Very close to the baseline means
        consistent_vec = [1.1] * FEATURE_COUNT  # 0.2σ away
        result = scorer.score_vector(consistent_vec, baseline_profile)
        assert result.aggregate_deviation < 1.0
        assert not result.alert_triggered

    def test_partial_drift_detected(self, scorer, baseline_profile):
        """Drift on a subset of features should raise aggregate."""
        vec = [1.0] * FEATURE_COUNT
        # Drift 5σ on 4 features only
        vec[0] = 3.5  # 5σ
        vec[3] = 3.5  # 5σ
        vec[7] = 3.5  # 5σ
        vec[11] = 3.5  # 5σ
        result = scorer.score_vector(vec, baseline_profile)
        assert result.aggregate_deviation > 0
        assert result.max_z_score == pytest.approx(5.0, abs=0.01)


# ── SP-342: Max z-score feature identification ────────────────────────


class TestMaxZScoreIdentification:

    def test_identifies_most_deviant_feature(self, scorer, baseline_profile):
        vec = [1.0] * FEATURE_COUNT
        vec[5] = 10.0  # hedging_language_freq, 18σ away
        result = scorer.score_vector(vec, baseline_profile)
        assert result.max_z_feature == "hedging_language_freq"
        assert result.max_z_score == pytest.approx(18.0, abs=0.01)

    def test_no_deviation_no_max_feature(self, scorer, baseline_profile):
        vec = [1.0] * FEATURE_COUNT
        result = scorer.score_vector(vec, baseline_profile)
        assert result.max_z_score == pytest.approx(0.0, abs=0.001)


# ── SP-342: score_response convenience method ─────────────────────────


class TestScoreResponse:

    def test_score_response_works(self, scorer, baseline_profile):
        result = scorer.score_response(
            "A simple test response for scoring purposes.",
            baseline_profile,
        )
        assert isinstance(result, DeviationResult)
        assert len(result.z_scores) == FEATURE_COUNT

    def test_scoring_time_recorded(self, scorer, baseline_profile):
        result = scorer.score_response(
            "Another test response to verify timing.",
            baseline_profile,
        )
        assert result.scoring_time_ms >= 0


# ── SP-342: Edge cases ─────────────────────────────────────────────────


class TestEdgeCases:

    def test_wrong_vector_length_raises(self, scorer, baseline_profile):
        with pytest.raises(ValueError, match="length mismatch"):
            scorer.score_vector([1.0, 2.0, 3.0], baseline_profile)

    def test_zero_std_handled_gracefully(self, scorer):
        """Features with zero std should not cause division by zero."""
        profile = BaselineProfile(
            means=[1.0] * FEATURE_COUNT,
            stds=[0.0] * FEATURE_COUNT,  # All zero std
            sample_count=50,
            created_at=1700000000.0,
        )
        vec = [2.0] * FEATURE_COUNT
        result = scorer.score_vector(vec, profile)
        # Should still produce a result, not crash
        assert all(z >= 0 for z in result.z_scores)

    def test_feature_deltas_helper(self, scorer, baseline_profile):
        vec = [1.5] * FEATURE_COUNT
        result = scorer.score_vector(vec, baseline_profile)
        deltas = result.feature_deltas()
        assert isinstance(deltas, dict)
        assert len(deltas) == FEATURE_COUNT
        assert all(name in deltas for name in FEATURE_NAMES)

    def test_to_dict(self, scorer, baseline_profile):
        vec = [1.0] * FEATURE_COUNT
        result = scorer.score_vector(vec, baseline_profile)
        d = result.to_dict()
        assert "z_scores" in d
        assert "aggregate_deviation" in d
        assert "alert_triggered" in d
        assert "threshold" in d


# ── Singleton tests ────────────────────────────────────────────────────


class TestSingleton:

    def test_get_returns_same_instance(self):
        reset_deviation_scorer()
        a = get_deviation_scorer()
        b = get_deviation_scorer()
        assert a is b
        reset_deviation_scorer()

    def test_reset_creates_new_instance(self):
        reset_deviation_scorer()
        a = get_deviation_scorer()
        reset_deviation_scorer()
        b = get_deviation_scorer()
        assert a is not b
        reset_deviation_scorer()
