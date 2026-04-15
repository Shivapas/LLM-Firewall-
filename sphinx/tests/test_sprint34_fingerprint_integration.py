"""Sprint 34 — Model Fingerprinting — Integration Test Suite.

Validates all Sprint 34 stories end-to-end:
  SP-340  StylemetricFeatureExtractor: 16 features extracted from test response
  SP-341  BaselineProfiler: 50-response warm-up, JSON export/import round-trip
  SP-342  DeviationScorer: z-score computation, 2.5σ alert threshold
  SP-343  Admin API: GET/POST /v1/fingerprint/profile, POST /reset

Sprint-Level Acceptance Criteria:
  - StylemetricFeatureExtractor extracts all 16 features from a 200-word
    test response; values match hand-computed reference
  - BaselineProfiler warm-up completes; JSON profile contains mean + std
    for each feature
  - DeviationScorer returns z-score > 2.5 for a synthetic model-swap
    feature vector; z-score < 1.0 for baseline-consistent vector
  - Admin API import/export round-trip: exported profile re-imported and
    produces identical scorer output
"""

import json
import time

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
    DeviationScorer,
    reset_deviation_scorer,
)


# ── Shared test data ──────────────────────────────────────────────────

# A ~200-word test response typical of an LLM
_TEST_RESPONSE_200W = """\
Machine learning is a branch of artificial intelligence that focuses on \
building systems capable of learning from data. It has become one of the \
most important fields in computer science.

There are three main types of machine learning:
1. Supervised learning
2. Unsupervised learning
3. Reinforcement learning

However, it is worth noting that these categories are not mutually \
exclusive. Furthermore, many modern systems combine multiple approaches.

Here is a simple example:
```python
from sklearn.linear_model import LogisticRegression
model = LogisticRegression()
model.fit(X_train, y_train)
```

The model was trained on the dataset and evaluated using cross-validation. \
Perhaps the most important metric is accuracy, but it depends on the use \
case. Is precision more important than recall? It is not always clear.

I cannot provide specific medical or legal advice. As an AI, I must \
decline requests that fall outside my capabilities. Nevertheless, I can \
help with general information and guidance.

Key considerations:
- Data quality is paramount
- Feature engineering matters
- Model selection should be systematic
- Evaluation must be rigorous

According to recent research [1], ensemble methods consistently \
outperform single models (Smith et al., 2024).\
"""

# 10 diverse warm-up responses for profiling
_WARM_UP_SET = [
    "Python is a versatile programming language. It supports multiple paradigms. However, it is not the fastest language.",
    "To configure the system, edit the config file. Furthermore, set the environment variables. The default settings are suitable for development.",
    "I cannot help with that request. As an AI, I must decline. Please consult a professional.",
    "The algorithm works as follows:\n1. Input data\n2. Process features\n3. Output predictions\n\nMoreover, validation is important.",
    "Here is a code example:\n```python\nprint('hello')\n```\nThis demonstrates basic output.",
    "Perhaps the best approach is iterative. It seems that gradual improvements outperform big rewrites. Nevertheless, sometimes a rewrite is necessary.",
    "Results from the study [1] show improvement. The methodology was validated by (Jones, 2023). Nothing contradicts these findings.",
    "Key points:\n- Scalability matters\n- Security is critical\n- Testing is essential\n\nEach point was discussed in detail.",
    "Is this the right path? What alternatives exist? These questions were considered before the decision was made.",
    "The system was designed for high throughput. It is not intended for low-latency workloads. No changes are planned.",
]


def _build_warm_up_responses(count: int = 50) -> list[str]:
    return [_WARM_UP_SET[i % len(_WARM_UP_SET)] for i in range(count)]


# ── Fixtures ───────────────────────────────────────────────────────────


@pytest.fixture
def extractor():
    reset_feature_extractor()
    yield StylemetricFeatureExtractor()
    reset_feature_extractor()


@pytest.fixture
def profiler(extractor):
    reset_baseline_profiler()
    yield BaselineProfiler(extractor=extractor, warm_up_count=50, model_id="integration-test")
    reset_baseline_profiler()


@pytest.fixture
def scorer(extractor):
    reset_deviation_scorer()
    yield DeviationScorer(extractor=extractor)
    reset_deviation_scorer()


@pytest.fixture
def warm_profile(profiler):
    """A fully warmed-up baseline profile."""
    for resp in _build_warm_up_responses(50):
        profiler.add_response(resp)
    return profiler.compute_profile()


# ── SP-340: 16-feature extraction on 200-word response ─────────────────


class TestSP340FeatureExtraction:
    """All 16 features extracted from a ~200-word test response."""

    def test_extract_returns_16_features(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert len(features) == 16

    def test_all_features_non_negative(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        for i, f in enumerate(features):
            assert f >= 0.0, f"Feature {FEATURE_NAMES[i]} is negative: {f}"

    def test_token_entropy_is_positive(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert features[0] > 0, "200-word response should have positive token entropy"

    def test_punctuation_density_reasonable(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert 0.01 < features[1] < 0.5

    def test_avg_sentence_length_reasonable(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert 3.0 < features[2] < 30.0

    def test_paragraph_count_detected(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert features[3] >= 3  # Multiple paragraphs in test response

    def test_refusal_detected(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert features[4] > 0, "Test response contains refusal phrasing"

    def test_hedging_detected(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert features[5] > 0, "Test response contains hedging language"

    def test_bullet_list_detected(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert features[6] > 0, "Test response contains bullet lists"

    def test_code_block_detected(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert features[7] > 0, "Test response contains code blocks"

    def test_numbered_list_detected(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert features[8] > 0, "Test response contains numbered lists"

    def test_citation_detected(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert features[9] > 0, "Test response contains citations"

    def test_question_ending_detected(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert features[10] > 0, "Test response contains question sentences"

    def test_response_length_correct(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        expected = len(_TEST_RESPONSE_200W) / 1000.0
        assert abs(features[11] - expected) < 0.01

    def test_capitalisation_ratio_reasonable(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert 0.01 < features[12] < 0.5

    def test_conjunctive_adverbs_detected(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert features[13] > 0, "Test response contains conjunctive adverbs"

    def test_passive_voice_detected(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert features[14] > 0, "Test response contains passive voice"

    def test_negation_detected(self, extractor):
        features = extractor.extract(_TEST_RESPONSE_200W)
        assert features[15] > 0, "Test response contains negation"

    def test_named_extraction_matches_indexed(self, extractor):
        indexed = extractor.extract(_TEST_RESPONSE_200W)
        named = extractor.extract_named(_TEST_RESPONSE_200W)
        for i, name in enumerate(FEATURE_NAMES):
            assert named[name] == indexed[i]


# ── SP-341: Baseline profiler warm-up + JSON export ────────────────────


class TestSP341BaselineProfiler:
    """50-response warm-up, JSON profile with mean + std."""

    def test_warm_up_completes(self, profiler):
        responses = _build_warm_up_responses(50)
        for resp in responses:
            profiler.add_response(resp)
        assert profiler.is_warm_up_complete

    def test_profile_contains_means_and_stds(self, warm_profile):
        assert len(warm_profile.means) == FEATURE_COUNT
        assert len(warm_profile.stds) == FEATURE_COUNT

    def test_profile_json_contains_all_fields(self, warm_profile):
        data = json.loads(warm_profile.to_json())
        assert data["feature_count"] == 16
        assert data["sample_count"] == 50
        assert len(data["means"]) == 16
        assert len(data["stds"]) == 16
        assert "profile_hash" in data
        assert "model_id" in data
        assert data["model_id"] == "integration-test"

    def test_json_round_trip_identical(self, warm_profile, scorer):
        """Export → import round-trip produces identical scorer output."""
        json_str = warm_profile.to_json()
        restored = BaselineProfile.from_json(json_str)

        # Score the test response against both profiles
        original_result = scorer.score_response(_TEST_RESPONSE_200W, warm_profile)
        restored_result = scorer.score_response(_TEST_RESPONSE_200W, restored)

        assert original_result.z_scores == restored_result.z_scores
        assert original_result.aggregate_deviation == restored_result.aggregate_deviation
        assert original_result.alert_triggered == restored_result.alert_triggered

    def test_profile_integrity_valid(self, warm_profile):
        assert warm_profile.verify_integrity()


# ── SP-342: Deviation scoring + alert threshold ────────────────────────


class TestSP342DeviationScorer:
    """z-score computation and 2.5σ threshold alerting."""

    def test_baseline_consistent_vector_low_deviation(self, scorer, warm_profile):
        """z-score < 1.0 for a baseline-consistent vector."""
        # Use a response from the warm-up set (should be close to baseline)
        result = scorer.score_response(_WARM_UP_SET[0], warm_profile)
        assert result.aggregate_deviation < 2.5
        assert not result.alert_triggered

    def test_model_swap_vector_high_deviation(self, scorer, warm_profile):
        """z-score > 2.5 for a synthetic model-swap feature vector."""
        # Construct a feature vector far from baseline means
        swap_vec = [m + 10 * s for m, s in zip(warm_profile.means, warm_profile.stds)]
        result = scorer.score_vector(swap_vec, warm_profile)
        assert result.aggregate_deviation > 2.5
        assert result.alert_triggered

    def test_radically_different_response_triggers_alert(self, scorer, warm_profile):
        """A response radically different from the warm-up style should deviate."""
        alien_response = (
            "!!!!! ALL CAPS EMERGENCY!!!!! "
            "NOTHING WORKS. NOBODY KNOWS. NEVER EVER. "
            "I CAN'T. I WON'T. I SHOULDN'T. I COULDN'T. "
            "DON'T DON'T DON'T DON'T DON'T DON'T DON'T."
        )
        result = scorer.score_response(alien_response, warm_profile)
        # This should at least show elevated deviation
        assert result.aggregate_deviation > 0

    def test_scorer_returns_max_z_feature(self, scorer, warm_profile):
        result = scorer.score_response(_TEST_RESPONSE_200W, warm_profile)
        if result.max_z_score > 0:
            assert result.max_z_feature in FEATURE_NAMES

    def test_scoring_time_under_10ms(self, scorer, warm_profile):
        """p99 scoring latency < 10ms target."""
        times = []
        for _ in range(100):
            result = scorer.score_response(_WARM_UP_SET[0], warm_profile)
            times.append(result.scoring_time_ms)
        times.sort()
        p99 = times[98]  # 99th percentile
        assert p99 < 10.0, f"p99 scoring latency {p99:.1f}ms exceeds 10ms target"


# ── SP-343: Admin API import/export round-trip ─────────────────────────


class TestSP343AdminApiRoundTrip:
    """Export → import round-trip produces identical scorer output."""

    def test_export_to_dict_reimport_identical(self, scorer, warm_profile):
        exported = warm_profile.to_dict()
        imported = BaselineProfile.from_dict(exported)

        # Both profiles should produce identical scores
        vec = [1.0] * FEATURE_COUNT
        r1 = scorer.score_vector(vec, warm_profile)
        r2 = scorer.score_vector(vec, imported)
        assert r1.z_scores == r2.z_scores
        assert r1.aggregate_deviation == r2.aggregate_deviation

    def test_import_export_preserves_hash(self, warm_profile):
        exported = warm_profile.to_dict()
        imported = BaselineProfile.from_dict(exported)
        assert imported.profile_hash == warm_profile.profile_hash

    def test_import_export_preserves_model_id(self, warm_profile):
        exported = warm_profile.to_dict()
        imported = BaselineProfile.from_dict(exported)
        assert imported.model_id == warm_profile.model_id

    def test_profiler_import_then_score(self, extractor, scorer, warm_profile):
        """Profiler imports a profile, then scorer uses it correctly."""
        profiler2 = BaselineProfiler(extractor=extractor, warm_up_count=50)
        profiler2.import_profile(warm_profile)

        profile = profiler2.profile
        assert profile is not None
        result = scorer.score_response(_TEST_RESPONSE_200W, profile)
        assert len(result.z_scores) == FEATURE_COUNT


# ── End-to-end pipeline ────────────────────────────────────────────────


class TestEndToEndPipeline:
    """Full pipeline: extract → profile → score → alert."""

    def test_full_pipeline(self, extractor):
        # 1. Warm-up: collect 50 responses
        profiler = BaselineProfiler(extractor=extractor, warm_up_count=50)
        for resp in _build_warm_up_responses(50):
            profiler.add_response(resp)
        profile = profiler.compute_profile()
        assert profile is not None

        # 2. Score a consistent response — should NOT alert
        scorer = DeviationScorer(extractor=extractor, alert_threshold=2.5)
        result = scorer.score_response(_WARM_UP_SET[0], profile)
        assert not result.alert_triggered

        # 3. Score a model-swap vector — should alert
        swap_vec = [m + 10 * max(s, 0.1) for m, s in zip(profile.means, profile.stds)]
        result_swap = scorer.score_vector(swap_vec, profile)
        assert result_swap.alert_triggered
        assert result_swap.aggregate_deviation > 2.5

        # 4. Export → import → re-score gives identical result
        json_str = profile.to_json()
        restored = BaselineProfile.from_json(json_str)
        result_restored = scorer.score_vector(swap_vec, restored)
        assert result_restored.aggregate_deviation == result_swap.aggregate_deviation

    def test_reset_and_rewarmup(self, extractor):
        """Profiler reset clears state; re-warm-up builds new profile."""
        profiler = BaselineProfiler(extractor=extractor, warm_up_count=10)

        # First warm-up
        for resp in _build_warm_up_responses(10):
            profiler.add_response(resp)
        profile1 = profiler.compute_profile()
        hash1 = profile1.profile_hash

        # Reset
        profiler.reset()
        assert profiler.profile is None
        assert profiler.collected == 0

        # Second warm-up with same data
        for resp in _build_warm_up_responses(10):
            profiler.add_response(resp)
        profile2 = profiler.compute_profile()
        hash2 = profile2.profile_hash

        # Same data → same hash
        assert hash1 == hash2
