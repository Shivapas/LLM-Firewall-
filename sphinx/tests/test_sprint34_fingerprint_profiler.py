"""Sprint 34 — Model Fingerprinting — Unit Tests: BaselineProfiler.

Validates SP-341:
  - Profiler completes warm-up with configurable sample count
  - JSON profile exported and re-importable (round-trip)
  - Profile stable (< 5% variance across two warm-up runs)
  - Profile integrity hash verified
"""

import json
import time

import pytest

from app.services.fingerprint.feature_extractor import (
    FEATURE_COUNT,
    StylemetricFeatureExtractor,
    reset_feature_extractor,
)
from app.services.fingerprint.baseline_profiler import (
    BaselineProfile,
    BaselineProfiler,
    get_baseline_profiler,
    reset_baseline_profiler,
)


# ── Fixtures ───────────────────────────────────────────────────────────

# Synthetic warm-up responses that mimic typical LLM output
_WARM_UP_RESPONSES = [
    "Machine learning is a subset of artificial intelligence. It focuses on building systems that learn from data. However, it requires careful tuning.",
    "To install the package, run pip install sphinx-firewall. This will set up all dependencies. Furthermore, you should configure the environment variables.",
    "The algorithm works in three steps:\n1. Collect data\n2. Train the model\n3. Evaluate results\n\nMoreover, you should validate on a held-out set.",
    "I cannot provide medical advice. As an AI, I must decline requests for diagnosis. Please consult a healthcare professional.",
    "Here is an example:\n```python\ndef hello():\n    print('Hello, world!')\n```\nThis function prints a greeting.",
    "Perhaps the most important factor is data quality. It seems that clean data consistently outperforms larger noisy datasets. Nevertheless, scale matters too.",
    "The results were published in [1] and confirmed by (Smith, 2023). The methodology was reviewed and validated by independent researchers.",
    "- Feature extraction\n- Model training\n- Evaluation\n- Deployment\n\nEach step is crucial for success.",
    "Is this the right approach? What alternatives exist? These are questions worth exploring before committing to a solution.",
    "The system was designed to handle large-scale data processing. It is not intended for real-time applications. Nothing in the architecture supports sub-millisecond latency.",
]


def _generate_responses(count: int) -> list[str]:
    """Generate a list of responses by cycling through templates."""
    return [_WARM_UP_RESPONSES[i % len(_WARM_UP_RESPONSES)] for i in range(count)]


@pytest.fixture
def extractor():
    reset_feature_extractor()
    ext = StylemetricFeatureExtractor()
    yield ext
    reset_feature_extractor()


@pytest.fixture
def profiler(extractor):
    reset_baseline_profiler()
    prof = BaselineProfiler(extractor=extractor, warm_up_count=10, model_id="test-model-v1")
    yield prof
    reset_baseline_profiler()


# ── SP-341: Warm-up collection ─────────────────────────────────────────


class TestWarmUpCollection:

    def test_initial_state(self, profiler):
        assert profiler.collected == 0
        assert not profiler.is_warm_up_complete
        assert profiler.profile is None

    def test_add_response_increments_count(self, profiler):
        profiler.add_response("Test response one.")
        assert profiler.collected == 1

    def test_warm_up_completes_at_target(self, profiler):
        responses = _generate_responses(10)
        for i, resp in enumerate(responses):
            result = profiler.add_response(resp)
            if i < 9:
                assert not result
            else:
                assert result  # 10th response triggers completion
        assert profiler.is_warm_up_complete

    def test_extra_responses_ignored(self, profiler):
        responses = _generate_responses(15)
        for resp in responses:
            profiler.add_response(resp)
        assert profiler.collected == 10  # Capped at warm_up_count


# ── SP-341: Profile computation ────────────────────────────────────────


class TestProfileComputation:

    def test_compute_returns_profile(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        profile = profiler.compute_profile()
        assert isinstance(profile, BaselineProfile)

    def test_profile_has_correct_dimensions(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        profile = profiler.compute_profile()
        assert len(profile.means) == FEATURE_COUNT
        assert len(profile.stds) == FEATURE_COUNT

    def test_profile_sample_count(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        profile = profiler.compute_profile()
        assert profile.sample_count == 10

    def test_profile_model_id(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        profile = profiler.compute_profile()
        assert profile.model_id == "test-model-v1"

    def test_profile_has_hash(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        profile = profiler.compute_profile()
        assert len(profile.profile_hash) == 64  # SHA-256 hex digest

    def test_profile_has_timestamp(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        before = time.time()
        profile = profiler.compute_profile()
        after = time.time()
        assert before <= profile.created_at <= after

    def test_compute_raises_on_empty(self, profiler):
        with pytest.raises(ValueError, match="No responses collected"):
            profiler.compute_profile()

    def test_means_are_reasonable(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        profile = profiler.compute_profile()
        # All means should be non-negative
        for m in profile.means:
            assert m >= 0.0

    def test_stds_are_non_negative(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        profile = profiler.compute_profile()
        for s in profile.stds:
            assert s >= 0.0


# ── SP-341: JSON export / import round-trip ────────────────────────────


class TestJsonRoundTrip:

    def test_to_dict_contains_required_keys(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        profile = profiler.compute_profile()
        d = profile.to_dict()
        assert "version" in d
        assert "feature_count" in d
        assert "means" in d
        assert "stds" in d
        assert "sample_count" in d
        assert "created_at" in d
        assert "profile_hash" in d
        assert "model_id" in d

    def test_json_round_trip_preserves_data(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        original = profiler.compute_profile()
        json_str = original.to_json()

        restored = BaselineProfile.from_json(json_str)
        assert restored.means == original.means
        assert restored.stds == original.stds
        assert restored.sample_count == original.sample_count
        assert restored.profile_hash == original.profile_hash
        assert restored.model_id == original.model_id

    def test_from_dict_round_trip(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        original = profiler.compute_profile()
        d = original.to_dict()

        restored = BaselineProfile.from_dict(d)
        assert restored.means == original.means
        assert restored.stds == original.stds

    def test_json_is_valid_json(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        profile = profiler.compute_profile()
        json_str = profile.to_json()
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)


# ── SP-341: Profile integrity ──────────────────────────────────────────


class TestProfileIntegrity:

    def test_verify_integrity_passes(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        profile = profiler.compute_profile()
        assert profile.verify_integrity()

    def test_tampered_means_fails_integrity(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        profile = profiler.compute_profile()
        profile.means[0] = 999.999
        assert not profile.verify_integrity()

    def test_tampered_stds_fails_integrity(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        profile = profiler.compute_profile()
        profile.stds[0] = 999.999
        assert not profile.verify_integrity()


# ── SP-341: Profile import ─────────────────────────────────────────────


class TestProfileImport:

    def test_import_replaces_current_profile(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        original = profiler.compute_profile()

        # Create a different profile to import
        new_profile = BaselineProfile(
            means=[0.5] * FEATURE_COUNT,
            stds=[0.1] * FEATURE_COUNT,
            sample_count=100,
            created_at=time.time(),
            model_id="imported-model",
        )
        profiler.import_profile(new_profile)
        assert profiler.profile is not None
        assert profiler.profile.model_id == "imported-model"
        assert profiler.profile.sample_count == 100

    def test_import_tampered_profile_raises(self, profiler):
        bad_profile = BaselineProfile(
            means=[0.5] * FEATURE_COUNT,
            stds=[0.1] * FEATURE_COUNT,
            sample_count=100,
            created_at=time.time(),
        )
        bad_profile.profile_hash = "tampered_hash"
        with pytest.raises(ValueError, match="integrity check failed"):
            profiler.import_profile(bad_profile)

    def test_import_clears_warm_up_data(self, profiler):
        profiler.add_response("Some response text for warm-up.")
        assert profiler.collected == 1

        new_profile = BaselineProfile(
            means=[0.5] * FEATURE_COUNT,
            stds=[0.1] * FEATURE_COUNT,
            sample_count=50,
            created_at=time.time(),
        )
        profiler.import_profile(new_profile)
        assert profiler.collected == 0


# ── SP-341: Profiler reset ─────────────────────────────────────────────


class TestProfilerReset:

    def test_reset_clears_profile(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        profiler.compute_profile()
        assert profiler.profile is not None
        profiler.reset()
        assert profiler.profile is None
        assert profiler.collected == 0
        assert not profiler.is_warm_up_complete


# ── SP-341: Profile stability ──────────────────────────────────────────


class TestProfileStability:
    """Verify < 5% variance across two warm-up runs with same data."""

    def test_two_runs_produce_stable_means(self, extractor):
        responses = _generate_responses(50)

        p1 = BaselineProfiler(extractor=extractor, warm_up_count=50)
        for resp in responses:
            p1.add_response(resp)
        profile1 = p1.compute_profile()

        p2 = BaselineProfiler(extractor=extractor, warm_up_count=50)
        for resp in responses:
            p2.add_response(resp)
        profile2 = p2.compute_profile()

        # Same data should produce identical profiles
        for i in range(FEATURE_COUNT):
            assert profile1.means[i] == profile2.means[i]
            assert profile1.stds[i] == profile2.stds[i]

    def test_warm_up_duration_recorded(self, profiler):
        for resp in _generate_responses(10):
            profiler.add_response(resp)
        profiler.compute_profile()
        assert profiler.warm_up_duration_ms is not None
        assert profiler.warm_up_duration_ms >= 0


# ── Singleton tests ────────────────────────────────────────────────────


class TestSingleton:

    def test_get_returns_same_instance(self):
        reset_baseline_profiler()
        a = get_baseline_profiler()
        b = get_baseline_profiler()
        assert a is b
        reset_baseline_profiler()

    def test_reset_creates_new_instance(self):
        reset_baseline_profiler()
        a = get_baseline_profiler()
        reset_baseline_profiler()
        b = get_baseline_profiler()
        assert a is not b
        reset_baseline_profiler()
