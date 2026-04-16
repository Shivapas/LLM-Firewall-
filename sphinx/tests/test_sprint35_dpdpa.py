"""Sprint 35 — SP-355: DPDPA Compliance Annotation Test Suite.

Tests for DPDPA compliance of feature vectors:
  - Feature vectors contain only aggregate statistics (no PII)
  - Baseline profiles contain only numerical summaries
  - TrustDLP integration note generated correctly
  - Feature names do not reference PII types
"""

import pytest

from app.services.fingerprint.feature_extractor import (
    FEATURE_COUNT,
    FEATURE_NAMES,
    StylemetricFeatureExtractor,
    reset_feature_extractor,
)
from app.services.fingerprint.baseline_profiler import (
    BaselineProfiler,
    reset_baseline_profiler,
)
from app.services.fingerprint.dpdpa_compliance import (
    DPDPAComplianceValidator,
    reset_dpdpa_validator,
)


@pytest.fixture
def validator():
    reset_dpdpa_validator()
    yield DPDPAComplianceValidator()
    reset_dpdpa_validator()


@pytest.fixture
def extractor():
    reset_feature_extractor()
    yield StylemetricFeatureExtractor()
    reset_feature_extractor()


@pytest.fixture
def sample_profile(extractor):
    reset_baseline_profiler()
    profiler = BaselineProfiler(extractor=extractor, warm_up_count=10, model_id="test-model")
    responses = [
        "Python is a versatile language. It supports multiple paradigms.",
        "The algorithm processes data in stages. Each stage has validation.",
        "I cannot help with that. As an AI, I must decline.",
        "Key points:\n- Quality\n- Speed\n- Reliability",
        "Perhaps the best approach is iterative. However, it depends on context.",
        "Results from [1] confirm the hypothesis. Nothing contradicts it.",
        "Here is code:\n```python\nprint('test')\n```\nDone.",
        "Is this correct? What alternatives exist? The team considered both.",
        "The system was designed for scale. It is not for small datasets.",
        "Furthermore, testing is essential. Additionally, documentation helps.",
    ]
    for r in responses:
        profiler.add_response(r)
    profile = profiler.compute_profile()
    reset_baseline_profiler()
    return profile


class TestSP355FeatureVectorCompliance:
    """Feature vectors contain no PII."""

    def test_feature_vector_is_compliant(self, validator, extractor):
        vec = extractor.extract("A sample response for testing compliance.")
        report = validator.validate_feature_vector(vec)
        assert report["compliant"] is True
        assert report["pii_present"] is False
        assert report["standard"] == "DPDPA"
        assert len(report["issues"]) == 0

    def test_all_features_are_numeric(self, validator, extractor):
        vec = extractor.extract("Testing that all features are numeric values.")
        for i, val in enumerate(vec):
            assert isinstance(val, float), (
                f"Feature {FEATURE_NAMES[i]} is {type(val).__name__}, expected float"
            )

    def test_feature_names_contain_no_pii_indicators(self, validator):
        """Feature names must not reference PII types."""
        pii_indicators = [
            "name", "email", "phone", "address", "aadhaar", "pan",
            "passport", "ssn", "bank_account", "credit_card",
        ]
        for feature_name in FEATURE_NAMES:
            for pii in pii_indicators:
                assert pii not in feature_name.lower(), (
                    f"Feature name '{feature_name}' contains PII indicator '{pii}'"
                )

    def test_empty_text_produces_zero_vector(self, validator, extractor):
        vec = extractor.extract("")
        report = validator.validate_feature_vector(vec)
        assert report["compliant"] is True
        assert all(v == 0.0 for v in vec)

    def test_wrong_length_vector_flagged(self, validator):
        report = validator.validate_feature_vector([1.0] * 10)
        assert "Unexpected feature count" in report["issues"][0]


class TestSP355BaselineProfileCompliance:
    """Baseline profiles contain only numerical summaries."""

    def test_profile_is_compliant(self, validator, sample_profile):
        report = validator.validate_baseline_profile(sample_profile.to_dict())
        assert report["compliant"] is True
        assert report["pii_present"] is False
        assert report["standard"] == "DPDPA"

    def test_profile_means_are_numeric(self, sample_profile):
        for i, m in enumerate(sample_profile.means):
            assert isinstance(m, float), (
                f"Profile mean[{i}] is {type(m).__name__}"
            )

    def test_profile_stds_are_numeric(self, sample_profile):
        for i, s in enumerate(sample_profile.stds):
            assert isinstance(s, float), (
                f"Profile std[{i}] is {type(s).__name__}"
            )

    def test_profile_contains_no_text_content(self, sample_profile):
        d = sample_profile.to_dict()
        # Only allowed string fields: version, profile_hash, model_id, feature_names
        for key, value in d.items():
            if key in ("version", "profile_hash", "model_id"):
                assert isinstance(value, str)
            elif key == "feature_names":
                assert isinstance(value, list)
                for name in value:
                    assert isinstance(name, str)
            elif key in ("means", "stds"):
                assert isinstance(value, list)
                for v in value:
                    assert isinstance(v, (int, float))


class TestSP355TrustDLPIntegrationNote:
    """TrustDLP integration note generated correctly."""

    def test_note_contains_required_sections(self, validator):
        note = validator.generate_trustdlp_integration_note()
        assert note["module"] == "E17-ModelFingerprint"
        assert note["compliance_standard"] == "DPDPA (Digital Personal Data Protection Act, 2023)"
        assert note["data_classification"] == "NON_PERSONAL"
        assert note["pii_assessment"]["contains_pii"] is False
        assert note["baseline_profile_assessment"]["contains_pii"] is False

    def test_note_lists_all_features(self, validator):
        note = validator.generate_trustdlp_integration_note()
        reviewed_features = note["pii_assessment"]["features_reviewed"]
        assert len(reviewed_features) == FEATURE_COUNT
        for name in FEATURE_NAMES:
            assert name in reviewed_features

    def test_note_data_handling_section(self, validator):
        note = validator.generate_trustdlp_integration_note()
        handling = note["data_handling"]
        assert "storage" in handling
        assert "transmission" in handling
        assert "cross_region" in handling
        assert "retention" in handling

    def test_note_reconstruction_risk_none(self, validator):
        note = validator.generate_trustdlp_integration_note()
        assert "NONE" in note["pii_assessment"]["reconstruction_risk"]
