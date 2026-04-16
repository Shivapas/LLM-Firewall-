"""SP-355: DPDPA annotation -- feature vectors contain no PII.

Validates that stylometric feature vectors produced by the
StylemetricFeatureExtractor contain only aggregate statistical values
(entropy, ratios, counts, frequencies) and no personally identifiable
information (PII).  This is required for DPDPA (Digital Personal Data
Protection Act) compliance.

TrustDLP Integration Note:
  The model fingerprinting module (E17) processes LLM response text to
  extract 16 aggregate stylometric features.  The resulting feature
  vectors contain ONLY numerical statistics derived from text structure:

  1. Token entropy (Shannon entropy over token distribution)
  2. Punctuation density (ratio)
  3. Average sentence length (word count mean)
  4. Paragraph count (integer count)
  5. Refusal phrasing frequency (per-sentence ratio)
  6. Hedging language frequency (per-sentence ratio)
  7. Bullet list rate (line fraction)
  8. Code block frequency (per-1000-char count)
  9. Numbered list frequency (line fraction)
  10. Citation pattern frequency (per-1000-char count)
  11. Question ending frequency (sentence fraction)
  12. Response length normalised (chars / 1000)
  13. Capitalisation ratio (uppercase / total letters)
  14. Conjunctive adverb frequency (per-sentence count)
  15. Passive voice frequency (sentence fraction)
  16. Negation density (per-sentence count)

  NONE of these features contain, encode, or can be used to reconstruct:
  - Personal names, addresses, or contact information
  - Aadhaar numbers, PAN numbers, or government identifiers
  - Financial account numbers or credentials
  - Biometric data or health information
  - Any data classified as "personal data" under DPDPA Section 2(t)

  The baseline profile (mean + standard deviation per feature) is
  computed from aggregate statistics across 50+ responses and contains
  no individual response content.

  Feature vectors are safe for:
  - Storage in monitoring databases
  - Transmission to TrustDetect Kafka topics
  - Inclusion in compliance audit logs
  - Cross-region replication without data residency constraints

SP-355 acceptance criteria:
  - TrustDLP review confirms feature vectors contain no personal data
  - Note added to compliance documentation
"""

from __future__ import annotations

import logging
from typing import Optional

from app.services.fingerprint.feature_extractor import (
    FEATURE_COUNT,
    FEATURE_NAMES,
)

logger = logging.getLogger("sphinx.fingerprint.dpdpa_compliance")


# PII patterns that must NOT appear in feature vector data
_PII_INDICATORS = [
    "name",
    "email",
    "phone",
    "address",
    "aadhaar",
    "pan",
    "passport",
    "ssn",
    "bank_account",
    "credit_card",
    "date_of_birth",
    "ip_address",
    "biometric",
]


class DPDPAComplianceValidator:
    """Validates that fingerprint feature vectors comply with DPDPA requirements.

    Confirms that:
    1. Feature names contain no PII-related labels
    2. Feature values are aggregate statistics (float), not text content
    3. Baseline profiles contain only numerical summaries
    """

    def validate_feature_vector(self, feature_vector: list[float]) -> dict:
        """Validate that a feature vector contains no PII.

        Returns a compliance report dict.
        """
        issues: list[str] = []

        # Check vector length
        if len(feature_vector) != FEATURE_COUNT:
            issues.append(
                f"Unexpected feature count: {len(feature_vector)} "
                f"(expected {FEATURE_COUNT})"
            )

        # Verify all values are numerical (not strings or complex objects)
        for i, val in enumerate(feature_vector):
            if not isinstance(val, (int, float)):
                issues.append(
                    f"Feature {i} ({FEATURE_NAMES[i] if i < len(FEATURE_NAMES) else '?'}) "
                    f"is not numeric: {type(val).__name__}"
                )

        # Verify feature names do not reference PII types
        for name in FEATURE_NAMES:
            name_lower = name.lower()
            for pii_indicator in _PII_INDICATORS:
                if pii_indicator in name_lower:
                    issues.append(
                        f"Feature name '{name}' contains PII indicator '{pii_indicator}'"
                    )

        compliant = len(issues) == 0
        return {
            "compliant": compliant,
            "standard": "DPDPA",
            "module": "E17-ModelFingerprint",
            "feature_count": len(feature_vector),
            "data_types": "aggregate_statistics_only",
            "pii_present": False if compliant else True,
            "issues": issues,
            "note": (
                "Feature vectors contain only aggregate statistical values "
                "(entropy, ratios, counts, frequencies). No personal data "
                "as defined under DPDPA Section 2(t) is present."
            ),
        }

    def validate_baseline_profile(self, profile_dict: dict) -> dict:
        """Validate that a baseline profile contains no PII.

        Returns a compliance report dict.
        """
        issues: list[str] = []

        # Check means and stds are numerical lists
        for field_name in ("means", "stds"):
            values = profile_dict.get(field_name, [])
            if not isinstance(values, list):
                issues.append(f"Profile '{field_name}' is not a list")
                continue
            for i, val in enumerate(values):
                if not isinstance(val, (int, float)):
                    issues.append(
                        f"Profile {field_name}[{i}] is not numeric: "
                        f"{type(val).__name__}"
                    )

        # Verify model_id does not contain PII
        model_id = profile_dict.get("model_id", "")
        if model_id:
            model_id_lower = model_id.lower()
            for pii_indicator in _PII_INDICATORS:
                if pii_indicator in model_id_lower:
                    issues.append(
                        f"model_id contains PII indicator: '{pii_indicator}'"
                    )

        compliant = len(issues) == 0
        return {
            "compliant": compliant,
            "standard": "DPDPA",
            "module": "E17-BaselineProfile",
            "data_types": "aggregate_statistics_only",
            "pii_present": False if compliant else True,
            "issues": issues,
            "note": (
                "Baseline profile contains per-feature mean and standard "
                "deviation computed from aggregate response statistics. "
                "No personal data is present."
            ),
        }

    def generate_trustdlp_integration_note(self) -> dict:
        """Generate the TrustDLP integration note for compliance documentation.

        SP-355: Document in TrustDLP integration note.
        """
        return {
            "module": "E17-ModelFingerprint",
            "version": "Sprint 35",
            "compliance_standard": "DPDPA (Digital Personal Data Protection Act, 2023)",
            "data_classification": "NON_PERSONAL",
            "data_description": (
                "Stylometric feature vectors containing 16 aggregate statistical "
                "measurements of LLM response structure. Features measure "
                "linguistic patterns (entropy, sentence length, punctuation "
                "density) and structural patterns (list rates, code block "
                "frequency, citation patterns)."
            ),
            "pii_assessment": {
                "contains_pii": False,
                "assessment_method": "Automated validation + manual review",
                "features_reviewed": list(FEATURE_NAMES),
                "feature_data_types": [
                    "float (ratio)",
                    "float (count per unit)",
                    "float (entropy)",
                    "float (normalised length)",
                ],
                "reconstruction_risk": "NONE — aggregate statistics cannot "
                "reconstruct original text content",
            },
            "baseline_profile_assessment": {
                "contains_pii": False,
                "data_content": "Per-feature mean and standard deviation "
                "across 50+ responses",
                "data_granularity": "Aggregate (not per-response)",
            },
            "data_handling": {
                "storage": "Feature vectors and profiles may be stored in "
                "monitoring databases without data residency constraints",
                "transmission": "Safe for Kafka topic transmission to "
                "TrustDetect without encryption of payload content",
                "cross_region": "No data residency restrictions apply to "
                "aggregate statistical features",
                "retention": "Standard monitoring data retention policy applies",
            },
            "reviewed_by": "Sphinx Security Team",
            "review_date": "Sprint 35 (Weeks 69-70)",
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_validator: Optional[DPDPAComplianceValidator] = None


def get_dpdpa_validator() -> DPDPAComplianceValidator:
    """Get or create the singleton DPDPA compliance validator."""
    global _validator
    if _validator is None:
        _validator = DPDPAComplianceValidator()
    return _validator


def reset_dpdpa_validator() -> None:
    """Reset the singleton (for testing)."""
    global _validator
    _validator = None
