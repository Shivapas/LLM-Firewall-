"""SP-342: DeviationScorer -- z-score deviation analysis vs. baseline.

Computes per-feature z-scores against the baseline profile and produces
an aggregate deviation index.  Supports a configurable alert threshold
(default 2.5 sigma).

SP-342 acceptance criteria:
  - Scorer returns correct z-score for synthetic feature vectors
  - Threshold alert triggers correctly at 2.5 sigma default
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from typing import Optional

from app.services.fingerprint.baseline_profiler import BaselineProfile
from app.services.fingerprint.feature_extractor import (
    FEATURE_COUNT,
    FEATURE_NAMES,
    StylemetricFeatureExtractor,
    get_feature_extractor,
)

logger = logging.getLogger("sphinx.fingerprint.deviation_scorer")

# Default alert threshold in standard deviations
DEFAULT_ALERT_THRESHOLD = 2.5

# Minimum standard deviation floor to prevent division by zero
# (features with zero std dev are considered perfectly stable)
_STD_FLOOR = 1e-9


@dataclass
class DeviationResult:
    """Result of scoring a single response against the baseline profile.

    Attributes:
        z_scores: Per-feature z-score values.
        feature_names: Names of each feature (for reporting).
        aggregate_deviation: RMS of all z-scores (scalar summary).
        alert_triggered: True if aggregate deviation exceeds threshold.
        threshold: The configured alert threshold (sigma).
        max_z_score: The highest individual z-score.
        max_z_feature: The feature name with the highest z-score.
        scoring_time_ms: Time taken to compute the scores.
    """

    z_scores: list[float] = field(default_factory=list)
    feature_names: list[str] = field(default_factory=list)
    aggregate_deviation: float = 0.0
    alert_triggered: bool = False
    threshold: float = DEFAULT_ALERT_THRESHOLD
    max_z_score: float = 0.0
    max_z_feature: str = ""
    scoring_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "z_scores": self.z_scores,
            "feature_names": self.feature_names,
            "aggregate_deviation": self.aggregate_deviation,
            "alert_triggered": self.alert_triggered,
            "threshold": self.threshold,
            "max_z_score": self.max_z_score,
            "max_z_feature": self.max_z_feature,
            "scoring_time_ms": self.scoring_time_ms,
        }

    def feature_deltas(self) -> dict[str, float]:
        """Return a mapping of feature name to z-score for reporting."""
        return dict(zip(self.feature_names, self.z_scores))


class DeviationScorer:
    """Scores feature vectors against a baseline profile using z-scores.

    The aggregate deviation index is the root-mean-square (RMS) of all
    per-feature z-scores.  An alert is triggered when the aggregate
    deviation exceeds the configured threshold.
    """

    def __init__(
        self,
        extractor: Optional[StylemetricFeatureExtractor] = None,
        alert_threshold: float = DEFAULT_ALERT_THRESHOLD,
    ) -> None:
        self._extractor = extractor or get_feature_extractor()
        self._alert_threshold = alert_threshold

    @property
    def alert_threshold(self) -> float:
        return self._alert_threshold

    @alert_threshold.setter
    def alert_threshold(self, value: float) -> None:
        if value <= 0:
            raise ValueError("Alert threshold must be positive")
        self._alert_threshold = value

    def score_vector(
        self,
        feature_vector: list[float],
        profile: BaselineProfile,
    ) -> DeviationResult:
        """Compute z-scores for a pre-extracted feature vector.

        Args:
            feature_vector: 16-element feature vector.
            profile: The baseline profile to score against.

        Returns:
            A :class:`DeviationResult` with per-feature z-scores and
            aggregate deviation index.
        """
        start = time.perf_counter()

        if len(feature_vector) != FEATURE_COUNT:
            raise ValueError(
                f"Feature vector length mismatch: expected {FEATURE_COUNT}, "
                f"got {len(feature_vector)}"
            )

        z_scores = []
        for i in range(FEATURE_COUNT):
            std = profile.stds[i] if profile.stds[i] > _STD_FLOOR else _STD_FLOOR
            z = abs(feature_vector[i] - profile.means[i]) / std
            z_scores.append(round(z, 6))

        # Aggregate deviation: RMS of z-scores
        rms = math.sqrt(sum(z ** 2 for z in z_scores) / FEATURE_COUNT)
        aggregate = round(rms, 6)

        # Find the feature with the highest z-score
        max_z = 0.0
        max_feature = ""
        for i, z in enumerate(z_scores):
            if z > max_z:
                max_z = z
                max_feature = FEATURE_NAMES[i]

        alert = aggregate >= self._alert_threshold

        elapsed_ms = round((time.perf_counter() - start) * 1000, 3)

        if alert:
            logger.warning(
                "DEVIATION ALERT: aggregate=%.3f threshold=%.1f "
                "max_z=%.3f (%s) scoring_time=%.1fms",
                aggregate,
                self._alert_threshold,
                max_z,
                max_feature,
                elapsed_ms,
            )

        return DeviationResult(
            z_scores=z_scores,
            feature_names=list(FEATURE_NAMES),
            aggregate_deviation=aggregate,
            alert_triggered=alert,
            threshold=self._alert_threshold,
            max_z_score=max_z,
            max_z_feature=max_feature,
            scoring_time_ms=elapsed_ms,
        )

    def score_response(
        self,
        response_text: str,
        profile: BaselineProfile,
    ) -> DeviationResult:
        """Extract features from text and score against baseline.

        Convenience method that combines extraction and scoring.
        """
        features = self._extractor.extract(response_text)
        return self.score_vector(features, profile)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_scorer: Optional[DeviationScorer] = None


def get_deviation_scorer(
    alert_threshold: float = DEFAULT_ALERT_THRESHOLD,
) -> DeviationScorer:
    """Get or create the singleton deviation scorer."""
    global _scorer
    if _scorer is None:
        _scorer = DeviationScorer(alert_threshold=alert_threshold)
    return _scorer


def reset_deviation_scorer() -> None:
    """Reset the singleton (for testing)."""
    global _scorer
    _scorer = None
