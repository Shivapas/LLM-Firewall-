"""SP-341: BaselineProfiler -- warm-up profiling and JSON baseline export.

Collects a configurable number of warm-up responses (default 50) at
deployment time, computes per-feature mean and standard deviation, and
exports the resulting baseline profile as a JSON document.

The profile is cryptographically anchored via a SHA-256 digest of the
serialised feature statistics, enabling tamper detection on re-import.

SP-341 acceptance criteria:
  - Profiler completes 50-response warm-up in < 200ms (async, background)
  - JSON profile exported and re-importable
  - Profile stable (< 5% variance across two warm-up runs)
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import time
from threading import Lock
from typing import Optional

from app.services.fingerprint.feature_extractor import (
    FEATURE_COUNT,
    FEATURE_NAMES,
    StylemetricFeatureExtractor,
    get_feature_extractor,
)

logger = logging.getLogger("sphinx.fingerprint.baseline_profiler")


class BaselineProfile:
    """Immutable baseline profile containing per-feature statistics.

    Attributes:
        means: Per-feature mean values (length ``FEATURE_COUNT``).
        stds: Per-feature standard deviations (length ``FEATURE_COUNT``).
        sample_count: Number of responses used to compute the profile.
        created_at: Unix timestamp when the profile was computed.
        profile_hash: SHA-256 digest of the serialised statistics.
        model_id: Optional identifier for the inference model.
    """

    __slots__ = (
        "means",
        "stds",
        "sample_count",
        "created_at",
        "profile_hash",
        "model_id",
        "feature_names",
    )

    def __init__(
        self,
        means: list[float],
        stds: list[float],
        sample_count: int,
        created_at: float,
        profile_hash: str = "",
        model_id: str = "",
    ) -> None:
        self.means = means
        self.stds = stds
        self.sample_count = sample_count
        self.created_at = created_at
        self.model_id = model_id
        self.feature_names = list(FEATURE_NAMES)
        self.profile_hash = profile_hash or self._compute_hash()

    def _compute_hash(self) -> str:
        """SHA-256 digest of means + stds for tamper detection."""
        payload = json.dumps(
            {"means": self.means, "stds": self.stds},
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def verify_integrity(self) -> bool:
        """Return True if the stored hash matches the recomputed hash."""
        return self.profile_hash == self._compute_hash()

    def to_dict(self) -> dict:
        """Serialise the profile to a JSON-friendly dict."""
        return {
            "version": "1.0",
            "feature_count": FEATURE_COUNT,
            "feature_names": self.feature_names,
            "means": self.means,
            "stds": self.stds,
            "sample_count": self.sample_count,
            "created_at": self.created_at,
            "profile_hash": self.profile_hash,
            "model_id": self.model_id,
        }

    def to_json(self, indent: int = 2) -> str:
        """Export profile as a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict) -> "BaselineProfile":
        """Reconstruct a profile from a dict (e.g. parsed JSON)."""
        return cls(
            means=data["means"],
            stds=data["stds"],
            sample_count=data["sample_count"],
            created_at=data["created_at"],
            profile_hash=data.get("profile_hash", ""),
            model_id=data.get("model_id", ""),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "BaselineProfile":
        """Reconstruct a profile from a JSON string."""
        return cls.from_dict(json.loads(json_str))


class BaselineProfiler:
    """Collects warm-up responses and computes a baseline profile.

    The profiler operates in two phases:

    1. **Warm-up** -- call :meth:`add_response` for each LLM response until
       the target sample count is reached.
    2. **Compute** -- call :meth:`compute_profile` to finalise the baseline.

    Once a profile is computed, the profiler can be reset for re-warm-up
    via :meth:`reset`.
    """

    def __init__(
        self,
        extractor: Optional[StylemetricFeatureExtractor] = None,
        warm_up_count: int = 50,
        model_id: str = "",
    ) -> None:
        self._extractor = extractor or get_feature_extractor()
        self._warm_up_count = warm_up_count
        self._model_id = model_id
        self._lock = Lock()
        self._feature_vectors: list[list[float]] = []
        self._profile: Optional[BaselineProfile] = None
        self._warm_up_start: Optional[float] = None
        self._warm_up_duration_ms: Optional[float] = None

    @property
    def warm_up_count(self) -> int:
        return self._warm_up_count

    @property
    def collected(self) -> int:
        with self._lock:
            return len(self._feature_vectors)

    @property
    def is_warm_up_complete(self) -> bool:
        with self._lock:
            return len(self._feature_vectors) >= self._warm_up_count

    @property
    def profile(self) -> Optional[BaselineProfile]:
        with self._lock:
            return self._profile

    @property
    def warm_up_duration_ms(self) -> Optional[float]:
        return self._warm_up_duration_ms

    def add_response(self, response_text: str) -> bool:
        """Extract features from a response and add to the warm-up set.

        Returns True if the warm-up target has been reached (profile ready
        to compute).
        """
        with self._lock:
            if self._warm_up_start is None:
                self._warm_up_start = time.perf_counter()

            if len(self._feature_vectors) >= self._warm_up_count:
                return True  # Already have enough samples

            features = self._extractor.extract(response_text)
            self._feature_vectors.append(features)

            if len(self._feature_vectors) >= self._warm_up_count:
                logger.info(
                    "Warm-up target reached: %d responses collected",
                    self._warm_up_count,
                )
                return True
            return False

    def compute_profile(self) -> BaselineProfile:
        """Compute the baseline profile from collected feature vectors.

        Raises ValueError if insufficient samples have been collected.
        """
        with self._lock:
            n = len(self._feature_vectors)
            if n == 0:
                raise ValueError("No responses collected; cannot compute profile")

            means = [0.0] * FEATURE_COUNT
            stds = [0.0] * FEATURE_COUNT

            # Compute means
            for vec in self._feature_vectors:
                for i in range(FEATURE_COUNT):
                    means[i] += vec[i]
            for i in range(FEATURE_COUNT):
                means[i] /= n

            # Compute standard deviations (sample std dev if n > 1)
            if n > 1:
                for vec in self._feature_vectors:
                    for i in range(FEATURE_COUNT):
                        stds[i] += (vec[i] - means[i]) ** 2
                for i in range(FEATURE_COUNT):
                    stds[i] = math.sqrt(stds[i] / (n - 1))

            # Round for stability
            means = [round(m, 8) for m in means]
            stds = [round(s, 8) for s in stds]

            now = time.time()
            profile = BaselineProfile(
                means=means,
                stds=stds,
                sample_count=n,
                created_at=now,
                model_id=self._model_id,
            )

            self._profile = profile

            if self._warm_up_start is not None:
                self._warm_up_duration_ms = round(
                    (time.perf_counter() - self._warm_up_start) * 1000, 3
                )
                logger.info(
                    "Baseline profile computed: %d samples, %.1fms warm-up, "
                    "hash=%s model=%s",
                    n,
                    self._warm_up_duration_ms,
                    profile.profile_hash[:12],
                    self._model_id or "(unset)",
                )

            return profile

    def import_profile(self, profile: BaselineProfile) -> None:
        """Import an external baseline profile (e.g. from JSON export).

        Replaces any in-progress warm-up data.
        """
        if not profile.verify_integrity():
            raise ValueError(
                "Profile integrity check failed: hash mismatch "
                f"(expected={profile._compute_hash()[:12]}..., "
                f"stored={profile.profile_hash[:12]}...)"
            )
        with self._lock:
            self._profile = profile
            self._feature_vectors = []
            self._warm_up_start = None
            self._warm_up_duration_ms = None
            logger.info(
                "Baseline profile imported: %d samples, hash=%s",
                profile.sample_count,
                profile.profile_hash[:12],
            )

    def reset(self) -> None:
        """Clear all warm-up data and the current profile for re-warm-up."""
        with self._lock:
            self._feature_vectors = []
            self._profile = None
            self._warm_up_start = None
            self._warm_up_duration_ms = None
            logger.info("Baseline profiler reset for re-warm-up")


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_profiler: Optional[BaselineProfiler] = None


def get_baseline_profiler(
    warm_up_count: int = 50,
    model_id: str = "",
) -> BaselineProfiler:
    """Get or create the singleton baseline profiler."""
    global _profiler
    if _profiler is None:
        _profiler = BaselineProfiler(
            warm_up_count=warm_up_count,
            model_id=model_id,
        )
    return _profiler


def reset_baseline_profiler() -> None:
    """Reset the singleton (for testing)."""
    global _profiler
    _profiler = None
