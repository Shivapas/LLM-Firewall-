"""SP-320 / SP-322 / SP-324 / SP-325: IPIA Detector — pre-context-injection intercept.

Scans all RAG chunks before context assembly.  Clean chunks pass through;
injection chunks are blocked with a 400 response and a HIGH-severity
threat event emitted to the TrustDetect Kafka topic.

Features:
  - SP-320: Wire into pre-context-injection intercept layer
  - SP-322: Emit IPIA threat events (severity=HIGH, category=IPIA)
  - SP-324: Per-policy configurable threshold (ipia_threshold: 0.0–1.0)
  - SP-325: CERT-In compliance annotation on detection events
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

from app.services.ipia.embedding_service import (
    IPIAEmbeddingService,
    IPIAScanResult,
    get_ipia_service,
)

logger = logging.getLogger("sphinx.ipia.detector")

# ---------------------------------------------------------------------------
# CERT-In advisory reference (SP-325)
# ---------------------------------------------------------------------------
CERT_IN_AI_SECURITY_REF = "CERT-In-AI-SEC-2025-001"

# ---------------------------------------------------------------------------
# IPIA Threat Event schema (SP-322)
# ---------------------------------------------------------------------------


@dataclass
class IPIAThreatEvent:
    """TrustDetect-compatible threat event for IPIA detection (SP-322).

    Emitted when an indirect prompt injection is detected in a RAG chunk.
    Schema follows UCDM threat event specification.
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    severity: str = "HIGH"
    category: str = "IPIA"
    chunk_hash: str = ""
    confidence: float = 0.0
    reason: str = ""
    tenant_id: str = ""
    policy_id: str = ""
    threshold_used: float = 0.50
    max_similarity: float = 0.0
    chunk_query_similarity: Optional[float] = None
    scan_time_ms: float = 0.0
    # SP-325: CERT-In compliance annotation
    cert_in_ref: str = CERT_IN_AI_SECURITY_REF
    owasp_category: str = "LLM08-2025"

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "category": self.category,
            "chunk_hash": self.chunk_hash,
            "confidence": self.confidence,
            "reason": self.reason,
            "tenant_id": self.tenant_id,
            "policy_id": self.policy_id,
            "threshold_used": self.threshold_used,
            "max_similarity": self.max_similarity,
            "chunk_query_similarity": self.chunk_query_similarity,
            "scan_time_ms": self.scan_time_ms,
            "cert_in_ref": self.cert_in_ref,
            "owasp_category": self.owasp_category,
        }


# ---------------------------------------------------------------------------
# Detection metrics store (SP-323)
# ---------------------------------------------------------------------------


class IPIAMetricsStore:
    """Thread-safe rolling metrics store for IPIA detections.

    Tracks detection events within a 24-hour rolling window for the
    admin dashboard widget (SP-323).
    """

    _WINDOW_SECONDS = 86400  # 24 hours

    def __init__(self) -> None:
        self._lock = Lock()
        self._detections: deque[dict] = deque()
        self._total_scans: int = 0
        self._total_detections: int = 0

    def record_scan(self, is_injection: bool, category: str = "unknown") -> None:
        """Record an IPIA scan result."""
        now = time.time()
        with self._lock:
            self._total_scans += 1
            if is_injection:
                self._total_detections += 1
                self._detections.append({"ts": now, "category": category})
            self._prune(now)

    def get_rolling_stats(self) -> dict:
        """Return rolling 24h detection statistics for the dashboard widget."""
        now = time.time()
        with self._lock:
            self._prune(now)
            # Count detections by category
            category_counts: dict[str, int] = {}
            for det in self._detections:
                cat = det.get("category", "unknown")
                category_counts[cat] = category_counts.get(cat, 0) + 1
            # Sort by count descending, take top 5
            top_categories = sorted(
                category_counts.items(), key=lambda x: x[1], reverse=True
            )[:5]

            return {
                "rolling_24h_detection_count": len(self._detections),
                "total_scans": self._total_scans,
                "total_detections": self._total_detections,
                "top_blocked_categories": [
                    {"category": cat, "count": cnt} for cat, cnt in top_categories
                ],
                "detection_rate": (
                    round(self._total_detections / self._total_scans, 4)
                    if self._total_scans > 0
                    else 0.0
                ),
                "window_seconds": self._WINDOW_SECONDS,
            }

    def _prune(self, now: float) -> None:
        """Remove detections outside the rolling window."""
        cutoff = now - self._WINDOW_SECONDS
        while self._detections and self._detections[0]["ts"] < cutoff:
            self._detections.popleft()


# ---------------------------------------------------------------------------
# IPIA Chunk Detection Result
# ---------------------------------------------------------------------------


@dataclass
class IPIAChunkResult:
    """Result for a single chunk processed through the IPIA detector."""

    chunk_index: int
    is_injection: bool
    confidence: float
    reason: str
    chunk_hash: str
    max_similarity: float = 0.0
    chunk_query_similarity: Optional[float] = None
    scan_time_ms: float = 0.0


@dataclass
class IPIAInterceptResult:
    """Aggregate result of IPIA interception on a set of RAG chunks."""

    allowed: bool  # True if all chunks are clean
    blocked_count: int
    total_count: int
    chunk_results: list[IPIAChunkResult] = field(default_factory=list)
    threat_events: list[IPIAThreatEvent] = field(default_factory=list)
    total_scan_time_ms: float = 0.0


# ---------------------------------------------------------------------------
# IPIADetector — core intercept logic (SP-320)
# ---------------------------------------------------------------------------


class IPIADetector:
    """Pre-context-injection intercept: scans RAG chunks before context assembly.

    Integrates with the IPIA embedding engine (Sprint 31) to detect indirect
    prompt injection in retrieved content.  Emits threat events for TrustDetect
    and records metrics for the dashboard widget.

    Feature flag: ``ipia_enabled`` (default False in Sprint 32, opt-in per policy).
    Per-policy threshold override: ``ipia_threshold`` (0.0–1.0).
    """

    def __init__(
        self,
        service: IPIAEmbeddingService | None = None,
        default_threshold: float = 0.50,
        enabled: bool = False,
    ) -> None:
        self._service = service
        self._default_threshold = default_threshold
        self._enabled = enabled
        self._metrics = IPIAMetricsStore()
        logger.info(
            "IPIADetector initialised: enabled=%s default_threshold=%.2f",
            self._enabled,
            self._default_threshold,
        )

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    @property
    def metrics(self) -> IPIAMetricsStore:
        return self._metrics

    @property
    def default_threshold(self) -> float:
        return self._default_threshold

    def _get_service(self) -> IPIAEmbeddingService:
        if self._service is None:
            self._service = get_ipia_service()
        return self._service

    # -- SP-324: resolve threshold per policy --------------------------------

    def _resolve_threshold(
        self,
        policy_threshold: Optional[float] = None,
    ) -> float:
        """Resolve the effective IPIA threshold.

        Priority: policy-level override > detector default.
        SP-324: threshold 0.0 blocks all chunks; threshold 1.0 passes all.
        """
        if policy_threshold is not None and 0.0 <= policy_threshold <= 1.0:
            return policy_threshold
        return self._default_threshold

    # -- Main intercept method (SP-320) -------------------------------------

    def scan_chunks(
        self,
        chunks: list[str],
        user_query: str,
        tenant_id: str = "",
        policy_id: str = "",
        ipia_threshold: Optional[float] = None,
        ipia_enabled: Optional[bool] = None,
    ) -> IPIAInterceptResult:
        """Scan RAG chunks before context assembly.

        Returns an :class:`IPIAInterceptResult`.  If ``ipia_enabled`` is
        explicitly ``False`` (or the detector is globally disabled and no
        per-policy override), all chunks pass through without scanning.

        SP-320: injection chunks blocked with threat event.
        SP-322: threat events emitted for TrustDetect.
        SP-324: per-policy threshold override.
        SP-325: CERT-In ref in threat events.
        """
        # Resolve enabled flag: per-policy override > global setting
        effective_enabled = ipia_enabled if ipia_enabled is not None else self._enabled
        if not effective_enabled:
            return IPIAInterceptResult(
                allowed=True,
                blocked_count=0,
                total_count=len(chunks),
            )

        effective_threshold = self._resolve_threshold(ipia_threshold)
        svc = self._get_service()

        start = time.perf_counter()
        chunk_results: list[IPIAChunkResult] = []
        threat_events: list[IPIAThreatEvent] = []
        blocked = 0

        # SP-324 boundary: threshold 1.0 passes all chunks unconditionally
        if effective_threshold >= 1.0:
            total_ms = (time.perf_counter() - start) * 1000
            for idx, chunk_text in enumerate(chunks):
                self._metrics.record_scan(False, category="benign")
            return IPIAInterceptResult(
                allowed=True,
                blocked_count=0,
                total_count=len(chunks),
                total_scan_time_ms=round(total_ms, 3),
            )

        # SP-324 boundary: threshold 0.0 blocks all chunks unconditionally
        if effective_threshold <= 0.0:
            for idx, chunk_text in enumerate(chunks):
                chunk_hash = hashlib.sha256(chunk_text.encode("utf-8")).hexdigest()[:16]
                cr = IPIAChunkResult(
                    chunk_index=idx,
                    is_injection=True,
                    confidence=1.0,
                    reason="Threshold 0.0: all chunks blocked by policy",
                    chunk_hash=chunk_hash,
                )
                chunk_results.append(cr)
                self._metrics.record_scan(True, category="policy_block_all")
                threat_events.append(IPIAThreatEvent(
                    chunk_hash=chunk_hash,
                    confidence=1.0,
                    reason="Threshold 0.0: all chunks blocked by policy",
                    tenant_id=tenant_id,
                    policy_id=policy_id,
                    threshold_used=0.0,
                ))
                blocked += 1
            total_ms = (time.perf_counter() - start) * 1000
            return IPIAInterceptResult(
                allowed=False,
                blocked_count=blocked,
                total_count=len(chunks),
                chunk_results=chunk_results,
                threat_events=threat_events,
                total_scan_time_ms=round(total_ms, 3),
            )

        # Temporarily override scorer threshold for this scan
        original_threshold = svc.scorer.threshold
        svc.scorer.threshold = effective_threshold

        try:
            for idx, chunk_text in enumerate(chunks):
                scan_result = svc.scan(chunk_text, user_query)
                chunk_hash = hashlib.sha256(chunk_text.encode("utf-8")).hexdigest()[:16]

                cr = IPIAChunkResult(
                    chunk_index=idx,
                    is_injection=scan_result.is_injection,
                    confidence=scan_result.confidence,
                    reason=scan_result.reason,
                    chunk_hash=chunk_hash,
                    max_similarity=scan_result.max_similarity,
                    chunk_query_similarity=scan_result.chunk_query_similarity,
                    scan_time_ms=scan_result.scan_time_ms,
                )
                chunk_results.append(cr)

                # Determine category from reason for metrics
                category = "injection_override" if scan_result.is_injection else "benign"
                self._metrics.record_scan(scan_result.is_injection, category=category)

                if scan_result.is_injection:
                    blocked += 1
                    # SP-322: emit threat event
                    threat_event = IPIAThreatEvent(
                        chunk_hash=chunk_hash,
                        confidence=scan_result.confidence,
                        reason=scan_result.reason,
                        tenant_id=tenant_id,
                        policy_id=policy_id,
                        threshold_used=effective_threshold,
                        max_similarity=scan_result.max_similarity,
                        chunk_query_similarity=scan_result.chunk_query_similarity,
                        scan_time_ms=scan_result.scan_time_ms,
                    )
                    threat_events.append(threat_event)
                    logger.warning(
                        "IPIA BLOCKED chunk %d/%d hash=%s confidence=%.3f tenant=%s policy=%s",
                        idx + 1,
                        len(chunks),
                        chunk_hash,
                        scan_result.confidence,
                        tenant_id,
                        policy_id,
                    )
        finally:
            # Restore original threshold
            svc.scorer.threshold = original_threshold

        total_ms = (time.perf_counter() - start) * 1000

        return IPIAInterceptResult(
            allowed=(blocked == 0),
            blocked_count=blocked,
            total_count=len(chunks),
            chunk_results=chunk_results,
            threat_events=threat_events,
            total_scan_time_ms=round(total_ms, 3),
        )


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_detector: Optional[IPIADetector] = None


def get_ipia_detector(
    service: IPIAEmbeddingService | None = None,
    default_threshold: float = 0.50,
    enabled: bool = False,
) -> IPIADetector:
    """Get or create the singleton IPIA detector."""
    global _detector
    if _detector is None:
        _detector = IPIADetector(
            service=service,
            default_threshold=default_threshold,
            enabled=enabled,
        )
    return _detector


def reset_ipia_detector() -> None:
    """Reset the singleton (for testing)."""
    global _detector
    _detector = None
