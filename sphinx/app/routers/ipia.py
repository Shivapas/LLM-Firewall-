"""IPIA router — embedding, injection detection, and admin endpoints.

Sprint 31 endpoints:
  POST /v1/ipia/embed       — return 384-dim embedding for input text
  POST /v1/ipia/scan        — scan a single (chunk, query) pair
  POST /v1/ipia/scan/batch  — scan multiple chunks against one query
  GET  /v1/ipia/health      — health / readiness check

Sprint 32 endpoints (SP-321 / SP-323 / SP-324):
  POST /v1/ipia/scan        — enhanced: accepts array of chunks + query (batch mode)
  GET  /v1/ipia/metrics      — rolling 24h detection stats for dashboard widget
  GET  /v1/ipia/config       — current IPIA configuration
  PUT  /v1/ipia/config       — update IPIA feature flag / threshold at runtime
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.ipia.embedding_service import (
    EmbedRequest,
    EmbedResponse,
    IPIABatchScanRequest,
    IPIABatchScanResponse,
    IPIAHealthResponse,
    IPIAScanRequest,
    IPIAScanResult,
    get_ipia_service,
)
from app.services.ipia.detector import get_ipia_detector
from app.services.ipia.threat_event import get_ipia_threat_emitter

logger = logging.getLogger("sphinx.routers.ipia")

router = APIRouter(prefix="/v1/ipia", tags=["IPIA"])


# ---------------------------------------------------------------------------
# Sprint 31 endpoints (unchanged)
# ---------------------------------------------------------------------------


@router.post("/embed", response_model=EmbedResponse)
async def embed_text(req: EmbedRequest) -> EmbedResponse:
    """Return a 384-dimensional embedding vector for the given text."""
    try:
        svc = get_ipia_service()
        return svc.embed(req.text)
    except Exception:
        logger.exception("IPIA embed failed")
        raise HTTPException(status_code=500, detail="Embedding service error")


@router.post("/scan", response_model=IPIAScanResult)
async def scan_chunk(req: IPIAScanRequest) -> IPIAScanResult:
    """Scan a single RAG chunk for indirect prompt injection."""
    try:
        svc = get_ipia_service()
        return svc.scan(req.chunk, req.query)
    except Exception:
        logger.exception("IPIA scan failed")
        raise HTTPException(status_code=500, detail="IPIA scan error")


@router.post("/scan/batch", response_model=IPIABatchScanResponse)
async def batch_scan_chunks(req: IPIABatchScanRequest) -> IPIABatchScanResponse:
    """Scan multiple RAG chunks for indirect prompt injection.

    SP-321: POST /v1/ipia/scan/batch accepts array of chunks + user_query;
    returns per-chunk {isInjection, confidence, reason} with p99 < 50ms
    for a batch of 10 chunks.
    """
    try:
        svc = get_ipia_service()
        result = svc.batch_scan(req.chunks, req.query)

        # SP-322: emit threat events for any detected injections
        try:
            detector = get_ipia_detector()
            emitter = get_ipia_threat_emitter()
            for idx, scan_result in enumerate(result.results):
                detector.metrics.record_scan(
                    scan_result.is_injection,
                    category="batch_scan_injection" if scan_result.is_injection else "benign",
                )
                if scan_result.is_injection:
                    import hashlib
                    from app.services.ipia.detector import IPIAThreatEvent
                    chunk_hash = hashlib.sha256(
                        req.chunks[idx].encode("utf-8")
                    ).hexdigest()[:16]
                    event = IPIAThreatEvent(
                        chunk_hash=chunk_hash,
                        confidence=scan_result.confidence,
                        reason=scan_result.reason,
                        max_similarity=scan_result.max_similarity,
                        chunk_query_similarity=scan_result.chunk_query_similarity,
                        scan_time_ms=scan_result.scan_time_ms,
                    )
                    await emitter.emit(event)
        except Exception:
            logger.debug("Failed to emit batch scan threat events", exc_info=True)

        return result
    except Exception:
        logger.exception("IPIA batch scan failed")
        raise HTTPException(status_code=500, detail="IPIA batch scan error")


@router.get("/health", response_model=IPIAHealthResponse)
async def ipia_health() -> IPIAHealthResponse:
    """IPIA service health and readiness check."""
    try:
        svc = get_ipia_service()
        return svc.health()
    except Exception:
        logger.exception("IPIA health check failed")
        raise HTTPException(status_code=503, detail="IPIA service unavailable")


# ---------------------------------------------------------------------------
# Sprint 32 endpoints
# ---------------------------------------------------------------------------


class IPIAMetricsResponse(BaseModel):
    """SP-323: Rolling 24h detection metrics for dashboard widget."""
    rolling_24h_detection_count: int = 0
    total_scans: int = 0
    total_detections: int = 0
    top_blocked_categories: list[dict] = Field(default_factory=list)
    detection_rate: float = 0.0
    window_seconds: int = 86400


@router.get("/metrics", response_model=IPIAMetricsResponse)
async def ipia_metrics() -> IPIAMetricsResponse:
    """SP-323: Rolling 24h IPIA detection statistics for dashboard widget.

    Returns detection count, top blocked categories, and detection rate
    within the last 24 hours.
    """
    try:
        detector = get_ipia_detector()
        stats = detector.metrics.get_rolling_stats()
        return IPIAMetricsResponse(**stats)
    except Exception:
        logger.exception("IPIA metrics failed")
        raise HTTPException(status_code=500, detail="IPIA metrics unavailable")


class IPIAConfigResponse(BaseModel):
    """Current IPIA configuration."""
    ipia_enabled: bool = False
    default_threshold: float = 0.50
    emitter_connected: bool = False
    emitter_emitted_count: int = 0
    emitter_fallback_queue_size: int = 0


@router.get("/config", response_model=IPIAConfigResponse)
async def ipia_config() -> IPIAConfigResponse:
    """Return current IPIA detector configuration."""
    try:
        detector = get_ipia_detector()
        emitter = get_ipia_threat_emitter()
        return IPIAConfigResponse(
            ipia_enabled=detector.enabled,
            default_threshold=detector.default_threshold,
            emitter_connected=emitter._initialized,
            emitter_emitted_count=emitter.emitted_count,
            emitter_fallback_queue_size=emitter.fallback_queue_size,
        )
    except Exception:
        logger.exception("IPIA config read failed")
        raise HTTPException(status_code=500, detail="IPIA config unavailable")


class IPIAConfigUpdateRequest(BaseModel):
    """SP-324: Runtime IPIA configuration update."""
    ipia_enabled: Optional[bool] = None
    default_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)


@router.put("/config", response_model=IPIAConfigResponse)
async def update_ipia_config(req: IPIAConfigUpdateRequest) -> IPIAConfigResponse:
    """Update IPIA feature flag and/or default threshold at runtime.

    SP-324: threshold 0.0 blocks all chunks; threshold 1.0 passes all.
    """
    try:
        detector = get_ipia_detector()
        if req.ipia_enabled is not None:
            detector.enabled = req.ipia_enabled
            logger.info("IPIA enabled set to %s", req.ipia_enabled)
        if req.default_threshold is not None:
            detector._default_threshold = req.default_threshold
            logger.info("IPIA default threshold set to %.2f", req.default_threshold)
        return await ipia_config()
    except Exception:
        logger.exception("IPIA config update failed")
        raise HTTPException(status_code=500, detail="IPIA config update failed")
