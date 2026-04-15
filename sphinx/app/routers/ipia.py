"""IPIA router — embedding and injection detection endpoints (Sprint 31).

Exposes the IPIA embedding microservice within the Sphinx gateway pod:

* ``POST /v1/ipia/embed`` — return 384-dim embedding for input text
* ``POST /v1/ipia/scan`` — scan a single (chunk, query) pair
* ``POST /v1/ipia/scan/batch`` — scan multiple chunks against one query
* ``GET  /v1/ipia/health`` — health / readiness check
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

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

logger = logging.getLogger("sphinx.routers.ipia")

router = APIRouter(prefix="/v1/ipia", tags=["IPIA"])


@router.post("/embed", response_model=EmbedResponse)
async def embed_text(req: EmbedRequest) -> EmbedResponse:
    """Return a 384-dimensional embedding vector for the given text.

    Responds in < 5 ms on CPU with the SentenceTransformers backend,
    or < 1 ms with the hash-based fallback.
    """
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
    """Scan multiple RAG chunks for indirect prompt injection."""
    try:
        svc = get_ipia_service()
        return svc.batch_scan(req.chunks, req.query)
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
