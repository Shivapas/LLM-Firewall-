"""SP-310: SentenceTransformers embedding FastAPI microservice.

Provides a ``/v1/ipia/embed`` endpoint that accepts text and returns a
384-dimensional embedding vector.  The service wraps whichever
:class:`PluggableEmbeddingBackend` is configured (defaulting to
``all-MiniLM-L6-v2`` when ``sentence-transformers`` is installed, or the
hash-based fallback otherwise).

The endpoint is designed to be low-latency (<5 ms on CPU for 512-token
inputs with SentenceTransformers, <1 ms with the hash backend).

This module also exposes the IPIA scan endpoint that combines the
embedding service, joint-context encoder, and similarity scorer into a
single detection pipeline.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from pydantic import BaseModel, Field

from app.services.ipia.embedding_backend import (
    PluggableEmbeddingBackend,
    create_default_backend,
)
from app.services.ipia.joint_context_encoder import JointContextEncoder
from app.services.ipia.scorer import IPIAClassification, IPIASimilarityScorer

logger = logging.getLogger("sphinx.ipia.embedding_service")


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class EmbedRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Text to embed")


class EmbedResponse(BaseModel):
    embedding: list[float]
    dimension: int
    backend: str
    latency_ms: float


class IPIAScanRequest(BaseModel):
    chunk: str = Field(..., min_length=1, description="Retrieved RAG chunk")
    query: str = Field(..., min_length=1, description="User query")


class IPIAScanResult(BaseModel):
    is_injection: bool
    confidence: float
    reason: str
    max_similarity: float
    chunk_query_similarity: Optional[float] = None
    scan_time_ms: float


class IPIABatchScanRequest(BaseModel):
    chunks: list[str] = Field(..., min_length=1, description="List of RAG chunks")
    query: str = Field(..., min_length=1, description="User query")


class IPIABatchScanResponse(BaseModel):
    results: list[IPIAScanResult]
    total_scan_time_ms: float
    injections_found: int


class IPIAHealthResponse(BaseModel):
    status: str
    backend: str
    dimension: int
    reference_count: int
    threshold: float


# ---------------------------------------------------------------------------
# Service class
# ---------------------------------------------------------------------------


class IPIAEmbeddingService:
    """Core IPIA service combining embedding, encoding, and scoring.

    This is the central orchestrator initialised at gateway startup.
    """

    def __init__(
        self,
        backend: PluggableEmbeddingBackend | None = None,
        threshold: float = 0.50,
    ) -> None:
        self._backend = backend or create_default_backend()
        self._encoder = JointContextEncoder(self._backend)
        self._scorer = IPIASimilarityScorer(self._backend, threshold=threshold)
        logger.info(
            "IPIAEmbeddingService initialised: backend=%s dim=%d threshold=%.2f",
            self._backend.name,
            self._backend.dimension,
            threshold,
        )

    # -- Embedding --------------------------------------------------------

    def embed(self, text: str) -> EmbedResponse:
        """Embed a single text string (SP-310 /embed endpoint)."""
        start = time.perf_counter()
        vec = self._backend.embed(text)
        elapsed = (time.perf_counter() - start) * 1000
        return EmbedResponse(
            embedding=vec,
            dimension=self._backend.dimension,
            backend=self._backend.name,
            latency_ms=round(elapsed, 3),
        )

    # -- Single scan ------------------------------------------------------

    def scan(self, chunk: str, query: str) -> IPIAScanResult:
        """Run IPIA detection on a single (chunk, query) pair."""
        joint = self._encoder.encode(chunk, query)
        classification = self._scorer.score_joint(chunk, joint)
        return self._to_result(classification)

    # -- Batch scan -------------------------------------------------------

    def batch_scan(self, chunks: list[str], query: str) -> IPIABatchScanResponse:
        """Run IPIA detection on multiple chunks against the same query."""
        start = time.perf_counter()
        results: list[IPIAScanResult] = []
        injections = 0
        for chunk in chunks:
            r = self.scan(chunk, query)
            results.append(r)
            if r.is_injection:
                injections += 1
        total_ms = (time.perf_counter() - start) * 1000
        return IPIABatchScanResponse(
            results=results,
            total_scan_time_ms=round(total_ms, 3),
            injections_found=injections,
        )

    # -- Health -----------------------------------------------------------

    def health(self) -> IPIAHealthResponse:
        return IPIAHealthResponse(
            status="ok",
            backend=self._backend.name,
            dimension=self._backend.dimension,
            reference_count=self._scorer.reference_count,
            threshold=self._scorer.threshold,
        )

    # -- Accessors --------------------------------------------------------

    @property
    def backend(self) -> PluggableEmbeddingBackend:
        return self._backend

    @property
    def scorer(self) -> IPIASimilarityScorer:
        return self._scorer

    @property
    def encoder(self) -> JointContextEncoder:
        return self._encoder

    # -- Internal ---------------------------------------------------------

    @staticmethod
    def _to_result(c: IPIAClassification) -> IPIAScanResult:
        return IPIAScanResult(
            is_injection=c.is_injection,
            confidence=round(c.confidence, 4),
            reason=c.reason,
            max_similarity=round(c.max_similarity, 4),
            chunk_query_similarity=(
                round(c.chunk_query_similarity, 4)
                if c.chunk_query_similarity is not None
                else None
            ),
            scan_time_ms=round(c.scan_time_ms, 3),
        )


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_service: Optional[IPIAEmbeddingService] = None


def get_ipia_service(
    backend: PluggableEmbeddingBackend | None = None,
    threshold: float = 0.50,
) -> IPIAEmbeddingService:
    """Get or create the singleton IPIA embedding service."""
    global _service
    if _service is None:
        _service = IPIAEmbeddingService(backend=backend, threshold=threshold)
    return _service


def reset_ipia_service() -> None:
    """Reset the singleton (for testing)."""
    global _service
    _service = None
