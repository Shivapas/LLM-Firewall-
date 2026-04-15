"""IPIA — Indirect Prompt Injection Analysis engine (Module E15).

Sprint 31: Embedding service, joint-context encoder, cosine similarity scorer.
Sprint 32: Pre-context-injection detector, threat event emission, per-policy
           threshold config, CERT-In compliance annotation, dashboard metrics.
"""

from app.services.ipia.embedding_backend import (
    CallableEmbeddingBackend,
    HashEmbeddingBackend,
    PluggableEmbeddingBackend,
    SentenceTransformersBackend,
    create_default_backend,
)
from app.services.ipia.embedding_service import (
    IPIAEmbeddingService,
    get_ipia_service,
    reset_ipia_service,
)
from app.services.ipia.joint_context_encoder import JointContextEncoder, JointEmbeddingResult
from app.services.ipia.scorer import IPIAClassification, IPIASimilarityScorer

# Sprint 32 components
from app.services.ipia.detector import (
    IPIADetector,
    IPIAInterceptResult,
    IPIAChunkResult,
    IPIAThreatEvent,
    IPIAMetricsStore,
    get_ipia_detector,
    reset_ipia_detector,
)
from app.services.ipia.threat_event import (
    IPIAThreatEventEmitter,
    get_ipia_threat_emitter,
    reset_ipia_threat_emitter,
)

__all__ = [
    # Backend interface + implementations
    "PluggableEmbeddingBackend",
    "SentenceTransformersBackend",
    "HashEmbeddingBackend",
    "CallableEmbeddingBackend",
    "create_default_backend",
    # Joint-context encoder
    "JointContextEncoder",
    "JointEmbeddingResult",
    # Scorer
    "IPIASimilarityScorer",
    "IPIAClassification",
    # Service + singleton
    "IPIAEmbeddingService",
    "get_ipia_service",
    "reset_ipia_service",
    # Sprint 32: Detector + intercept
    "IPIADetector",
    "IPIAInterceptResult",
    "IPIAChunkResult",
    "IPIAThreatEvent",
    "IPIAMetricsStore",
    "get_ipia_detector",
    "reset_ipia_detector",
    # Sprint 32: Threat event emitter
    "IPIAThreatEventEmitter",
    "get_ipia_threat_emitter",
    "reset_ipia_threat_emitter",
]
