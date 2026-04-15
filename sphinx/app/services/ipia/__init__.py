"""IPIA — Indirect Prompt Injection Analysis engine (Sprint 31, Module E15).

Provides embedding-based detection of indirect prompt injection attacks
in RAG-retrieved content.
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
]
