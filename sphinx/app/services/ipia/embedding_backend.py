"""SP-313: Pluggable Embedding Backend Interface.

Provides an abstract base class for embedding backends, enabling seamless
swap between SentenceTransformers (MiniLM) and any future model without
code changes.  Ships with two concrete implementations:

* **SentenceTransformersBackend** -- wraps ``all-MiniLM-L6-v2`` (384-dim).
* **HashEmbeddingBackend** -- lightweight, dependency-free fallback using
  character/word n-gram hashing (384-dim).  Used when ``sentence-transformers``
  is not installed or in unit-test environments.
"""

from __future__ import annotations

import hashlib
import logging
import math
from abc import ABC, abstractmethod
from typing import Callable, Optional

logger = logging.getLogger("sphinx.ipia.embedding_backend")

# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------


class PluggableEmbeddingBackend(ABC):
    """Backend-agnostic embedding interface.

    Any object that satisfies ``embed(text) -> list[float]`` and exposes a
    ``dimension`` property can be plugged into the IPIA pipeline.
    """

    @abstractmethod
    def embed(self, text: str) -> list[float]:
        """Return a unit-normalised embedding vector for *text*."""

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Dimensionality of the vectors produced by this backend."""

    @property
    def name(self) -> str:
        return self.__class__.__name__


# ---------------------------------------------------------------------------
# SentenceTransformers backend (production)
# ---------------------------------------------------------------------------


class SentenceTransformersBackend(PluggableEmbeddingBackend):
    """Wraps ``sentence-transformers/all-MiniLM-L6-v2`` (384-dim).

    The model is loaded eagerly on construction so that the gateway cold-start
    cost is paid once.  ``encode`` is called with ``normalize_embeddings=True``
    so that downstream cosine similarity reduces to a dot product.
    """

    _DIMENSION = 384
    _DEFAULT_MODEL = "all-MiniLM-L6-v2"

    def __init__(self, model_name: str | None = None) -> None:
        model_name = model_name or self._DEFAULT_MODEL
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "sentence-transformers is required for SentenceTransformersBackend. "
                "Install it with: pip install sentence-transformers"
            ) from exc

        logger.info("Loading SentenceTransformer model: %s", model_name)
        self._model = SentenceTransformer(model_name)
        self._dim = self._model.get_sentence_embedding_dimension() or self._DIMENSION
        logger.info("SentenceTransformer model loaded: dim=%d", self._dim)

    def embed(self, text: str) -> list[float]:
        vec = self._model.encode(text, normalize_embeddings=True)
        return vec.tolist()

    @property
    def dimension(self) -> int:
        return self._dim


# ---------------------------------------------------------------------------
# Hash-based fallback backend (testing / lightweight)
# ---------------------------------------------------------------------------


class HashEmbeddingBackend(PluggableEmbeddingBackend):
    """Deterministic hash-based embedding backend (384-dim by default).

    Uses character trigrams, word hashing, and bigram hashing to produce
    a fixed-size, L2-normalised vector.  No external dependencies.
    Suitable for unit tests and environments without GPU/model files.
    """

    def __init__(self, dim: int = 384) -> None:
        self._dim = dim

    def embed(self, text: str) -> list[float]:
        return _hash_embedding(text, self._dim)

    @property
    def dimension(self) -> int:
        return self._dim


# ---------------------------------------------------------------------------
# Callable wrapper backend (for mocks / lambdas)
# ---------------------------------------------------------------------------


class CallableEmbeddingBackend(PluggableEmbeddingBackend):
    """Wraps any ``embed(text) -> vector`` callable as a backend.

    Useful for injecting mock or custom embedding functions in tests.
    """

    def __init__(self, fn: Callable[[str], list[float]], dim: int) -> None:
        self._fn = fn
        self._dim = dim

    def embed(self, text: str) -> list[float]:
        return self._fn(text)

    @property
    def dimension(self) -> int:
        return self._dim


# ---------------------------------------------------------------------------
# Factory helper
# ---------------------------------------------------------------------------


def create_default_backend() -> PluggableEmbeddingBackend:
    """Create the best available backend.

    Tries ``SentenceTransformersBackend`` first; falls back to
    ``HashEmbeddingBackend`` if ``sentence-transformers`` is not installed.
    """
    try:
        return SentenceTransformersBackend()
    except ImportError:
        logger.warning(
            "sentence-transformers not available; falling back to HashEmbeddingBackend"
        )
        return HashEmbeddingBackend(dim=384)


# ---------------------------------------------------------------------------
# Hash embedding implementation
# ---------------------------------------------------------------------------


def _hash_embedding(text: str, dim: int = 384) -> list[float]:
    """Generate a deterministic, L2-normalised embedding from *text*.

    Combines character trigram hashing, word-level hashing, and word-bigram
    hashing to capture lexical and shallow semantic signals.
    """
    text_lower = text.lower().strip()
    vec = [0.0] * dim

    # Character trigram hashing
    for i in range(len(text_lower) - 2):
        trigram = text_lower[i: i + 3]
        h = int(hashlib.md5(trigram.encode()).hexdigest(), 16)
        idx = h % dim
        sign = 1.0 if (h // dim) % 2 == 0 else -1.0
        vec[idx] += sign

    # Word-level hashing (weighted higher)
    words = text_lower.split()
    for word in words:
        h = int(hashlib.sha256(word.encode()).hexdigest(), 16)
        idx = h % dim
        sign = 1.0 if (h // dim) % 2 == 0 else -1.0
        vec[idx] += sign * 2.0

    # Word-bigram hashing
    for i in range(len(words) - 1):
        bigram = f"{words[i]} {words[i + 1]}"
        h = int(hashlib.md5(bigram.encode()).hexdigest(), 16)
        idx = h % dim
        sign = 1.0 if (h // dim) % 2 == 0 else -1.0
        vec[idx] += sign * 1.5

    # L2 normalise
    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0:
        vec = [x / norm for x in vec]

    return vec
