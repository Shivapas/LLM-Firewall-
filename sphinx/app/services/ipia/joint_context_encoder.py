"""SP-311: Joint-Context Encoder for IPIA detection.

Encodes a (retrieved_chunk, user_query) pair as a single *joint embedding*
by concatenating the two texts with a separator token, embedding the
concatenation, and L2-normalising the result.

The joint embedding captures the *relationship* between the chunk content
and the user's intent, enabling the downstream scorer to detect semantic
misalignment that indicates indirect prompt injection.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Optional

from app.services.ipia.embedding_backend import PluggableEmbeddingBackend

logger = logging.getLogger("sphinx.ipia.joint_context_encoder")

_DEFAULT_SEPARATOR = " [SEP] "


@dataclass
class JointEmbeddingResult:
    """Result of encoding a (chunk, query) pair."""

    joint_vector: list[float]
    chunk_vector: list[float]
    query_vector: list[float]
    dimension: int

    def is_normalised(self, tol: float = 1e-5) -> bool:
        """Check whether the joint vector is approximately unit-length."""
        norm = math.sqrt(sum(x * x for x in self.joint_vector))
        return abs(norm - 1.0) < tol


class JointContextEncoder:
    """Encodes a (retrieved_chunk, user_query) pair into a joint embedding.

    The encoder concatenates the chunk and query with a separator token,
    then runs the concatenation through the configured
    :class:`PluggableEmbeddingBackend` to produce a single vector that
    captures the joint semantic context.

    Individual chunk and query embeddings are also retained so that the
    downstream scorer can compute pairwise similarity if needed.
    """

    def __init__(
        self,
        backend: PluggableEmbeddingBackend,
        separator: str = _DEFAULT_SEPARATOR,
    ) -> None:
        self._backend = backend
        self._separator = separator

    def encode(
        self,
        retrieved_chunk: str,
        user_query: str,
    ) -> JointEmbeddingResult:
        """Produce a joint embedding for the given chunk and query.

        Returns a :class:`JointEmbeddingResult` containing the joint vector
        as well as the individual chunk and query vectors.
        """
        # Individual embeddings
        chunk_vec = self._backend.embed(retrieved_chunk)
        query_vec = self._backend.embed(user_query)

        # Joint embedding from concatenation
        joint_text = f"{retrieved_chunk}{self._separator}{user_query}"
        joint_vec = self._backend.embed(joint_text)

        # Ensure L2 normalisation
        joint_vec = _l2_normalise(joint_vec)

        return JointEmbeddingResult(
            joint_vector=joint_vec,
            chunk_vector=chunk_vec,
            query_vector=query_vec,
            dimension=self._backend.dimension,
        )

    @property
    def dimension(self) -> int:
        return self._backend.dimension

    @property
    def backend_name(self) -> str:
        return self._backend.name


def _l2_normalise(vec: list[float]) -> list[float]:
    """Return a copy of *vec* with unit L2 norm."""
    norm = math.sqrt(sum(x * x for x in vec))
    if norm == 0.0:
        return vec
    return [x / norm for x in vec]
