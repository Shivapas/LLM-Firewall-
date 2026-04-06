"""Chunk Scanner — scans retrieved document chunks for indirect injection,
sensitive field violations, and embedding anomalies before context assembly.

Sprint 9: Chunk Scanning & Indirect Injection Prevention.
"""

import hashlib
import json
import logging
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from app.services.threat_detection.pattern_library import PatternLibrary
from app.services.threat_detection.scorer import ThreatScorer, ThreatScore

logger = logging.getLogger("sphinx.vectordb.chunk_scanner")


# ── Data classes ─────────────────────────────────────────────────────────


@dataclass
class ChunkScanResult:
    """Result of scanning a single chunk."""
    chunk_id: str = ""
    blocked: bool = False
    block_reason: str = ""
    threat_score: Optional[ThreatScore] = None
    sensitive_field_matched: bool = False
    matched_sensitive_fields: list[str] = field(default_factory=list)
    content_hash: str = ""
    token_count: int = 0
    truncated: bool = False

    def to_dict(self) -> dict:
        d = {
            "chunk_id": self.chunk_id,
            "blocked": self.blocked,
            "content_hash": self.content_hash,
            "token_count": self.token_count,
            "truncated": self.truncated,
        }
        if self.block_reason:
            d["block_reason"] = self.block_reason
        if self.threat_score:
            d["threat_score"] = self.threat_score.to_dict()
        if self.sensitive_field_matched:
            d["sensitive_field_matched"] = True
            d["matched_sensitive_fields"] = self.matched_sensitive_fields
        return d


@dataclass
class ChunkScanBatchResult:
    """Result of scanning a batch of chunks."""
    total_chunks: int = 0
    allowed_chunks: int = 0
    blocked_chunks: int = 0
    truncated_chunks: int = 0
    injection_blocks: int = 0
    sensitive_field_blocks: int = 0
    context_limit_applied: bool = False
    original_chunk_count: int = 0
    enforced_chunk_count: int = 0
    anomaly_detected: bool = False
    anomaly_distance: float = 0.0
    scan_time_ms: float = 0.0
    chunk_results: list[ChunkScanResult] = field(default_factory=list)
    allowed_documents: list[dict[str, Any]] = field(default_factory=list)
    incidents: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_chunks": self.total_chunks,
            "allowed_chunks": self.allowed_chunks,
            "blocked_chunks": self.blocked_chunks,
            "truncated_chunks": self.truncated_chunks,
            "injection_blocks": self.injection_blocks,
            "sensitive_field_blocks": self.sensitive_field_blocks,
            "context_limit_applied": self.context_limit_applied,
            "original_chunk_count": self.original_chunk_count,
            "enforced_chunk_count": self.enforced_chunk_count,
            "anomaly_detected": self.anomaly_detected,
            "anomaly_distance": round(self.anomaly_distance, 6),
            "scan_time_ms": round(self.scan_time_ms, 2),
            "allowed_document_count": len(self.allowed_documents),
            "incident_count": len(self.incidents),
        }


@dataclass
class ChunkScanPolicy:
    """Policy configuration for chunk scanning."""
    scan_for_injection: bool = True
    block_sensitive_documents: bool = False
    sensitive_fields: list[str] = field(default_factory=list)
    sensitive_field_patterns: list[str] = field(default_factory=list)
    max_chunks: int = 10
    max_tokens_per_chunk: int = 512
    anomaly_distance_threshold: float = 0.0  # 0 = disabled
    collection_name: str = ""
    tenant_id: str = ""


# ── Chunk Scanner ────────────────────────────────────────────────────────


class ChunkScanner:
    """Scans retrieved document chunks before they enter context assembly.

    Enforcement pipeline per chunk:
    1. Injection scan — Tier 1 patterns applied to chunk content
    2. Sensitive field block — if enabled, check metadata fields against patterns
    3. Token truncation — enforce max_tokens_per_chunk limit

    Batch-level enforcement:
    4. Max chunks limit — enforce max_chunks cap
    5. Embedding anomaly detection — cosine distance from collection centroid
    """

    def __init__(self, scorer: Optional[ThreatScorer] = None):
        self._scorer = scorer
        self._compiled_patterns: dict[str, re.Pattern] = {}

    def _get_scorer(self) -> ThreatScorer:
        """Lazy-load the scorer from the threat engine if not provided."""
        if self._scorer is None:
            from app.services.threat_detection.engine import get_threat_engine
            engine = get_threat_engine()
            self._scorer = engine.scorer
        return self._scorer

    def scan_chunks(
        self,
        documents: list[dict[str, Any]],
        policy: ChunkScanPolicy,
        query_embedding: Optional[list[float]] = None,
        collection_centroid: Optional[list[float]] = None,
    ) -> ChunkScanBatchResult:
        """Scan a batch of retrieved chunks and enforce policies.

        Args:
            documents: List of document dicts with 'id', 'content', 'metadata'
            policy: Chunk scan policy configuration
            query_embedding: Query embedding vector (for anomaly detection)
            collection_centroid: Collection centroid vector (for anomaly detection)

        Returns:
            ChunkScanBatchResult with allowed documents and scan details
        """
        start = time.perf_counter()
        result = ChunkScanBatchResult(
            total_chunks=len(documents),
            original_chunk_count=len(documents),
        )

        # Step 5: Embedding anomaly detection (batch-level, runs first for alerting)
        if (
            policy.anomaly_distance_threshold > 0
            and query_embedding is not None
            and collection_centroid is not None
        ):
            distance = self._compute_cosine_distance(query_embedding, collection_centroid)
            result.anomaly_distance = distance
            if distance > policy.anomaly_distance_threshold:
                result.anomaly_detected = True
                logger.warning(
                    "ANOMALY: query embedding distance %.4f exceeds threshold %.4f "
                    "for collection=%s tenant=%s",
                    distance, policy.anomaly_distance_threshold,
                    policy.collection_name, policy.tenant_id,
                )
                result.incidents.append({
                    "incident_type": "embedding_anomaly",
                    "tenant_id": policy.tenant_id,
                    "collection_name": policy.collection_name,
                    "risk_level": "high",
                    "score": distance,
                    "action_taken": "alerted",
                    "metadata": {
                        "anomaly_distance": distance,
                        "threshold": policy.anomaly_distance_threshold,
                    },
                })

        # Step 4: Context minimization — enforce max_chunks cap
        chunks_to_scan = documents
        if len(documents) > policy.max_chunks:
            chunks_to_scan = documents[: policy.max_chunks]
            result.context_limit_applied = True
            result.enforced_chunk_count = policy.max_chunks
        else:
            result.enforced_chunk_count = len(documents)

        # Steps 1-3: Per-chunk scanning
        for doc in chunks_to_scan:
            chunk_result = self._scan_single_chunk(doc, policy)
            result.chunk_results.append(chunk_result)

            if chunk_result.blocked:
                result.blocked_chunks += 1
                if chunk_result.threat_score and chunk_result.threat_score.score > 0:
                    result.injection_blocks += 1
                    result.incidents.append({
                        "incident_type": "indirect_injection",
                        "tenant_id": policy.tenant_id,
                        "collection_name": policy.collection_name,
                        "chunk_id": chunk_result.chunk_id,
                        "chunk_content_hash": chunk_result.content_hash,
                        "risk_level": chunk_result.threat_score.risk_level,
                        "score": chunk_result.threat_score.score,
                        "action_taken": "blocked",
                        "matched_patterns": [
                            m.pattern_id for m in chunk_result.threat_score.matches
                        ],
                    })
                if chunk_result.sensitive_field_matched:
                    result.sensitive_field_blocks += 1
                    result.incidents.append({
                        "incident_type": "sensitive_field_block",
                        "tenant_id": policy.tenant_id,
                        "collection_name": policy.collection_name,
                        "chunk_id": chunk_result.chunk_id,
                        "chunk_content_hash": chunk_result.content_hash,
                        "risk_level": "high",
                        "score": 1.0,
                        "action_taken": "blocked",
                        "matched_fields": chunk_result.matched_sensitive_fields,
                    })
            else:
                result.allowed_chunks += 1
                result.allowed_documents.append(doc)

            if chunk_result.truncated:
                result.truncated_chunks += 1

        result.scan_time_ms = (time.perf_counter() - start) * 1000
        return result

    def _scan_single_chunk(
        self, doc: dict[str, Any], policy: ChunkScanPolicy
    ) -> ChunkScanResult:
        """Scan a single document chunk for injection and sensitive fields."""
        chunk_id = str(doc.get("id", ""))
        content = str(doc.get("content", ""))
        metadata = doc.get("metadata", {})

        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()[:32]
        token_count = self._estimate_tokens(content)

        chunk_result = ChunkScanResult(
            chunk_id=chunk_id,
            content_hash=content_hash,
            token_count=token_count,
        )

        # Step 1: Injection scan — apply Tier 1 patterns to chunk content
        if policy.scan_for_injection and content:
            scorer = self._get_scorer()
            threat_score = scorer.scan(content)
            chunk_result.threat_score = threat_score

            if threat_score.risk_level in ("critical", "high"):
                chunk_result.blocked = True
                chunk_result.block_reason = (
                    f"Indirect injection detected: risk={threat_score.risk_level} "
                    f"score={threat_score.score:.4f} "
                    f"patterns={[m.pattern_id for m in threat_score.matches]}"
                )
                logger.warning(
                    "INDIRECT INJECTION: chunk %s in collection=%s tenant=%s "
                    "risk=%s score=%.4f patterns=%s",
                    chunk_id, policy.collection_name, policy.tenant_id,
                    threat_score.risk_level, threat_score.score,
                    [m.pattern_id for m in threat_score.matches],
                )
                return chunk_result

        # Step 2: Sensitive field block
        if policy.block_sensitive_documents:
            matched = self._check_sensitive_fields(metadata, policy)
            if matched:
                chunk_result.blocked = True
                chunk_result.sensitive_field_matched = True
                chunk_result.matched_sensitive_fields = matched
                chunk_result.block_reason = (
                    f"Sensitive field match: fields={matched}"
                )
                logger.warning(
                    "SENSITIVE FIELD BLOCK: chunk %s in collection=%s tenant=%s "
                    "matched_fields=%s",
                    chunk_id, policy.collection_name, policy.tenant_id, matched,
                )
                return chunk_result

        # Step 3: Token truncation
        if policy.max_tokens_per_chunk > 0 and token_count > policy.max_tokens_per_chunk:
            truncated_content = self._truncate_to_tokens(content, policy.max_tokens_per_chunk)
            doc["content"] = truncated_content
            chunk_result.truncated = True
            chunk_result.token_count = policy.max_tokens_per_chunk
            logger.debug(
                "Chunk %s truncated from %d to %d tokens",
                chunk_id, token_count, policy.max_tokens_per_chunk,
            )

        return chunk_result

    def _check_sensitive_fields(
        self, metadata: dict[str, Any], policy: ChunkScanPolicy
    ) -> list[str]:
        """Check if any metadata field matches configured sensitive field patterns.

        Two-layer check:
        1. If field name is in policy.sensitive_fields list → match
        2. If field value matches any regex in policy.sensitive_field_patterns → match
        """
        matched: list[str] = []

        # Layer 1: Exact field name match
        for field_name in policy.sensitive_fields:
            if field_name in metadata and metadata[field_name]:
                matched.append(field_name)

        # Layer 2: Field value pattern match
        for pattern_str in policy.sensitive_field_patterns:
            compiled = self._get_compiled_pattern(pattern_str)
            if compiled is None:
                continue
            for field_name, field_value in metadata.items():
                if isinstance(field_value, str) and compiled.search(field_value):
                    key = f"{field_name}:pattern({pattern_str})"
                    if key not in matched:
                        matched.append(key)

        return matched

    def _get_compiled_pattern(self, pattern_str: str) -> Optional[re.Pattern]:
        """Compile and cache a regex pattern."""
        if pattern_str not in self._compiled_patterns:
            try:
                self._compiled_patterns[pattern_str] = re.compile(pattern_str, re.IGNORECASE)
            except re.error:
                logger.error("Invalid sensitive field pattern: %s", pattern_str)
                return None
        return self._compiled_patterns[pattern_str]

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """Estimate token count using ~4 chars per token heuristic."""
        return max(1, len(text) // 4)

    @staticmethod
    def _truncate_to_tokens(text: str, max_tokens: int) -> str:
        """Truncate text to approximate token limit (4 chars/token)."""
        max_chars = max_tokens * 4
        if len(text) <= max_chars:
            return text
        # Truncate at word boundary
        truncated = text[:max_chars]
        last_space = truncated.rfind(" ")
        if last_space > max_chars * 0.8:
            truncated = truncated[:last_space]
        return truncated + "..."

    @staticmethod
    def _compute_cosine_distance(vec_a: list[float], vec_b: list[float]) -> float:
        """Compute cosine distance (1 - cosine_similarity) between two vectors."""
        if len(vec_a) != len(vec_b) or not vec_a:
            return 1.0

        dot_product = sum(a * b for a, b in zip(vec_a, vec_b))
        norm_a = math.sqrt(sum(a * a for a in vec_a))
        norm_b = math.sqrt(sum(b * b for b in vec_b))

        if norm_a == 0 or norm_b == 0:
            return 1.0

        cosine_sim = dot_product / (norm_a * norm_b)
        # Clamp to [-1, 1] to handle floating point errors
        cosine_sim = max(-1.0, min(1.0, cosine_sim))
        return 1.0 - cosine_sim


# ── Incident Logger ──────────────────────────────────────────────────────


class IncidentLogger:
    """Logs indirect injection incidents to the database."""

    def __init__(self):
        self._pending: list[dict[str, Any]] = []

    def record_injection_incident(
        self,
        chunk_id: str,
        content_hash: str,
        collection_name: str,
        tenant_id: str,
        threat_score: ThreatScore,
        metadata: Optional[dict] = None,
    ) -> dict[str, Any]:
        """Create an incident record for a detected indirect injection."""
        incident = {
            "incident_type": "indirect_injection",
            "tenant_id": tenant_id,
            "collection_name": collection_name,
            "chunk_content_hash": content_hash,
            "chunk_id": chunk_id,
            "matched_patterns": json.dumps(
                [m.pattern_id for m in threat_score.matches]
            ),
            "risk_level": threat_score.risk_level,
            "score": threat_score.score,
            "action_taken": "blocked",
            "metadata": metadata or {},
        }
        self._pending.append(incident)
        logger.info(
            "Incident recorded: type=indirect_injection chunk=%s collection=%s "
            "tenant=%s risk=%s score=%.4f",
            chunk_id, collection_name, tenant_id,
            threat_score.risk_level, threat_score.score,
        )
        return incident

    def record_sensitive_field_incident(
        self,
        chunk_id: str,
        content_hash: str,
        collection_name: str,
        tenant_id: str,
        matched_fields: list[str],
    ) -> dict[str, Any]:
        """Create an incident record for a sensitive field block."""
        incident = {
            "incident_type": "sensitive_field_block",
            "tenant_id": tenant_id,
            "collection_name": collection_name,
            "chunk_content_hash": content_hash,
            "chunk_id": chunk_id,
            "matched_patterns": json.dumps(matched_fields),
            "risk_level": "high",
            "score": 1.0,
            "action_taken": "blocked",
            "metadata": {"matched_fields": matched_fields},
        }
        self._pending.append(incident)
        return incident

    def record_anomaly_incident(
        self,
        collection_name: str,
        tenant_id: str,
        distance: float,
        threshold: float,
    ) -> dict[str, Any]:
        """Create an incident record for an embedding anomaly."""
        incident = {
            "incident_type": "embedding_anomaly",
            "tenant_id": tenant_id,
            "collection_name": collection_name,
            "chunk_content_hash": "",
            "chunk_id": "",
            "matched_patterns": "[]",
            "risk_level": "high",
            "score": distance,
            "action_taken": "alerted",
            "metadata": {
                "anomaly_distance": distance,
                "threshold": threshold,
            },
        }
        self._pending.append(incident)
        return incident

    def get_pending(self) -> list[dict[str, Any]]:
        """Get and clear pending incidents."""
        incidents = list(self._pending)
        self._pending.clear()
        return incidents


# ── Singletons ───────────────────────────────────────────────────────────

_scanner: Optional[ChunkScanner] = None
_incident_logger: Optional[IncidentLogger] = None


def get_chunk_scanner() -> ChunkScanner:
    global _scanner
    if _scanner is None:
        _scanner = ChunkScanner()
    return _scanner


def reset_chunk_scanner() -> None:
    global _scanner
    _scanner = None


def get_incident_logger() -> IncidentLogger:
    global _incident_logger
    if _incident_logger is None:
        _incident_logger = IncidentLogger()
    return _incident_logger


def reset_incident_logger() -> None:
    global _incident_logger
    _incident_logger = None
