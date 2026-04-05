"""RAG Pipeline orchestrator — coordinates classification, query firewall, and intent analysis.

This is the main entry point for RAG enforcement in the gateway proxy.
"""

import json
import logging
import time
from dataclasses import dataclass
from typing import Optional

from app.services.rag.classifier import (
    RAGRequestClassifier, ClassificationResult, RequestType, get_rag_classifier,
)
from app.services.rag.query_firewall import (
    QueryFirewall, QueryFirewallResult, get_query_firewall,
)
from app.services.rag.intent_classifier import (
    IntentClassifier, IntentResult, IntentRiskLevel, get_intent_classifier,
)

logger = logging.getLogger("sphinx.rag.pipeline")


@dataclass
class RAGPipelineResult:
    """Full result of running the RAG pipeline on a request."""
    classification: ClassificationResult
    query_firewall: Optional[QueryFirewallResult] = None
    intent: Optional[IntentResult] = None
    allowed: bool = True
    blocked_reason: Optional[str] = None
    total_time_ms: float = 0.0

    def to_dict(self) -> dict:
        result = {
            "classification": self.classification.to_dict(),
            "allowed": self.allowed,
            "total_time_ms": round(self.total_time_ms, 2),
        }
        if self.query_firewall:
            result["query_firewall"] = self.query_firewall.to_dict()
        if self.intent:
            result["intent"] = self.intent.to_dict()
        if self.blocked_reason:
            result["blocked_reason"] = self.blocked_reason
        return result


class RAGPipeline:
    """Orchestrates the full RAG enforcement pipeline.

    Flow for RAG queries:
    1. Classify request → Standard Chat / RAG Query / MCP Tool Call
    2. If RAG Query:
       a. Run intent classifier → flag high-risk intents
       b. Run query firewall (threat detection + PII redaction)
       c. Block if injection detected / high-risk intent with policy
    3. Return result with modified body if redaction occurred
    """

    def __init__(
        self,
        classifier: RAGRequestClassifier | None = None,
        query_firewall: QueryFirewall | None = None,
        intent_classifier: IntentClassifier | None = None,
        block_high_risk_intents: bool = False,
    ):
        self._classifier = classifier
        self._query_firewall = query_firewall
        self._intent_classifier = intent_classifier
        self._block_high_risk_intents = block_high_risk_intents

    @property
    def classifier(self) -> RAGRequestClassifier:
        if self._classifier is None:
            self._classifier = get_rag_classifier()
        return self._classifier

    @property
    def query_firewall(self) -> QueryFirewall:
        if self._query_firewall is None:
            self._query_firewall = get_query_firewall()
        return self._query_firewall

    @property
    def intent_classifier(self) -> IntentClassifier:
        if self._intent_classifier is None:
            self._intent_classifier = get_intent_classifier()
        return self._intent_classifier

    def process(
        self,
        body: bytes,
        tenant_id: str = "",
        session_id: str = "",
    ) -> tuple[bytes, RAGPipelineResult]:
        """Process a request through the RAG pipeline.

        Returns (possibly_modified_body, pipeline_result).
        """
        start = time.perf_counter()

        # Step 1: Classify the request
        classification = self.classifier.classify(body)

        # If not a RAG query, return immediately — standard pipeline handles it
        if classification.request_type != RequestType.RAG_QUERY:
            total_time = (time.perf_counter() - start) * 1000
            return body, RAGPipelineResult(
                classification=classification,
                allowed=True,
                total_time_ms=total_time,
            )

        logger.info(
            "RAG query detected (confidence=%.2f signals=%s) tenant=%s",
            classification.confidence, classification.signals, tenant_id,
        )

        # Step 2: Intent classification
        query_text = classification.rag_query_text or ""
        intent = self.intent_classifier.classify(query_text)

        # Step 3: Check if high-risk intent should block
        if self._block_high_risk_intents and intent.risk_level == IntentRiskLevel.HIGH:
            total_time = (time.perf_counter() - start) * 1000
            logger.warning(
                "RAG query blocked by intent classifier: intent=%s risk=%s tenant=%s",
                intent.intent.value, intent.risk_level.value, tenant_id,
            )
            return body, RAGPipelineResult(
                classification=classification,
                intent=intent,
                allowed=False,
                blocked_reason=f"High-risk intent detected: {intent.description}",
                total_time_ms=total_time,
            )

        # Step 4: Query firewall (threat detection + PII redaction)
        modified_body, firewall_result = self.query_firewall.scan_query_from_body(
            body, tenant_id=tenant_id, session_id=session_id,
        )

        if not firewall_result.allowed:
            total_time = (time.perf_counter() - start) * 1000
            return body, RAGPipelineResult(
                classification=classification,
                query_firewall=firewall_result,
                intent=intent,
                allowed=False,
                blocked_reason=firewall_result.blocked_reason,
                total_time_ms=total_time,
            )

        # Attach intent to firewall result
        firewall_result.intent = intent

        total_time = (time.perf_counter() - start) * 1000

        return modified_body, RAGPipelineResult(
            classification=classification,
            query_firewall=firewall_result,
            intent=intent,
            allowed=True,
            total_time_ms=total_time,
        )


# Singleton
_pipeline: Optional[RAGPipeline] = None


def get_rag_pipeline() -> RAGPipeline:
    """Get or create the singleton RAG pipeline."""
    global _pipeline
    if _pipeline is None:
        _pipeline = RAGPipeline()
    return _pipeline


def reset_rag_pipeline() -> None:
    """Reset the singleton (for testing)."""
    global _pipeline
    _pipeline = None
