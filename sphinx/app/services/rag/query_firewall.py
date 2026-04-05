"""Query-stage injection detection — applies Tier 1 + Tier 2 detection to RAG queries.

Blocks retrieval before it reaches the vector DB on critical findings.
Also applies Data Shield PII redaction to RAG queries before they reach the vector store.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from app.services.threat_detection.engine import ThreatDetectionEngine, get_threat_engine
from app.services.threat_detection.action_engine import ActionResult
from app.services.data_shield.engine import DataShieldEngine, DataShieldResult, get_data_shield_engine

logger = logging.getLogger("sphinx.rag.query_firewall")


@dataclass
class QueryFirewallResult:
    """Combined result of query-stage firewall checks."""
    allowed: bool
    query_text: str
    redacted_query: Optional[str] = None
    threat_result: Optional[ActionResult] = None
    shield_result: Optional[DataShieldResult] = None
    intent: Optional["IntentResult"] = None
    scan_time_ms: float = 0.0
    blocked_reason: Optional[str] = None

    def to_dict(self) -> dict:
        result = {
            "allowed": self.allowed,
            "scan_time_ms": round(self.scan_time_ms, 2),
        }
        if self.blocked_reason:
            result["blocked_reason"] = self.blocked_reason
        if self.threat_result:
            result["threat"] = self.threat_result.to_dict()
        if self.shield_result:
            result["data_shield"] = self.shield_result.to_dict()
        if self.intent:
            result["intent"] = self.intent.to_dict()
        if self.redacted_query and self.redacted_query != self.query_text:
            result["query_redacted"] = True
        return result


class QueryFirewall:
    """Applies threat detection and PII redaction to RAG queries before vector DB retrieval.

    Pipeline:
    1. Threat detection (Tier 1 pattern matching) on the query text
    2. PII/PHI/credential redaction on the query text
    3. If threat is critical/high → block before vector DB
    4. If PII found → redact before vector store receives query
    """

    def __init__(
        self,
        threat_engine: ThreatDetectionEngine | None = None,
        data_shield: DataShieldEngine | None = None,
    ):
        self._threat_engine = threat_engine
        self._data_shield = data_shield

    @property
    def threat_engine(self) -> ThreatDetectionEngine:
        if self._threat_engine is None:
            self._threat_engine = get_threat_engine()
        return self._threat_engine

    @property
    def data_shield(self) -> DataShieldEngine:
        if self._data_shield is None:
            self._data_shield = get_data_shield_engine()
        return self._data_shield

    def scan_query(
        self,
        query_text: str,
        tenant_id: str = "",
        session_id: str = "",
    ) -> QueryFirewallResult:
        """Run the full query-stage firewall pipeline.

        Returns a QueryFirewallResult indicating whether the query should proceed
        and the (possibly redacted) query text to use for retrieval.
        """
        start = time.perf_counter()

        # Step 1: Threat detection on query text
        threat_result = self.threat_engine.evaluate(query_text)

        # Step 2: If threat action is block → stop immediately
        if threat_result.action == "block":
            scan_time = (time.perf_counter() - start) * 1000
            logger.warning(
                "Query firewall BLOCKED RAG query: risk=%s score=%.3f reason=%s tenant=%s",
                threat_result.risk_level, threat_result.score, threat_result.reason, tenant_id,
            )
            return QueryFirewallResult(
                allowed=False,
                query_text=query_text,
                threat_result=threat_result,
                scan_time_ms=scan_time,
                blocked_reason=f"Injection detected in RAG query: {threat_result.reason}",
            )

        # Step 3: PII redaction on query text
        shield_result = self.data_shield.scan_and_redact(
            query_text,
            use_vault=bool(tenant_id and session_id),
            tenant_id=tenant_id,
            session_id=session_id,
        )

        redacted_query = query_text
        if shield_result.redaction and shield_result.redaction.redaction_count > 0:
            redacted_query = shield_result.redaction.redacted_text
            logger.info(
                "Query firewall redacted %d PII entities from RAG query tenant=%s",
                shield_result.redaction.redaction_count, tenant_id,
            )

        # Step 4: If threat rewrite, apply to query
        if threat_result.action == "rewrite" and threat_result.rewritten_text:
            redacted_query = threat_result.rewritten_text
            logger.info("Query firewall rewrote RAG query tenant=%s", tenant_id)

        scan_time = (time.perf_counter() - start) * 1000

        return QueryFirewallResult(
            allowed=True,
            query_text=query_text,
            redacted_query=redacted_query,
            threat_result=threat_result,
            shield_result=shield_result,
            scan_time_ms=scan_time,
        )

    def scan_query_from_body(
        self,
        body: bytes,
        tenant_id: str = "",
        session_id: str = "",
    ) -> tuple[bytes, QueryFirewallResult]:
        """Extract query from request body, run firewall, return modified body + result."""
        if not body:
            return body, QueryFirewallResult(
                allowed=True, query_text="", scan_time_ms=0.0,
            )

        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            return body, QueryFirewallResult(
                allowed=True, query_text="", scan_time_ms=0.0,
            )

        query_text = self._extract_query_text(payload)
        if not query_text:
            return body, QueryFirewallResult(
                allowed=True, query_text="", scan_time_ms=0.0,
            )

        result = self.scan_query(query_text, tenant_id, session_id)

        if not result.allowed:
            return body, result

        # Apply redacted query back to body if changed
        if result.redacted_query and result.redacted_query != query_text:
            payload = self._apply_redacted_query(payload, query_text, result.redacted_query)
            body = json.dumps(payload).encode()

        return body, result

    def _extract_query_text(self, payload: dict) -> str:
        """Extract the query text from a RAG request payload."""
        # Direct query field
        if "query" in payload:
            return str(payload["query"])

        # Retrieval query
        if "retrieval_query" in payload:
            return str(payload["retrieval_query"])

        # Last user message
        parts: list[str] = []
        if "messages" in payload:
            for msg in reversed(payload["messages"]):
                if msg.get("role") in ("user", "human"):
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        parts.append(content)
                    elif isinstance(content, list):
                        for item in content:
                            if isinstance(item, dict) and "text" in item:
                                parts.append(item["text"])
                    break

        if "prompt" in payload:
            parts.append(str(payload["prompt"]))

        return "\n".join(parts)

    def _apply_redacted_query(self, payload: dict, original: str, redacted: str) -> dict:
        """Replace original query text with redacted version in the payload."""
        if "query" in payload and str(payload["query"]) == original:
            payload["query"] = redacted
        if "retrieval_query" in payload and str(payload["retrieval_query"]) == original:
            payload["retrieval_query"] = redacted
        if "prompt" in payload and str(payload["prompt"]) == original:
            payload["prompt"] = redacted
        if "messages" in payload:
            for msg in reversed(payload["messages"]):
                if msg.get("role") in ("user", "human"):
                    if isinstance(msg.get("content"), str) and msg["content"] == original:
                        msg["content"] = redacted
                    break
        return payload


# Singleton
_firewall: Optional[QueryFirewall] = None


def get_query_firewall() -> QueryFirewall:
    """Get or create the singleton query firewall."""
    global _firewall
    if _firewall is None:
        _firewall = QueryFirewall()
    return _firewall


def reset_query_firewall() -> None:
    """Reset the singleton (for testing)."""
    global _firewall
    _firewall = None
