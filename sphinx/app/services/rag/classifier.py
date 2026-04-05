"""RAG request classifier — classifies inbound requests as Standard Chat, RAG Query, or MCP Tool Call.

Routes each request to the appropriate enforcement branch based on payload signals.
"""

import json
import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger("sphinx.rag.classifier")


class RequestType(str, Enum):
    """Classification of an inbound request."""
    STANDARD_CHAT = "standard_chat"
    RAG_QUERY = "rag_query"
    MCP_TOOL_CALL = "mcp_tool_call"


@dataclass
class ClassificationResult:
    """Result of classifying an inbound request."""
    request_type: RequestType
    confidence: float  # 0.0 – 1.0
    signals: list[str]  # which signals triggered this classification
    rag_query_text: Optional[str] = None  # extracted RAG query if applicable
    tool_name: Optional[str] = None  # extracted tool name if MCP

    def to_dict(self) -> dict:
        result = {
            "request_type": self.request_type.value,
            "confidence": round(self.confidence, 4),
            "signals": self.signals,
        }
        if self.rag_query_text:
            result["rag_query_text"] = self.rag_query_text
        if self.tool_name:
            result["tool_name"] = self.tool_name
        return result


# Signals that indicate a RAG query
_RAG_FIELD_SIGNALS = {
    "knowledge_base", "knowledge_base_id", "retrieval", "retrieval_config",
    "context_sources", "vector_store", "vector_store_id", "data_sources",
    "rag_config", "rag", "search_config", "retrieval_query",
    "collection", "collection_id", "namespace", "index_name",
}

_RAG_KEYWORD_PATTERNS = [
    re.compile(r"\b(?:search|retrieve|look\s*up|find|query)\s+(?:in|from|the)\s+(?:knowledge\s*base|database|documents?|index|collection)", re.IGNORECASE),
    re.compile(r"\b(?:according\s+to|based\s+on|from)\s+(?:the|my|our)\s+(?:documents?|knowledge\s*base|data|files?|records?)", re.IGNORECASE),
    re.compile(r"\bRAG\b"),
    re.compile(r"\b(?:search|retrieve|look\s*up|find|query)\b.*\b(?:knowledge\s*base|documents?|index|collection)\b", re.IGNORECASE),
]

# Signals that indicate an MCP tool call
_MCP_FIELD_SIGNALS = {
    "tool_calls", "tools", "tool_choice", "function_call", "functions",
}

_MCP_TOOL_CALL_FIELDS = {"tool_calls", "function_call"}


class RAGRequestClassifier:
    """Classifies inbound LLM gateway requests into routing categories."""

    def __init__(
        self,
        rag_field_signals: set[str] | None = None,
        mcp_field_signals: set[str] | None = None,
    ):
        self._rag_fields = rag_field_signals or _RAG_FIELD_SIGNALS
        self._mcp_fields = mcp_field_signals or _MCP_FIELD_SIGNALS

    def classify(self, body: bytes) -> ClassificationResult:
        """Classify a raw request body."""
        if not body:
            return ClassificationResult(
                request_type=RequestType.STANDARD_CHAT,
                confidence=1.0,
                signals=["empty_body"],
            )

        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            return ClassificationResult(
                request_type=RequestType.STANDARD_CHAT,
                confidence=0.9,
                signals=["non_json_body"],
            )

        return self.classify_payload(payload)

    def classify_payload(self, payload: dict) -> ClassificationResult:
        """Classify a parsed JSON payload."""
        signals: list[str] = []
        rag_score = 0.0
        mcp_score = 0.0

        # ── Check for MCP tool call signals ──
        mcp_signals = self._check_mcp_signals(payload)
        if mcp_signals:
            signals.extend(mcp_signals)
            mcp_score += 0.4 * len(mcp_signals)
            tool_name = self._extract_tool_name(payload)
            if tool_name:
                mcp_score += 0.3

        # ── Check for RAG field signals ──
        rag_field_signals = self._check_rag_field_signals(payload)
        if rag_field_signals:
            signals.extend(rag_field_signals)
            rag_score += 0.4 * len(rag_field_signals)

        # ── Check for RAG keyword patterns in message text ──
        prompt_text = self._extract_prompt_text(payload)
        keyword_signals = self._check_rag_keywords(prompt_text)
        if keyword_signals:
            signals.extend(keyword_signals)
            rag_score += 0.2 * len(keyword_signals)

        # ── Check for explicit RAG type marker ──
        req_type = payload.get("type", "").lower()
        if req_type in ("rag", "retrieval", "rag_query"):
            signals.append(f"explicit_type:{req_type}")
            rag_score += 0.8

        # ── Decide classification ──
        if mcp_score > rag_score and mcp_score >= 0.4:
            return ClassificationResult(
                request_type=RequestType.MCP_TOOL_CALL,
                confidence=min(1.0, mcp_score),
                signals=signals,
                tool_name=self._extract_tool_name(payload),
            )

        if rag_score >= 0.4:
            return ClassificationResult(
                request_type=RequestType.RAG_QUERY,
                confidence=min(1.0, rag_score),
                signals=signals,
                rag_query_text=prompt_text or None,
            )

        return ClassificationResult(
            request_type=RequestType.STANDARD_CHAT,
            confidence=max(0.5, 1.0 - rag_score - mcp_score),
            signals=signals or ["no_special_signals"],
        )

    def _check_mcp_signals(self, payload: dict) -> list[str]:
        """Check payload for MCP/tool call signals."""
        found = []
        for field in self._mcp_fields:
            if field in payload:
                val = payload[field]
                if val is not None and val != [] and val != {}:
                    found.append(f"mcp_field:{field}")
        # Check within messages for tool_calls
        for msg in payload.get("messages", []):
            if "tool_calls" in msg or "function_call" in msg:
                found.append("mcp_message_tool_call")
                break
        return found

    def _check_rag_field_signals(self, payload: dict) -> list[str]:
        """Check payload for RAG-specific fields."""
        found = []
        for field in self._rag_fields:
            if field in payload:
                found.append(f"rag_field:{field}")
        # Check nested config
        for key in ("config", "metadata", "extra"):
            nested = payload.get(key, {})
            if isinstance(nested, dict):
                for field in self._rag_fields:
                    if field in nested:
                        found.append(f"rag_nested:{key}.{field}")
        return found

    def _check_rag_keywords(self, text: str) -> list[str]:
        """Check prompt text for RAG-related keyword patterns."""
        if not text:
            return []
        found = []
        for pattern in _RAG_KEYWORD_PATTERNS:
            if pattern.search(text):
                found.append(f"rag_keyword:{pattern.pattern[:40]}")
        return found

    def _extract_prompt_text(self, payload: dict) -> str:
        """Extract user prompt text from payload."""
        parts: list[str] = []
        if "messages" in payload:
            for msg in payload["messages"]:
                if msg.get("role") in ("user", "human"):
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        parts.append(content)
                    elif isinstance(content, list):
                        for item in content:
                            if isinstance(item, dict) and "text" in item:
                                parts.append(item["text"])
        if "prompt" in payload:
            parts.append(str(payload["prompt"]))
        if "query" in payload:
            parts.append(str(payload["query"]))
        return "\n".join(parts)

    def _extract_tool_name(self, payload: dict) -> str | None:
        """Extract tool name from MCP tool call."""
        if "tool_calls" in payload:
            calls = payload["tool_calls"]
            if isinstance(calls, list) and calls:
                call = calls[0]
                if isinstance(call, dict):
                    return call.get("function", {}).get("name") or call.get("name")
        if "function_call" in payload:
            fc = payload["function_call"]
            if isinstance(fc, dict):
                return fc.get("name")
        for msg in payload.get("messages", []):
            if "tool_calls" in msg:
                calls = msg["tool_calls"]
                if isinstance(calls, list) and calls:
                    call = calls[0]
                    if isinstance(call, dict):
                        return call.get("function", {}).get("name") or call.get("name")
        return None


# Singleton
_classifier: Optional[RAGRequestClassifier] = None


def get_rag_classifier() -> RAGRequestClassifier:
    """Get or create the singleton RAG request classifier."""
    global _classifier
    if _classifier is None:
        _classifier = RAGRequestClassifier()
    return _classifier


def reset_rag_classifier() -> None:
    """Reset the singleton classifier (for testing)."""
    global _classifier
    _classifier = None
