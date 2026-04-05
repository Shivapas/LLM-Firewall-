"""Lightweight intent classifier for RAG queries.

Classifies query intent: data extraction attempt, normal retrieval, sensitive topic.
Flags high-risk intents for additional scrutiny.
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger("sphinx.rag.intent_classifier")


class QueryIntent(str, Enum):
    """Classified intent of a RAG query."""
    NORMAL_RETRIEVAL = "normal_retrieval"
    DATA_EXTRACTION = "data_extraction"
    SENSITIVE_TOPIC = "sensitive_topic"
    ENUMERATION = "enumeration"
    SYSTEM_PROBE = "system_probe"


class IntentRiskLevel(str, Enum):
    """Risk level for the classified intent."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class IntentResult:
    """Result of intent classification."""
    intent: QueryIntent
    risk_level: IntentRiskLevel
    confidence: float
    signals: list[str]
    description: str

    def to_dict(self) -> dict:
        return {
            "intent": self.intent.value,
            "risk_level": self.risk_level.value,
            "confidence": round(self.confidence, 4),
            "signals": self.signals,
            "description": self.description,
        }


# Data extraction patterns — attempts to exfiltrate bulk data from the knowledge base
_DATA_EXTRACTION_PATTERNS = [
    (re.compile(r"\b(?:list|show|give|dump|export|extract|return)\s+(?:all|every|each|complete)\b", re.IGNORECASE), "bulk_data_request"),
    (re.compile(r"\b(?:all|every)\s+(?:records?|entries?|documents?|rows?|items?|users?|customers?|employees?|patients?)\b", re.IGNORECASE), "all_records_request"),
    (re.compile(r"\b(?:database|db|table|schema|structure|columns?|fields?)\b.*\b(?:dump|export|list|show)\b", re.IGNORECASE), "schema_probing"),
    (re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\s", re.IGNORECASE), "sql_keywords"),
    (re.compile(r"\bsensitive\s+(?:data|info|information|records?)\b", re.IGNORECASE), "sensitive_data_request"),
    (re.compile(r"\b(?:password|secret|credential|api[_\s]?key|token|ssn|social\s+security)\b", re.IGNORECASE), "credential_request"),
]

# Sensitive topic patterns — queries touching regulated/sensitive areas
_SENSITIVE_TOPIC_PATTERNS = [
    (re.compile(r"\b(?:medical|health|diagnosis|treatment|prescription|patient|HIPAA)\b", re.IGNORECASE), "medical_topic"),
    (re.compile(r"\b(?:salary|compensation|payroll|income|financial|bank|account\s+number)\b", re.IGNORECASE), "financial_topic"),
    (re.compile(r"\b(?:legal|lawsuit|litigation|compliance|regulation|GDPR|CCPA|SOX)\b", re.IGNORECASE), "legal_topic"),
    (re.compile(r"\b(?:classified|confidential|top\s+secret|restricted|internal\s+only)\b", re.IGNORECASE), "confidential_topic"),
    (re.compile(r"\b(?:PII|PHI|personally\s+identifiable|protected\s+health)\b", re.IGNORECASE), "pii_phi_topic"),
]

# Enumeration patterns — attempts to systematically discover data
_ENUMERATION_PATTERNS = [
    (re.compile(r"\b(?:how\s+many|count|total\s+number|list\s+all|enumerate)\b", re.IGNORECASE), "enumeration_query"),
    (re.compile(r"\b(?:what\s+(?:other|else)|anything\s+else|more\s+like)\b", re.IGNORECASE), "probing_query"),
    (re.compile(r"\b(?:next|previous|remaining|rest\s+of)\b", re.IGNORECASE), "pagination_probe"),
]

# System probe patterns — attempts to learn about the RAG system itself
_SYSTEM_PROBE_PATTERNS = [
    (re.compile(r"\b(?:what\s+(?:model|system|instructions?|prompt)|your\s+(?:instructions?|system\s+prompt|configuration))\b", re.IGNORECASE), "system_prompt_probe"),
    (re.compile(r"\b(?:which\s+(?:database|vector\s+store|index|collection)|what\s+data\s+source)\b", re.IGNORECASE), "infrastructure_probe"),
    (re.compile(r"\b(?:ignore\s+(?:previous|above|prior)|disregard|forget|override)\b", re.IGNORECASE), "instruction_override"),
]


class IntentClassifier:
    """Classifies RAG query intent for risk assessment."""

    def classify(self, query_text: str) -> IntentResult:
        """Classify the intent of a RAG query."""
        if not query_text or not query_text.strip():
            return IntentResult(
                intent=QueryIntent.NORMAL_RETRIEVAL,
                risk_level=IntentRiskLevel.LOW,
                confidence=1.0,
                signals=["empty_query"],
                description="Empty or blank query",
            )

        signals: list[str] = []
        scores: dict[QueryIntent, float] = {
            QueryIntent.NORMAL_RETRIEVAL: 0.2,  # baseline
            QueryIntent.DATA_EXTRACTION: 0.0,
            QueryIntent.SENSITIVE_TOPIC: 0.0,
            QueryIntent.ENUMERATION: 0.0,
            QueryIntent.SYSTEM_PROBE: 0.0,
        }

        # Check data extraction patterns
        for pattern, signal in _DATA_EXTRACTION_PATTERNS:
            if pattern.search(query_text):
                scores[QueryIntent.DATA_EXTRACTION] += 0.3
                signals.append(signal)

        # Check sensitive topic patterns
        for pattern, signal in _SENSITIVE_TOPIC_PATTERNS:
            if pattern.search(query_text):
                scores[QueryIntent.SENSITIVE_TOPIC] += 0.25
                signals.append(signal)

        # Check enumeration patterns
        for pattern, signal in _ENUMERATION_PATTERNS:
            if pattern.search(query_text):
                scores[QueryIntent.ENUMERATION] += 0.25
                signals.append(signal)

        # Check system probe patterns
        for pattern, signal in _SYSTEM_PROBE_PATTERNS:
            if pattern.search(query_text):
                scores[QueryIntent.SYSTEM_PROBE] += 0.35
                signals.append(signal)

        # Find highest scoring intent
        best_intent = max(scores, key=scores.get)  # type: ignore[arg-type]
        best_score = scores[best_intent]

        # Determine risk level
        if best_intent == QueryIntent.NORMAL_RETRIEVAL:
            risk_level = IntentRiskLevel.LOW
        elif best_intent in (QueryIntent.SENSITIVE_TOPIC, QueryIntent.ENUMERATION):
            risk_level = IntentRiskLevel.MEDIUM
        else:  # DATA_EXTRACTION or SYSTEM_PROBE
            risk_level = IntentRiskLevel.HIGH

        # If multiple high-risk intents score above threshold, escalate
        high_count = sum(1 for i, s in scores.items() if s >= 0.3 and i != QueryIntent.NORMAL_RETRIEVAL)
        if high_count >= 2:
            risk_level = IntentRiskLevel.HIGH

        description = self._describe_intent(best_intent, signals)

        return IntentResult(
            intent=best_intent,
            risk_level=risk_level,
            confidence=min(1.0, best_score),
            signals=signals if signals else ["no_risk_signals"],
            description=description,
        )

    def _describe_intent(self, intent: QueryIntent, signals: list[str]) -> str:
        """Generate a human-readable description of the classified intent."""
        descriptions = {
            QueryIntent.NORMAL_RETRIEVAL: "Standard information retrieval query",
            QueryIntent.DATA_EXTRACTION: f"Potential data extraction attempt ({', '.join(signals[:3])})",
            QueryIntent.SENSITIVE_TOPIC: f"Query touches sensitive/regulated topics ({', '.join(signals[:3])})",
            QueryIntent.ENUMERATION: f"Systematic data enumeration attempt ({', '.join(signals[:3])})",
            QueryIntent.SYSTEM_PROBE: f"System/infrastructure probing detected ({', '.join(signals[:3])})",
        }
        return descriptions.get(intent, "Unknown intent")


# Singleton
_intent_classifier: Optional[IntentClassifier] = None


def get_intent_classifier() -> IntentClassifier:
    """Get or create the singleton intent classifier."""
    global _intent_classifier
    if _intent_classifier is None:
        _intent_classifier = IntentClassifier()
    return _intent_classifier


def reset_intent_classifier() -> None:
    """Reset the singleton (for testing)."""
    global _intent_classifier
    _intent_classifier = None
