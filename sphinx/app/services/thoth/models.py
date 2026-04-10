"""Data models for Thoth classification request/response and ClassificationContext.

Implements the API contract defined in PRD §7.3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------

@dataclass
class ClassificationRequest:
    """Payload sent from Sphinx to Thoth for semantic classification (FR-PRE-02)."""

    request_id: str
    content: str                          # Raw prompt text
    content_type: str = "prompt"
    system_prompt: Optional[str] = None  # System prompt if available
    user_id: Optional[str] = None        # Hashed user identity
    application_id: Optional[str] = None
    model_endpoint: Optional[str] = None
    session_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "content_type": self.content_type,
            "content": self.content,
            "system_prompt": self.system_prompt,
            "context": {
                "user_id": self.user_id,
                "application_id": self.application_id,
                "model_endpoint": self.model_endpoint,
                "session_id": self.session_id,
            },
        }


# ---------------------------------------------------------------------------
# Response / ClassificationContext
# ---------------------------------------------------------------------------

@dataclass
class ClassificationContext:
    """Internal Sphinx representation of a Thoth classification result (FR-PRE-03).

    This is the canonical object stored on policy evaluation context and in
    audit records.  The ``source`` field distinguishes live Thoth results from
    structural-only fallback entries.
    """

    request_id: str
    intent: str                          # Thoth intent category
    risk_level: str                      # LOW | MEDIUM | HIGH | CRITICAL
    confidence: float                    # 0.00–1.00
    pii_detected: bool
    pii_types: list[str] = field(default_factory=list)  # e.g. ["AADHAAR", "EMAIL"]
    recommended_action: str = "ALLOW"    # Advisory only — Sphinx policy overrides
    classification_model_version: str = "unknown"
    latency_ms: int = 0
    source: str = "thoth"                # "thoth" | "structural_fallback"

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "intent": self.intent,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "pii_detected": self.pii_detected,
            "pii_types": self.pii_types,
            "recommended_action": self.recommended_action,
            "classification_model_version": self.classification_model_version,
            "latency_ms": self.latency_ms,
            "source": self.source,
        }


# ---------------------------------------------------------------------------
# Fallback helpers
# ---------------------------------------------------------------------------

def make_unavailable_context(request_id: str, reason: str = "thoth_unavailable") -> ClassificationContext:
    """Return a sentinel ClassificationContext used when Thoth is unreachable.

    Policy rules that reference ``classification.*`` attributes will receive
    safe defaults, allowing graceful degradation per FR-POL-05.
    """
    return ClassificationContext(
        request_id=request_id,
        intent="unknown",
        risk_level="UNKNOWN",
        confidence=0.0,
        pii_detected=False,
        pii_types=[],
        recommended_action="ALLOW",
        classification_model_version="unavailable",
        latency_ms=0,
        source="structural_fallback",
    )


def make_timeout_context(request_id: str) -> ClassificationContext:
    """Return a sentinel ClassificationContext used when Thoth times out (FR-PRE-06)."""
    return ClassificationContext(
        request_id=request_id,
        intent="unknown",
        risk_level="UNKNOWN",
        confidence=0.0,
        pii_detected=False,
        pii_types=[],
        recommended_action="ALLOW",
        classification_model_version="timeout",
        latency_ms=0,
        source="structural_fallback",
    )


# ---------------------------------------------------------------------------
# Sprint 4 — Post-inference response classification request (FR-POST-01/02)
# ---------------------------------------------------------------------------

@dataclass
class ResponseClassificationRequest:
    """Payload sent from Sphinx to Thoth for post-inference response classification.

    Extends the base classification contract with response-specific fields:
    - ``content_type`` is always ``"response"`` to signal post-inference mode.
    - ``prompt_request_id`` correlates this classification to the original prompt
      request's Sphinx trace ID, enabling full prompt-response linkage in audit
      records (FR-POST-03).
    - ``audit_event_id`` optionally links to the prompt-phase audit event.
    """

    request_id: str                          # New unique ID for this response classification
    content: str                             # LLM response text
    content_type: str = "response"
    prompt_request_id: str = ""             # Original prompt Sphinx trace ID (correlation)
    system_prompt: Optional[str] = None
    user_id: Optional[str] = None
    application_id: Optional[str] = None
    model_endpoint: Optional[str] = None
    session_id: Optional[str] = None
    audit_event_id: Optional[str] = None    # Original prompt audit event ID

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "content_type": self.content_type,
            "content": self.content,
            "system_prompt": self.system_prompt,
            "context": {
                "user_id": self.user_id,
                "application_id": self.application_id,
                "model_endpoint": self.model_endpoint,
                "session_id": self.session_id,
                "prompt_request_id": self.prompt_request_id,
                "audit_event_id": self.audit_event_id,
            },
        }
