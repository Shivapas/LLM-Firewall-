"""Sphinx-side Thoth classification orchestrator.

Sprint 1 / S1-T2 — entry point for proxy.py; wraps ThothClient with
timeout-guard, fallback, and structured audit logging.

Sprint 2 enhancements
---------------------
S2-T1  Timeout enforcement: configurable per-request timeout, structural-only
       fallback on expiry, FAIL_CLOSED support via caller (proxy.py).
S2-T2  Circuit breaker: ``ThothCircuitBreaker`` is checked before every call.
       When the circuit is OPEN, return ``"circuit_open"`` event immediately
       without making a network request. Successes and failures are recorded
       to drive open/close transitions.
S2-T4  Dedicated audit helper: ``make_unavailability_audit_metadata()`` builds
       the structured payload for the dedicated classification-unavailability
       audit event emitted by proxy.py.

Event types returned by ``classify_prompt()``
---------------------------------------------
"classified"    Successful Thoth classification.
"timeout"       Thoth exceeded configured latency budget (FR-PRE-06).
"unavailable"   Thoth API error / unreachable (FR-PRE-07).
"circuit_open"  Circuit breaker is open — Thoth calls suppressed (S2-T2).
"disabled"      Thoth integration not enabled in config.
"no_content"    No prompt text could be extracted from the request body.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Optional

import httpx

from app.services.thoth.client import get_thoth_client
from app.services.thoth.circuit_breaker import get_thoth_circuit_breaker
from app.services.thoth.models import (
    ClassificationContext,
    ClassificationRequest,
    make_timeout_context,
    make_unavailable_context,
)

logger = logging.getLogger("sphinx.thoth.classifier")

# Events that represent Thoth being unavailable for dedicated audit emission
UNAVAILABILITY_EVENTS: frozenset[str] = frozenset(
    {"timeout", "unavailable", "circuit_open"}
)


def _extract_prompt_and_system(body: bytes) -> tuple[str, Optional[str]]:
    """Extract (prompt_text, system_prompt) from an LLM API request body.

    Supports OpenAI chat, Anthropic messages, and simple ``prompt`` field formats.
    Returns (content, None) if the body is non-JSON or has no recognisable prompt.
    """
    if not body:
        return "", None

    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return "", None

    system_prompt: Optional[str] = None
    parts: list[str] = []

    # System prompt (Anthropic / OpenAI)
    if "system" in payload:
        system = payload["system"]
        if isinstance(system, str):
            system_prompt = system
        elif isinstance(system, list):
            fragments = []
            for item in system:
                if isinstance(item, dict) and "text" in item:
                    fragments.append(item["text"])
            if fragments:
                system_prompt = " ".join(fragments)

    # Messages array
    if "messages" in payload:
        for msg in payload["messages"]:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role in ("user", "human", "system"):
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and "text" in item:
                            parts.append(item["text"])

    # Simple prompt field
    if "prompt" in payload:
        parts.append(str(payload["prompt"]))

    return "\n".join(parts), system_prompt


async def classify_prompt(
    body: bytes,
    *,
    tenant_id: str = "unknown",
    application_id: str = "unknown",
    model_endpoint: str = "unknown",
    session_id: Optional[str] = None,
    request_id: Optional[str] = None,
    timeout_ms: int = 150,
    circuit_breaker_enabled: bool = True,
) -> tuple[Optional[ClassificationContext], str]:
    """Classify a prompt via Thoth and return (context, event_type).

    Args:
        body:                    Raw HTTP request body bytes.
        tenant_id:               Hashed tenant identifier (for logging/audit).
        application_id:          Application / project identifier.
        model_endpoint:          Target LLM endpoint name.
        session_id:              Optional session correlation ID.
        request_id:              Optional Sphinx trace ID; generated if None.
        timeout_ms:              Per-request Thoth API timeout in milliseconds
                                 (S2-T1 — configurable, default 150ms per FR-PRE-06).
        circuit_breaker_enabled: Whether to consult the Thoth circuit breaker
                                 before making a call (S2-T2).

    Returns:
        Tuple of (ClassificationContext | None, event_type).

        The ClassificationContext is always non-None for event types other than
        ``"disabled"`` and ``"no_content"``.
    """
    thoth = get_thoth_client()
    if thoth is None:
        return None, "disabled"

    prompt_text, system_prompt = _extract_prompt_and_system(body)
    if not prompt_text:
        return None, "no_content"

    trace_id = request_id or str(uuid.uuid4())

    # ── S2-T2: Circuit breaker check ──────────────────────────────────────
    if circuit_breaker_enabled:
        cb = get_thoth_circuit_breaker()
        if not cb.is_available():
            logger.warning(
                "Thoth circuit breaker OPEN — skipping classification call "
                "tenant=%s trace_id=%s",
                tenant_id,
                trace_id,
            )
            return make_unavailable_context(trace_id, reason="circuit_open"), "circuit_open"

    classification_request = ClassificationRequest(
        request_id=trace_id,
        content=prompt_text,
        content_type="prompt",
        system_prompt=system_prompt,
        user_id=tenant_id,          # hashed tenant used as proxy for user identity
        application_id=application_id,
        model_endpoint=model_endpoint,
        session_id=session_id,
    )

    # ── S2-T1: Timeout-guarded Thoth call ─────────────────────────────────
    timeout_s = timeout_ms / 1000.0

    try:
        ctx = await asyncio.wait_for(
            thoth.classify(classification_request),
            timeout=timeout_s,
        )

        # Record success to circuit breaker
        if circuit_breaker_enabled:
            get_thoth_circuit_breaker().record_success()

        logger.info(
            "Thoth classification: intent=%s risk=%s confidence=%.2f "
            "pii=%s latency_ms=%d tenant=%s",
            ctx.intent,
            ctx.risk_level,
            ctx.confidence,
            ctx.pii_detected,
            ctx.latency_ms,
            tenant_id,
        )
        return ctx, "classified"

    except (asyncio.TimeoutError, httpx.TimeoutException):
        # Record failure to circuit breaker (S2-T2)
        if circuit_breaker_enabled:
            get_thoth_circuit_breaker().record_failure()

        logger.warning(
            "Thoth classification TIMEOUT (>%dms) — structural-only enforcement "
            "active tenant=%s trace_id=%s",
            timeout_ms,
            tenant_id,
            trace_id,
        )
        return make_timeout_context(trace_id), "timeout"

    except Exception as exc:
        # Record failure to circuit breaker (S2-T2)
        if circuit_breaker_enabled:
            get_thoth_circuit_breaker().record_failure()

        logger.warning(
            "Thoth classification UNAVAILABLE — structural-only enforcement "
            "active tenant=%s trace_id=%s error=%s",
            tenant_id,
            trace_id,
            exc,
        )
        return make_unavailable_context(trace_id), "unavailable"


def make_unavailability_audit_metadata(
    *,
    classification_event: str,
    tenant_id: str,
    trace_id: str,
    fail_closed_enabled: bool = False,
    circuit_breaker_status: Optional[dict] = None,
) -> dict:
    """Build structured metadata for a dedicated classification-unavailability
    audit event (S2-T4 / FR-AUD-03).

    This payload is included in the audit event emitted by proxy.py when
    ``classification_event`` is one of ``"timeout"``, ``"unavailable"``, or
    ``"circuit_open"``.

    Args:
        classification_event:    The event type from ``classify_prompt()``.
        tenant_id:               Tenant identifier for context.
        trace_id:                Sphinx trace / request ID.
        fail_closed_enabled:     Whether FAIL_CLOSED mode is active.
        circuit_breaker_status:  Optional snapshot from
                                 ``ThothCircuitBreaker.get_status()``.

    Returns:
        Dictionary suitable for use as the ``metadata`` field of an audit event.
    """
    return {
        "event_type": "thoth_classification_unavailability",
        "classification_event": classification_event,
        "fallback_mode": "structural_only",
        "severity": "WARNING",
        "fail_closed_enabled": fail_closed_enabled,
        "tenant_id": tenant_id,
        "trace_id": trace_id,
        "circuit_breaker": circuit_breaker_status or {},
    }
