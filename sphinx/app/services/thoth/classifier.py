"""Sphinx-side Thoth classification orchestrator.

Sprint 1 / S1-T2 support layer:
Wraps ThothClient with timeout-guard, fallback, and structured audit logging
so that proxy.py calls a single ``classify_prompt()`` async function.

Responsibilities:
- Extract prompt text + system prompt from request body.
- Build a ClassificationRequest with Sphinx trace context.
- Call ThothClient within the configured latency budget.
- On timeout  → return make_timeout_context() and log FR-PRE-06 event.
- On error    → return make_unavailable_context() and log FR-PRE-07 event.
- On success  → return populated ClassificationContext.
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
from app.services.thoth.models import (
    ClassificationContext,
    ClassificationRequest,
    make_timeout_context,
    make_unavailable_context,
)

logger = logging.getLogger("sphinx.thoth.classifier")


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
) -> tuple[Optional[ClassificationContext], str]:
    """Classify a prompt via Thoth and return (context, event_type).

    Returns:
        (ClassificationContext, event_type) where event_type is one of:
        - ``"classified"``         — successful Thoth classification
        - ``"timeout"``            — Thoth exceeded latency budget (FR-PRE-06)
        - ``"unavailable"``        — Thoth API error / unreachable (FR-PRE-07)
        - ``"disabled"``           — Thoth not enabled in config
        - ``"no_content"``         — No prompt text to classify

    The returned ClassificationContext is always non-None for types other than
    ``"disabled"`` and ``"no_content"``.
    """
    thoth = get_thoth_client()
    if thoth is None:
        return None, "disabled"

    prompt_text, system_prompt = _extract_prompt_and_system(body)
    if not prompt_text:
        return None, "no_content"

    trace_id = request_id or str(uuid.uuid4())

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

    timeout_s = timeout_ms / 1000.0

    try:
        ctx = await asyncio.wait_for(
            thoth.classify(classification_request),
            timeout=timeout_s,
        )
        logger.info(
            "Thoth classification: intent=%s risk=%s confidence=%.2f pii=%s latency_ms=%d tenant=%s",
            ctx.intent,
            ctx.risk_level,
            ctx.confidence,
            ctx.pii_detected,
            ctx.latency_ms,
            tenant_id,
        )
        return ctx, "classified"

    except (asyncio.TimeoutError, httpx.TimeoutException):
        logger.warning(
            "Thoth classification TIMEOUT (>%dms) — structural-only enforcement active tenant=%s",
            timeout_ms,
            tenant_id,
        )
        return make_timeout_context(trace_id), "timeout"

    except Exception as exc:
        logger.warning(
            "Thoth classification UNAVAILABLE — structural-only enforcement active tenant=%s error=%s",
            tenant_id,
            exc,
        )
        return make_unavailable_context(trace_id), "unavailable"
