"""Post-inference Thoth classification worker — Sprint 4.

Sprint 4 tasks implemented
--------------------------
S4-T1  submit_post_inference_classification() — non-blocking fire-and-forget
       wrapper. Creates an asyncio Task that processes response classification
       without blocking the main request path or response delivery.
       Uses non-blocking I/O per the NFR scalability requirement.

S4-T2  build_response_classification_request() — assembles the Thoth API
       payload from LLM response content and Sphinx pipeline correlation
       context.  Extracts text from OpenAI, Anthropic, and generic response
       formats.

S4-T3  _enrich_audit_with_response_classification() — writes a dedicated
       ``post_inference_classification`` audit event to the Sphinx audit stream,
       correlated to the original prompt audit record via ``prompt_request_id``
       (FR-POST-03).

S4-T4  _evaluate_post_inference_alert_rules() — evaluates post-inference
       classification outcomes against configured alert rules and fires alerts
       for high-risk responses within the sub-5-second processing window
       (FR-POST-04).

Data flow (FR-POST-01 / FR-POST-02):
  [LLM Response]
       ├── [Deliver to Application]         ← main request path returns here
       └── [asyncio.create_task]
               │
               ▼ (non-blocking background Task)
          [Thoth Async Classification]
               │
               ▼
          [Audit Stream enrichment]  ← FR-POST-03
               │
               ├── [Near-RT Alert Rules]    ← FR-POST-04
               │
               └── [SIEM Export]            ← FR-POST-05
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Optional

import httpx

from app.services.thoth.models import (
    ClassificationContext,
    ClassificationRequest,
    ResponseClassificationRequest,
)
from app.services.thoth.client import get_thoth_client
from app.services.thoth.circuit_breaker import get_thoth_circuit_breaker
from app.services.audit import emit_audit_event

logger = logging.getLogger("sphinx.thoth.post_inference")

# Risk levels that trigger near-RT alerts (FR-POST-04)
_ALERT_RISK_LEVELS: frozenset[str] = frozenset({"HIGH", "CRITICAL"})

# Minimum confidence to trigger a PII-based alert
_PII_ALERT_CONFIDENCE_THRESHOLD: float = 0.75


# ---------------------------------------------------------------------------
# S4-T2: Response text extraction
# ---------------------------------------------------------------------------

def _extract_response_text(response_body: bytes) -> str:
    """Extract text content from an LLM HTTP response body.

    Supports:
    - OpenAI chat completions: ``choices[].message.content``
    - Anthropic messages: ``content[].text`` (type==text blocks)
    - Simple ``text`` or ``output`` fields (legacy / OSS formats)

    Returns an empty string if no text can be extracted (e.g. streaming
    chunk, tool-only response, or non-JSON body).
    """
    if not response_body:
        return ""

    try:
        data = json.loads(response_body)
    except (ValueError, TypeError):
        return ""

    parts: list[str] = []

    # OpenAI chat completions: choices[].message.content
    for choice in data.get("choices", []):
        message = choice.get("message", {})
        content = message.get("content")
        if isinstance(content, str) and content:
            parts.append(content)

    # Anthropic messages API: content[].{type: "text", text: "..."}
    if not parts and isinstance(data.get("content"), list):
        for block in data["content"]:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text", "")
                if text:
                    parts.append(text)

    # Simple text / output fields (OSS / legacy formats)
    if not parts:
        for key in ("text", "output", "response", "completion"):
            val = data.get(key)
            if isinstance(val, str) and val:
                parts.append(val)
                break

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# S4-T2: Payload builder — public API
# ---------------------------------------------------------------------------

def build_response_classification_request(
    response_body: bytes,
    *,
    prompt_request_id: str,
    tenant_id: str = "unknown",
    application_id: str = "unknown",
    model_endpoint: str = "unknown",
    session_id: Optional[str] = None,
    audit_event_id: Optional[str] = None,
) -> Optional[ResponseClassificationRequest]:
    """Assemble a Thoth classification request from the LLM response (S4-T2).

    Extracts response text and packages it with full correlation context
    so the resulting classification can be linked to the original prompt
    audit record.

    Args:
        response_body:       Raw LLM HTTP response body bytes.
        prompt_request_id:   Sphinx trace ID from the original prompt request
                             (used as the correlation key in audit records).
        tenant_id:           Hashed tenant identifier.
        application_id:      Application/project identifier.
        model_endpoint:      Target LLM endpoint name.
        session_id:          Optional session correlation ID.
        audit_event_id:      Original prompt audit event ID for enrichment.

    Returns:
        A ``ResponseClassificationRequest`` ready for Thoth submission, or
        ``None`` if the response contains no extractable text content.
    """
    response_text = _extract_response_text(response_body)
    if not response_text:
        logger.debug(
            "Post-inference: no extractable text from response body "
            "prompt_request_id=%s",
            prompt_request_id,
        )
        return None

    return ResponseClassificationRequest(
        request_id=str(uuid.uuid4()),
        content=response_text,
        content_type="response",
        prompt_request_id=prompt_request_id,
        user_id=tenant_id,
        application_id=application_id,
        model_endpoint=model_endpoint,
        session_id=session_id,
        audit_event_id=audit_event_id,
    )


# ---------------------------------------------------------------------------
# S4-T3: Audit record enrichment
# ---------------------------------------------------------------------------

async def _enrich_audit_with_response_classification(
    classification_ctx: ClassificationContext,
    *,
    prompt_request_id: str,
    audit_event_id: str,
    tenant_id: str,
    project_id: str,
    api_key_id: str,
    model_endpoint: str,
    classification_latency_ms: int,
) -> None:
    """Write a post-inference classification audit event to the Sphinx audit stream.

    FR-POST-03: Post-inference classifications SHALL be written to Sphinx's
    audit event stream with full prompt-response correlation.

    The emitted audit event carries:
    - ``action == "post_inference_classification"`` for stream filtering
    - ``metadata.prompt_request_id`` linking back to the prompt audit record
    - ``metadata.audit_event_id`` for direct audit event correlation
    - Full Thoth classification payload (intent, risk, confidence, PII flags)
    - Classification timestamp and latency for SLA tracking (FR-AUD-02)
    """
    risk_score = (
        classification_ctx.confidence
        if classification_ctx.risk_level in _ALERT_RISK_LEVELS
        else 0.0
    )

    try:
        await emit_audit_event(
            request_body=b"",
            tenant_id=tenant_id,
            project_id=project_id,
            api_key_id=api_key_id,
            model=model_endpoint,
            action="post_inference_classification",
            status_code=0,
            latency_ms=float(classification_latency_ms),
            risk_score=risk_score,
            action_taken="post_inference_classification",
            enforcement_duration_ms=float(classification_latency_ms),
            metadata={
                "event_type": "post_inference_classification",
                "classification_stage": "response",
                # Correlation fields (FR-POST-03)
                "prompt_request_id": prompt_request_id,
                "original_audit_event_id": audit_event_id,
                # Thoth classification payload (FR-AUD-01/02)
                "thoth_classification": classification_ctx.to_dict(),
                "classification_timestamp": time.time(),
                "classification_latency_ms": classification_latency_ms,
            },
        )
        logger.info(
            "Post-inference audit enriched: intent=%s risk=%s confidence=%.2f "
            "latency_ms=%d prompt_request_id=%s",
            classification_ctx.intent,
            classification_ctx.risk_level,
            classification_ctx.confidence,
            classification_latency_ms,
            prompt_request_id,
        )
    except Exception:
        logger.warning(
            "Failed to write post-inference classification audit event "
            "prompt_request_id=%s",
            prompt_request_id,
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# S4-T4: Near-RT alert rule evaluation
# ---------------------------------------------------------------------------

async def _evaluate_post_inference_alert_rules(
    classification_ctx: ClassificationContext,
    *,
    prompt_request_id: str,
    tenant_id: str,
    model_endpoint: str,
) -> None:
    """Evaluate post-inference classification against alert rules (S4-T4).

    FR-POST-04: Policy rules SHALL be configurable to quarantine or alert
    based on post-inference classification outcomes in near-real-time
    (sub-5-second loop).

    Alert conditions checked:
    1. Response risk_level is HIGH or CRITICAL
    2. PII detected in response with confidence >= 0.75

    Alert delivery:
    - A dedicated ``post_inference_alert`` audit event is always written to
      the Sphinx audit stream for SIEM forwarding.
    - The alert engine is notified for delivery to configured channels
      (webhook, email) via rules with condition_type == "post_inference_risk_alert".
    """
    if classification_ctx.source == "structural_fallback":
        # No live Thoth data — nothing to evaluate
        return

    should_alert = classification_ctx.risk_level in _ALERT_RISK_LEVELS or (
        classification_ctx.pii_detected
        and classification_ctx.confidence >= _PII_ALERT_CONFIDENCE_THRESHOLD
    )

    if not should_alert:
        return

    severity = "CRITICAL" if classification_ctx.risk_level == "CRITICAL" else "HIGH"
    alert_message = (
        f"Post-inference response classified as {classification_ctx.risk_level} risk "
        f"(intent={classification_ctx.intent}, "
        f"confidence={classification_ctx.confidence:.2f}, "
        f"pii={classification_ctx.pii_detected})"
    )

    logger.warning(
        "Post-inference alert TRIGGERED: intent=%s risk=%s confidence=%.2f "
        "pii=%s pii_types=%s prompt_request_id=%s tenant=%s",
        classification_ctx.intent,
        classification_ctx.risk_level,
        classification_ctx.confidence,
        classification_ctx.pii_detected,
        classification_ctx.pii_types,
        prompt_request_id,
        tenant_id,
    )

    # Write post-inference alert audit event (always, for SIEM export)
    alert_metadata = {
        "event_type": "post_inference_alert",
        "alert_trigger": "post_inference_classification",
        "classification_stage": "response",
        "prompt_request_id": prompt_request_id,
        "risk_level": classification_ctx.risk_level,
        "intent": classification_ctx.intent,
        "confidence": classification_ctx.confidence,
        "pii_detected": classification_ctx.pii_detected,
        "pii_types": classification_ctx.pii_types,
        "severity": severity,
        "recommended_action": classification_ctx.recommended_action,
    }
    try:
        await emit_audit_event(
            request_body=b"",
            tenant_id=tenant_id,
            project_id="",
            api_key_id="",
            model=model_endpoint,
            action="post_inference_alert",
            status_code=0,
            latency_ms=0.0,
            risk_score=classification_ctx.confidence,
            action_taken="alert",
            enforcement_duration_ms=0.0,
            metadata=alert_metadata,
        )
    except Exception:
        logger.warning(
            "Failed to emit post-inference alert audit event "
            "prompt_request_id=%s",
            prompt_request_id,
            exc_info=True,
        )

    # Dispatch to alert engine for rule-based delivery (webhook/email)
    # Best-effort — post-inference alerting does not block the pipeline
    try:
        from app.services.dashboard.alert_engine import (
            get_alert_engine_service,
            AlertTriggerContext,
        )
        alert_engine = get_alert_engine_service()
        trigger_ctx = AlertTriggerContext(
            condition_type="post_inference_risk_alert",
            tenant_id=tenant_id,
            metric_value=classification_ctx.confidence,
            threshold=_PII_ALERT_CONFIDENCE_THRESHOLD,
            message=alert_message,
            metadata=alert_metadata,
        )
        await alert_engine.notify_post_inference_alert(trigger_ctx)
    except Exception:
        logger.debug(
            "Alert engine notify skipped (best-effort) prompt_request_id=%s",
            prompt_request_id,
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# S4-T1: Async classification worker (internal)
# ---------------------------------------------------------------------------

async def _classify_response_worker(
    payload: ResponseClassificationRequest,
    *,
    tenant_id: str,
    project_id: str,
    api_key_id: str,
    model_endpoint: str,
    circuit_breaker_enabled: bool,
    timeout_ms: int,
) -> None:
    """Background async worker — calls Thoth and drives post-inference actions.

    Called exclusively via ``asyncio.create_task()`` from
    ``submit_post_inference_classification()``.  Never blocks the main
    request path.

    Sequence:
      1. Circuit breaker guard — skips classification if Thoth is unhealthy
      2. Thoth API call with configurable timeout (default 5 s for responses)
      3. S4-T3: Audit record enrichment
      4. S4-T4: Near-RT alert rule evaluation
      5. S4-T5: SIEM export (best-effort)
    """
    t0 = time.monotonic()
    logger.debug(
        "Post-inference worker started: request_id=%s prompt_request_id=%s tenant=%s",
        payload.request_id,
        payload.prompt_request_id,
        tenant_id,
    )

    thoth = get_thoth_client()
    if thoth is None:
        logger.debug(
            "Post-inference: Thoth client not initialised, skipping "
            "prompt_request_id=%s",
            payload.prompt_request_id,
        )
        return

    # 1. Circuit breaker guard
    if circuit_breaker_enabled:
        cb = get_thoth_circuit_breaker()
        if not cb.is_available():
            logger.debug(
                "Post-inference: circuit breaker OPEN — skipping response "
                "classification prompt_request_id=%s",
                payload.prompt_request_id,
            )
            return

    # 2. Thoth classification call
    # Reuse the existing ThothClient.classify() which accepts a ClassificationRequest.
    # We build one from the ResponseClassificationRequest, preserving content_type="response"
    # so Thoth knows this is a post-inference payload.
    thoth_request = ClassificationRequest(
        request_id=payload.request_id,
        content=payload.content,
        content_type="response",   # Signals post-inference mode to Thoth
        system_prompt=payload.system_prompt,
        user_id=payload.user_id,
        application_id=payload.application_id,
        model_endpoint=payload.model_endpoint,
        session_id=payload.session_id,
    )

    classification_ctx: Optional[ClassificationContext] = None
    timeout_s = timeout_ms / 1000.0

    try:
        classification_ctx = await asyncio.wait_for(
            thoth.classify(thoth_request),
            timeout=timeout_s,
        )
        if circuit_breaker_enabled:
            get_thoth_circuit_breaker().record_success()

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        logger.info(
            "Post-inference classification complete: intent=%s risk=%s "
            "confidence=%.2f latency_ms=%d prompt_request_id=%s",
            classification_ctx.intent,
            classification_ctx.risk_level,
            classification_ctx.confidence,
            elapsed_ms,
            payload.prompt_request_id,
        )

    except (asyncio.TimeoutError, httpx.TimeoutException):
        if circuit_breaker_enabled:
            get_thoth_circuit_breaker().record_failure()
        logger.warning(
            "Post-inference Thoth TIMEOUT (>%dms) — no response classification "
            "prompt_request_id=%s",
            timeout_ms,
            payload.prompt_request_id,
        )
        return

    except Exception as exc:
        if circuit_breaker_enabled:
            get_thoth_circuit_breaker().record_failure()
        logger.warning(
            "Post-inference Thoth error: %s — prompt_request_id=%s",
            exc,
            payload.prompt_request_id,
        )
        return

    elapsed_ms = int((time.monotonic() - t0) * 1000)

    # 3. S4-T3: Audit enrichment
    await _enrich_audit_with_response_classification(
        classification_ctx,
        prompt_request_id=payload.prompt_request_id,
        audit_event_id=payload.audit_event_id or "",
        tenant_id=tenant_id,
        project_id=project_id,
        api_key_id=api_key_id,
        model_endpoint=model_endpoint,
        classification_latency_ms=elapsed_ms,
    )

    # 4. S4-T4: Near-RT alert rule evaluation
    await _evaluate_post_inference_alert_rules(
        classification_ctx,
        prompt_request_id=payload.prompt_request_id,
        tenant_id=tenant_id,
        model_endpoint=model_endpoint,
    )

    # 5. S4-T5: SIEM export (best-effort)
    try:
        from app.services.siem_export import get_siem_exporter
        siem = get_siem_exporter()
        if siem is not None:
            await siem.export_classification_event(
                classification_ctx=classification_ctx,
                prompt_request_id=payload.prompt_request_id,
                tenant_id=tenant_id,
                model_endpoint=model_endpoint,
                event_type="post_inference",
            )
    except Exception:
        logger.debug(
            "SIEM export skipped (best-effort) prompt_request_id=%s",
            payload.prompt_request_id,
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# S4-T1: Public fire-and-forget entry point
# ---------------------------------------------------------------------------

def submit_post_inference_classification(
    response_body: bytes,
    *,
    prompt_request_id: str,
    tenant_id: str = "unknown",
    project_id: str = "unknown",
    api_key_id: str = "",
    model_endpoint: str = "unknown",
    session_id: Optional[str] = None,
    audit_event_id: Optional[str] = None,
    circuit_breaker_enabled: bool = True,
    timeout_ms: int = 5000,
) -> Optional[asyncio.Task]:
    """Schedule non-blocking post-inference Thoth classification (S4-T1).

    Creates an asyncio Task that classifies the LLM response via Thoth
    without blocking response delivery to the calling application.

    FR-POST-01: Sphinx SHALL submit LLM responses to Thoth asynchronously
    after delivery to the requesting application.
    FR-POST-02: Thoth SHALL classify response content for risk state,
    sensitive data exposure, and output intent alignment.

    Args:
        response_body:            Raw LLM HTTP response body bytes.
        prompt_request_id:        Sphinx trace ID from the original prompt —
                                  used as correlation key in audit records.
        tenant_id:                Hashed tenant identifier.
        project_id:               Application/project identifier.
        api_key_id:               API key ID for audit records.
        model_endpoint:           Target LLM endpoint name.
        session_id:               Optional session correlation ID.
        audit_event_id:           Original prompt audit event ID.
        circuit_breaker_enabled:  Whether to gate on Thoth circuit breaker state.
        timeout_ms:               Thoth API timeout for response classification.
                                  Default 5 s (longer than prompt path 150 ms
                                  since post-inference is async/non-blocking).

    Returns:
        The asyncio Task handle, or ``None`` if the response contains no
        extractable text (e.g. streaming chunks, tool-only responses).
    """
    payload = build_response_classification_request(
        response_body,
        prompt_request_id=prompt_request_id,
        tenant_id=tenant_id,
        application_id=project_id,
        model_endpoint=model_endpoint,
        session_id=session_id,
        audit_event_id=audit_event_id,
    )

    if payload is None:
        return None

    task = asyncio.create_task(
        _classify_response_worker(
            payload,
            tenant_id=tenant_id,
            project_id=project_id,
            api_key_id=api_key_id,
            model_endpoint=model_endpoint,
            circuit_breaker_enabled=circuit_breaker_enabled,
            timeout_ms=timeout_ms,
        ),
        name=f"post_inf_{payload.request_id[:8]}",
    )

    logger.debug(
        "Post-inference task created: task=%s prompt_request_id=%s",
        task.get_name(),
        prompt_request_id,
    )
    return task
