"""Gateway proxy router with multi-provider routing, audit events, and streaming support."""

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Request
from starlette.responses import JSONResponse, Response

from app.services.proxy import proxy_request
from app.services.rate_limiter import check_rate_limit
from app.services.kill_switch import check_kill_switch
from app.services.token_budget import record_token_usage, get_budget_state, persist_usage_to_db
from app.services.routing import resolve_provider, route_request
from app.services.audit import emit_audit_event
from app.services.threat_detection.engine import get_threat_engine
from app.services.data_shield.engine import get_data_shield_engine
from app.services.rag.pipeline import get_rag_pipeline
from app.services.rag.classifier import RequestType
from app.services.routing_policy import get_routing_policy_evaluator, RoutingContext, RoutingAction
from app.services.budget_downgrade import get_budget_downgrade_service
from app.services.routing_audit import emit_routing_audit_event
from app.services.database import async_session
from app.config import get_settings

_scan_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="gateway-scan")

logger = logging.getLogger("sphinx.proxy")

router = APIRouter()


def _extract_model_from_body(body: bytes) -> str | None:
    """Extract the model name from request body JSON."""
    if not body:
        return None
    try:
        payload = json.loads(body)
        return payload.get("model")
    except (ValueError, AttributeError):
        return None


def _estimate_prompt_tokens(body: bytes) -> int:
    """Rough estimate of prompt tokens from request body size. ~4 chars per token."""
    return max(1, len(body) // 4)


@router.api_route(
    "/v1/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
async def gateway_proxy(request: Request, path: str) -> Response:
    """Main gateway proxy endpoint with multi-provider routing, audit, rate limiting, and kill-switch."""
    settings = get_settings()
    start_time = time.time()

    tenant_id = getattr(request.state, "tenant_id", "unknown")
    project_id = getattr(request.state, "project_id", "unknown")
    api_key_id = getattr(request.state, "api_key_id", None)
    tpm_limit = getattr(request.state, "tpm_limit", 100000)

    body = await request.body()
    model_name = _extract_model_from_body(body)
    audit_action = "allowed"
    provider_name = ""

    # ── Kill-switch check (earliest pipeline stage) ──
    if model_name:
        ks = await check_kill_switch(model_name)
        if ks is not None:
            if ks["action"] == "block":
                error_msg = ks.get("error_message", "Model temporarily unavailable")
                logger.warning(
                    "Kill-switch BLOCKED model=%s tenant=%s activated_by=%s reason=%s timestamp=%s",
                    model_name, tenant_id, ks.get("activated_by", "unknown"),
                    ks.get("reason", ""), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                )
                latency_ms = (time.time() - start_time) * 1000
                try:
                    await emit_audit_event(
                        request_body=body, tenant_id=tenant_id, project_id=project_id,
                        api_key_id=str(api_key_id) if api_key_id else "",
                        model=model_name, action="blocked_kill_switch",
                        status_code=503, latency_ms=latency_ms,
                        metadata={
                            "reason": ks.get("reason", "Kill-switch active"),
                            "activated_by": ks.get("activated_by", "unknown"),
                            "kill_switch_action": "block",
                        },
                    )
                except Exception:
                    logger.debug("Failed to emit audit event", exc_info=True)

                return JSONResponse(
                    status_code=503,
                    content={
                        "error": error_msg,
                        "model": model_name,
                        "reason": ks.get("reason", "Kill-switch active"),
                    },
                )
            elif ks["action"] == "reroute" and ks.get("fallback_model"):
                original_model = model_name
                logger.info(
                    "Kill-switch REROUTING model=%s -> %s tenant=%s activated_by=%s reason=%s timestamp=%s",
                    model_name, ks["fallback_model"], tenant_id,
                    ks.get("activated_by", "unknown"), ks.get("reason", ""),
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                )
                audit_action = "rerouted_kill_switch"
                payload = json.loads(body)
                payload["model"] = ks["fallback_model"]
                body = json.dumps(payload).encode()
                model_name = ks["fallback_model"]

                # Log reroute event for audit
                try:
                    await emit_audit_event(
                        request_body=body, tenant_id=tenant_id, project_id=project_id,
                        api_key_id=str(api_key_id) if api_key_id else "",
                        model=original_model, action="rerouted_kill_switch",
                        status_code=200, latency_ms=0,
                        metadata={
                            "original_model": original_model,
                            "fallback_model": ks["fallback_model"],
                            "activated_by": ks.get("activated_by", "unknown"),
                            "reason": ks.get("reason", ""),
                            "kill_switch_action": "reroute",
                        },
                    )
                except Exception:
                    logger.debug("Failed to emit reroute audit event", exc_info=True)

    # ── RAG Pipeline Classification & Query Firewall ──
    rag_pipeline = get_rag_pipeline()
    loop = asyncio.get_event_loop()
    rag_body, rag_result = await loop.run_in_executor(
        _scan_executor,
        lambda: rag_pipeline.process(body, tenant_id=tenant_id),
    )

    if not rag_result.allowed:
        logger.warning(
            "RAG pipeline BLOCKED request tenant=%s reason=%s",
            tenant_id, rag_result.blocked_reason,
        )
        latency_ms = (time.time() - start_time) * 1000
        try:
            await emit_audit_event(
                request_body=body, tenant_id=tenant_id, project_id=project_id,
                api_key_id=str(api_key_id) if api_key_id else "",
                model=model_name or "unknown", action="blocked_rag",
                status_code=403, latency_ms=latency_ms,
                metadata={"reason": rag_result.blocked_reason, "rag": rag_result.to_dict()},
            )
        except Exception:
            logger.debug("Failed to emit audit event", exc_info=True)

        return JSONResponse(
            status_code=403,
            content={
                "error": "Request blocked by RAG security policy",
                "reason": rag_result.blocked_reason,
                "classification": rag_result.classification.to_dict(),
            },
        )

    # If RAG pipeline modified the body (PII redaction in query), use modified body
    if rag_result.classification.request_type == RequestType.RAG_QUERY:
        body = rag_body
        logger.info(
            "RAG query processed: type=%s intent=%s tenant=%s",
            rag_result.classification.request_type.value,
            rag_result.intent.intent.value if rag_result.intent else "n/a",
            tenant_id,
        )

    # ── Tier 1 + Tier 2 Threat Detection + Data Shield (parallel) ──
    threat_engine = get_threat_engine()
    data_shield = get_data_shield_engine()

    threat_future = loop.run_in_executor(
        _scan_executor, threat_engine.scan_request_body_with_escalation, body,
    )
    shield_future = loop.run_in_executor(
        _scan_executor, lambda: data_shield.scan_request_body(body),
    )

    (threat_result, escalation_decision), (shielded_body, shield_result) = await asyncio.gather(
        threat_future, shield_future,
    )

    # Apply PII redaction to body (before threat action enforcement)
    if shield_result and shield_result.redaction and shield_result.redaction.redaction_count > 0:
        body = shielded_body
        logger.info(
            "Data Shield redacted %d entities (pii=%d phi=%d cred=%d) tenant=%s",
            shield_result.redaction.redaction_count,
            shield_result.pii_count,
            shield_result.phi_count,
            shield_result.credential_count,
            tenant_id,
        )

    # Build audit metadata for escalation
    threat_metadata = {
        "reason": threat_result.reason,
        "risk_level": threat_result.risk_level,
        "score": threat_result.score,
        "matched_patterns": threat_result.matched_patterns or [],
    }
    if escalation_decision:
        threat_metadata["escalation"] = escalation_decision.to_dict()

    if threat_result.action == "block":
        logger.warning(
            "Threat detection BLOCKED request tenant=%s risk=%s score=%.3f reason=%s escalated=%s",
            tenant_id, threat_result.risk_level, threat_result.score, threat_result.reason,
            escalation_decision.escalated_to_tier2 if escalation_decision else False,
        )
        latency_ms = (time.time() - start_time) * 1000
        try:
            await emit_audit_event(
                request_body=body, tenant_id=tenant_id, project_id=project_id,
                api_key_id=str(api_key_id) if api_key_id else "",
                model=model_name or "unknown", action="blocked_threat",
                status_code=403, latency_ms=latency_ms,
                metadata=threat_metadata,
            )
        except Exception:
            logger.debug("Failed to emit audit event", exc_info=True)

        return JSONResponse(
            status_code=403,
            content={
                "error": "Request blocked by security policy",
                "risk_level": threat_result.risk_level,
                "score": round(threat_result.score, 4),
                "reason": threat_result.reason,
            },
        )
    elif threat_result.action == "rewrite":
        logger.info(
            "Threat detection REWRITING request tenant=%s risk=%s",
            tenant_id, threat_result.risk_level,
        )
        body = threat_engine.apply_rewrite_to_body(body, threat_result)
        audit_action = "rewritten_threat"
    elif threat_result.action == "downgrade":
        logger.info(
            "Threat detection DOWNGRADING model tenant=%s risk=%s -> %s",
            tenant_id, threat_result.risk_level, threat_result.downgrade_model,
        )
        body = threat_engine.apply_downgrade_to_body(body, threat_result)
        model_name = threat_result.downgrade_model or model_name
        audit_action = "downgraded_threat"

    # ── Rate limit check ──
    estimated_tokens = _estimate_prompt_tokens(body)
    if api_key_id:
        rate_result = await check_rate_limit(api_key_id, tpm_limit, estimated_tokens)
        if not rate_result["allowed"]:
            logger.warning(
                "Rate limit exceeded key=%s usage=%d limit=%d",
                api_key_id, rate_result["current_usage"], tpm_limit,
            )
            latency_ms = (time.time() - start_time) * 1000
            try:
                await emit_audit_event(
                    request_body=body, tenant_id=tenant_id, project_id=project_id,
                    api_key_id=str(api_key_id), model=model_name or "unknown",
                    action="rate_limited", status_code=429, latency_ms=latency_ms,
                )
            except Exception:
                logger.debug("Failed to emit audit event", exc_info=True)

            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "current_usage": rate_result["current_usage"],
                    "limit": tpm_limit,
                },
                headers={"Retry-After": str(rate_result.get("retry_after", 60))},
            )

    # ── Routing policy evaluation (sensitivity + budget) ──
    routing_decision = None
    downgrade_info = None
    if model_name and api_key_id:
        # Collect compliance tags from data shield scan
        compliance_tags = []
        requires_private = False
        if shield_result:
            if shield_result.pii_count > 0:
                compliance_tags.append("PII")
            if shield_result.phi_count > 0:
                compliance_tags.append("PHI")
            if shield_result.credential_count > 0:
                compliance_tags.append("IP")

        # Check budget state for downgrade evaluation
        budget_state = await get_budget_state(api_key_id)
        current_usage = budget_state.get("total_tokens", 0)
        budget_svc = get_budget_downgrade_service()
        budget_exceeded = budget_svc.is_budget_exceeded(model_name, current_usage, tenant_id)
        budget_usage_pct = budget_svc.get_budget_usage_pct(model_name, current_usage, tenant_id)

        # Build routing context
        routing_ctx = RoutingContext(
            model_name=model_name,
            tenant_id=tenant_id,
            api_key_id=api_key_id,
            compliance_tags=compliance_tags,
            sensitivity_score=getattr(request.state, "risk_score", 0.0),
            requires_private_model=requires_private,
            kill_switch_active=False,
            budget_exceeded=budget_exceeded,
            budget_usage_pct=budget_usage_pct,
        )

        # Evaluate routing policy
        evaluator = get_routing_policy_evaluator()
        routing_decision = evaluator.evaluate(routing_ctx)

        if routing_decision.action == RoutingAction.ROUTE and routing_decision.target_model != model_name:
            logger.info(
                "Routing policy rerouted: model=%s -> %s reason=%s tenant=%s",
                model_name, routing_decision.target_model, routing_decision.reason, tenant_id,
            )
            payload = json.loads(body)
            payload["model"] = routing_decision.target_model
            body = json.dumps(payload).encode()
            model_name = routing_decision.target_model
            audit_action = "routed_sensitivity"

        elif routing_decision.action == RoutingAction.BLOCK:
            latency_ms = (time.time() - start_time) * 1000
            await emit_routing_audit_event(
                request_body=body, decision=routing_decision,
                tenant_id=tenant_id, project_id=project_id,
                api_key_id=str(api_key_id),
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by routing policy",
                    "reason": routing_decision.reason,
                },
            )

        # Budget-triggered downgrade (if no sensitivity reroute already happened)
        if routing_decision.action == RoutingAction.DEFAULT and budget_exceeded:
            budget_decision = await budget_svc.evaluate(model_name, api_key_id, tenant_id)
            if budget_decision.should_downgrade:
                downgrade_info = budget_decision.to_dict()
                payload = json.loads(body)
                payload["model"] = budget_decision.downgrade_model
                body = json.dumps(payload).encode()
                model_name = budget_decision.downgrade_model
                audit_action = "downgraded_budget"
                logger.info(
                    "Budget downgrade: %s -> %s usage=%d/%d tenant=%s",
                    budget_decision.original_model, budget_decision.downgrade_model,
                    budget_decision.current_usage, budget_decision.budget_limit, tenant_id,
                )

    # ── Multi-provider routing ──
    provider = resolve_provider(model_name) if model_name else None

    if provider:
        provider_name = provider.provider_name
        logger.info(
            "Routing request path=/v1/%s model=%s -> provider=%s tenant=%s project=%s",
            path, model_name, provider_name, tenant_id, project_id,
        )
        response = await route_request(request, body, model_name, provider)
    else:
        # Fallback: proxy directly to default provider (backward compatible)
        target_url = settings.default_provider_url
        logger.info(
            "Proxying request path=/v1/%s tenant=%s project=%s method=%s model=%s (default provider)",
            path, tenant_id, project_id, request.method, model_name or "unknown",
        )
        response = await proxy_request(request, target_url)

    # ── Routing decision audit log ──
    if routing_decision and routing_decision.action != RoutingAction.DEFAULT:
        try:
            await emit_routing_audit_event(
                request_body=body, decision=routing_decision,
                tenant_id=tenant_id, project_id=project_id,
                api_key_id=str(api_key_id) if api_key_id else "",
                downgrade_info=downgrade_info,
            )
        except Exception:
            logger.debug("Failed to emit routing audit event", exc_info=True)

    # ── Audit event emission ──
    latency_ms = (time.time() - start_time) * 1000
    audit_metadata = {}
    if rag_result.classification.request_type == RequestType.RAG_QUERY:
        audit_metadata["rag"] = rag_result.to_dict()
    if shield_result and shield_result.redaction and shield_result.redaction.redaction_count > 0:
        audit_metadata["data_shield"] = shield_result.to_dict()
    if routing_decision:
        audit_metadata["routing_decision"] = routing_decision.to_dict()
    if downgrade_info:
        audit_metadata["budget_downgrade"] = downgrade_info
    try:
        await emit_audit_event(
            request_body=body,
            tenant_id=tenant_id,
            project_id=project_id,
            api_key_id=str(api_key_id) if api_key_id else "",
            model=model_name or "unknown",
            provider=provider_name,
            action=audit_action,
            status_code=response.status_code,
            latency_ms=latency_ms,
            prompt_tokens=estimated_tokens,
            metadata=audit_metadata if audit_metadata else None,
        )
    except Exception:
        logger.debug("Failed to emit audit event", exc_info=True)

    # ── Token budget tracking (async, best-effort) ──
    if api_key_id and response.status_code == 200:
        try:
            if hasattr(response, "body"):
                resp_data = json.loads(response.body)
                usage = resp_data.get("usage", {})
                prompt_tokens = usage.get("prompt_tokens", estimated_tokens)
                completion_tokens = usage.get("completion_tokens", 0)
                total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)

                await record_token_usage(
                    api_key_id=api_key_id,
                    model=model_name or "unknown",
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                )

                try:
                    async with async_session() as db:
                        await persist_usage_to_db(
                            db=db,
                            api_key_id=api_key_id,
                            model=model_name or "unknown",
                            prompt_tokens=prompt_tokens,
                            completion_tokens=completion_tokens,
                            total_tokens=total_tokens,
                        )
                except Exception:
                    logger.debug("Failed to persist token usage to DB", exc_info=True)
        except Exception:
            logger.debug("Failed to track token usage", exc_info=True)

    return response
