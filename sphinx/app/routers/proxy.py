import json
import logging

from fastapi import APIRouter, Request
from starlette.responses import JSONResponse, Response

from app.services.proxy import proxy_request
from app.services.rate_limiter import check_rate_limit
from app.services.kill_switch import check_kill_switch
from app.services.token_budget import record_token_usage, persist_usage_to_db
from app.services.database import async_session
from app.config import get_settings

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
    """Main gateway proxy endpoint with rate limiting, kill-switch, and token tracking."""
    settings = get_settings()
    target_url = settings.default_provider_url

    tenant_id = getattr(request.state, "tenant_id", "unknown")
    project_id = getattr(request.state, "project_id", "unknown")
    api_key_id = getattr(request.state, "api_key_id", None)
    tpm_limit = getattr(request.state, "tpm_limit", 100000)

    body = await request.body()
    model_name = _extract_model_from_body(body)

    # ── Kill-switch check (earliest pipeline stage) ──
    if model_name:
        ks = await check_kill_switch(model_name)
        if ks is not None:
            if ks["action"] == "block":
                logger.warning(
                    "Kill-switch BLOCKED model=%s tenant=%s reason=%s",
                    model_name, tenant_id, ks.get("reason", ""),
                )
                return JSONResponse(
                    status_code=503,
                    content={
                        "error": "Model temporarily unavailable",
                        "model": model_name,
                        "reason": ks.get("reason", "Kill-switch active"),
                    },
                )
            elif ks["action"] == "reroute" and ks.get("fallback_model"):
                logger.info(
                    "Kill-switch REROUTING model=%s -> %s tenant=%s",
                    model_name, ks["fallback_model"], tenant_id,
                )
                # Rewrite the model in the body
                payload = json.loads(body)
                payload["model"] = ks["fallback_model"]
                body = json.dumps(payload).encode()
                model_name = ks["fallback_model"]

    # ── Rate limit check ──
    if api_key_id:
        estimated_tokens = _estimate_prompt_tokens(body)
        rate_result = await check_rate_limit(api_key_id, tpm_limit, estimated_tokens)
        if not rate_result["allowed"]:
            logger.warning(
                "Rate limit exceeded key=%s usage=%d limit=%d",
                api_key_id, rate_result["current_usage"], tpm_limit,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "current_usage": rate_result["current_usage"],
                    "limit": tpm_limit,
                },
                headers={"Retry-After": str(rate_result.get("retry_after", 60))},
            )

    logger.info(
        "Proxying request path=/v1/%s tenant=%s project=%s method=%s model=%s",
        path, tenant_id, project_id, request.method, model_name or "unknown",
    )

    # ── Proxy to upstream ──
    response = await proxy_request(request, target_url)

    # ── Token budget tracking (async, best-effort) ──
    if api_key_id and response.status_code == 200:
        try:
            # For non-streaming responses, try to extract usage from response
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

                # Persist to Postgres asynchronously
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
