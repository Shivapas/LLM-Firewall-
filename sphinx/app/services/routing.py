"""Basic routing engine: resolves model name to provider and routes requests."""

from __future__ import annotations

import json
import logging
from typing import Optional

import httpx
from fastapi import Request
from starlette.responses import Response, StreamingResponse

from app.services.providers.base import BaseProvider, UnifiedRequest, UnifiedMessage
from app.services.providers.registry import ProviderRegistry
from app.services.proxy import get_http_client

logger = logging.getLogger("sphinx.routing")

# Global registry instance
_registry: Optional[ProviderRegistry] = None


def get_registry() -> ProviderRegistry:
    """Get or create the global provider registry."""
    global _registry
    if _registry is None:
        _registry = ProviderRegistry()
    return _registry


async def initialize_registry(providers: list[dict]) -> ProviderRegistry:
    """Initialize the provider registry from credential store data.

    Args:
        providers: list of dicts with keys: provider_name, api_key, base_url, weight (optional)
    """
    from app.services.providers.openai import OpenAIProvider
    from app.services.providers.anthropic import AnthropicProvider
    from app.services.providers.gemini import GeminiProvider
    from app.services.providers.llama import LlamaProvider
    from app.services.providers.bedrock import BedrockProvider
    from app.services.providers.azure_openai import AzureOpenAIProvider

    registry = get_registry()

    provider_classes = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "gemini": GeminiProvider,
        "llama": LlamaProvider,
        "bedrock": BedrockProvider,
        "azure_openai": AzureOpenAIProvider,
    }

    for p in providers:
        name = p["provider_name"].lower()
        cls = provider_classes.get(name)
        if cls is None:
            logger.warning("Unknown provider: %s", name)
            continue

        instance = cls(
            base_url=p.get("base_url", ""),
            api_key=p.get("api_key", ""),
        )
        weight = p.get("weight", 1.0)
        registry.register(instance, weight=weight)

    logger.info("Provider registry initialized with %s", registry.list_providers())
    return registry


def resolve_provider(model_name: str) -> Optional[BaseProvider]:
    """Resolve a model name to a provider adapter."""
    registry = get_registry()
    return registry.get_provider_for_model(model_name)


async def route_request(
    request: Request,
    body: bytes,
    model_name: str,
    provider: BaseProvider,
) -> Response:
    """Route a request through the resolved provider adapter.

    Normalizes the request to provider format, forwards it, and normalizes the response back.
    """
    # Parse the unified request from the incoming body
    try:
        raw = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        raw = {}

    unified = UnifiedRequest(
        model=model_name,
        messages=[
            UnifiedMessage(role=m.get("role", "user"), content=m.get("content", ""))
            for m in raw.get("messages", [])
        ],
        temperature=raw.get("temperature"),
        max_tokens=raw.get("max_tokens"),
        top_p=raw.get("top_p"),
        stream=raw.get("stream", False),
    )

    # Convert to provider-specific format
    url, headers, provider_body = provider.normalize_request(unified)

    client = await get_http_client()

    if unified.stream:
        return await _route_streaming(client, url, headers, provider_body, provider, model_name)
    else:
        return await _route_non_streaming(client, url, headers, provider_body, provider)


async def _route_non_streaming(
    client: httpx.AsyncClient,
    url: str,
    headers: dict,
    body: bytes,
    provider: BaseProvider,
) -> Response:
    """Forward a non-streaming request and normalize the response."""
    upstream = await client.request(
        method="POST",
        url=url,
        headers=headers,
        content=body,
    )

    if upstream.status_code != 200:
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type="application/json",
        )

    try:
        raw_data = upstream.json()
        unified_resp = provider.normalize_response(upstream.status_code, raw_data)

        # Return in OpenAI-compatible format for client consistency
        resp_body = {
            "id": unified_resp.id,
            "object": "chat.completion",
            "created": unified_resp.created,
            "model": unified_resp.model,
            "provider": unified_resp.provider,
            "choices": [
                {
                    "index": c.index,
                    "message": {"role": c.message.role, "content": c.message.content},
                    "finish_reason": c.finish_reason,
                }
                for c in unified_resp.choices
            ],
            "usage": {
                "prompt_tokens": unified_resp.usage.prompt_tokens,
                "completion_tokens": unified_resp.usage.completion_tokens,
                "total_tokens": unified_resp.usage.total_tokens,
            },
        }
        return Response(
            content=json.dumps(resp_body).encode(),
            status_code=200,
            media_type="application/json",
        )
    except Exception:
        logger.exception("Failed to normalize response from %s", provider.provider_name)
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type="application/json",
        )


async def _route_streaming(
    client: httpx.AsyncClient,
    url: str,
    headers: dict,
    body: bytes,
    provider: BaseProvider,
    model_name: str,
) -> StreamingResponse:
    """Forward a streaming request with provider-aware SSE normalization."""
    upstream_req = client.build_request(
        method="POST",
        url=url,
        headers=headers,
        content=body,
    )
    upstream = await client.send(upstream_req, stream=True)

    async def normalized_stream():
        try:
            buffer = ""
            async for raw_bytes in upstream.aiter_bytes():
                buffer += raw_bytes.decode("utf-8", errors="replace")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue

                    chunk = provider.normalize_stream_chunk(line)
                    if chunk is not None:
                        chunk.model = model_name
                        yield provider.build_sse_line(chunk)

            yield "data: [DONE]\n\n"
        finally:
            await upstream.aclose()

    return StreamingResponse(
        normalized_stream(),
        status_code=upstream.status_code,
        media_type="text/event-stream",
    )
