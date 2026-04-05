import logging

import httpx
from fastapi import Request
from starlette.responses import StreamingResponse, Response

from app.config import get_settings

logger = logging.getLogger("sphinx.proxy")

# Persistent async client for connection pooling
_http_client: httpx.AsyncClient | None = None


async def get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0))
    return _http_client


async def close_http_client() -> None:
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None


async def proxy_request(request: Request, target_url: str, provider_api_key: str | None = None) -> Response:
    """Proxy an incoming request to the target LLM provider endpoint."""
    settings = get_settings()
    url = target_url or settings.default_provider_url

    # Build the upstream path
    path = request.url.path
    if path.startswith("/v1"):
        upstream_url = f"{url}{path}"
    else:
        upstream_url = f"{url}/v1{path}"

    # Forward headers, replacing auth if provider key is available
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)
    if provider_api_key:
        headers["authorization"] = f"Bearer {provider_api_key}"

    body = await request.body()
    client = await get_http_client()

    # Check if streaming is requested
    import json as _json
    is_streaming = False
    if body:
        try:
            payload = _json.loads(body)
            is_streaming = payload.get("stream", False)
        except (ValueError, KeyError):
            pass

    if is_streaming:
        # Stream the response back to the client without buffering
        upstream_request = client.build_request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            content=body,
        )
        upstream_response = await client.send(upstream_request, stream=True)

        async def stream_generator():
            try:
                async for chunk in upstream_response.aiter_bytes():
                    yield chunk
            finally:
                await upstream_response.aclose()

        return StreamingResponse(
            stream_generator(),
            status_code=upstream_response.status_code,
            headers=dict(upstream_response.headers),
            media_type=upstream_response.headers.get("content-type", "text/event-stream"),
        )
    else:
        # Non-streaming: forward and return complete response
        upstream_response = await client.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            content=body,
        )
        return Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            headers=dict(upstream_response.headers),
            media_type=upstream_response.headers.get("content-type"),
        )
