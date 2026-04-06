import logging
from typing import Optional

import httpx
from fastapi import Request
from starlette.responses import StreamingResponse, Response

from app.config import get_settings
from app.services.output_scanner.engine import (
    OutputScannerEngine,
    OutputScanContext,
    get_output_scanner_engine,
)

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


async def proxy_request(
    request: Request,
    target_url: str,
    provider_api_key: str | None = None,
    output_scan_context: OutputScanContext | None = None,
) -> Response:
    """Proxy an incoming request to the target LLM provider endpoint.

    Args:
        request: The incoming FastAPI request.
        target_url: Target LLM provider URL.
        provider_api_key: Optional provider API key override.
        output_scan_context: Optional context for output scanning (compliance tags, tenant, etc.).
    """
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

    # Get output scanner engine for response scanning
    output_scanner = get_output_scanner_engine()

    if is_streaming:
        # Stream the response back to the client with output scanning
        upstream_request = client.build_request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            content=body,
        )
        upstream_response = await client.send(upstream_request, stream=True)

        async def raw_chunk_iter():
            try:
                async for chunk in upstream_response.aiter_bytes():
                    yield chunk
            finally:
                await upstream_response.aclose()

        # Wrap with output scanner for PII/credential/policy scanning
        scanned_stream = output_scanner.scan_stream(
            raw_chunk_iter(),
            context=output_scan_context,
        )

        async def stream_generator():
            async for chunk in scanned_stream:
                yield chunk

        return StreamingResponse(
            stream_generator(),
            status_code=upstream_response.status_code,
            headers=dict(upstream_response.headers),
            media_type=upstream_response.headers.get("content-type", "text/event-stream"),
        )
    else:
        # Non-streaming: forward, scan, and return complete response
        upstream_response = await client.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            content=body,
        )
        response_content = upstream_response.content

        # Scan non-streaming response for sensitive data
        if upstream_response.status_code == 200 and response_content:
            response_content, scan_result = output_scanner.scan_non_streaming_response(
                response_content,
                context=output_scan_context,
            )
            if scan_result.entities_found > 0:
                logger.info(
                    "Output scan redacted %d entities in non-streaming response",
                    scan_result.entities_redacted,
                )

        return Response(
            content=response_content,
            status_code=upstream_response.status_code,
            headers=dict(upstream_response.headers),
            media_type=upstream_response.headers.get("content-type"),
        )
