import asyncio
import json
import logging
from typing import Optional
from urllib.parse import urlparse

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
_http_client_lock = asyncio.Lock()

# Headers that must NOT be forwarded to upstream providers
_STRIP_REQUEST_HEADERS = {
    "host", "content-length", "cookie", "set-cookie",
    "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host",
    "x-real-ip", "cf-connecting-ip", "true-client-ip",
}

# Headers that must NOT be forwarded from upstream responses
_STRIP_RESPONSE_HEADERS = {
    "transfer-encoding", "content-encoding", "content-length",
    "connection", "keep-alive",
}


def _validate_upstream_url(url: str) -> bool:
    """Validate that the upstream URL is allowed (SSRF protection)."""
    settings = get_settings()
    allowed_hosts_str = settings.allowed_provider_hosts

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Block private/internal network ranges
    if hostname in ("", "localhost", "127.0.0.1", "0.0.0.0"):
        if not settings.default_provider_url.startswith(f"{parsed.scheme}://{hostname}"):
            return False
    if hostname.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                            "172.20.", "172.21.", "172.22.", "172.23.",
                            "172.24.", "172.25.", "172.26.", "172.27.",
                            "172.28.", "172.29.", "172.30.", "172.31.",
                            "192.168.", "169.254.")):
        return False

    # If an explicit allowlist is configured, enforce it
    if allowed_hosts_str:
        allowed_hosts = {h.strip().lower() for h in allowed_hosts_str.split(",") if h.strip()}
        if hostname.lower() not in allowed_hosts:
            logger.warning("SSRF blocked: host %s not in allowlist", hostname)
            return False

    return True


async def get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is not None:
        return _http_client
    async with _http_client_lock:
        if _http_client is None:
            _http_client = httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0))
    return _http_client


async def close_http_client() -> None:
    global _http_client
    async with _http_client_lock:
        if _http_client is not None:
            await _http_client.aclose()
            _http_client = None


def _filter_request_headers(headers: dict, provider_api_key: str | None = None) -> dict:
    """Filter request headers, removing sensitive ones before forwarding to upstream."""
    filtered = {}
    for key, value in headers.items():
        if key.lower() not in _STRIP_REQUEST_HEADERS:
            filtered[key] = value

    if provider_api_key:
        filtered["authorization"] = f"Bearer {provider_api_key}"

    return filtered


def _filter_response_headers(headers: dict) -> dict:
    """Filter response headers from upstream before forwarding to client."""
    return {
        k: v for k, v in headers.items()
        if k.lower() not in _STRIP_RESPONSE_HEADERS
    }


async def proxy_request(
    request: Request,
    target_url: str,
    provider_api_key: str | None = None,
    output_scan_context: OutputScanContext | None = None,
    body_override: bytes | None = None,
) -> Response:
    """Proxy an incoming request to the target LLM provider endpoint.

    Args:
        request: The incoming FastAPI request.
        target_url: Target LLM provider URL.
        provider_api_key: Optional provider API key override.
        output_scan_context: Optional context for output scanning.
        body_override: Optional pre-modified body to use instead of reading from request.
    """
    settings = get_settings()
    url = target_url or settings.default_provider_url

    # Build the upstream path
    path = request.url.path
    if path.startswith("/v1"):
        upstream_url = f"{url}{path}"
    else:
        upstream_url = f"{url}/v1{path}"

    # SSRF protection: validate upstream URL
    if not _validate_upstream_url(upstream_url):
        logger.error("SSRF protection blocked request to %s", upstream_url)
        return Response(
            content=json.dumps({"error": "Upstream URL not allowed"}).encode(),
            status_code=403,
            media_type="application/json",
        )

    # Filter headers — strip sensitive ones before forwarding
    headers = _filter_request_headers(dict(request.headers), provider_api_key)

    body = body_override if body_override is not None else await request.body()
    client = await get_http_client()

    # Check if streaming is requested
    is_streaming = False
    if body:
        try:
            payload = json.loads(body)
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
            headers=_filter_response_headers(dict(upstream_response.headers)),
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
            headers=_filter_response_headers(dict(upstream_response.headers)),
            media_type=upstream_response.headers.get("content-type"),
        )
