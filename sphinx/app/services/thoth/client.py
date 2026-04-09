"""Thoth API client — async REST client with auth, timeout enforcement, and retry logic.

Sprint 1 / S1-T1: Establishes Thoth API connectivity from the Sphinx intercept pipeline.

Key behaviours:
- Authenticates via Bearer API key (mTLS upgrade planned in Sprint 8).
- Enforces per-request timeout (default 150 ms, configurable via settings).
- Retries transient errors with short exponential back-off.
- On TimeoutException: raises immediately (no retry) so the caller can log
  FR-PRE-06 timeout event and fall back to structural-only enforcement.
- Singleton instance managed by initialize/close helpers for lifecycle control.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

import httpx

from app.services.thoth.models import (
    ClassificationRequest,
    ClassificationContext,
    make_timeout_context,
    make_unavailable_context,
)

logger = logging.getLogger("sphinx.thoth.client")

_client: Optional["ThothClient"] = None

# Classification endpoint path on the Thoth API
_CLASSIFY_PATH = "/v1/classify"


class ThothClient:
    """Async HTTP client for the Thoth Semantic Classification API.

    Args:
        api_url:     Base URL of the Thoth API (e.g. ``https://thoth.internal``).
        api_key:     Bearer token for authentication.
        timeout_ms:  Per-request read timeout in milliseconds (default 150).
        max_retries: Number of additional attempts on transient errors (not timeouts).
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        timeout_ms: int = 150,
        max_retries: int = 1,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._timeout_s = timeout_ms / 1000.0
        self._max_retries = max_retries

        self._http = httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Sphinx-Client": "sphinx-firewall/1.0",
            },
            timeout=httpx.Timeout(
                connect=2.0,
                read=self._timeout_s,
                write=2.0,
                pool=5.0,
            ),
        )
        logger.info(
            "ThothClient initialised: url=%s timeout_ms=%d max_retries=%d",
            self._api_url,
            timeout_ms,
            max_retries,
        )

    async def classify(self, request: ClassificationRequest) -> ClassificationContext:
        """Call Thoth classification API synchronously (from caller's perspective).

        Raises:
            httpx.TimeoutException: if the request exceeds the configured timeout.
            httpx.HTTPStatusError: on 4xx/5xx responses after all retries exhausted.
            Exception: on other transport errors after all retries exhausted.
        """
        payload = request.to_dict()
        url = self._api_url + _CLASSIFY_PATH

        last_exc: Exception = RuntimeError("Thoth classify: no attempts made")

        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                # Short back-off: 50 ms, 100 ms, …
                await asyncio.sleep(0.05 * (2 ** (attempt - 1)))

            try:
                t0 = time.monotonic()
                resp = await self._http.post(url, json=payload)
                resp.raise_for_status()
                elapsed_ms = int((time.monotonic() - t0) * 1000)

                data = resp.json()
                cls = data["classification"]

                return ClassificationContext(
                    request_id=data.get("request_id", request.request_id),
                    intent=cls.get("intent", "unknown"),
                    risk_level=cls.get("risk_level", "UNKNOWN"),
                    confidence=float(cls.get("confidence", 0.0)),
                    pii_detected=bool(cls.get("pii_detected", False)),
                    pii_types=cls.get("pii_types", []),
                    recommended_action=cls.get("recommended_action", "ALLOW"),
                    classification_model_version=cls.get("classification_model_version", "unknown"),
                    latency_ms=data.get("latency_ms", elapsed_ms),
                    source="thoth",
                )

            except httpx.TimeoutException as exc:
                # Do NOT retry on timeout — preserve latency budget for caller
                logger.warning(
                    "Thoth classification TIMEOUT request_id=%s url=%s",
                    request.request_id,
                    url,
                )
                raise exc

            except httpx.HTTPStatusError as exc:
                last_exc = exc
                logger.warning(
                    "Thoth HTTP error attempt=%d/%d status=%d request_id=%s",
                    attempt + 1,
                    self._max_retries + 1,
                    exc.response.status_code,
                    request.request_id,
                )

            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "Thoth transport error attempt=%d/%d error=%s request_id=%s",
                    attempt + 1,
                    self._max_retries + 1,
                    exc,
                    request.request_id,
                )

        raise last_exc

    async def health_check(self) -> bool:
        """Lightweight liveness probe against the Thoth API."""
        try:
            resp = await self._http.get(
                self._api_url + "/health",
                timeout=httpx.Timeout(connect=1.0, read=2.0, write=1.0, pool=2.0),
            )
            return resp.status_code < 500
        except Exception:
            return False

    async def close(self) -> None:
        """Gracefully close the underlying HTTP connection pool."""
        await self._http.aclose()
        logger.info("ThothClient closed")


# ---------------------------------------------------------------------------
# Singleton lifecycle helpers
# ---------------------------------------------------------------------------

def get_thoth_client() -> Optional[ThothClient]:
    """Return the singleton ThothClient, or None if not initialised."""
    return _client


def initialize_thoth_client(
    api_url: str,
    api_key: str,
    timeout_ms: int = 150,
    max_retries: int = 1,
) -> ThothClient:
    """Create and register the singleton ThothClient.

    Called once during application lifespan startup when ``thoth_enabled=True``.
    """
    global _client
    _client = ThothClient(
        api_url=api_url,
        api_key=api_key,
        timeout_ms=timeout_ms,
        max_retries=max_retries,
    )
    return _client


async def close_thoth_client() -> None:
    """Close and deregister the singleton ThothClient."""
    global _client
    if _client is not None:
        await _client.close()
        _client = None
