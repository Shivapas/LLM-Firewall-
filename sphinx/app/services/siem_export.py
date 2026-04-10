"""SIEM / data lake export connector — Sprint 4 (S4-T5).

Exports Sphinx audit events — including Thoth classification metadata — to
configurable SIEM / data lake targets via async HTTP.

FR-POST-05: Post-inference classifications SHALL be exportable to SIEM, data
lake, and GRC tool integrations via Sphinx's existing export connectors.

Supported export formats
------------------------
``webhook``     Generic JSON POST.  Compatible with Elasticsearch, Sumo Logic,
                Splunk HTTP Event Collector (JSON mode), custom ingest APIs.
``splunk_hec``  Splunk HTTP Event Collector format with HEC envelope.
``datadog``     Datadog Logs API format with ddsource / ddtags.

Batching & delivery
--------------------
Events are accumulated in a local batch and flushed either when the batch
reaches ``batch_size`` or every ``flush_interval_s`` seconds (background loop).
This ensures sub-5-second delivery for high-risk events when batch_size=1.

Configuration (via Settings / env vars)
-----------------------------------------
SIEM_EXPORT_ENABLED           bool   Enable export (default: False)
SIEM_EXPORT_URL               str    Target endpoint URL
SIEM_EXPORT_API_KEY           str    API key / Bearer token
SIEM_EXPORT_FORMAT            str    webhook | splunk_hec | datadog
SIEM_EXPORT_TIMEOUT_MS        int    Per-request timeout ms (default: 5000)
SIEM_EXPORT_BATCH_SIZE        int    Events per flush (default: 50)
SIEM_EXPORT_FLUSH_INTERVAL_S  float  Background flush interval s (default: 5.0)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Optional

import httpx

from app.services.thoth.models import ClassificationContext

logger = logging.getLogger("sphinx.siem_export")

_siem_exporter: Optional["SIEMExporter"] = None


class SIEMExporter:
    """Async SIEM / data lake export connector.

    Accumulates classification events in a local batch and flushes them to
    the configured target at regular intervals or when the batch is full.
    All I/O is non-blocking (asyncio + httpx).
    """

    def __init__(
        self,
        export_url: str,
        api_key: str,
        export_format: str = "webhook",
        timeout_ms: int = 5000,
        batch_size: int = 50,
        flush_interval_s: float = 5.0,
    ) -> None:
        self._url = export_url
        self._format = export_format.lower()
        self._timeout_s = timeout_ms / 1000.0
        self._batch_size = batch_size
        self._flush_interval_s = flush_interval_s

        # Build auth header for each SIEM format
        if self._format == "splunk_hec":
            auth_header = {"Authorization": f"Splunk {api_key}"}
        elif self._format == "datadog":
            auth_header = {"DD-API-KEY": api_key}
        else:
            auth_header = {"Authorization": f"Bearer {api_key}"}

        self._http = httpx.AsyncClient(
            headers={
                **auth_header,
                "Content-Type": "application/json",
                "X-Sphinx-Exporter": "sphinx-firewall/1.0",
            },
            timeout=httpx.Timeout(
                connect=2.0,
                read=self._timeout_s,
                write=2.0,
                pool=5.0,
            ),
        )

        self._batch: list[dict] = []
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the background flush loop."""
        self._running = True
        self._flush_task = asyncio.create_task(
            self._flush_loop(),
            name="siem_export_flush",
        )
        logger.info(
            "SIEM exporter started: url=%s format=%s batch_size=%d "
            "flush_interval=%.1fs",
            self._url,
            self._format,
            self._batch_size,
            self._flush_interval_s,
        )

    async def stop(self) -> None:
        """Stop the background flush loop and flush any remaining events."""
        self._running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        # Final flush before shutdown
        if self._batch:
            await self._flush_batch()
        await self._http.aclose()
        logger.info("SIEM exporter stopped")

    # ------------------------------------------------------------------
    # S4-T5: Classification event export — public API
    # ------------------------------------------------------------------

    async def export_classification_event(
        self,
        classification_ctx: ClassificationContext,
        *,
        prompt_request_id: str,
        tenant_id: str,
        model_endpoint: str,
        event_type: str = "post_inference",
        additional_metadata: Optional[dict] = None,
    ) -> None:
        """Queue a Thoth classification event for SIEM export (S4-T5).

        FR-POST-05: Post-inference classifications SHALL be exportable to
        SIEM, data lake, and GRC tool integrations via Sphinx's existing
        export connectors.

        Events are batched and flushed at configured intervals. This method
        is non-blocking — it enqueues the event and returns immediately.

        Args:
            classification_ctx:  Thoth classification result for the response.
            prompt_request_id:   Sphinx trace ID for correlation.
            tenant_id:           Hashed tenant identifier.
            model_endpoint:      Target LLM endpoint name.
            event_type:          Classification stage label
                                 (``"post_inference"`` | ``"pre_inference"``).
            additional_metadata: Optional extra fields merged into the payload.
        """
        event = self._build_event_payload(
            classification_ctx,
            prompt_request_id=prompt_request_id,
            tenant_id=tenant_id,
            model_endpoint=model_endpoint,
            event_type=event_type,
            event_timestamp=time.time(),
            additional_metadata=additional_metadata or {},
        )

        # Apply format-specific envelope
        if self._format == "splunk_hec":
            event = self._wrap_splunk_hec(event)
        elif self._format == "datadog":
            event = self._wrap_datadog(event)

        self._batch.append(event)
        logger.debug(
            "SIEM event queued: event_type=%s tenant=%s risk=%s batch_size=%d",
            event_type,
            tenant_id,
            classification_ctx.risk_level,
            len(self._batch),
        )

        # Flush immediately if batch is full
        if len(self._batch) >= self._batch_size:
            await self._flush_batch()

    # ------------------------------------------------------------------
    # Payload builders
    # ------------------------------------------------------------------

    @staticmethod
    def _build_event_payload(
        classification_ctx: ClassificationContext,
        *,
        prompt_request_id: str,
        tenant_id: str,
        model_endpoint: str,
        event_type: str,
        event_timestamp: float,
        additional_metadata: dict,
    ) -> dict:
        """Build the canonical Sphinx classification event payload."""
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": event_timestamp,
            "event_type": event_type,
            "source": "sphinx_ai_firewall",
            "tenant_id": tenant_id,
            "model_endpoint": model_endpoint,
            "prompt_request_id": prompt_request_id,
            "classification": {
                "intent": classification_ctx.intent,
                "risk_level": classification_ctx.risk_level,
                "confidence": classification_ctx.confidence,
                "pii_detected": classification_ctx.pii_detected,
                "pii_types": classification_ctx.pii_types,
                "recommended_action": classification_ctx.recommended_action,
                "model_version": classification_ctx.classification_model_version,
                "latency_ms": classification_ctx.latency_ms,
                "source": classification_ctx.source,
            },
            **additional_metadata,
        }

    @staticmethod
    def _wrap_splunk_hec(event: dict) -> dict:
        """Wrap event in a Splunk HTTP Event Collector envelope."""
        return {
            "time": event.get("timestamp", time.time()),
            "host": "sphinx-firewall",
            "source": "sphinx:thoth_classification",
            "sourcetype": "sphinx:ai_classification",
            "index": "ai_security",
            "event": event,
        }

    @staticmethod
    def _wrap_datadog(event: dict) -> dict:
        """Format event for the Datadog Logs API."""
        cls = event.get("classification", {})
        return {
            "ddsource": "sphinx_ai_firewall",
            "ddtags": (
                f"tenant:{event.get('tenant_id', 'unknown')},"
                f"risk:{cls.get('risk_level', 'UNKNOWN')},"
                f"intent:{cls.get('intent', 'unknown')},"
                f"event_type:{event.get('event_type', 'unknown')}"
            ),
            "hostname": "sphinx-firewall",
            "service": "sphinx",
            "message": json.dumps(event),
        }

    # ------------------------------------------------------------------
    # Flush mechanics
    # ------------------------------------------------------------------

    async def _flush_batch(self) -> bool:
        """Send the accumulated batch to the configured SIEM endpoint.

        Returns ``True`` on success, ``False`` on transport error.
        On failure, events are dropped (not re-queued) to prevent unbounded
        memory growth.  Operators should monitor the SIEM exporter logs for
        repeated failures and configure appropriate alerting.
        """
        if not self._batch:
            return True

        batch_to_send = self._batch[:]
        self._batch = []
        count = len(batch_to_send)

        try:
            if self._format == "splunk_hec":
                # Splunk HEC requires newline-delimited JSON
                body = "\n".join(json.dumps(e) for e in batch_to_send)
                resp = await self._http.post(self._url, content=body.encode("utf-8"))
            else:
                resp = await self._http.post(self._url, json=batch_to_send)

            resp.raise_for_status()
            logger.info(
                "SIEM batch exported: count=%d status=%d format=%s",
                count,
                resp.status_code,
                self._format,
            )
            return True

        except httpx.TimeoutException:
            logger.warning(
                "SIEM export TIMEOUT: %d events dropped url=%s",
                count,
                self._url,
            )
            return False

        except httpx.HTTPStatusError as exc:
            logger.warning(
                "SIEM export HTTP error: status=%d %d events dropped url=%s",
                exc.response.status_code,
                count,
                self._url,
            )
            return False

        except Exception as exc:
            logger.warning(
                "SIEM export error: %s — %d events dropped",
                exc,
                count,
            )
            return False

    async def _flush_loop(self) -> None:
        """Background loop: flush batched events every ``flush_interval_s`` seconds."""
        while self._running:
            try:
                await asyncio.sleep(self._flush_interval_s)
                if self._batch:
                    await self._flush_batch()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.warning("SIEM flush loop error", exc_info=True)


# ---------------------------------------------------------------------------
# Singleton lifecycle helpers
# ---------------------------------------------------------------------------

def get_siem_exporter() -> Optional[SIEMExporter]:
    """Return the singleton SIEMExporter, or None if not initialised."""
    return _siem_exporter


def initialize_siem_exporter(
    export_url: str,
    api_key: str,
    export_format: str = "webhook",
    timeout_ms: int = 5000,
    batch_size: int = 50,
    flush_interval_s: float = 5.0,
) -> SIEMExporter:
    """Create and register the singleton SIEMExporter.

    Called during application lifespan startup when
    ``siem_export_enabled=True``.
    """
    global _siem_exporter
    _siem_exporter = SIEMExporter(
        export_url=export_url,
        api_key=api_key,
        export_format=export_format,
        timeout_ms=timeout_ms,
        batch_size=batch_size,
        flush_interval_s=flush_interval_s,
    )
    return _siem_exporter


async def close_siem_exporter() -> None:
    """Stop and deregister the singleton SIEMExporter."""
    global _siem_exporter
    if _siem_exporter is not None:
        await _siem_exporter.stop()
        _siem_exporter = None
