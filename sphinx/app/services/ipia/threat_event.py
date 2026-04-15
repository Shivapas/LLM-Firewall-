"""SP-322: IPIA Threat Event emitter for TrustDetect Kafka topic.

Publishes IPIA threat events to a dedicated Kafka topic
(``sphinx.trustdetect.ipia``) with UCDM-compliant schema.

Events are emitted within 200ms of detection.  Falls back to an
in-memory queue if Kafka is unavailable.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Optional

from app.services.ipia.detector import IPIAThreatEvent

logger = logging.getLogger("sphinx.ipia.threat_event")

_TOPIC = "sphinx.trustdetect.ipia"


class IPIAThreatEventEmitter:
    """Async emitter that publishes IPIA threat events to TrustDetect Kafka."""

    def __init__(
        self,
        kafka_bootstrap_servers: str = "localhost:9092",
        topic: str = _TOPIC,
    ) -> None:
        self._bootstrap_servers = kafka_bootstrap_servers
        self._topic = topic
        self._producer = None
        self._initialized = False
        self._fallback_queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=5000)
        self._emitted_count = 0

    async def initialize(self) -> None:
        """Initialize the Kafka producer for IPIA threat events."""
        try:
            from aiokafka import AIOKafkaProducer

            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                acks="all",
                retry_backoff_ms=50,
                linger_ms=5,
            )
            await self._producer.start()
            self._initialized = True
            logger.info(
                "IPIA threat event producer connected: topic=%s servers=%s",
                self._topic,
                self._bootstrap_servers,
            )
        except Exception:
            logger.warning(
                "IPIA Kafka producer unavailable at %s — using fallback queue",
                self._bootstrap_servers,
                exc_info=True,
            )
            self._initialized = False

    async def emit(self, event: IPIAThreatEvent) -> bool:
        """Emit an IPIA threat event to the TrustDetect Kafka topic.

        Returns True if sent to Kafka, False if queued locally.
        SP-322 acceptance: event appears in stream within 200ms of detection.
        """
        event_dict = event.to_dict()

        if self._producer and self._initialized:
            try:
                await self._producer.send_and_wait(
                    self._topic,
                    value=event_dict,
                    key=event.chunk_hash.encode("utf-8") if event.chunk_hash else None,
                )
                self._emitted_count += 1
                logger.debug(
                    "IPIA threat event emitted: id=%s chunk=%s severity=%s",
                    event.event_id,
                    event.chunk_hash,
                    event.severity,
                )
                return True
            except Exception:
                logger.warning(
                    "Failed to emit IPIA threat event to Kafka, queuing",
                    exc_info=True,
                )

        # Fallback: local queue
        try:
            self._fallback_queue.put_nowait(event_dict)
        except asyncio.QueueFull:
            logger.error(
                "IPIA threat event fallback queue full, dropping event %s",
                event.event_id,
            )
            return False
        return False

    async def emit_batch(self, events: list[IPIAThreatEvent]) -> int:
        """Emit multiple threat events. Returns count of successfully sent."""
        sent = 0
        for event in events:
            if await self.emit(event):
                sent += 1
        return sent

    @property
    def emitted_count(self) -> int:
        return self._emitted_count

    @property
    def fallback_queue_size(self) -> int:
        return self._fallback_queue.qsize()

    async def close(self) -> None:
        """Shut down the Kafka producer."""
        if self._producer:
            try:
                await self._producer.stop()
            except Exception:
                logger.warning("Error closing IPIA Kafka producer", exc_info=True)
            self._producer = None
            self._initialized = False


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_emitter: Optional[IPIAThreatEventEmitter] = None


def get_ipia_threat_emitter(
    kafka_bootstrap_servers: str = "localhost:9092",
) -> IPIAThreatEventEmitter:
    """Get or create the singleton IPIA threat event emitter."""
    global _emitter
    if _emitter is None:
        _emitter = IPIAThreatEventEmitter(
            kafka_bootstrap_servers=kafka_bootstrap_servers,
        )
    return _emitter


def reset_ipia_threat_emitter() -> None:
    """Reset the singleton (for testing)."""
    global _emitter
    _emitter = None
