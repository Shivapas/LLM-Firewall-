"""SP-333: Canary CRITICAL threat event emitter for TrustDetect.

Emits CRITICAL severity threat events to the TrustDetect Kafka topic
(``sphinx.trustdetect.canary``) when canary token leakage is detected.

Events include OWASP LLM07-2025 (Sensitive Information Disclosure) tag
and extraction_confidence=1.0 (deterministic detection).

SP-333 acceptance criteria:
  - CRITICAL event visible in TrustDetect within 100ms of detection
  - OWASP tag LLM07-2025 present in event
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("sphinx.canary.threat_event")

_TOPIC = "sphinx.trustdetect.canary"


@dataclass
class CanaryThreatEvent:
    """TrustDetect-compatible CRITICAL threat event for canary leakage.

    Emitted when a session canary token is reproduced in an LLM response,
    indicating system prompt extraction.
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    severity: str = "CRITICAL"
    category: str = "CANARY_LEAKAGE"
    session_id: str = ""
    turn_index: int = 0
    detection_timestamp: float = 0.0
    extraction_confidence: float = 1.0
    owasp_category: str = "LLM07-2025"
    tenant_id: str = ""
    policy_id: str = ""
    token_hash: str = ""  # SHA-256 hash of token (not the token itself)
    match_position: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "category": self.category,
            "session_id": self.session_id,
            "turn_index": self.turn_index,
            "detection_timestamp": self.detection_timestamp,
            "extraction_confidence": self.extraction_confidence,
            "owasp_category": self.owasp_category,
            "tenant_id": self.tenant_id,
            "policy_id": self.policy_id,
            "token_hash": self.token_hash,
            "match_position": self.match_position,
        }


class CanaryThreatEventEmitter:
    """Async emitter for canary leakage CRITICAL events to TrustDetect Kafka."""

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
        """Initialize the Kafka producer for canary threat events."""
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
                "Canary threat event producer connected: topic=%s servers=%s",
                self._topic,
                self._bootstrap_servers,
            )
        except Exception:
            logger.warning(
                "Canary Kafka producer unavailable at %s — using fallback queue",
                self._bootstrap_servers,
                exc_info=True,
            )
            self._initialized = False

    async def emit(self, event: CanaryThreatEvent) -> bool:
        """Emit a CRITICAL canary leakage event to TrustDetect.

        SP-333: event appears in stream within 100ms of detection.
        Returns True if sent to Kafka, False if queued locally.
        """
        event_dict = event.to_dict()

        if self._producer and self._initialized:
            try:
                await self._producer.send_and_wait(
                    self._topic,
                    value=event_dict,
                    key=event.session_id.encode("utf-8") if event.session_id else None,
                )
                self._emitted_count += 1
                logger.warning(
                    "CRITICAL canary leakage event emitted: id=%s session=%s "
                    "owasp=%s confidence=%.1f",
                    event.event_id,
                    event.session_id,
                    event.owasp_category,
                    event.extraction_confidence,
                )
                return True
            except Exception:
                logger.warning(
                    "Failed to emit canary threat event to Kafka, queuing",
                    exc_info=True,
                )

        # Fallback: local queue
        try:
            self._fallback_queue.put_nowait(event_dict)
        except asyncio.QueueFull:
            logger.error(
                "Canary threat event fallback queue full, dropping event %s",
                event.event_id,
            )
            return False
        return False

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
                logger.warning("Error closing canary Kafka producer", exc_info=True)
            self._producer = None
            self._initialized = False


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_emitter: Optional[CanaryThreatEventEmitter] = None


def get_canary_threat_emitter(
    kafka_bootstrap_servers: str = "localhost:9092",
) -> CanaryThreatEventEmitter:
    """Get or create the singleton canary threat event emitter."""
    global _emitter
    if _emitter is None:
        _emitter = CanaryThreatEventEmitter(
            kafka_bootstrap_servers=kafka_bootstrap_servers,
        )
    return _emitter


def reset_canary_threat_emitter() -> None:
    """Reset the singleton (for testing)."""
    global _emitter
    _emitter = None
