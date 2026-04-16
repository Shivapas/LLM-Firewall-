"""SP-352: Supply chain swap HIGH threat event emitter for TrustDetect.

Publishes HIGH severity threat events to the TrustDetect Kafka topic
(``sphinx.trustdetect.supply_chain``) when a model swap is detected
by the SupplyChainMonitor.

Events include:
  - model_id, baseline_version, deviation_scores[], feature_delta,
    consecutive_count
  - All required fields per TrustDetect UCDM schema

SP-352 acceptance criteria:
  - TrustDetect receives HIGH event with feature_delta within 200ms
    of 5th consecutive breach
  - All required fields present in the event
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from app.services.fingerprint.supply_chain_monitor import SupplyChainAlert

logger = logging.getLogger("sphinx.fingerprint.threat_event")

_TOPIC = "sphinx.trustdetect.supply_chain"


@dataclass
class SupplyChainThreatEvent:
    """TrustDetect-compatible HIGH threat event for supply chain swap detection.

    Emitted when N consecutive LLM responses deviate beyond the configured
    threshold, indicating a potential model substitution.
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    severity: str = "HIGH"
    category: str = "SUPPLY_CHAIN_SWAP"
    model_id: str = ""
    baseline_version: str = ""
    deviation_scores: list[float] = field(default_factory=list)
    feature_delta: dict[str, float] = field(default_factory=dict)
    consecutive_count: int = 0
    alignment_status: str = "SWAPPED"
    owasp_category: str = "LLM03-2025"  # Supply Chain Vulnerabilities

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "category": self.category,
            "model_id": self.model_id,
            "baseline_version": self.baseline_version,
            "deviation_scores": self.deviation_scores,
            "feature_delta": self.feature_delta,
            "consecutive_count": self.consecutive_count,
            "alignment_status": self.alignment_status,
            "owasp_category": self.owasp_category,
        }

    @classmethod
    def from_alert(cls, alert: SupplyChainAlert) -> "SupplyChainThreatEvent":
        """Create a threat event from a SupplyChainAlert."""
        return cls(
            timestamp=alert.timestamp,
            severity=alert.severity,
            category=alert.category,
            model_id=alert.model_id,
            baseline_version=alert.baseline_version,
            deviation_scores=list(alert.deviation_scores),
            feature_delta=dict(alert.feature_delta),
            consecutive_count=alert.consecutive_count,
            alignment_status=alert.alignment_status,
        )


class SupplyChainThreatEventEmitter:
    """Async emitter for supply chain swap HIGH events to TrustDetect Kafka."""

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
        """Initialize the Kafka producer for supply chain threat events."""
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
                "Supply chain threat event producer connected: topic=%s servers=%s",
                self._topic,
                self._bootstrap_servers,
            )
        except Exception:
            logger.warning(
                "Supply chain Kafka producer unavailable at %s — using fallback queue",
                self._bootstrap_servers,
                exc_info=True,
            )
            self._initialized = False

    async def emit(self, event: SupplyChainThreatEvent) -> bool:
        """Emit a HIGH supply chain swap event to TrustDetect.

        SP-352: event appears in stream within 200ms of detection.
        Returns True if sent to Kafka, False if queued locally.
        """
        event_dict = event.to_dict()

        if self._producer and self._initialized:
            try:
                await self._producer.send_and_wait(
                    self._topic,
                    value=event_dict,
                    key=event.model_id.encode("utf-8") if event.model_id else None,
                )
                self._emitted_count += 1
                logger.warning(
                    "HIGH supply chain threat event emitted: id=%s model=%s "
                    "consecutive=%d owasp=%s",
                    event.event_id,
                    event.model_id,
                    event.consecutive_count,
                    event.owasp_category,
                )
                return True
            except Exception:
                logger.warning(
                    "Failed to emit supply chain threat event to Kafka, queuing",
                    exc_info=True,
                )

        # Fallback: local queue
        try:
            self._fallback_queue.put_nowait(event_dict)
        except asyncio.QueueFull:
            logger.error(
                "Supply chain threat event fallback queue full, dropping event %s",
                event.event_id,
            )
            return False
        return False

    async def emit_from_alert(self, alert: SupplyChainAlert) -> bool:
        """Create a threat event from a SupplyChainAlert and emit it."""
        event = SupplyChainThreatEvent.from_alert(alert)
        return await self.emit(event)

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
                logger.warning("Error closing supply chain Kafka producer", exc_info=True)
            self._producer = None
            self._initialized = False


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_emitter: Optional[SupplyChainThreatEventEmitter] = None


def get_supply_chain_threat_emitter(
    kafka_bootstrap_servers: str = "localhost:9092",
) -> SupplyChainThreatEventEmitter:
    """Get or create the singleton supply chain threat event emitter."""
    global _emitter
    if _emitter is None:
        _emitter = SupplyChainThreatEventEmitter(
            kafka_bootstrap_servers=kafka_bootstrap_servers,
        )
    return _emitter


def reset_supply_chain_threat_emitter() -> None:
    """Reset the singleton (for testing)."""
    global _emitter
    _emitter = None
