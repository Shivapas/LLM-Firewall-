"""Async audit event writer (Kafka producer) and Postgres consumer."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("sphinx.audit")


class AuditEvent(BaseModel):
    """Schema for audit events written to Kafka."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    request_hash: str = ""
    tenant_id: str = ""
    project_id: str = ""
    api_key_id: str = ""
    model: str = ""
    provider: str = ""
    action: str = ""  # allowed, blocked, rerouted, rate_limited
    policy_version: str = ""
    status_code: int = 0
    latency_ms: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    metadata: dict = Field(default_factory=dict)


def compute_request_hash(body: bytes, api_key_id: str, timestamp: float) -> str:
    """Compute a deterministic hash for request deduplication."""
    data = f"{api_key_id}:{timestamp}:{hashlib.sha256(body).hexdigest()}"
    return hashlib.sha256(data.encode()).hexdigest()[:32]


class AuditEventWriter:
    """Async audit event writer that publishes to Kafka.

    Falls back to in-memory queue if Kafka is unavailable.
    """

    def __init__(self, kafka_bootstrap_servers: str = "localhost:9092", topic: str = "sphinx.audit.events"):
        self._bootstrap_servers = kafka_bootstrap_servers
        self._topic = topic
        self._producer = None
        self._fallback_queue: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=10000)
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the Kafka producer."""
        try:
            from aiokafka import AIOKafkaProducer
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                acks="all",
                retry_backoff_ms=100,
                max_batch_size=16384,
                linger_ms=10,
            )
            await self._producer.start()
            self._initialized = True
            logger.info("Kafka audit producer connected to %s", self._bootstrap_servers)
        except Exception:
            logger.warning(
                "Kafka unavailable at %s, using in-memory fallback queue",
                self._bootstrap_servers,
                exc_info=True,
            )
            self._initialized = False

    async def write_event(self, event: AuditEvent) -> bool:
        """Write an audit event asynchronously.

        Returns True if successfully sent to Kafka, False if queued in fallback.
        """
        event_dict = event.model_dump()

        if self._producer and self._initialized:
            try:
                await self._producer.send_and_wait(
                    self._topic,
                    value=event_dict,
                    key=event.request_hash.encode("utf-8") if event.request_hash else None,
                )
                logger.debug("Audit event %s sent to Kafka", event.event_id)
                return True
            except Exception:
                logger.warning("Failed to send audit event to Kafka, queuing locally", exc_info=True)

        # Fallback: queue in-memory
        try:
            self._fallback_queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.error("Audit fallback queue full, dropping event %s", event.event_id)
            return False
        return False

    async def flush_fallback_queue(self) -> list[AuditEvent]:
        """Drain the fallback queue and return events for manual processing."""
        events = []
        while not self._fallback_queue.empty():
            try:
                events.append(self._fallback_queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return events

    def fallback_queue_size(self) -> int:
        return self._fallback_queue.qsize()

    async def close(self) -> None:
        """Shut down the Kafka producer."""
        if self._producer:
            try:
                await self._producer.stop()
            except Exception:
                logger.warning("Error closing Kafka producer", exc_info=True)
            self._producer = None
            self._initialized = False


class AuditEventConsumer:
    """Kafka consumer that writes audit events to Postgres.

    Performs idempotent inserts using request_hash as dedup key.
    """

    def __init__(
        self,
        kafka_bootstrap_servers: str = "localhost:9092",
        topic: str = "sphinx.audit.events",
        group_id: str = "sphinx-audit-consumer",
    ):
        self._bootstrap_servers = kafka_bootstrap_servers
        self._topic = topic
        self._group_id = group_id
        self._consumer = None
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self, session_factory) -> None:
        """Start consuming audit events from Kafka."""
        try:
            from aiokafka import AIOKafkaConsumer
            self._consumer = AIOKafkaConsumer(
                self._topic,
                bootstrap_servers=self._bootstrap_servers,
                group_id=self._group_id,
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                auto_offset_reset="earliest",
                enable_auto_commit=True,
            )
            await self._consumer.start()
            self._running = True
            self._task = asyncio.create_task(self._consume_loop(session_factory))
            logger.info("Audit consumer started on topic=%s", self._topic)
        except Exception:
            logger.warning("Failed to start Kafka audit consumer", exc_info=True)

    async def _consume_loop(self, session_factory) -> None:
        """Main consumption loop: reads events and persists to Postgres."""
        from app.models.api_key import AuditLog
        from sqlalchemy import select

        while self._running:
            try:
                msg_batch = await self._consumer.getmany(timeout_ms=1000, max_records=100)
                for tp, messages in msg_batch.items():
                    for msg in messages:
                        event_data = msg.value
                        await self._persist_event(session_factory, event_data)
            except Exception:
                if self._running:
                    logger.exception("Error in audit consumer loop")
                    await asyncio.sleep(1)

    async def _persist_event(self, session_factory, event_data: dict) -> None:
        """Idempotent insert of an audit event into Postgres."""
        from app.models.api_key import AuditLog
        from sqlalchemy import select

        request_hash = event_data.get("request_hash", "")

        async with session_factory() as db:
            # Dedup check by request_hash
            if request_hash:
                existing = await db.execute(
                    select(AuditLog).where(AuditLog.request_hash == request_hash)
                )
                if existing.scalar_one_or_none() is not None:
                    logger.debug("Duplicate audit event skipped: hash=%s", request_hash)
                    return

            record = AuditLog(
                id=uuid.UUID(event_data.get("event_id", str(uuid.uuid4()))),
                request_hash=request_hash,
                tenant_id=event_data.get("tenant_id", ""),
                project_id=event_data.get("project_id", ""),
                api_key_id=event_data.get("api_key_id", ""),
                model=event_data.get("model", ""),
                provider=event_data.get("provider", ""),
                action=event_data.get("action", ""),
                policy_version=event_data.get("policy_version", ""),
                status_code=event_data.get("status_code", 0),
                latency_ms=event_data.get("latency_ms", 0.0),
                prompt_tokens=event_data.get("prompt_tokens", 0),
                completion_tokens=event_data.get("completion_tokens", 0),
                metadata_json=json.dumps(event_data.get("metadata", {})),
                event_timestamp=event_data.get("timestamp", time.time()),
            )
            db.add(record)
            await db.commit()
            logger.debug("Audit event persisted: hash=%s", request_hash)

    async def stop(self) -> None:
        """Stop the consumer."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._consumer:
            try:
                await self._consumer.stop()
            except Exception:
                logger.warning("Error stopping Kafka consumer", exc_info=True)


# Module-level singleton instances
_audit_writer: Optional[AuditEventWriter] = None
_audit_consumer: Optional[AuditEventConsumer] = None


def get_audit_writer() -> AuditEventWriter:
    global _audit_writer
    if _audit_writer is None:
        _audit_writer = AuditEventWriter()
    return _audit_writer


def get_audit_consumer() -> AuditEventConsumer:
    global _audit_consumer
    if _audit_consumer is None:
        _audit_consumer = AuditEventConsumer()
    return _audit_consumer


async def emit_audit_event(
    request_body: bytes,
    tenant_id: str = "",
    project_id: str = "",
    api_key_id: str = "",
    model: str = "",
    provider: str = "",
    action: str = "allowed",
    policy_version: str = "",
    status_code: int = 200,
    latency_ms: float = 0.0,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    metadata: Optional[dict] = None,
) -> AuditEvent:
    """Convenience function to emit an audit event."""
    ts = time.time()
    event = AuditEvent(
        timestamp=ts,
        request_hash=compute_request_hash(request_body, api_key_id, ts),
        tenant_id=tenant_id,
        project_id=project_id,
        api_key_id=api_key_id,
        model=model,
        provider=provider,
        action=action,
        policy_version=policy_version,
        status_code=status_code,
        latency_ms=latency_ms,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        metadata=metadata or {},
    )

    writer = get_audit_writer()
    await writer.write_event(event)
    return event
