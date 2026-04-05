"""Tests for the audit event writer and consumer."""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.services.audit import (
    AuditEvent,
    AuditEventWriter,
    compute_request_hash,
    emit_audit_event,
)


class TestAuditEvent:
    def test_event_creation(self):
        event = AuditEvent(
            tenant_id="t1",
            project_id="p1",
            api_key_id="k1",
            model="gpt-4",
            provider="openai",
            action="allowed",
            status_code=200,
        )
        assert event.event_id  # auto-generated
        assert event.timestamp > 0
        assert event.tenant_id == "t1"
        assert event.model == "gpt-4"

    def test_event_serialization(self):
        event = AuditEvent(
            tenant_id="t1",
            model="gpt-4",
            action="blocked",
            metadata={"reason": "kill-switch"},
        )
        data = event.model_dump()
        assert data["tenant_id"] == "t1"
        assert data["action"] == "blocked"
        assert data["metadata"]["reason"] == "kill-switch"


class TestRequestHash:
    def test_deterministic(self):
        body = b'{"model": "gpt-4", "messages": []}'
        h1 = compute_request_hash(body, "key1", 1000.0)
        h2 = compute_request_hash(body, "key1", 1000.0)
        assert h1 == h2

    def test_different_keys(self):
        body = b'{"model": "gpt-4"}'
        h1 = compute_request_hash(body, "key1", 1000.0)
        h2 = compute_request_hash(body, "key2", 1000.0)
        assert h1 != h2

    def test_different_timestamps(self):
        body = b'{"model": "gpt-4"}'
        h1 = compute_request_hash(body, "key1", 1000.0)
        h2 = compute_request_hash(body, "key1", 2000.0)
        assert h1 != h2


class TestAuditEventWriter:
    @pytest.mark.asyncio
    async def test_fallback_queue_when_kafka_unavailable(self):
        writer = AuditEventWriter(kafka_bootstrap_servers="invalid:9999")
        # Don't initialize Kafka (it would fail)
        event = AuditEvent(
            tenant_id="t1", model="gpt-4", action="allowed",
            request_hash="abc123",
        )
        result = await writer.write_event(event)
        assert result is False  # Queued, not sent to Kafka
        assert writer.fallback_queue_size() == 1

    @pytest.mark.asyncio
    async def test_flush_fallback_queue(self):
        writer = AuditEventWriter()
        e1 = AuditEvent(tenant_id="t1", model="gpt-4", action="allowed")
        e2 = AuditEvent(tenant_id="t2", model="claude-3", action="blocked")
        await writer.write_event(e1)
        await writer.write_event(e2)

        events = await writer.flush_fallback_queue()
        assert len(events) == 2
        assert writer.fallback_queue_size() == 0

    @pytest.mark.asyncio
    async def test_close_without_init(self):
        writer = AuditEventWriter()
        await writer.close()  # Should not raise


@pytest.mark.asyncio
async def test_emit_audit_event():
    """Test the convenience emit function."""
    with patch("app.services.audit.get_audit_writer") as mock_get:
        mock_writer = AsyncMock()
        mock_writer.write_event = AsyncMock(return_value=True)
        mock_get.return_value = mock_writer

        event = await emit_audit_event(
            request_body=b'{"model":"gpt-4"}',
            tenant_id="t1",
            api_key_id="k1",
            model="gpt-4",
            provider="openai",
            action="allowed",
            status_code=200,
        )

        assert event.tenant_id == "t1"
        assert event.model == "gpt-4"
        assert event.request_hash  # auto-computed
        mock_writer.write_event.assert_called_once()
