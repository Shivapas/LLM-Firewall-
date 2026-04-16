"""Sprint 35 — SP-352: Supply Chain Threat Event Emitter Test Suite.

Tests for HIGH severity threat event emission:
  - SupplyChainThreatEvent contains all required fields
  - Event created from SupplyChainAlert correctly
  - Emitter uses fallback queue when Kafka unavailable
  - Event dict matches TrustDetect UCDM schema
"""

import asyncio
import time

import pytest

from app.services.fingerprint.supply_chain_monitor import SupplyChainAlert
from app.services.fingerprint.threat_event import (
    SupplyChainThreatEvent,
    SupplyChainThreatEventEmitter,
    reset_supply_chain_threat_emitter,
)


@pytest.fixture
def emitter():
    reset_supply_chain_threat_emitter()
    e = SupplyChainThreatEventEmitter(
        kafka_bootstrap_servers="localhost:19092",  # Non-existent
        topic="test.supply_chain",
    )
    yield e
    reset_supply_chain_threat_emitter()


@pytest.fixture
def sample_alert():
    return SupplyChainAlert(
        alert_id="test-alert-001",
        timestamp=time.time(),
        severity="HIGH",
        category="SUPPLY_CHAIN_SWAP",
        model_id="gpt-4-staging",
        baseline_version="abc12345",
        deviation_scores=[3.1, 3.2, 3.0, 2.9, 3.3],
        feature_delta={"token_entropy": 4.5, "punctuation_density": 3.2},
        consecutive_count=5,
        alignment_status="SWAPPED",
    )


class TestSP352ThreatEventSchema:
    """Threat event contains all required TrustDetect fields."""

    def test_event_has_all_required_fields(self):
        event = SupplyChainThreatEvent(
            model_id="test-model",
            baseline_version="v1",
            deviation_scores=[3.0, 3.1],
            feature_delta={"f0": 3.0},
            consecutive_count=5,
        )
        d = event.to_dict()
        required_fields = [
            "event_id",
            "timestamp",
            "severity",
            "category",
            "model_id",
            "baseline_version",
            "deviation_scores",
            "feature_delta",
            "consecutive_count",
            "alignment_status",
            "owasp_category",
        ]
        for field in required_fields:
            assert field in d, f"Missing required field: {field}"

    def test_severity_is_high(self):
        event = SupplyChainThreatEvent()
        assert event.severity == "HIGH"

    def test_owasp_category_is_llm03(self):
        event = SupplyChainThreatEvent()
        assert event.owasp_category == "LLM03-2025"

    def test_category_is_supply_chain_swap(self):
        event = SupplyChainThreatEvent()
        assert event.category == "SUPPLY_CHAIN_SWAP"

    def test_event_id_is_unique(self):
        e1 = SupplyChainThreatEvent()
        e2 = SupplyChainThreatEvent()
        assert e1.event_id != e2.event_id


class TestSP352FromAlert:
    """Event creation from SupplyChainAlert."""

    def test_from_alert_copies_all_fields(self, sample_alert):
        event = SupplyChainThreatEvent.from_alert(sample_alert)
        assert event.model_id == "gpt-4-staging"
        assert event.baseline_version == "abc12345"
        assert event.deviation_scores == [3.1, 3.2, 3.0, 2.9, 3.3]
        assert event.consecutive_count == 5
        assert event.alignment_status == "SWAPPED"
        assert event.severity == "HIGH"

    def test_from_alert_preserves_feature_delta(self, sample_alert):
        event = SupplyChainThreatEvent.from_alert(sample_alert)
        assert event.feature_delta == {"token_entropy": 4.5, "punctuation_density": 3.2}


class TestSP352Emitter:
    """Emitter falls back to local queue when Kafka unavailable."""

    @pytest.mark.asyncio
    async def test_emit_uses_fallback_queue(self, emitter):
        event = SupplyChainThreatEvent(
            model_id="test",
            deviation_scores=[3.0],
            consecutive_count=5,
        )
        result = await emitter.emit(event)
        assert result is False  # Kafka not available
        assert emitter.fallback_queue_size == 1

    @pytest.mark.asyncio
    async def test_emit_from_alert(self, emitter, sample_alert):
        result = await emitter.emit_from_alert(sample_alert)
        assert result is False  # Kafka not available
        assert emitter.fallback_queue_size == 1

    @pytest.mark.asyncio
    async def test_emitted_count_starts_zero(self, emitter):
        assert emitter.emitted_count == 0

    @pytest.mark.asyncio
    async def test_close_is_safe(self, emitter):
        await emitter.close()  # Should not raise
