"""Sprint 26 — Agent Memory Store Firewall: Read Controls + Lifecycle.

Tests cover:
1. ReadAnomalyDetector: cross-agent read detection, stale read detection
2. MemoryLifecycleManager: token cap enforcement, eviction
3. MemoryIntegrityVerifier: hash-chain verification, tamper detection
4. MemoryIsolationEnforcer: cross-agent isolation, permission grants
5. Acceptance criteria validation
"""

from __future__ import annotations

import time
from datetime import datetime, timezone, timedelta

import pytest

# ── Read Anomaly Detection ──────────────────────────────────────────────

from app.services.memory_firewall.read_anomaly import (
    ReadAnomalyDetector,
    MemoryReadRequest,
    MemoryChunkMetadata,
    ReadAnomalyAlert,
    get_read_anomaly_detector,
    reset_read_anomaly_detector,
)


class TestReadAnomalyDetector:
    """Tests for memory read anomaly detection."""

    def setup_method(self):
        self.detector = ReadAnomalyDetector(stale_threshold_days=30)

    def test_register_chunk(self):
        chunk = self.detector.register_chunk(
            content_key="key-1",
            writer_agent_id="agent-A",
            namespace="ns1",
            token_count=100,
            content_hash="abc123",
        )
        assert chunk.content_key == "key-1"
        assert chunk.writer_agent_id == "agent-A"
        assert chunk.namespace == "ns1"
        assert chunk.token_count == 100
        assert self.detector.chunk_count() == 1

    def test_same_agent_read_no_anomaly(self):
        """Same-agent reads should produce no anomalies."""
        self.detector.register_chunk("key-1", writer_agent_id="agent-A")
        req = MemoryReadRequest(reader_agent_id="agent-A", content_key="key-1")
        alerts = self.detector.check_read(req)
        assert len(alerts) == 0
        assert self.detector.get_stats()["clean_reads"] == 1

    def test_cross_agent_read_flagged(self):
        """Reads of content written by a different agent should be flagged."""
        self.detector.register_chunk("key-1", writer_agent_id="agent-A")
        req = MemoryReadRequest(reader_agent_id="agent-B", content_key="key-1")
        alerts = self.detector.check_read(req)
        assert len(alerts) == 1
        assert alerts[0].anomaly_type == "cross_agent_read"
        assert alerts[0].severity == "high"
        assert "agent-B" in alerts[0].details
        assert "agent-A" in alerts[0].details
        assert self.detector.get_stats()["cross_agent_reads"] == 1

    def test_cross_agent_read_permitted(self):
        """Cross-agent reads with explicit permission should NOT be flagged."""
        self.detector.register_chunk("key-1", writer_agent_id="agent-A")
        req = MemoryReadRequest(reader_agent_id="agent-B", content_key="key-1")
        # permitted_cross_agents contains writer IDs that the reader is allowed to access
        alerts = self.detector.check_read(req, permitted_cross_agents={"agent-A"})
        assert len(alerts) == 0

    def test_stale_read_flagged(self):
        """Reads of chunks not accessed in threshold days should be flagged."""
        old_time = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        self.detector.register_chunk("key-old", writer_agent_id="agent-A", token_count=50)
        # Manually set last_accessed_at to old date
        chunk = self.detector.get_chunk("key-old")
        chunk.last_accessed_at = old_time
        chunk.written_at = old_time

        req = MemoryReadRequest(reader_agent_id="agent-A", content_key="key-old")
        alerts = self.detector.check_read(req)
        stale_alerts = [a for a in alerts if a.anomaly_type == "stale_read"]
        assert len(stale_alerts) == 1
        assert stale_alerts[0].days_since_last_access > 30
        assert self.detector.get_stats()["stale_reads"] == 1

    def test_stale_read_updates_last_accessed(self):
        """After a stale read, the chunk's last_accessed_at should be updated."""
        old_time = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        self.detector.register_chunk("key-old", writer_agent_id="agent-A")
        chunk = self.detector.get_chunk("key-old")
        chunk.last_accessed_at = old_time

        req = MemoryReadRequest(reader_agent_id="agent-A", content_key="key-old")
        self.detector.check_read(req)

        # Second read should NOT be stale since last_accessed_at was updated
        alerts = self.detector.check_read(req)
        stale_alerts = [a for a in alerts if a.anomaly_type == "stale_read"]
        assert len(stale_alerts) == 0

    def test_unknown_chunk_no_anomaly(self):
        """Reads of unknown chunks should produce no anomalies."""
        req = MemoryReadRequest(reader_agent_id="agent-A", content_key="unknown-key")
        alerts = self.detector.check_read(req)
        assert len(alerts) == 0

    def test_both_anomalies_cross_agent_and_stale(self):
        """A read can trigger both cross-agent and stale anomalies."""
        old_time = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        self.detector.register_chunk("key-both", writer_agent_id="agent-A")
        chunk = self.detector.get_chunk("key-both")
        chunk.last_accessed_at = old_time
        chunk.written_at = old_time

        req = MemoryReadRequest(reader_agent_id="agent-B", content_key="key-both")
        alerts = self.detector.check_read(req)
        types = {a.anomaly_type for a in alerts}
        assert "cross_agent_read" in types
        assert "stale_read" in types

    def test_get_alerts_filtering(self):
        self.detector.register_chunk("k1", writer_agent_id="agent-A")
        self.detector.register_chunk("k2", writer_agent_id="agent-A")
        self.detector.check_read(MemoryReadRequest(reader_agent_id="agent-B", content_key="k1"))
        self.detector.check_read(MemoryReadRequest(reader_agent_id="agent-C", content_key="k2"))

        all_alerts = self.detector.get_alerts()
        assert len(all_alerts) == 2

        agent_b_alerts = self.detector.get_alerts(agent_id="agent-B")
        assert len(agent_b_alerts) == 1

        cross_alerts = self.detector.get_alerts(anomaly_type="cross_agent_read")
        assert len(cross_alerts) == 2

    def test_clear_alerts(self):
        self.detector.register_chunk("k1", writer_agent_id="agent-A")
        self.detector.check_read(MemoryReadRequest(reader_agent_id="agent-B", content_key="k1"))
        assert self.detector.alert_count() == 1
        cleared = self.detector.clear_alerts()
        assert cleared == 1
        assert self.detector.alert_count() == 0

    def test_list_chunks_by_agent(self):
        self.detector.register_chunk("k1", writer_agent_id="agent-A")
        self.detector.register_chunk("k2", writer_agent_id="agent-B")
        self.detector.register_chunk("k3", writer_agent_id="agent-A")
        chunks = self.detector.list_chunks(agent_id="agent-A")
        assert len(chunks) == 2

    def test_remove_chunk(self):
        self.detector.register_chunk("k1", writer_agent_id="agent-A")
        assert self.detector.chunk_count() == 1
        removed = self.detector.remove_chunk("k1")
        assert removed is True
        assert self.detector.chunk_count() == 0
        assert self.detector.remove_chunk("nonexistent") is False

    def test_custom_stale_threshold(self):
        detector = ReadAnomalyDetector(stale_threshold_days=7)
        assert detector.stale_threshold_days == 7
        old_time = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        detector.register_chunk("k1", writer_agent_id="agent-A")
        chunk = detector.get_chunk("k1")
        chunk.last_accessed_at = old_time
        alerts = detector.check_read(MemoryReadRequest(reader_agent_id="agent-A", content_key="k1"))
        assert any(a.anomaly_type == "stale_read" for a in alerts)

    def test_alert_serialization(self):
        self.detector.register_chunk("k1", writer_agent_id="agent-A")
        self.detector.check_read(MemoryReadRequest(reader_agent_id="agent-B", content_key="k1"))
        alert = self.detector.get_alerts()[0]
        d = alert.to_dict()
        assert "alert_id" in d
        assert d["anomaly_type"] == "cross_agent_read"
        assert d["reader_agent_id"] == "agent-B"
        assert d["writer_agent_id"] == "agent-A"

    def test_chunk_metadata_serialization(self):
        chunk = self.detector.register_chunk("k1", writer_agent_id="agent-A", token_count=42)
        d = chunk.to_dict()
        assert d["content_key"] == "k1"
        assert d["writer_agent_id"] == "agent-A"
        assert d["token_count"] == 42

    def test_singleton_lifecycle(self):
        reset_read_anomaly_detector()
        d1 = get_read_anomaly_detector()
        d2 = get_read_anomaly_detector()
        assert d1 is d2
        reset_read_anomaly_detector()
        d3 = get_read_anomaly_detector()
        assert d3 is not d1


# ── Memory Lifecycle Cap Enforcement ────────────────────────────────────

from app.services.memory_firewall.lifecycle import (
    MemoryLifecycleManager,
    MemoryEntry,
    EvictionEvent,
    AgentMemoryCap,
    get_memory_lifecycle_manager,
    reset_memory_lifecycle_manager,
)


class TestMemoryLifecycleManager:
    """Tests for memory lifecycle cap enforcement and eviction."""

    def setup_method(self):
        self.manager = MemoryLifecycleManager(default_max_tokens=1000)

    def test_default_cap(self):
        cap = self.manager.get_cap("agent-A")
        assert cap.max_tokens == 1000
        assert cap.current_tokens == 0

    def test_set_custom_cap(self):
        cap = self.manager.set_cap("agent-A", 5000)
        assert cap.max_tokens == 5000
        assert cap.agent_id == "agent-A"

    def test_add_entry_within_cap(self):
        entry, evictions = self.manager.add_entry(
            agent_id="agent-A",
            content_key="k1",
            token_count=500,
        )
        assert entry.token_count == 500
        assert entry.agent_id == "agent-A"
        assert len(evictions) == 0
        cap = self.manager.get_cap("agent-A")
        assert cap.current_tokens == 500

    def test_eviction_on_cap_exceeded(self):
        """When token cap is exceeded, oldest entries should be evicted."""
        self.manager.add_entry("agent-A", "k1", 400)
        self.manager.add_entry("agent-A", "k2", 400)
        # This should trigger eviction of k1 (400 + 400 + 300 = 1100 > 1000)
        entry, evictions = self.manager.add_entry("agent-A", "k3", 300)
        assert len(evictions) >= 1
        assert evictions[0].evicted_content_key == "k1"
        assert evictions[0].evicted_token_count == 400
        cap = self.manager.get_cap("agent-A")
        assert cap.current_tokens <= 1000

    def test_multiple_evictions(self):
        """Multiple old entries may be evicted to make room."""
        self.manager.add_entry("agent-A", "k1", 300)
        self.manager.add_entry("agent-A", "k2", 300)
        self.manager.add_entry("agent-A", "k3", 300)
        # Adding 500 tokens: 300+300+300+500=1400 > 1000. Need to evict until room.
        entry, evictions = self.manager.add_entry("agent-A", "k4", 500)
        assert len(evictions) >= 2  # k1 and k2 evicted
        evicted_keys = [e.evicted_content_key for e in evictions]
        assert "k1" in evicted_keys
        assert "k2" in evicted_keys

    def test_eviction_log(self):
        self.manager.add_entry("agent-A", "k1", 600)
        self.manager.add_entry("agent-A", "k2", 600)  # triggers eviction of k1
        log = self.manager.get_eviction_log()
        assert len(log) >= 1
        assert log[0].agent_id == "agent-A"

    def test_eviction_log_filter_by_agent(self):
        self.manager.set_cap("agent-A", 500)
        self.manager.set_cap("agent-B", 500)
        self.manager.add_entry("agent-A", "k1", 400)
        self.manager.add_entry("agent-A", "k2", 400)  # evicts k1
        self.manager.add_entry("agent-B", "k3", 400)
        self.manager.add_entry("agent-B", "k4", 400)  # evicts k3
        log_a = self.manager.get_eviction_log(agent_id="agent-A")
        log_b = self.manager.get_eviction_log(agent_id="agent-B")
        assert all(e.agent_id == "agent-A" for e in log_a)
        assert all(e.agent_id == "agent-B" for e in log_b)

    def test_token_usage_summary(self):
        self.manager.add_entry("agent-A", "k1", 500)
        usage = self.manager.get_agent_token_usage("agent-A")
        assert usage["current_tokens"] == 500
        assert usage["max_tokens"] == 1000
        assert usage["utilization_pct"] == 50.0
        assert usage["entry_count"] == 1

    def test_remove_entry(self):
        self.manager.add_entry("agent-A", "k1", 300)
        self.manager.add_entry("agent-A", "k2", 200)
        assert self.manager.remove_entry("agent-A", "k1") is True
        cap = self.manager.get_cap("agent-A")
        assert cap.current_tokens == 200
        assert self.manager.remove_entry("agent-A", "nonexistent") is False

    def test_get_entries(self):
        self.manager.add_entry("agent-A", "k1", 100)
        self.manager.add_entry("agent-A", "k2", 200)
        entries = self.manager.get_entries("agent-A")
        assert len(entries) == 2

    def test_list_caps(self):
        self.manager.set_cap("agent-A", 1000)
        self.manager.set_cap("agent-B", 2000)
        caps = self.manager.list_caps()
        assert len(caps) == 2

    def test_stats(self):
        self.manager.add_entry("agent-A", "k1", 600)
        self.manager.add_entry("agent-A", "k2", 600)  # evicts k1
        stats = self.manager.get_stats()
        assert stats["total_entries"] == 2
        assert stats["total_evictions"] >= 1
        assert stats["total_tokens_evicted"] >= 600
        assert stats["agents_tracked"] >= 1

    def test_cap_serialization(self):
        self.manager.set_cap("agent-A", 5000)
        self.manager.add_entry("agent-A", "k1", 2500)
        cap = self.manager.get_cap("agent-A")
        d = cap.to_dict()
        assert d["agent_id"] == "agent-A"
        assert d["max_tokens"] == 5000
        assert d["current_tokens"] == 2500
        assert d["utilization_pct"] == 50.0

    def test_entry_serialization(self):
        entry, _ = self.manager.add_entry("agent-A", "k1", 100, namespace="ns", content_hash="h")
        d = entry.to_dict()
        assert d["agent_id"] == "agent-A"
        assert d["content_key"] == "k1"
        assert d["namespace"] == "ns"

    def test_eviction_event_serialization(self):
        self.manager.add_entry("agent-A", "k1", 600)
        _, evictions = self.manager.add_entry("agent-A", "k2", 600)
        assert len(evictions) >= 1
        d = evictions[0].to_dict()
        assert "event_id" in d
        assert d["agent_id"] == "agent-A"
        assert d["evicted_content_key"] == "k1"

    def test_singleton_lifecycle(self):
        reset_memory_lifecycle_manager()
        m1 = get_memory_lifecycle_manager()
        m2 = get_memory_lifecycle_manager()
        assert m1 is m2
        reset_memory_lifecycle_manager()
        m3 = get_memory_lifecycle_manager()
        assert m3 is not m1


# ── Memory Integrity Verification ──────────────────────────────────────

from app.services.memory_firewall.integrity import (
    MemoryIntegrityVerifier,
    MemoryRecord,
    IntegrityAlert,
    VerificationResult,
    get_memory_integrity_verifier,
    reset_memory_integrity_verifier,
)


class TestMemoryIntegrityVerifier:
    """Tests for memory integrity hash-chain verification."""

    def setup_method(self):
        self.verifier = MemoryIntegrityVerifier()

    def test_add_record(self):
        record = self.verifier.add_record(
            agent_id="agent-A",
            content_key="k1",
            content_hash="hash-abc",
            namespace="ns1",
        )
        assert record.agent_id == "agent-A"
        assert record.content_key == "k1"
        assert record.previous_hash == "genesis"
        assert record.record_hash != ""
        assert self.verifier.record_count() == 1

    def test_chain_links(self):
        """Each record should link to the previous record's hash."""
        r1 = self.verifier.add_record("agent-A", "k1", "h1")
        r2 = self.verifier.add_record("agent-A", "k2", "h2")
        assert r2.previous_hash == r1.record_hash

    def test_verify_clean_chain(self):
        self.verifier.add_record("agent-A", "k1", "h1")
        self.verifier.add_record("agent-A", "k2", "h2")
        self.verifier.add_record("agent-B", "k3", "h3")
        result = self.verifier.verify_integrity()
        assert result.chain_valid is True
        assert result.records_checked == 3
        assert result.records_valid == 3
        assert result.records_tampered == 0
        assert len(result.alerts) == 0

    def test_detect_tampered_record(self):
        """Simulated post-write tampering should be detected."""
        self.verifier.add_record("agent-A", "k1", "h1")
        self.verifier.add_record("agent-A", "k2", "h2")

        # Tamper with the first record
        assert self.verifier.simulate_tamper(0, "TAMPERED_HASH") is True

        result = self.verifier.verify_integrity()
        assert result.chain_valid is False
        assert result.records_tampered >= 1
        assert any(a.failure_type == "hash_mismatch" for a in result.alerts)

    def test_detect_chain_break(self):
        """Manually breaking the chain link should be detected."""
        r1 = self.verifier.add_record("agent-A", "k1", "h1")
        r2 = self.verifier.add_record("agent-A", "k2", "h2")

        # Break the chain by modifying previous_hash
        self.verifier._records[1].previous_hash = "broken-link"

        result = self.verifier.verify_integrity()
        assert result.chain_valid is False
        assert any(a.failure_type == "chain_break" for a in result.alerts)

    def test_verify_empty_chain(self):
        result = self.verifier.verify_integrity()
        assert result.chain_valid is True
        assert result.records_checked == 0

    def test_integrity_alerts_persisted(self):
        self.verifier.add_record("agent-A", "k1", "h1")
        self.verifier.simulate_tamper(0, "TAMPERED")
        self.verifier.verify_integrity()
        alerts = self.verifier.get_alerts()
        assert len(alerts) >= 1
        assert alerts[0].severity == "critical"

    def test_verification_history(self):
        self.verifier.add_record("agent-A", "k1", "h1")
        self.verifier.verify_integrity()
        self.verifier.verify_integrity()
        history = self.verifier.get_verification_history()
        assert len(history) == 2

    def test_stats(self):
        self.verifier.add_record("agent-A", "k1", "h1")
        self.verifier.verify_integrity()
        stats = self.verifier.get_stats()
        assert stats["total_records"] == 1
        assert stats["verification_runs"] == 1
        assert stats["tampering_detected"] == 0

    def test_get_records_filter_by_agent(self):
        self.verifier.add_record("agent-A", "k1", "h1")
        self.verifier.add_record("agent-B", "k2", "h2")
        records_a = self.verifier.get_records(agent_id="agent-A")
        assert len(records_a) == 1
        assert records_a[0].agent_id == "agent-A"

    def test_record_serialization(self):
        record = self.verifier.add_record("agent-A", "k1", "h1")
        d = record.to_dict()
        assert d["agent_id"] == "agent-A"
        assert d["content_key"] == "k1"
        assert "record_hash" in d

    def test_verification_result_serialization(self):
        self.verifier.add_record("agent-A", "k1", "h1")
        result = self.verifier.verify_integrity()
        d = result.to_dict()
        assert d["chain_valid"] is True
        assert d["records_checked"] == 1

    def test_simulate_tamper_invalid_index(self):
        assert self.verifier.simulate_tamper(99, "x") is False

    def test_singleton_lifecycle(self):
        reset_memory_integrity_verifier()
        v1 = get_memory_integrity_verifier()
        v2 = get_memory_integrity_verifier()
        assert v1 is v2
        reset_memory_integrity_verifier()
        v3 = get_memory_integrity_verifier()
        assert v3 is not v1


# ── Cross-Agent Memory Isolation ────────────────────────────────────────

from app.services.memory_firewall.isolation import (
    MemoryIsolationEnforcer,
    CrossAgentPermission,
    IsolationCheckResult,
    IsolationAction,
    get_memory_isolation_enforcer,
    reset_memory_isolation_enforcer,
)


class TestMemoryIsolationEnforcer:
    """Tests for cross-agent memory namespace isolation."""

    def setup_method(self):
        self.enforcer = MemoryIsolationEnforcer()

    def test_same_agent_read_allowed(self):
        """Same-agent reads always pass isolation check."""
        result = self.enforcer.check_read(
            reader_agent_id="agent-A",
            writer_agent_id="agent-A",
            content_key="k1",
        )
        assert result.action == IsolationAction.ALLOWED
        assert result.reason == "Same-agent read"

    def test_cross_agent_read_blocked_no_permission(self):
        """Cross-agent reads without permission should be blocked."""
        result = self.enforcer.check_read(
            reader_agent_id="agent-B",
            writer_agent_id="agent-A",
            content_key="k1",
        )
        assert result.action == IsolationAction.BLOCKED
        assert "No cross-agent read permission" in result.reason

    def test_cross_agent_read_allowed_with_permission(self):
        """Cross-agent reads with granted permission should pass."""
        self.enforcer.grant_permission(
            reader_agent_id="agent-B",
            writer_agent_id="agent-A",
            granted_by="admin",
        )
        result = self.enforcer.check_read(
            reader_agent_id="agent-B",
            writer_agent_id="agent-A",
            content_key="k1",
        )
        assert result.action == IsolationAction.ALLOWED
        assert "Explicit cross-agent permission" in result.reason

    def test_cross_agent_permission_namespace_restriction(self):
        """Permission with namespace restriction blocks access to other namespaces."""
        self.enforcer.grant_permission(
            reader_agent_id="agent-B",
            writer_agent_id="agent-A",
            namespaces=["shared-ns"],
        )
        # Access to permitted namespace
        r1 = self.enforcer.check_read("agent-B", "agent-A", namespace="shared-ns")
        assert r1.action == IsolationAction.ALLOWED

        # Access to non-permitted namespace
        r2 = self.enforcer.check_read("agent-B", "agent-A", namespace="private-ns")
        assert r2.action == IsolationAction.BLOCKED
        assert "not in permitted namespaces" in r2.reason

    def test_revoke_permission(self):
        self.enforcer.grant_permission("agent-B", "agent-A")
        assert self.enforcer.revoke_permission("agent-B", "agent-A") is True
        result = self.enforcer.check_read("agent-B", "agent-A")
        assert result.action == IsolationAction.BLOCKED

    def test_revoke_nonexistent_permission(self):
        assert self.enforcer.revoke_permission("x", "y") is False

    def test_list_permissions(self):
        self.enforcer.grant_permission("agent-B", "agent-A")
        self.enforcer.grant_permission("agent-C", "agent-A")
        all_perms = self.enforcer.list_permissions()
        assert len(all_perms) == 2
        b_perms = self.enforcer.list_permissions(agent_id="agent-B")
        assert len(b_perms) == 1

    def test_get_permitted_writers(self):
        self.enforcer.grant_permission("agent-B", "agent-A")
        self.enforcer.grant_permission("agent-B", "agent-C")
        writers = self.enforcer.get_permitted_writers("agent-B")
        assert writers == {"agent-A", "agent-C"}

    def test_namespace_assignment(self):
        ns = self.enforcer.assign_namespace("agent-A")
        assert ns == "agent:agent-A"
        ns2 = self.enforcer.assign_namespace("agent-B", "custom-ns")
        assert ns2 == "custom-ns"
        assert self.enforcer.get_namespace("agent-A") == "agent:agent-A"

    def test_default_namespace(self):
        """Unassigned agents get auto-generated namespace."""
        ns = self.enforcer.get_namespace("agent-X")
        assert ns == "agent:agent-X"

    def test_list_namespaces(self):
        self.enforcer.assign_namespace("agent-A")
        self.enforcer.assign_namespace("agent-B", "ns-B")
        namespaces = self.enforcer.list_namespaces()
        assert len(namespaces) == 2

    def test_audit_log(self):
        self.enforcer.check_read("agent-A", "agent-A")
        self.enforcer.check_read("agent-B", "agent-A")
        audit = self.enforcer.get_audit()
        assert len(audit) == 2

    def test_audit_filter_by_action(self):
        self.enforcer.check_read("agent-A", "agent-A")  # allowed
        self.enforcer.check_read("agent-B", "agent-A")  # blocked
        blocked = self.enforcer.get_audit(action="blocked")
        assert len(blocked) == 1
        assert blocked[0].action == IsolationAction.BLOCKED

    def test_stats(self):
        self.enforcer.check_read("agent-A", "agent-A")
        self.enforcer.check_read("agent-B", "agent-A")
        stats = self.enforcer.get_stats()
        assert stats["total_checks"] == 2
        assert stats["allowed"] == 1
        assert stats["blocked"] == 1

    def test_permission_serialization(self):
        perm = self.enforcer.grant_permission("agent-B", "agent-A", granted_by="admin")
        d = perm.to_dict()
        assert d["reader_agent_id"] == "agent-B"
        assert d["writer_agent_id"] == "agent-A"
        assert d["granted_by"] == "admin"

    def test_check_result_serialization(self):
        result = self.enforcer.check_read("agent-B", "agent-A", content_key="k1")
        d = result.to_dict()
        assert d["action"] == "blocked"
        assert d["reader_agent_id"] == "agent-B"

    def test_singleton_lifecycle(self):
        reset_memory_isolation_enforcer()
        e1 = get_memory_isolation_enforcer()
        e2 = get_memory_isolation_enforcer()
        assert e1 is e2
        reset_memory_isolation_enforcer()
        e3 = get_memory_isolation_enforcer()
        assert e3 is not e1


# ── Sprint 26 Acceptance Criteria ───────────────────────────────────────


class TestSprint26AcceptanceCriteria:
    """Validate Sprint 26 acceptance criteria."""

    def test_ac1_cross_agent_read_blocked_legitimate_passes(self):
        """AC1: Cross-agent memory read blocked when not in permitted scope;
        legitimate same-agent reads pass."""
        enforcer = MemoryIsolationEnforcer()
        detector = ReadAnomalyDetector()

        # Register memory owned by agent-A
        detector.register_chunk("secret-data", writer_agent_id="agent-A", namespace="agent:agent-A")

        # Agent-B tries to read agent-A's memory → blocked
        isolation_result = enforcer.check_read(
            reader_agent_id="agent-B",
            writer_agent_id="agent-A",
            content_key="secret-data",
        )
        assert isolation_result.action == IsolationAction.BLOCKED

        # Read anomaly is also flagged
        read_alerts = detector.check_read(
            MemoryReadRequest(reader_agent_id="agent-B", content_key="secret-data")
        )
        assert len(read_alerts) >= 1
        assert any(a.anomaly_type == "cross_agent_read" for a in read_alerts)

        # Agent-A reads its own memory → allowed, no anomalies
        isolation_result_same = enforcer.check_read(
            reader_agent_id="agent-A",
            writer_agent_id="agent-A",
            content_key="secret-data",
        )
        assert isolation_result_same.action == IsolationAction.ALLOWED

        same_agent_alerts = detector.check_read(
            MemoryReadRequest(reader_agent_id="agent-A", content_key="secret-data")
        )
        assert len(same_agent_alerts) == 0

    def test_ac2_lifecycle_cap_enforced_eviction_fires(self):
        """AC2: Memory lifecycle cap enforced; eviction fires when token limit
        is reached."""
        manager = MemoryLifecycleManager(default_max_tokens=500)

        # Fill memory to near-cap
        manager.add_entry("agent-A", "chunk-1", token_count=200)
        manager.add_entry("agent-A", "chunk-2", token_count=200)

        # This write exceeds cap → triggers eviction
        entry, evictions = manager.add_entry("agent-A", "chunk-3", token_count=200)

        # Verify eviction happened
        assert len(evictions) >= 1
        evicted_keys = [e.evicted_content_key for e in evictions]
        assert "chunk-1" in evicted_keys  # oldest evicted first

        # Verify cap not exceeded
        cap = manager.get_cap("agent-A")
        assert cap.current_tokens <= cap.max_tokens

        # Verify eviction log
        log = manager.get_eviction_log(agent_id="agent-A")
        assert len(log) >= 1

    def test_ac3_integrity_verification_detects_tampering(self):
        """AC3: Memory integrity verification detects simulated post-write
        tampering and fires alert."""
        verifier = MemoryIntegrityVerifier()

        # Add legitimate records
        verifier.add_record("agent-A", "k1", content_hash="original-hash-1")
        verifier.add_record("agent-A", "k2", content_hash="original-hash-2")
        verifier.add_record("agent-B", "k3", content_hash="original-hash-3")

        # Verify chain is initially valid
        initial_result = verifier.verify_integrity()
        assert initial_result.chain_valid is True

        # Simulate post-write tampering
        assert verifier.simulate_tamper(1, "TAMPERED-HASH") is True

        # Verify tampering is detected
        tampered_result = verifier.verify_integrity()
        assert tampered_result.chain_valid is False
        assert tampered_result.records_tampered >= 1

        # Verify alert was fired
        alerts = verifier.get_alerts()
        assert len(alerts) >= 1
        assert any(a.failure_type == "hash_mismatch" for a in alerts)
        assert any(a.severity == "critical" for a in alerts)


class TestSprint26Integration:
    """Integration tests combining multiple Sprint 26 components."""

    def test_write_registers_chunk_and_lifecycle(self):
        """Memory writes should register chunks for read tracking and lifecycle."""
        from app.services.memory_firewall.proxy import MemoryStoreProxy, MemoryWriteRequest
        from app.services.memory_firewall.policy import MemoryWritePolicyStore, WritePolicy

        proxy = MemoryStoreProxy()
        detector = ReadAnomalyDetector()
        manager = MemoryLifecycleManager(default_max_tokens=10000)
        verifier = MemoryIntegrityVerifier()

        # Simulate a write going through the pipeline
        write_req = MemoryWriteRequest(
            agent_id="agent-A",
            content="Normal agent memory content about user preferences",
            content_key="pref-1",
            backend="redis",
            framework="langchain",
            namespace="agent:agent-A",
        )
        result = proxy.intercept_write(write_req)
        assert result.action.value == "allowed"

        # Register in downstream services
        detector.register_chunk(
            content_key=write_req.content_key,
            writer_agent_id=write_req.agent_id,
            namespace=write_req.namespace,
            token_count=50,
            content_hash=write_req.content_hash(),
        )
        manager.add_entry(
            agent_id=write_req.agent_id,
            content_key=write_req.content_key,
            token_count=50,
            namespace=write_req.namespace,
            content_hash=write_req.content_hash(),
        )
        verifier.add_record(
            agent_id=write_req.agent_id,
            content_key=write_req.content_key,
            content_hash=write_req.content_hash(),
            namespace=write_req.namespace,
        )

        # Verify all services have the data
        assert detector.chunk_count() == 1
        assert manager.get_cap("agent-A").current_tokens == 50
        assert verifier.record_count() == 1

    def test_isolation_enforcer_integrates_with_read_detector(self):
        """Isolation enforcer and read detector work together."""
        enforcer = MemoryIsolationEnforcer()
        detector = ReadAnomalyDetector()

        # Agent-A writes memory
        detector.register_chunk("data-1", writer_agent_id="agent-A")

        # Agent-B attempts read — check both isolation and anomaly
        iso_result = enforcer.check_read("agent-B", "agent-A", content_key="data-1")
        assert iso_result.action == IsolationAction.BLOCKED

        permitted = enforcer.get_permitted_writers("agent-B")
        anomaly_alerts = detector.check_read(
            MemoryReadRequest(reader_agent_id="agent-B", content_key="data-1"),
            permitted_cross_agents=permitted,
        )
        assert len(anomaly_alerts) >= 1

        # Grant permission and retry
        enforcer.grant_permission("agent-B", "agent-A")
        iso_result2 = enforcer.check_read("agent-B", "agent-A", content_key="data-1")
        assert iso_result2.action == IsolationAction.ALLOWED

        permitted2 = enforcer.get_permitted_writers("agent-B")
        anomaly_alerts2 = detector.check_read(
            MemoryReadRequest(reader_agent_id="agent-B", content_key="data-1"),
            permitted_cross_agents=permitted2,
        )
        # No cross-agent alert since permission is now granted
        cross_alerts = [a for a in anomaly_alerts2 if a.anomaly_type == "cross_agent_read"]
        assert len(cross_alerts) == 0
