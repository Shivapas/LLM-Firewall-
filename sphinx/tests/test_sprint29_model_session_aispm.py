"""Sprint 29 — ML Model Scanning + Multi-Turn Security + AI-SPM Integration Tests.

Covers:
1. Model artifact scanner — pickle exploit detection, clean model pass
2. Model provenance registry — registration, verification, hash mismatch
3. Session context store — session lifecycle, turn recording, expiry
4. Cross-turn risk accumulation — escalation on cumulative risk, consecutive high turns
5. AI-SPM integration — asset discovery, ungoverned flagging, enrollment workflow
6. Sprint 29 acceptance criteria validation
"""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest


# ══════════════════════════════════════════════════════════════════════════
# 1. Model Artifact Scanner
# ══════════════════════════════════════════════════════════════════════════


class TestModelArtifactScanner:
    """Test model file scanning for deserialization attacks."""

    def _scanner(self):
        from app.services.model_scanner.artifact_scanner import ModelArtifactScanner
        return ModelArtifactScanner()

    def test_detect_pytorch_format(self):
        scanner = self._scanner()
        # ZIP magic = PyTorch
        data = b"PK\x03\x04" + b"\x00" * 100
        fmt = scanner.detect_format(data, "model.pt")
        assert fmt.value == "pytorch"

    def test_detect_safetensors_format(self):
        scanner = self._scanner()
        fmt = scanner.detect_format(b"", "model.safetensors")
        assert fmt.value == "safetensors"

    def test_detect_gguf_format(self):
        scanner = self._scanner()
        data = b"GGUF" + b"\x00" * 100
        fmt = scanner.detect_format(data, "model.gguf")
        assert fmt.value == "gguf"

    def test_clean_safetensors_passes(self):
        """Clean safetensors file should pass with no findings."""
        scanner = self._scanner()
        # safetensors header (8 bytes length) + small JSON header + tensor data
        import struct
        header = b'{"weight": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}'
        header_len = struct.pack("<Q", len(header))
        tensor_data = b"\x00" * 16
        data = header_len + header + tensor_data

        result = scanner.scan(data, "clean_model.safetensors")
        assert result.verdict == "safe"
        assert len(result.findings) == 0
        assert result.model_format == "safetensors"

    def test_malicious_pickle_payload_detected(self):
        """Model with malicious pickle payload should be flagged as malicious.

        Sprint 29 acceptance criteria: Model scanner detects known-malicious
        pickle payload in test model file.
        """
        scanner = self._scanner()
        # Simulate a pickle exploit: os.system via GLOBAL opcode
        # The 'c' byte (0x63) is the GLOBAL opcode in pickle protocol
        malicious_payload = (
            b"\x80\x02"  # pickle protocol 2
            b"cos\nsystem\n"  # GLOBAL: import os.system
            b"\x52"  # REDUCE opcode
            b"."  # STOP
        )
        result = scanner.scan(malicious_payload, "evil_model.bin")
        assert result.verdict == "malicious"
        assert len(result.findings) > 0
        assert any(f.category == "pickle_exploit" for f in result.findings)
        assert any("os" in f.details.get("module", "") for f in result.findings)

    def test_subprocess_payload_detected(self):
        scanner = self._scanner()
        payload = (
            b"\x80\x02"
            b"csubprocess\nPopen\n"
            b"\x52"
            b"."
        )
        result = scanner.scan(payload, "backdoor.bin")
        assert result.verdict == "malicious"
        assert any(
            f.details.get("module") == "subprocess"
            for f in result.findings
        )

    def test_eval_exec_backdoor_pattern(self):
        scanner = self._scanner()
        data = b"GGUF" + b"\x00" * 50 + b"eval(malicious_code)" + b"\x00" * 50
        result = scanner.scan(data, "model.gguf")
        assert result.verdict in ("malicious", "suspicious")
        assert any(f.category in ("embedded_code", "backdoor_trigger") for f in result.findings)

    def test_clean_model_no_false_positive(self):
        """Clean model should not produce false positives.

        Sprint 29 acceptance criteria: clean models pass with no false positive.
        """
        scanner = self._scanner()
        # Random binary data — no pickle or backdoor patterns
        import struct
        data = b"GGUF" + struct.pack("<I", 3)  # version 3
        data += b"\x00" * 1000  # clean tensor data
        result = scanner.scan(data, "clean_model.gguf")
        assert result.verdict == "safe"
        assert len(result.findings) == 0

    def test_scan_stats_tracked(self):
        scanner = self._scanner()
        scanner.scan(b"\x00" * 100, "a.gguf")
        scanner.scan(b"cos\nsystem\n\x52", "b.bin")
        stats = scanner.get_stats()
        assert stats["total_scans"] == 2

    def test_scan_history(self):
        scanner = self._scanner()
        scanner.scan(b"\x00" * 100, "test.bin")
        history = scanner.get_scan_history()
        assert len(history) == 1
        assert history[0].filename == "test.bin"


# ══════════════════════════════════════════════════════════════════════════
# 2. Model Provenance Registry
# ══════════════════════════════════════════════════════════════════════════


class TestModelProvenanceRegistry:
    """Test hash-based model integrity registry."""

    def _registry(self):
        from app.services.model_scanner.provenance_registry import ModelProvenanceRegistry
        return ModelProvenanceRegistry()

    def test_register_and_verify(self):
        registry = self._registry()
        reg = registry.register(
            model_name="llama-7b",
            model_version="v1.0",
            file_hash="abc123def456",
            source="huggingface",
        )
        assert reg.model_name == "llama-7b"
        assert reg.is_active

        check = registry.verify("llama-7b", "abc123def456")
        assert check.is_registered
        assert check.hash_matches
        assert check.action == "allow"

    def test_block_unregistered_model(self):
        registry = self._registry()
        check = registry.verify("unknown-model", "somehash")
        assert not check.is_registered
        assert not check.hash_matches
        assert check.action == "block"

    def test_block_hash_mismatch(self):
        registry = self._registry()
        registry.register(
            model_name="llama-7b",
            model_version="v1.0",
            file_hash="correct_hash",
        )
        check = registry.verify("llama-7b", "wrong_hash")
        assert check.is_registered
        assert not check.hash_matches
        assert check.action == "block"

    def test_revoke_model(self):
        registry = self._registry()
        registry.register("model-a", "v1", "hash1")
        ok = registry.revoke("model-a", "v1")
        assert ok

        # After revoke, verify should fail (hash lookup won't find active)
        check = registry.verify("model-a", "hash1")
        # The hash is still in index but registration is inactive
        assert check.action == "block"

    def test_list_registrations(self):
        registry = self._registry()
        registry.register("model-a", "v1", "h1")
        registry.register("model-a", "v2", "h2")
        registry.register("model-b", "v1", "h3")
        assert len(registry.list_registrations("model-a")) == 2
        assert len(registry.list_registrations()) == 3

    def test_stats(self):
        registry = self._registry()
        registry.register("m", "v1", "h1")
        registry.verify("m", "h1")
        registry.verify("m", "bad")
        stats = registry.get_stats()
        assert stats["total_registrations"] == 1
        assert stats["total_checks"] == 2
        assert stats["checks_passed"] == 1
        assert stats["checks_blocked"] == 1


# ══════════════════════════════════════════════════════════════════════════
# 3. Session Context Store
# ══════════════════════════════════════════════════════════════════════════


class TestSessionContextStore:
    """Test multi-turn session context management."""

    def _store(self):
        from app.services.session_security.context_store import SessionContextStore
        return SessionContextStore(max_turns=10, inactivity_timeout_seconds=1800)

    def test_create_session(self):
        store = self._store()
        session = store.get_or_create_session("s1", "tenant1", "agent1")
        assert session.session_id == "s1"
        assert session.tenant_id == "tenant1"
        assert session.turn_count == 0
        assert not session.expired

    def test_record_turns(self):
        store = self._store()
        store.get_or_create_session("s1")

        turn1 = store.record_turn("s1", risk_score=0.3, risk_level="low")
        assert turn1.turn_number == 1

        turn2 = store.record_turn("s1", risk_score=0.8, risk_level="high")
        assert turn2.turn_number == 2

        session = store.get_session("s1")
        assert session.turn_count == 2
        assert session.cumulative_risk_score == pytest.approx(1.1)
        assert session.max_risk_level == "high"

    def test_max_turns_trimming(self):
        store = self._store()
        store.get_or_create_session("s1")
        for i in range(15):
            store.record_turn("s1", risk_score=0.1)
        session = store.get_session("s1")
        assert len(session.turns) == 10  # trimmed to max

    def test_expire_session(self):
        store = self._store()
        store.get_or_create_session("s1")
        ok = store.expire_session("s1")
        assert ok
        session = store.get_session("s1")
        assert session.expired

    def test_list_sessions(self):
        store = self._store()
        store.get_or_create_session("s1", "t1")
        store.get_or_create_session("s2", "t1")
        store.get_or_create_session("s3", "t2")
        assert len(store.list_sessions("t1")) == 2
        assert len(store.list_sessions()) == 3

    def test_stats(self):
        store = self._store()
        store.get_or_create_session("s1")
        store.record_turn("s1", risk_score=0.5)
        stats = store.get_stats()
        assert stats["total_sessions"] == 1
        assert stats["total_turns"] == 1


# ══════════════════════════════════════════════════════════════════════════
# 4. Cross-Turn Risk Accumulation
# ══════════════════════════════════════════════════════════════════════════


class TestCrossTurnRiskAccumulation:
    """Test cross-turn risk escalation logic."""

    def _accumulator(self, threshold=3.0, consecutive=3):
        from app.services.session_security.context_store import reset_session_context_store
        from app.services.session_security.cross_turn_risk import CrossTurnRiskAccumulator
        reset_session_context_store()
        return CrossTurnRiskAccumulator(
            escalation_threshold=threshold,
            consecutive_high_threshold=consecutive,
            escalation_action="block",
        )

    def test_no_escalation_below_threshold(self):
        acc = self._accumulator(threshold=5.0)
        result = acc.evaluate_turn("s1", risk_score=0.5, risk_level="low")
        assert result["action"] == "allowed"
        assert not result["escalated"]

    def test_escalation_on_cumulative_risk(self):
        """Sprint 29 acceptance criteria: Cross-turn escalation triggers
        correctly when risk accumulates across a multi-turn jailbreak simulation.
        """
        acc = self._accumulator(threshold=2.5)
        # Simulate multi-turn jailbreak with escalating risk
        acc.evaluate_turn("s1", risk_score=0.8, risk_level="medium")
        acc.evaluate_turn("s1", risk_score=0.9, risk_level="high")
        result = acc.evaluate_turn("s1", risk_score=1.0, risk_level="high")

        assert result["escalated"]
        assert result["action"] == "block"
        assert result["escalation_event"] is not None
        assert result["session"]["is_escalated"]

    def test_escalation_on_consecutive_high(self):
        acc = self._accumulator(threshold=100.0, consecutive=3)
        acc.evaluate_turn("s1", risk_score=0.8, risk_level="high")
        acc.evaluate_turn("s1", risk_score=0.9, risk_level="high")
        result = acc.evaluate_turn("s1", risk_score=0.7, risk_level="high")
        assert result["escalated"]

    def test_no_double_escalation(self):
        acc = self._accumulator(threshold=1.0)
        acc.evaluate_turn("s1", risk_score=1.5, risk_level="high")
        # Already escalated — second turn shouldn't re-escalate
        result = acc.evaluate_turn("s1", risk_score=1.0, risk_level="high")
        assert not result["escalated"]

    def test_reset_escalation(self):
        acc = self._accumulator(threshold=1.0)
        acc.evaluate_turn("s1", risk_score=2.0, risk_level="high")
        ok = acc.reset_session_escalation("s1")
        assert ok

    def test_escalation_events_tracked(self):
        acc = self._accumulator(threshold=1.0)
        acc.evaluate_turn("s1", risk_score=2.0, risk_level="high")
        events = acc.get_escalation_events()
        assert len(events) == 1
        assert events[0].session_id == "s1"


# ══════════════════════════════════════════════════════════════════════════
# 5. AI-SPM Integration (Shadow AI Discovery)
# ══════════════════════════════════════════════════════════════════════════


class TestAISPMDiscovery:
    """Test AI asset inventory and shadow AI discovery."""

    def _service(self):
        from app.services.ai_spm.discovery import AISPMDiscoveryService
        return AISPMDiscoveryService()

    def test_discover_ungoverned_asset(self):
        """Sprint 29 acceptance criteria: Ungoverned AI assets discovered
        by AI-SPM appear in Sphinx dashboard with enrollment prompt.
        """
        svc = self._service()
        asset = svc.discover_asset(
            name="Marketing GPT",
            asset_type="chatbot",
            provider="openai",
            endpoint="https://api.openai.com/v1/chat",
            tenant_id="tenant-1",
            team="marketing",
            discovery_source="network_scan",
        )
        assert asset.status == "ungoverned"

        # Should appear in ungoverned list
        ungoverned = svc.list_ungoverned()
        assert len(ungoverned) == 1
        assert ungoverned[0].name == "Marketing GPT"

        # Should appear in dashboard
        dashboard = svc.get_dashboard_summary()
        assert dashboard["ungoverned"] == 1
        assert len(dashboard["ungoverned_assets"]) == 1

    def test_governed_asset(self):
        svc = self._service()
        svc.register_governed_endpoint("https://sphinx-gateway/v1/chat")
        asset = svc.discover_asset(
            name="Governed Bot",
            endpoint="https://sphinx-gateway/v1/chat",
        )
        assert asset.status == "governed"

    def test_enrollment_workflow(self):
        svc = self._service()
        asset = svc.discover_asset(name="Shadow Bot", endpoint="https://shadow.api/v1")

        # Request enrollment
        req = svc.request_enrollment(asset.asset_id, "admin")
        assert req is not None
        assert req.status == "pending"
        assert svc.get_asset(asset.asset_id).status == "pending_enrollment"

        # Approve enrollment
        ok = svc.approve_enrollment(req.request_id, "Approved for production")
        assert ok
        assert svc.get_asset(asset.asset_id).status == "enrolled"

        stats = svc.get_stats()
        assert stats["completed_enrollments"] == 1
        assert stats["governed_assets"] == 1

    def test_reject_enrollment(self):
        svc = self._service()
        asset = svc.discover_asset(name="Risky Bot", endpoint="https://risky.api/v1")
        req = svc.request_enrollment(asset.asset_id)
        ok = svc.reject_enrollment(req.request_id, "Too risky")
        assert ok
        assert svc.get_asset(asset.asset_id).status == "ungoverned"

    def test_ignore_asset(self):
        svc = self._service()
        asset = svc.discover_asset(name="Test Bot")
        ok = svc.ignore_asset(asset.asset_id)
        assert ok
        assert svc.get_asset(asset.asset_id).status == "ignored"

    def test_filter_by_status(self):
        svc = self._service()
        svc.register_governed_endpoint("https://governed.api/v1")
        svc.discover_asset(name="A", endpoint="https://governed.api/v1")
        svc.discover_asset(name="B", endpoint="https://ungoverned.api/v1")
        assert len(svc.list_assets(status="governed")) == 1
        assert len(svc.list_assets(status="ungoverned")) == 1
