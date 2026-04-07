"""Sprint 27 — Inter-Agent A2A Protocol Firewall.

Tests cover:
1. A2AInterceptor: message interception with full security pipeline
2. AgentTokenIssuer: JWT token issuance, validation, revocation
3. MessageSignatureVerifier: HMAC signature verification, nonce replay blocking
4. MTLSEnforcer: certificate issuance, mTLS enforcement, revocation
5. A2AAuditLog: per-message audit with tamper-evident hash chain
6. Acceptance criteria:
   - A2A message from unregistered agent rejected with audit record
   - Replay attack (reused nonce) blocked correctly
   - mTLS enforced between agents in LangGraph multi-agent integration test
"""

from __future__ import annotations

import time

import pytest

# ── Token Issuer Tests ────────────────────────────────────────────────────

from app.services.a2a.token_issuer import (
    AgentTokenIssuer,
    AgentRegistration,
    IssuedToken,
    get_token_issuer,
    reset_token_issuer,
)


class TestAgentTokenIssuer:
    """Tests for agent identity JWT token issuance."""

    def setup_method(self):
        self.issuer = AgentTokenIssuer(master_secret="test-secret")

    def test_register_agent(self):
        reg = self.issuer.register_agent(
            agent_id="agent-A",
            display_name="Agent Alpha",
            allowed_downstream=["agent-B", "agent-C"],
            permission_scope=["read", "write", "execute"],
        )
        assert reg.agent_id == "agent-A"
        assert reg.display_name == "Agent Alpha"
        assert reg.allowed_downstream == ["agent-B", "agent-C"]
        assert reg.permission_scope == ["read", "write", "execute"]
        assert reg.is_active is True
        assert len(reg.signing_secret) > 0

    def test_register_and_list_agents(self):
        self.issuer.register_agent("agent-A")
        self.issuer.register_agent("agent-B")
        agents = self.issuer.list_agents()
        assert len(agents) == 2
        agent_ids = [a["agent_id"] for a in agents]
        assert "agent-A" in agent_ids
        assert "agent-B" in agent_ids

    def test_is_registered(self):
        self.issuer.register_agent("agent-A")
        assert self.issuer.is_registered("agent-A") is True
        assert self.issuer.is_registered("agent-X") is False

    def test_unregister_agent(self):
        self.issuer.register_agent("agent-A")
        assert self.issuer.is_registered("agent-A") is True
        self.issuer.unregister_agent("agent-A")
        assert self.issuer.is_registered("agent-A") is False

    def test_issue_token(self):
        self.issuer.register_agent("agent-A", allowed_downstream=["agent-B"])
        token = self.issuer.issue_token("agent-A")
        assert isinstance(token, IssuedToken)
        assert token.agent_id == "agent-A"
        assert len(token.token) > 0
        assert len(token.jti) > 0
        assert token.expires_at > token.issued_at

    def test_issue_token_unregistered_agent_raises(self):
        with pytest.raises(ValueError, match="not registered"):
            self.issuer.issue_token("agent-X")

    def test_issue_token_inactive_agent_raises(self):
        self.issuer.register_agent("agent-A")
        self.issuer.unregister_agent("agent-A")
        with pytest.raises(ValueError, match="not registered"):
            self.issuer.issue_token("agent-A")

    def test_validate_token_success(self):
        self.issuer.register_agent(
            "agent-A",
            allowed_downstream=["agent-B"],
            permission_scope=["read"],
        )
        token = self.issuer.issue_token("agent-A")
        result = self.issuer.validate_token(token.token, "agent-A")
        assert result["valid"] is True
        assert result["agent_id"] == "agent-A"
        assert result["allowed_downstream"] == ["agent-B"]
        assert result["permission_scope"] == ["read"]
        assert result["expired"] is False

    def test_validate_empty_token(self):
        result = self.issuer.validate_token("", "agent-A")
        assert result["valid"] is False
        assert "Empty" in result["reason"]

    def test_validate_malformed_token(self):
        result = self.issuer.validate_token("not-a-jwt", "agent-A")
        assert result["valid"] is False
        assert "Malformed" in result["reason"]

    def test_validate_token_unregistered_agent(self):
        self.issuer.register_agent("agent-A")
        token = self.issuer.issue_token("agent-A")
        self.issuer.unregister_agent("agent-A")
        result = self.issuer.validate_token(token.token, "agent-A")
        assert result["valid"] is False
        assert "not registered" in result["reason"]

    def test_validate_token_agent_id_mismatch(self):
        self.issuer.register_agent("agent-A")
        token = self.issuer.issue_token("agent-A")
        result = self.issuer.validate_token(token.token, "agent-B")
        assert result["valid"] is False
        assert "mismatch" in result["reason"]

    def test_validate_token_tampered_signature(self):
        self.issuer.register_agent("agent-A")
        token = self.issuer.issue_token("agent-A")
        # Tamper with signature
        parts = token.token.split(".")
        tampered = parts[0] + "." + parts[1] + ".tampered_signature"
        result = self.issuer.validate_token(tampered, "agent-A")
        assert result["valid"] is False
        assert "signature" in result["reason"].lower()

    def test_revoke_token(self):
        self.issuer.register_agent("agent-A")
        token = self.issuer.issue_token("agent-A")
        # Token should be valid before revocation
        result = self.issuer.validate_token(token.token, "agent-A")
        assert result["valid"] is True
        # Revoke
        self.issuer.revoke_token(token.jti)
        # Token should now be rejected
        result = self.issuer.validate_token(token.token, "agent-A")
        assert result["valid"] is False
        assert "revoked" in result["reason"].lower()

    def test_expired_token(self):
        self.issuer.register_agent("agent-A", token_ttl_seconds=0)
        token = self.issuer.issue_token("agent-A")
        time.sleep(0.1)
        result = self.issuer.validate_token(token.token, "agent-A")
        assert result["valid"] is False
        assert result.get("expired") is True

    def test_token_stats(self):
        self.issuer.register_agent("agent-A")
        self.issuer.issue_token("agent-A")
        self.issuer.validate_token("invalid", "agent-A")
        stats = self.issuer.get_stats()
        assert stats["tokens_issued"] == 1
        assert stats["tokens_validated"] >= 1

    def test_singleton_reset(self):
        issuer1 = get_token_issuer()
        reset_token_issuer()
        issuer2 = get_token_issuer()
        assert issuer1 is not issuer2


# ── Signature Verification Tests ──────────────────────────────────────────

from app.services.a2a.signature import (
    MessageSignatureVerifier,
    NonceStore,
    get_signature_verifier,
    reset_signature_verifier,
)

from app.services.a2a.interceptor import A2AMessage


class TestNonceStore:
    """Tests for nonce replay prevention store."""

    def test_mark_and_check_nonce(self):
        store = NonceStore(ttl_seconds=60)
        assert store.is_used("nonce-1") is False
        store.mark_used("nonce-1")
        assert store.is_used("nonce-1") is True

    def test_nonce_expiry(self):
        store = NonceStore(ttl_seconds=0)
        store.mark_used("nonce-1", time.time() - 10)
        assert store.is_used("nonce-1") is False

    def test_nonce_count(self):
        store = NonceStore(ttl_seconds=60)
        store.mark_used("n1")
        store.mark_used("n2")
        assert store.count() == 2

    def test_clear(self):
        store = NonceStore(ttl_seconds=60)
        store.mark_used("n1")
        store.clear()
        assert store.count() == 0


class TestMessageSignatureVerifier:
    """Tests for A2A message signature verification."""

    def setup_method(self):
        self.verifier = MessageSignatureVerifier(nonce_ttl_seconds=60)
        self.verifier.register_secret("agent-A", "secret-A")

    def _make_signed_message(self, sender="agent-A", receiver="agent-B",
                              content="hello", nonce=None):
        msg = A2AMessage(
            sender_agent_id=sender,
            receiver_agent_id=receiver,
            content=content,
            nonce=nonce or f"nonce-{time.time()}",
            timestamp=time.time(),
        )
        msg.signature = self.verifier.compute_signature(msg)
        return msg

    def test_valid_signature(self):
        msg = self._make_signed_message()
        result = self.verifier.verify(msg)
        assert result["valid"] is True
        assert result["nonce_valid"] is True

    def test_invalid_signature(self):
        msg = self._make_signed_message()
        msg.signature = "wrong_signature"
        result = self.verifier.verify(msg)
        assert result["valid"] is False
        assert "mismatch" in result["reason"].lower()

    def test_missing_signature(self):
        msg = A2AMessage(
            sender_agent_id="agent-A",
            receiver_agent_id="agent-B",
            nonce="n1",
        )
        result = self.verifier.verify(msg)
        assert result["valid"] is False
        assert "Missing" in result["reason"]

    def test_missing_nonce(self):
        msg = A2AMessage(
            sender_agent_id="agent-A",
            receiver_agent_id="agent-B",
            signature="some-sig",
        )
        result = self.verifier.verify(msg)
        assert result["valid"] is False
        assert "nonce" in result["reason"].lower()

    def test_no_secret_registered(self):
        msg = A2AMessage(
            sender_agent_id="agent-X",
            receiver_agent_id="agent-B",
            signature="sig",
            nonce="n1",
        )
        result = self.verifier.verify(msg)
        assert result["valid"] is False
        assert "No signing secret" in result["reason"]

    def test_replay_attack_blocked(self):
        """Reusing a nonce should be blocked."""
        msg = self._make_signed_message(nonce="replay-nonce-1")
        result1 = self.verifier.verify(msg)
        assert result1["valid"] is True

        # Replay same message with same nonce
        msg2 = self._make_signed_message(nonce="replay-nonce-1")
        result2 = self.verifier.verify(msg2)
        assert result2["valid"] is False
        assert result2["nonce_valid"] is False
        assert "replay" in result2["reason"].lower()

    def test_different_nonces_allowed(self):
        msg1 = self._make_signed_message(nonce="nonce-1")
        msg2 = self._make_signed_message(nonce="nonce-2")
        assert self.verifier.verify(msg1)["valid"] is True
        assert self.verifier.verify(msg2)["valid"] is True

    def test_stats(self):
        msg = self._make_signed_message()
        self.verifier.verify(msg)
        stats = self.verifier.get_stats()
        assert stats["verified"] == 1

    def test_singleton_reset(self):
        v1 = get_signature_verifier()
        reset_signature_verifier()
        v2 = get_signature_verifier()
        assert v1 is not v2


# ── mTLS Enforcer Tests ──────────────────────────────────────────────────

from app.services.a2a.mtls import (
    MTLSEnforcer,
    AgentCertificate,
    MTLSPolicy,
    get_mtls_enforcer,
    reset_mtls_enforcer,
)


class TestMTLSEnforcer:
    """Tests for mutual TLS enforcement."""

    def setup_method(self):
        self.enforcer = MTLSEnforcer(ca_name="test-ca")

    def test_issue_certificate(self):
        cert = self.enforcer.issue_certificate("agent-A")
        assert cert.agent_id == "agent-A"
        assert cert.status == "active"
        assert cert.issuer == "test-ca"
        assert len(cert.cert_fingerprint) > 0
        assert len(cert.serial_number) > 0
        assert cert.spiffe_id == "spiffe://sphinx/agent/agent-A"

    def test_issue_certificate_custom_spiffe(self):
        cert = self.enforcer.issue_certificate(
            "agent-A", spiffe_id="spiffe://custom/agent-A"
        )
        assert cert.spiffe_id == "spiffe://custom/agent-A"

    def test_revoke_certificate(self):
        self.enforcer.issue_certificate("agent-A")
        assert self.enforcer.revoke_certificate("agent-A") is True
        cert = self.enforcer.get_certificate("agent-A")
        assert cert.status == "revoked"

    def test_revoke_nonexistent_certificate(self):
        assert self.enforcer.revoke_certificate("agent-X") is False

    def test_list_certificates(self):
        self.enforcer.issue_certificate("agent-A")
        self.enforcer.issue_certificate("agent-B")
        certs = self.enforcer.list_certificates()
        assert len(certs) == 2

    def test_add_mtls_policy(self):
        policy = self.enforcer.add_policy(
            workflow_id="wf-1",
            agent_pairs=[("agent-A", "agent-B")],
            framework="langgraph",
        )
        assert policy.workflow_id == "wf-1"
        assert policy.required is True
        assert len(policy.agent_pairs) == 1

    def test_is_required_with_policy(self):
        self.enforcer.add_policy(
            workflow_id="wf-1",
            agent_pairs=[("agent-A", "agent-B")],
        )
        assert self.enforcer.is_required("agent-A", "agent-B") is True
        assert self.enforcer.is_required("agent-B", "agent-A") is True  # bidirectional
        assert self.enforcer.is_required("agent-C", "agent-D") is False

    def test_is_required_global(self):
        self.enforcer.set_global_mtls_required(True)
        assert self.enforcer.is_required("any-agent", "other-agent") is True

    def test_verify_channel_success(self):
        cert = self.enforcer.issue_certificate("agent-A")
        msg = A2AMessage(
            sender_agent_id="agent-A",
            receiver_agent_id="agent-B",
            mtls_verified=True,
            sender_cert_fingerprint=cert.cert_fingerprint,
        )
        result = self.enforcer.verify_channel(msg)
        assert result["verified"] is True
        assert "spiffe" in result.get("spiffe_id", "")

    def test_verify_channel_no_mtls(self):
        self.enforcer.issue_certificate("agent-A")
        msg = A2AMessage(
            sender_agent_id="agent-A",
            receiver_agent_id="agent-B",
            mtls_verified=False,
        )
        result = self.enforcer.verify_channel(msg)
        assert result["verified"] is False

    def test_verify_channel_no_certificate(self):
        msg = A2AMessage(
            sender_agent_id="agent-X",
            receiver_agent_id="agent-B",
            mtls_verified=True,
        )
        result = self.enforcer.verify_channel(msg)
        assert result["verified"] is False

    def test_verify_channel_revoked_certificate(self):
        self.enforcer.issue_certificate("agent-A")
        self.enforcer.revoke_certificate("agent-A")
        msg = A2AMessage(
            sender_agent_id="agent-A",
            receiver_agent_id="agent-B",
            mtls_verified=True,
        )
        result = self.enforcer.verify_channel(msg)
        assert result["verified"] is False

    def test_verify_channel_fingerprint_mismatch(self):
        self.enforcer.issue_certificate("agent-A")
        msg = A2AMessage(
            sender_agent_id="agent-A",
            receiver_agent_id="agent-B",
            mtls_verified=True,
            sender_cert_fingerprint="wrong-fingerprint",
        )
        result = self.enforcer.verify_channel(msg)
        assert result["verified"] is False

    def test_stats(self):
        cert = self.enforcer.issue_certificate("agent-A")
        msg = A2AMessage(
            sender_agent_id="agent-A",
            receiver_agent_id="agent-B",
            mtls_verified=True,
            sender_cert_fingerprint=cert.cert_fingerprint,
        )
        self.enforcer.verify_channel(msg)
        stats = self.enforcer.get_stats()
        assert stats["certs_issued"] == 1
        assert stats["verifications_passed"] == 1

    def test_singleton_reset(self):
        e1 = get_mtls_enforcer()
        reset_mtls_enforcer()
        e2 = get_mtls_enforcer()
        assert e1 is not e2


# ── A2A Audit Log Tests ──────────────────────────────────────────────────

from app.services.a2a.audit import (
    A2AAuditLog,
    A2AAuditRecord,
    get_a2a_audit_log,
    reset_a2a_audit_log,
)

from app.services.a2a.interceptor import InterceptionResult, MessageAction


class TestA2AAuditLog:
    """Tests for A2A per-message audit log."""

    def setup_method(self):
        self.audit = A2AAuditLog()

    def _make_message_and_result(self, sender="agent-A", receiver="agent-B",
                                  action=MessageAction.ALLOWED):
        msg = A2AMessage(
            sender_agent_id=sender,
            receiver_agent_id=receiver,
            content="test message",
            message_type="task",
            framework="langgraph",
            session_id="sess-1",
        )
        result = InterceptionResult(
            message_id="msg-001",
            sender_agent_id=sender,
            receiver_agent_id=receiver,
            action=action,
            reason="test",
            token_valid=True,
            signature_valid=True,
            nonce_valid=True,
            mtls_verified=True,
            enforcement_duration_ms=1.5,
        )
        return msg, result

    def test_record_audit(self):
        msg, result = self._make_message_and_result()
        record = self.audit.record(msg, result)
        assert record.sender_agent_id == "agent-A"
        assert record.receiver_agent_id == "agent-B"
        assert record.action_taken == "allowed"
        assert record.signature_verified is True
        assert len(record.content_hash) > 0
        assert len(record.record_hash) > 0

    def test_audit_count(self):
        msg, result = self._make_message_and_result()
        self.audit.record(msg, result)
        self.audit.record(msg, result)
        assert self.audit.count() == 2

    def test_query_by_sender(self):
        msg1, result1 = self._make_message_and_result(sender="agent-A")
        msg2, result2 = self._make_message_and_result(sender="agent-B", receiver="agent-C")
        self.audit.record(msg1, result1)
        self.audit.record(msg2, result2)
        records = self.audit.get_records(sender_agent_id="agent-A")
        assert len(records) == 1
        assert records[0].sender_agent_id == "agent-A"

    def test_query_by_action(self):
        msg1, result1 = self._make_message_and_result(action=MessageAction.ALLOWED)
        msg2, result2 = self._make_message_and_result(
            action=MessageAction.REJECTED_UNREGISTERED
        )
        self.audit.record(msg1, result1)
        self.audit.record(msg2, result2)
        records = self.audit.get_records(action="rejected_unregistered")
        assert len(records) == 1

    def test_hash_chain_integrity(self):
        for i in range(5):
            msg, result = self._make_message_and_result()
            self.audit.record(msg, result)
        integrity = self.audit.verify_chain_integrity()
        assert integrity["valid"] is True
        assert integrity["checked"] == 5

    def test_hash_chain_tamper_detection(self):
        msg, result = self._make_message_and_result()
        self.audit.record(msg, result)
        self.audit.record(msg, result)
        # Tamper with first record's hash
        self.audit._records[0].record_hash = "tampered"
        integrity = self.audit.verify_chain_integrity()
        assert integrity["valid"] is False

    def test_get_record_by_id(self):
        msg, result = self._make_message_and_result()
        record = self.audit.record(msg, result)
        found = self.audit.get_record_by_id(record.record_id)
        assert found is not None
        assert found.record_id == record.record_id

    def test_get_record_not_found(self):
        assert self.audit.get_record_by_id("nonexistent") is None

    def test_stats(self):
        msg1, result1 = self._make_message_and_result(action=MessageAction.ALLOWED)
        msg2, result2 = self._make_message_and_result(
            action=MessageAction.REJECTED_REPLAY
        )
        self.audit.record(msg1, result1)
        self.audit.record(msg2, result2)
        stats = self.audit.get_stats()
        assert stats["total_records"] == 2
        assert "allowed" in stats["actions"]

    def test_singleton_reset(self):
        a1 = get_a2a_audit_log()
        reset_a2a_audit_log()
        a2 = get_a2a_audit_log()
        assert a1 is not a2


# ── A2A Interceptor Tests ────────────────────────────────────────────────

from app.services.a2a.interceptor import (
    A2AInterceptor,
    get_a2a_interceptor,
    reset_a2a_interceptor,
)


class TestA2AInterceptor:
    """Tests for the central A2A message interception layer."""

    def setup_method(self):
        self.issuer = AgentTokenIssuer(master_secret="test-secret")
        self.verifier = MessageSignatureVerifier(nonce_ttl_seconds=60)
        self.mtls = MTLSEnforcer()
        self.audit = A2AAuditLog()

        self.interceptor = A2AInterceptor(
            token_issuer=self.issuer,
            signature_verifier=self.verifier,
            mtls_enforcer=self.mtls,
            audit_log=self.audit,
        )

        # Register agents
        self.issuer.register_agent(
            "agent-A",
            allowed_downstream=["agent-B"],
            permission_scope=["read", "write"],
        )
        self.issuer.register_agent(
            "agent-B",
            allowed_downstream=["agent-A"],
        )

        # Register signing secrets with verifier
        self.verifier.register_secret(
            "agent-A", self.issuer.get_signing_secret("agent-A")
        )
        self.verifier.register_secret(
            "agent-B", self.issuer.get_signing_secret("agent-B")
        )

        # Issue certificates
        self.mtls.issue_certificate("agent-A")
        self.mtls.issue_certificate("agent-B")

    def _make_valid_message(self, sender="agent-A", receiver="agent-B"):
        token = self.issuer.issue_token(sender)
        cert = self.mtls.get_certificate(sender)

        msg = A2AMessage(
            sender_agent_id=sender,
            receiver_agent_id=receiver,
            content="perform task X",
            message_type="task",
            framework="langgraph",
            session_id="sess-1",
            jwt_token=token.token,
            nonce=f"nonce-{time.time()}-{id(self)}",
            timestamp=time.time(),
            mtls_verified=True,
            sender_cert_fingerprint=cert.cert_fingerprint,
        )
        msg.signature = self.verifier.compute_signature(msg)
        return msg

    def test_fully_valid_message_allowed(self):
        msg = self._make_valid_message()
        result = self.interceptor.intercept(msg)
        assert result.action == MessageAction.ALLOWED
        assert result.token_valid is True
        assert result.signature_valid is True
        assert result.nonce_valid is True
        assert result.mtls_verified is True

    def test_unregistered_agent_rejected(self):
        """A2A message from unregistered agent should be rejected."""
        msg = A2AMessage(
            sender_agent_id="agent-UNKNOWN",
            receiver_agent_id="agent-B",
            content="malicious task",
            jwt_token="fake-token",
            nonce="n1",
            timestamp=time.time(),
        )
        result = self.interceptor.intercept(msg)
        assert result.action == MessageAction.REJECTED_UNREGISTERED
        assert result.token_valid is False

    def test_unregistered_agent_generates_audit_record(self):
        """Rejection of unregistered agent must create audit record."""
        msg = A2AMessage(
            sender_agent_id="agent-UNKNOWN",
            receiver_agent_id="agent-B",
            jwt_token="fake",
            nonce="n1",
        )
        self.interceptor.intercept(msg)
        records = self.audit.get_records(action="rejected_unregistered")
        assert len(records) == 1
        assert records[0].sender_agent_id == "agent-UNKNOWN"
        assert records[0].action_taken == "rejected_unregistered"

    def test_expired_token_rejected(self):
        # Re-register with 0 TTL
        self.issuer.register_agent("agent-C", token_ttl_seconds=0)
        self.verifier.register_secret(
            "agent-C", self.issuer.get_signing_secret("agent-C")
        )
        token = self.issuer.issue_token("agent-C")
        time.sleep(0.1)

        msg = A2AMessage(
            sender_agent_id="agent-C",
            receiver_agent_id="agent-B",
            jwt_token=token.token,
            nonce="n1",
            timestamp=time.time(),
        )
        result = self.interceptor.intercept(msg)
        assert result.action == MessageAction.REJECTED_EXPIRED_TOKEN

    def test_scope_violation_rejected(self):
        """Agent-A can only message agent-B; messaging agent-C should fail."""
        self.issuer.register_agent("agent-C")
        msg = self._make_valid_message(sender="agent-A", receiver="agent-C")
        result = self.interceptor.intercept(msg)
        assert result.action == MessageAction.REJECTED_SCOPE_VIOLATION

    def test_invalid_signature_rejected(self):
        msg = self._make_valid_message()
        msg.signature = "invalid_signature_value"
        result = self.interceptor.intercept(msg)
        assert result.action == MessageAction.REJECTED_INVALID_SIGNATURE

    def test_replay_attack_blocked(self):
        """Reusing a nonce should be blocked."""
        msg1 = self._make_valid_message()
        # Fix nonce for replay
        msg1.nonce = "fixed-replay-nonce"
        msg1.signature = self.verifier.compute_signature(msg1)

        result1 = self.interceptor.intercept(msg1)
        assert result1.action == MessageAction.ALLOWED

        # Replay with same nonce
        msg2 = self._make_valid_message()
        msg2.nonce = "fixed-replay-nonce"
        msg2.signature = self.verifier.compute_signature(msg2)

        result2 = self.interceptor.intercept(msg2)
        assert result2.action == MessageAction.REJECTED_REPLAY
        assert result2.nonce_valid is False

    def test_mtls_required_but_not_established(self):
        self.mtls.set_global_mtls_required(True)
        token = self.issuer.issue_token("agent-A")

        msg = A2AMessage(
            sender_agent_id="agent-A",
            receiver_agent_id="agent-B",
            content="task",
            jwt_token=token.token,
            nonce=f"nonce-{time.time()}",
            timestamp=time.time(),
            mtls_verified=False,  # mTLS not established
        )
        msg.signature = self.verifier.compute_signature(msg)
        result = self.interceptor.intercept(msg)
        assert result.action == MessageAction.REJECTED_MTLS_REQUIRED

    def test_all_intercepted_messages_audited(self):
        """Every intercepted message should generate an audit record."""
        # Valid message
        msg1 = self._make_valid_message()
        self.interceptor.intercept(msg1)

        # Invalid message
        msg2 = A2AMessage(
            sender_agent_id="agent-UNKNOWN",
            receiver_agent_id="agent-B",
            jwt_token="bad",
        )
        self.interceptor.intercept(msg2)

        assert self.audit.count() == 2

    def test_stats_tracking(self):
        msg = self._make_valid_message()
        self.interceptor.intercept(msg)
        stats = self.interceptor.get_stats()
        assert stats["total_intercepted"] == 1
        assert stats["allowed"] == 1

    def test_singleton_reset(self):
        i1 = get_a2a_interceptor()
        reset_a2a_interceptor()
        i2 = get_a2a_interceptor()
        assert i1 is not i2


# ── Acceptance Criteria Tests ────────────────────────────────────────────


class TestSprint27AcceptanceCriteria:
    """Tests validating Sprint 27 acceptance criteria."""

    def setup_method(self):
        self.issuer = AgentTokenIssuer(master_secret="acceptance-test")
        self.verifier = MessageSignatureVerifier(nonce_ttl_seconds=60)
        self.mtls = MTLSEnforcer()
        self.audit = A2AAuditLog()

        self.interceptor = A2AInterceptor(
            token_issuer=self.issuer,
            signature_verifier=self.verifier,
            mtls_enforcer=self.mtls,
            audit_log=self.audit,
        )

    def test_ac1_unregistered_agent_rejected_with_audit_record(self):
        """AC: A2A message from unregistered agent rejected with audit
        record in all test scenarios."""
        # Scenario 1: Completely unknown agent
        msg = A2AMessage(
            sender_agent_id="rogue-agent",
            receiver_agent_id="agent-B",
            content="steal data",
            jwt_token="forged-token.payload.sig",
            nonce="n1",
        )
        result = self.interceptor.intercept(msg)
        assert result.action == MessageAction.REJECTED_UNREGISTERED

        # Verify audit record exists
        records = self.audit.get_records(sender_agent_id="rogue-agent")
        assert len(records) == 1
        assert records[0].action_taken == "rejected_unregistered"
        assert records[0].token_valid is False

        # Scenario 2: Deactivated agent
        self.issuer.register_agent("agent-D")
        self.issuer.unregister_agent("agent-D")
        msg2 = A2AMessage(
            sender_agent_id="agent-D",
            receiver_agent_id="agent-B",
            content="task",
            jwt_token="fake.token.sig",
            nonce="n2",
        )
        result2 = self.interceptor.intercept(msg2)
        assert result2.action == MessageAction.REJECTED_UNREGISTERED

        records2 = self.audit.get_records(sender_agent_id="agent-D")
        assert len(records2) == 1
        assert records2[0].action_taken == "rejected_unregistered"

    def test_ac2_replay_attack_blocked(self):
        """AC: Replay attack (reused nonce) blocked correctly."""
        # Register legitimate agents
        self.issuer.register_agent("agent-A", allowed_downstream=["agent-B"])
        self.issuer.register_agent("agent-B")
        self.verifier.register_secret(
            "agent-A", self.issuer.get_signing_secret("agent-A")
        )

        token = self.issuer.issue_token("agent-A")

        # First message with nonce
        msg = A2AMessage(
            sender_agent_id="agent-A",
            receiver_agent_id="agent-B",
            content="legitimate task",
            jwt_token=token.token,
            nonce="unique-nonce-42",
            timestamp=time.time(),
        )
        msg.signature = self.verifier.compute_signature(msg)
        result1 = self.interceptor.intercept(msg)
        assert result1.action == MessageAction.ALLOWED

        # Replay: exact same nonce reused (attacker intercepted message)
        replay_msg = A2AMessage(
            sender_agent_id="agent-A",
            receiver_agent_id="agent-B",
            content="legitimate task",
            jwt_token=token.token,
            nonce="unique-nonce-42",  # Same nonce!
            timestamp=time.time(),
        )
        replay_msg.signature = self.verifier.compute_signature(replay_msg)
        result2 = self.interceptor.intercept(replay_msg)
        assert result2.action == MessageAction.REJECTED_REPLAY
        assert result2.nonce_valid is False

        # Verify both messages are audited
        assert self.audit.count() == 2

    def test_ac3_mtls_enforced_langgraph_integration(self):
        """AC: mTLS enforced between agents in LangGraph multi-agent
        integration test."""
        # Register agents for LangGraph workflow
        self.issuer.register_agent(
            "lg-planner", allowed_downstream=["lg-executor", "lg-reviewer"]
        )
        self.issuer.register_agent(
            "lg-executor", allowed_downstream=["lg-reviewer"]
        )
        self.issuer.register_agent(
            "lg-reviewer", allowed_downstream=["lg-planner"]
        )

        for agent_id in ["lg-planner", "lg-executor", "lg-reviewer"]:
            self.verifier.register_secret(
                agent_id, self.issuer.get_signing_secret(agent_id)
            )
            self.mtls.issue_certificate(agent_id)

        # Add mTLS policy for LangGraph workflow
        self.mtls.add_policy(
            workflow_id="langgraph-workflow-1",
            agent_pairs=[
                ("lg-planner", "lg-executor"),
                ("lg-executor", "lg-reviewer"),
                ("lg-reviewer", "lg-planner"),
            ],
            framework="langgraph",
            required=True,
        )

        # Message WITH mTLS should pass
        token = self.issuer.issue_token("lg-planner")
        cert = self.mtls.get_certificate("lg-planner")
        msg_ok = A2AMessage(
            sender_agent_id="lg-planner",
            receiver_agent_id="lg-executor",
            content="plan step 1",
            framework="langgraph",
            jwt_token=token.token,
            nonce=f"nonce-{time.time()}-ok",
            timestamp=time.time(),
            mtls_verified=True,
            sender_cert_fingerprint=cert.cert_fingerprint,
        )
        msg_ok.signature = self.verifier.compute_signature(msg_ok)
        result_ok = self.interceptor.intercept(msg_ok)
        assert result_ok.action == MessageAction.ALLOWED
        assert result_ok.mtls_verified is True

        # Message WITHOUT mTLS should be rejected
        token2 = self.issuer.issue_token("lg-executor")
        msg_no_mtls = A2AMessage(
            sender_agent_id="lg-executor",
            receiver_agent_id="lg-reviewer",
            content="execute result",
            framework="langgraph",
            jwt_token=token2.token,
            nonce=f"nonce-{time.time()}-fail",
            timestamp=time.time(),
            mtls_verified=False,  # No mTLS!
        )
        msg_no_mtls.signature = self.verifier.compute_signature(msg_no_mtls)
        result_fail = self.interceptor.intercept(msg_no_mtls)
        assert result_fail.action == MessageAction.REJECTED_MTLS_REQUIRED

        # Verify audit trail for both
        assert self.audit.count() >= 2
        audit_integrity = self.audit.verify_chain_integrity()
        assert audit_integrity["valid"] is True


# ── Multi-Framework Tests ────────────────────────────────────────────────


class TestMultiFrameworkSupport:
    """Tests for LangGraph, AutoGen, and CrewAI framework support."""

    def setup_method(self):
        self.issuer = AgentTokenIssuer(master_secret="framework-test")
        self.verifier = MessageSignatureVerifier()
        self.audit = A2AAuditLog()
        self.interceptor = A2AInterceptor(
            token_issuer=self.issuer,
            signature_verifier=self.verifier,
            audit_log=self.audit,
        )

    def _register_and_send(self, sender, receiver, framework):
        self.issuer.register_agent(sender, allowed_downstream=[receiver])
        self.issuer.register_agent(receiver, allowed_downstream=[sender])
        self.verifier.register_secret(
            sender, self.issuer.get_signing_secret(sender)
        )
        token = self.issuer.issue_token(sender)
        msg = A2AMessage(
            sender_agent_id=sender,
            receiver_agent_id=receiver,
            content=f"{framework} task",
            framework=framework,
            jwt_token=token.token,
            nonce=f"nonce-{framework}-{time.time()}",
            timestamp=time.time(),
        )
        msg.signature = self.verifier.compute_signature(msg)
        return self.interceptor.intercept(msg)

    def test_langgraph_framework(self):
        result = self._register_and_send("lg-a", "lg-b", "langgraph")
        assert result.action == MessageAction.ALLOWED

    def test_autogen_framework(self):
        result = self._register_and_send("ag-a", "ag-b", "autogen")
        assert result.action == MessageAction.ALLOWED

    def test_crewai_framework(self):
        result = self._register_and_send("cr-a", "cr-b", "crewai")
        assert result.action == MessageAction.ALLOWED

    def test_audit_records_framework(self):
        self._register_and_send("fw-a", "fw-b", "langgraph")
        self._register_and_send("fw-c", "fw-d", "autogen")
        self._register_and_send("fw-e", "fw-f", "crewai")
        records = self.audit.get_records()
        frameworks = {r.framework for r in records}
        assert "langgraph" in frameworks
        assert "autogen" in frameworks
        assert "crewai" in frameworks
