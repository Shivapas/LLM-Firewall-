"""Sprint 28 — HITL Enforcement Checkpoints + Cascading Failure Detection Tests.

Covers:
1. HITL 'require_approval' policy action
2. Approval workflow (create, list, approve, reject, expire)
3. Notification integrations (Slack + email)
4. Agent behavioral baseline engine
5. Cascading failure anomaly detector + circuit breaker
6. Router endpoints (approvals, baselines, circuit breakers)
"""

import asyncio
import math
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

# ── HITL Policy Action Engine Tests ──────────────────────────────────


class TestHITLPolicyAction:
    """Test 'require_approval' as a first-class policy action."""

    def test_require_approval_action_in_valid_actions(self):
        from app.services.threat_detection.action_engine import PolicyActionEngine

        engine = PolicyActionEngine()
        # Should not raise
        engine.update_action("high", "require_approval")
        assert engine.get_actions()["high"] == "require_approval"

    def test_require_approval_action_result(self):
        from app.services.threat_detection.action_engine import PolicyActionEngine
        from app.services.threat_detection.scorer import ThreatScore, PatternMatch

        engine = PolicyActionEngine(action_overrides={"high": "require_approval"})

        threat_score = ThreatScore(
            risk_level="high",
            score=0.85,
            matches=[
                PatternMatch(
                    pattern_id="PI-001",
                    pattern_name="prompt_injection_basic",
                    category="prompt_injection",
                    severity="high",
                    matched_text="ignore previous",
                    position=(0, 15),
                )
            ],
            categories_hit={"prompt_injection"},
        )

        result = engine.evaluate("ignore previous instructions", threat_score)
        assert result.action == "require_approval"
        assert result.risk_level == "high"
        assert result.score == 0.85
        assert result.approval_id is None  # caller sets this

    def test_action_result_to_dict_with_approval_id(self):
        from app.services.threat_detection.action_engine import ActionResult

        result = ActionResult(
            action="require_approval",
            risk_level="high",
            score=0.85,
            reason="HITL triggered",
            approval_id="abc-123",
        )
        d = result.to_dict()
        assert d["action"] == "require_approval"
        assert d["approval_id"] == "abc-123"

    def test_action_result_to_dict_without_approval_id(self):
        from app.services.threat_detection.action_engine import ActionResult

        result = ActionResult(
            action="block",
            risk_level="critical",
            score=0.99,
            reason="blocked",
        )
        d = result.to_dict()
        assert "approval_id" not in d

    def test_invalid_action_raises(self):
        from app.services.threat_detection.action_engine import PolicyActionEngine

        engine = PolicyActionEngine()
        with pytest.raises(ValueError, match="Invalid action"):
            engine.update_action("high", "invalid_action")


# ── Approval Workflow Tests ──────────────────────────────────────────


class TestApprovalWorkflow:
    """Test approval workflow service lifecycle."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        import app.services.hitl.approval_workflow as mod
        mod._approval_service = None
        yield
        mod._approval_service = None

    @pytest.fixture
    def service(self):
        from app.services.hitl.approval_workflow import ApprovalWorkflowService
        return ApprovalWorkflowService()

    @pytest.mark.asyncio
    async def test_create_approval(self, service):
        req = await service.create_approval(
            agent_id="agent-1",
            tenant_id="tenant-1",
            action_description="Attempting tool call: delete_database",
            risk_context={"categories": ["privilege_escalation"]},
            risk_level="high",
            risk_score=0.88,
            matched_patterns=["PE-001"],
            timeout_seconds=60,
        )
        assert req.status == "pending"
        assert req.agent_id == "agent-1"
        assert req.risk_level == "high"
        assert service.pending_count() == 1

    @pytest.mark.asyncio
    async def test_list_pending(self, service):
        await service.create_approval(
            agent_id="a1", tenant_id="t1",
            action_description="action1",
            risk_context={}, risk_level="high", risk_score=0.8,
            matched_patterns=[],
        )
        await service.create_approval(
            agent_id="a2", tenant_id="t2",
            action_description="action2",
            risk_context={}, risk_level="medium", risk_score=0.5,
            matched_patterns=[],
        )
        all_pending = await service.list_pending()
        assert len(all_pending) == 2

        t1_pending = await service.list_pending(tenant_id="t1")
        assert len(t1_pending) == 1
        assert t1_pending[0].agent_id == "a1"

    @pytest.mark.asyncio
    async def test_approve_request(self, service):
        req = await service.create_approval(
            agent_id="agent-1", tenant_id="tenant-1",
            action_description="test", risk_context={},
            risk_level="high", risk_score=0.9, matched_patterns=["PI-001"],
        )
        approved = await service.approve(req.id, decided_by="admin@example.com", reason="Looks safe")
        assert approved is not None
        assert approved.status == "approved"
        assert approved.decided_by == "admin@example.com"
        assert approved.decided_at is not None
        assert service.pending_count() == 0
        assert service.history_count() == 1

    @pytest.mark.asyncio
    async def test_reject_request(self, service):
        req = await service.create_approval(
            agent_id="agent-1", tenant_id="tenant-1",
            action_description="test", risk_context={},
            risk_level="high", risk_score=0.9, matched_patterns=[],
        )
        rejected = await service.reject(req.id, decided_by="admin@example.com", reason="Too risky")
        assert rejected is not None
        assert rejected.status == "rejected"
        assert service.pending_count() == 0

    @pytest.mark.asyncio
    async def test_approve_nonexistent_returns_none(self, service):
        result = await service.approve("nonexistent-id", decided_by="admin")
        assert result is None

    @pytest.mark.asyncio
    async def test_reject_nonexistent_returns_none(self, service):
        result = await service.reject("nonexistent-id", decided_by="admin")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_approval_from_pending(self, service):
        req = await service.create_approval(
            agent_id="a1", tenant_id="t1",
            action_description="test", risk_context={},
            risk_level="high", risk_score=0.8, matched_patterns=[],
        )
        found = await service.get_approval(req.id)
        assert found is not None
        assert found.id == req.id

    @pytest.mark.asyncio
    async def test_get_approval_from_history(self, service):
        req = await service.create_approval(
            agent_id="a1", tenant_id="t1",
            action_description="test", risk_context={},
            risk_level="high", risk_score=0.8, matched_patterns=[],
        )
        await service.approve(req.id, decided_by="admin")
        found = await service.get_approval(req.id)
        assert found is not None
        assert found.status == "approved"

    @pytest.mark.asyncio
    async def test_expire_with_auto_block(self, service):
        """Test that expired approvals with fallback=block are marked expired."""
        req = await service.create_approval(
            agent_id="agent-1", tenant_id="tenant-1",
            action_description="test", risk_context={},
            risk_level="high", risk_score=0.9, matched_patterns=[],
            fallback_action="block", timeout_seconds=0,
        )
        # Force expiry by setting expires_at to past
        req.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        await service._expire_timed_out()
        assert service.pending_count() == 0
        assert service.history_count() == 1
        hist = service._history[0]
        assert hist.status == "expired"
        assert hist.decided_by == "system:auto-block"

    @pytest.mark.asyncio
    async def test_expire_with_auto_approve(self, service):
        """Test that expired approvals with fallback=auto-approve are auto-approved."""
        req = await service.create_approval(
            agent_id="agent-1", tenant_id="tenant-1",
            action_description="test", risk_context={},
            risk_level="medium", risk_score=0.5, matched_patterns=[],
            fallback_action="auto-approve", timeout_seconds=0,
        )
        req.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        await service._expire_timed_out()
        assert service.pending_count() == 0
        hist = service._history[0]
        assert hist.status == "approved"
        assert hist.decided_by == "system:auto-approve"

    @pytest.mark.asyncio
    async def test_to_dict_serialization(self, service):
        req = await service.create_approval(
            agent_id="a1", tenant_id="t1",
            action_description="Test action",
            risk_context={"key": "value"},
            risk_level="high", risk_score=0.88,
            matched_patterns=["PI-001", "PI-002"],
        )
        d = service.to_dict(req)
        assert d["agent_id"] == "a1"
        assert d["status"] == "pending"
        assert d["risk_score"] == 0.88
        assert isinstance(d["created_at"], str)

    @pytest.mark.asyncio
    async def test_notification_called_on_create(self):
        from app.services.hitl.approval_workflow import ApprovalWorkflowService

        mock_notifier = AsyncMock()
        mock_notifier.send_approval_notification = AsyncMock(return_value={"slack": True})
        service = ApprovalWorkflowService(notification_service=mock_notifier)

        await service.create_approval(
            agent_id="a1", tenant_id="t1",
            action_description="test", risk_context={},
            risk_level="high", risk_score=0.9, matched_patterns=[],
        )
        mock_notifier.send_approval_notification.assert_called_once()


# ── Notification Integration Tests ───────────────────────────────────


class TestNotificationIntegrations:
    """Test Slack and email notification channels."""

    def test_slack_payload_structure(self):
        from app.services.hitl.notification import SlackNotifier, SlackConfig

        config = SlackConfig(
            webhook_url="https://hooks.slack.com/test",
            channel="#approvals",
        )
        notifier = SlackNotifier(config)
        assert notifier.config.channel == "#approvals"
        assert notifier.config.bot_name == "Sphinx HITL Bot"

    @pytest.mark.asyncio
    async def test_slack_send_success(self):
        from app.services.hitl.notification import SlackNotifier, SlackConfig
        from app.services.hitl.approval_workflow import ApprovalRequestDTO

        config = SlackConfig(webhook_url="https://hooks.slack.com/test")
        notifier = SlackNotifier(config)

        req = ApprovalRequestDTO(
            id="test-id", agent_id="agent-1", tenant_id="tenant-1",
            action_description="delete_database",
            risk_context={"categories": ["privilege_escalation"]},
            risk_level="critical", risk_score=0.95,
            matched_patterns=["PE-001"],
            status="pending", fallback_action="block",
            timeout_seconds=300, notification_channels=["slack"],
        )

        with patch("app.services.hitl.notification.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await notifier.send(req)
            assert result is True
            mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_slack_send_failure(self):
        from app.services.hitl.notification import SlackNotifier, SlackConfig
        from app.services.hitl.approval_workflow import ApprovalRequestDTO

        config = SlackConfig(webhook_url="https://hooks.slack.com/test")
        notifier = SlackNotifier(config)

        req = ApprovalRequestDTO(
            id="test-id", agent_id="agent-1", tenant_id="tenant-1",
            action_description="test", risk_context={},
            risk_level="high", risk_score=0.8,
            matched_patterns=[], status="pending",
            fallback_action="block", timeout_seconds=300,
            notification_channels=["slack"],
        )

        with patch("app.services.hitl.notification.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 500
            mock_resp.text = "Internal Server Error"
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await notifier.send(req)
            assert result is False

    @pytest.mark.asyncio
    async def test_email_notifier_no_recipients(self):
        from app.services.hitl.notification import EmailNotifier, EmailConfig
        from app.services.hitl.approval_workflow import ApprovalRequestDTO

        config = EmailConfig(to_addresses=[])
        notifier = EmailNotifier(config)

        req = ApprovalRequestDTO(
            id="test-id", agent_id="agent-1", tenant_id="tenant-1",
            action_description="test", risk_context={},
            risk_level="high", risk_score=0.8,
            matched_patterns=[], status="pending",
            fallback_action="block", timeout_seconds=300,
            notification_channels=["email"],
        )
        result = await notifier.send(req)
        assert result is False

    @pytest.mark.asyncio
    async def test_notification_service_dispatch(self):
        from app.services.hitl.notification import NotificationService
        from app.services.hitl.approval_workflow import ApprovalRequestDTO

        mock_slack = AsyncMock()
        mock_slack.send = AsyncMock(return_value=True)
        mock_email = AsyncMock()
        mock_email.send = AsyncMock(return_value=True)

        svc = NotificationService(slack_notifier=mock_slack, email_notifier=mock_email)

        req = ApprovalRequestDTO(
            id="test-id", agent_id="agent-1", tenant_id="tenant-1",
            action_description="test", risk_context={},
            risk_level="high", risk_score=0.8,
            matched_patterns=[], status="pending",
            fallback_action="block", timeout_seconds=300,
            notification_channels=["slack", "email"],
        )

        results = await svc.send_approval_notification(req)
        assert results["slack"] is True
        assert results["email"] is True
        mock_slack.send.assert_called_once()
        mock_email.send.assert_called_once()


# ── Agent Behavioral Baseline Engine Tests ───────────────────────────


class TestAgentBehavioralBaseline:
    """Test behavioral baseline computation from agent events."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        import app.services.hitl.baseline_engine as mod
        mod._baseline_engine = None
        yield
        mod._baseline_engine = None

    @pytest.fixture
    def engine(self):
        from app.services.hitl.baseline_engine import AgentBehavioralBaselineEngine
        return AgentBehavioralBaselineEngine(
            observation_days=7,
            min_observations=5,  # lowered for testing
            ngram_size=2,
        )

    def test_record_event_starts_observation(self, engine):
        engine.record_event(
            agent_id="agent-1", tenant_id="t1",
            tool_calls=["search", "read"],
            output_tokens=100, api_call_count=1,
        )
        assert engine.event_count("agent-1") == 1
        assert engine.agent_count() == 1
        assert not engine.is_baseline_ready("agent-1")

    def test_baseline_not_ready_before_observation_period(self, engine):
        for i in range(10):
            engine.record_event(
                agent_id="agent-1", tenant_id="t1",
                tool_calls=["search", "read"],
                output_tokens=100 + i, api_call_count=1,
            )
        # Observation period hasn't elapsed (7 days), so baseline not ready
        assert not engine.is_baseline_ready("agent-1")

    def test_force_compute_baseline(self, engine):
        for i in range(10):
            engine.record_event(
                agent_id="agent-1", tenant_id="t1",
                tool_calls=["search", "read", "write"],
                output_tokens=100 + i * 10, api_call_count=2,
            )
        baseline = engine.force_compute_baseline("agent-1", "t1")
        assert baseline is not None
        assert baseline.is_ready is True
        assert baseline.total_observations == 10
        assert baseline.avg_output_volume > 0
        assert "search->read" in baseline.tool_call_ngrams
        assert "read->write" in baseline.tool_call_ngrams
        assert "search" in baseline.known_tools

    def test_force_compute_no_events(self, engine):
        result = engine.force_compute_baseline("nonexistent")
        assert result is None

    def test_baseline_stats_correctness(self, engine):
        volumes = [100, 200, 300, 400, 500]
        for v in volumes:
            engine.record_event(
                agent_id="a1", tenant_id="t1",
                output_tokens=v, api_call_count=1,
            )
        baseline = engine.force_compute_baseline("a1", "t1")
        assert baseline is not None
        expected_avg = sum(volumes) / len(volumes)
        assert abs(baseline.avg_output_volume - expected_avg) < 0.01
        # Std should be positive
        assert baseline.std_output_volume > 0

    def test_baseline_to_dict(self, engine):
        for i in range(5):
            engine.record_event(
                agent_id="a1", tenant_id="t1",
                tool_calls=["search", "read"],
                output_tokens=100, api_call_count=1,
            )
        baseline = engine.force_compute_baseline("a1", "t1")
        d = engine.baseline_to_dict(baseline)
        assert d["agent_id"] == "a1"
        assert d["is_ready"] is True
        assert isinstance(d["known_tools"], list)
        assert isinstance(d["tool_call_ngrams"], dict)

    def test_multiple_agents_independent(self, engine):
        engine.record_event(agent_id="a1", tenant_id="t1", output_tokens=100)
        engine.record_event(agent_id="a2", tenant_id="t2", output_tokens=200)
        assert engine.event_count("a1") == 1
        assert engine.event_count("a2") == 1
        assert engine.agent_count() == 2


# ── Cascading Failure Anomaly Detector Tests ─────────────────────────


class TestCascadingFailureAnomalyDetector:
    """Test anomaly detection and per-agent circuit breaker."""

    @pytest.fixture(autouse=True)
    def reset_singletons(self):
        import app.services.hitl.baseline_engine as bmod
        import app.services.hitl.anomaly_detector as amod
        bmod._baseline_engine = None
        amod._anomaly_detector = None
        yield
        bmod._baseline_engine = None
        amod._anomaly_detector = None

    @pytest.fixture
    def setup(self):
        from app.services.hitl.baseline_engine import AgentBehavioralBaselineEngine
        from app.services.hitl.anomaly_detector import CascadingFailureAnomalyDetector

        baseline_engine = AgentBehavioralBaselineEngine(
            observation_days=7, min_observations=5, ngram_size=2,
        )
        # Build a baseline
        for i in range(10):
            baseline_engine.record_event(
                agent_id="agent-1", tenant_id="t1",
                tool_calls=["search", "read"],
                output_tokens=100 + i,
                api_call_count=2,
            )
        baseline_engine.force_compute_baseline("agent-1", "t1")

        detector = CascadingFailureAnomalyDetector(
            baseline_engine=baseline_engine,
            anomaly_threshold=2.0,
            consecutive_anomalies_to_open=3,
            anomaly_window_seconds=300,
            recovery_timeout_seconds=5,
        )
        return baseline_engine, detector

    def test_normal_behavior_passes(self, setup):
        _, detector = setup
        result = detector.check(
            agent_id="agent-1",
            tool_calls=["search", "read"],
            output_tokens=105,
            api_call_count=2,
        )
        assert result.is_anomalous is False
        assert result.action == "allow"
        assert result.circuit_state == "closed"

    def test_volume_spike_detected(self, setup):
        _, detector = setup
        result = detector.check(
            agent_id="agent-1",
            tool_calls=["search", "read"],
            output_tokens=99999,  # massive spike
            api_call_count=2,
        )
        assert result.is_anomalous is True
        assert "volume_spike" in result.anomaly_types
        assert result.action == "alert"

    def test_unknown_tool_detected(self, setup):
        _, detector = setup
        result = detector.check(
            agent_id="agent-1",
            tool_calls=["search", "MALICIOUS_TOOL"],
            output_tokens=100,
            api_call_count=2,
        )
        assert result.is_anomalous is True
        assert "unknown_tool" in result.anomaly_types

    def test_pattern_deviation_detected(self, setup):
        _, detector = setup
        # The baseline only knows "search->read", not "read->search"
        result = detector.check(
            agent_id="agent-1",
            tool_calls=["read", "search"],
            output_tokens=100,
            api_call_count=2,
        )
        assert result.is_anomalous is True
        assert "pattern_deviation" in result.anomaly_types

    def test_circuit_breaker_opens_after_consecutive_anomalies(self, setup):
        _, detector = setup
        # Send 3 consecutive anomalies (threshold)
        for _ in range(3):
            result = detector.check(
                agent_id="agent-1",
                tool_calls=["EVIL_TOOL"],
                output_tokens=99999,
                api_call_count=100,
            )
        assert result.circuit_state == "open"
        assert result.action == "block"

    def test_circuit_breaker_blocks_when_open(self, setup):
        _, detector = setup
        # Open the breaker
        for _ in range(3):
            detector.check(
                agent_id="agent-1",
                tool_calls=["EVIL_TOOL"],
                output_tokens=99999,
                api_call_count=100,
            )
        # Now all requests should be blocked
        result = detector.check(
            agent_id="agent-1",
            tool_calls=["search", "read"],
            output_tokens=100,
            api_call_count=2,
        )
        assert result.is_anomalous is True
        assert result.action == "block"
        assert result.circuit_state == "open"

    def test_no_baseline_allows_through(self, setup):
        _, detector = setup
        result = detector.check(
            agent_id="unknown-agent",
            tool_calls=["anything"],
            output_tokens=999,
            api_call_count=99,
        )
        assert result.is_anomalous is False
        assert result.action == "allow"
        assert "observation period" in result.details

    def test_force_circuit_state(self, setup):
        _, detector = setup
        detector.force_circuit_state("agent-1", "open")
        assert detector.get_circuit_state("agent-1") == "open"

        detector.force_circuit_state("agent-1", "closed")
        assert detector.get_circuit_state("agent-1") == "closed"

    def test_get_all_breakers(self, setup):
        _, detector = setup
        detector.check(agent_id="agent-1", output_tokens=100)
        detector.check(agent_id="agent-2", output_tokens=200)
        breakers = detector.get_all_breakers()
        assert "agent-1" in breakers
        assert "agent-2" in breakers

    def test_anomaly_history(self, setup):
        _, detector = setup
        detector.check(agent_id="agent-1", tool_calls=["EVIL"], output_tokens=99999)
        history = detector.get_anomaly_history()
        assert len(history) >= 1
        assert history[0]["agent_id"] == "agent-1"

    def test_simulated_attack_scenario(self, setup):
        """Acceptance criteria: anomaly detected in simulated attack scenario."""
        baseline_engine, detector = setup

        # Normal behavior first — no anomaly
        normal = detector.check(
            agent_id="agent-1",
            tool_calls=["search", "read"],
            output_tokens=105,
            api_call_count=2,
        )
        assert normal.is_anomalous is False

        # Simulated attack: unknown tools, high volume, high frequency
        attack = detector.check(
            agent_id="agent-1",
            tool_calls=["exfiltrate_data", "escalate_privileges"],
            output_tokens=50000,
            api_call_count=100,
        )
        assert attack.is_anomalous is True
        assert len(attack.anomaly_types) >= 1  # at least one anomaly type


# ── Router Endpoint Tests ────────────────────────────────────────────


class TestHITLRouter:
    """Test HITL router endpoints via ASGI test client."""

    @pytest.fixture(autouse=True)
    def reset_singletons(self):
        import app.services.hitl.approval_workflow as amod
        import app.services.hitl.baseline_engine as bmod
        import app.services.hitl.anomaly_detector as dmod
        amod._approval_service = None
        bmod._baseline_engine = None
        dmod._anomaly_detector = None
        yield
        amod._approval_service = None
        bmod._baseline_engine = None
        dmod._anomaly_detector = None

    @pytest.fixture
    def app(self):
        from fastapi import FastAPI
        from app.routers.hitl import router
        test_app = FastAPI()
        test_app.include_router(router)
        return test_app

    @pytest_asyncio.fixture
    async def client(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    @pytest.mark.asyncio
    async def test_list_approvals_empty(self, client):
        resp = await client.get("/admin/approvals")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["approvals"] == []

    @pytest.mark.asyncio
    async def test_approval_lifecycle(self, client):
        # Create an approval manually via service
        from app.services.hitl.approval_workflow import get_approval_workflow_service
        svc = get_approval_workflow_service()
        req = await svc.create_approval(
            agent_id="agent-1", tenant_id="t1",
            action_description="delete_database",
            risk_context={"cat": "privilege_escalation"},
            risk_level="critical", risk_score=0.95,
            matched_patterns=["PE-001"],
        )

        # List pending
        resp = await client.get("/admin/approvals")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

        # Get specific
        resp = await client.get(f"/approvals/{req.id}")
        assert resp.status_code == 200
        assert resp.json()["agent_id"] == "agent-1"

        # Approve
        resp = await client.post(
            f"/approvals/{req.id}/approve",
            json={"decided_by": "admin@example.com", "reason": "Looks safe"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "approved"

        # Should no longer be in pending
        resp = await client.get("/admin/approvals")
        assert resp.json()["total"] == 0

    @pytest.mark.asyncio
    async def test_reject_approval(self, client):
        from app.services.hitl.approval_workflow import get_approval_workflow_service
        svc = get_approval_workflow_service()
        req = await svc.create_approval(
            agent_id="agent-1", tenant_id="t1",
            action_description="test", risk_context={},
            risk_level="high", risk_score=0.8, matched_patterns=[],
        )
        resp = await client.post(
            f"/approvals/{req.id}/reject",
            json={"decided_by": "admin", "reason": "Too risky"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "rejected"

    @pytest.mark.asyncio
    async def test_approve_nonexistent_404(self, client):
        resp = await client.post(
            "/approvals/nonexistent/approve",
            json={"decided_by": "admin"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_reject_nonexistent_404(self, client):
        resp = await client.post(
            "/approvals/nonexistent/reject",
            json={"decided_by": "admin"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_nonexistent_approval_404(self, client):
        resp = await client.get("/approvals/nonexistent-id")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_record_event_and_get_baseline(self, client):
        # Record events
        for i in range(5):
            resp = await client.post(
                "/admin/agents/agent-1/events",
                json={
                    "tenant_id": "t1",
                    "tool_calls": ["search", "read"],
                    "output_tokens": 100 + i * 10,
                    "api_call_count": 2,
                },
            )
            assert resp.status_code == 200

        # Baseline not ready yet (observation period not elapsed)
        resp = await client.get("/admin/agents/agent-1/baseline")
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_ready"] is False

    @pytest.mark.asyncio
    async def test_get_baseline_nonexistent_404(self, client):
        resp = await client.get("/admin/agents/nonexistent/baseline")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_check_agent_behavior(self, client):
        resp = await client.post(
            "/admin/agents/agent-1/check",
            json={
                "tool_calls": ["search", "read"],
                "output_tokens": 100,
                "api_call_count": 2,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "is_anomalous" in data
        assert "circuit_state" in data

    @pytest.mark.asyncio
    async def test_circuit_breaker_get_and_force(self, client):
        # Get default state
        resp = await client.get("/admin/hitl/agents/agent-1/circuit-breaker")
        assert resp.status_code == 200
        assert resp.json()["state"] == "closed"

        # Force to open
        resp = await client.post(
            "/admin/hitl/agents/agent-1/circuit-breaker",
            json={"state": "open"},
        )
        assert resp.status_code == 200
        assert resp.json()["state"] == "open"

        # Verify
        resp = await client.get("/admin/hitl/agents/agent-1/circuit-breaker")
        assert resp.json()["state"] == "open"

    @pytest.mark.asyncio
    async def test_force_invalid_state_400(self, client):
        resp = await client.post(
            "/admin/hitl/agents/agent-1/circuit-breaker",
            json={"state": "invalid"},
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_list_all_circuit_breakers(self, client):
        resp = await client.get("/admin/hitl/circuit-breakers")
        assert resp.status_code == 200
        assert "circuit_breakers" in resp.json()

    @pytest.mark.asyncio
    async def test_list_anomalies(self, client):
        resp = await client.get("/admin/hitl/anomalies")
        assert resp.status_code == 200
        assert "anomalies" in resp.json()


# ── Integration / Acceptance Tests ───────────────────────────────────


class TestSprint28Acceptance:
    """Acceptance criteria tests for Sprint 28."""

    @pytest.fixture(autouse=True)
    def reset_singletons(self):
        import app.services.hitl.approval_workflow as amod
        import app.services.hitl.baseline_engine as bmod
        import app.services.hitl.anomaly_detector as dmod
        amod._approval_service = None
        bmod._baseline_engine = None
        dmod._anomaly_detector = None
        yield
        amod._approval_service = None
        bmod._baseline_engine = None
        dmod._anomaly_detector = None

    @pytest.mark.asyncio
    async def test_hitl_approval_resume_within_5s(self):
        """Approved action resumes within 5 seconds of approval."""
        from app.services.hitl.approval_workflow import ApprovalWorkflowService

        service = ApprovalWorkflowService()
        req = await service.create_approval(
            agent_id="agent-1", tenant_id="t1",
            action_description="sensitive_operation",
            risk_context={}, risk_level="high", risk_score=0.9,
            matched_patterns=["PI-001"],
        )

        import time
        start = time.monotonic()
        approved = await service.approve(req.id, decided_by="admin")
        elapsed = time.monotonic() - start

        assert approved is not None
        assert approved.status == "approved"
        assert elapsed < 5.0  # Must complete within 5 seconds

    @pytest.mark.asyncio
    async def test_auto_block_on_timeout_expiry(self):
        """Auto-block fires correctly when approval timeout expires with no response."""
        from app.services.hitl.approval_workflow import ApprovalWorkflowService

        service = ApprovalWorkflowService()
        req = await service.create_approval(
            agent_id="agent-1", tenant_id="t1",
            action_description="test",
            risk_context={}, risk_level="high", risk_score=0.9,
            matched_patterns=[], fallback_action="block",
            timeout_seconds=0,
        )
        req.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await service._expire_timed_out()

        assert service.pending_count() == 0
        hist = service._history[0]
        assert hist.decided_by == "system:auto-block"

    def test_baseline_after_observation_period(self):
        """Agent behavioral baseline established after observation period."""
        from app.services.hitl.baseline_engine import AgentBehavioralBaselineEngine

        engine = AgentBehavioralBaselineEngine(
            observation_days=0,  # immediate for testing
            min_observations=10,
        )

        for i in range(15):
            engine.record_event(
                agent_id="agent-1", tenant_id="t1",
                tool_calls=["search", "read", "write"],
                output_tokens=100 + i * 5,
                api_call_count=2,
            )

        baseline = engine.get_baseline("agent-1")
        assert baseline is not None
        assert baseline.is_ready is True
        assert baseline.total_observations == 15
        assert len(baseline.tool_call_ngrams) > 0
        assert len(baseline.known_tools) == 3

    def test_anomaly_detected_in_simulated_attack(self):
        """Anomaly detected in simulated attack scenario."""
        from app.services.hitl.baseline_engine import AgentBehavioralBaselineEngine
        from app.services.hitl.anomaly_detector import CascadingFailureAnomalyDetector

        engine = AgentBehavioralBaselineEngine(
            observation_days=0, min_observations=10,
        )
        for i in range(20):
            engine.record_event(
                agent_id="agent-1", tenant_id="t1",
                tool_calls=["search", "read"],
                output_tokens=100 + i,
                api_call_count=2,
            )

        detector = CascadingFailureAnomalyDetector(
            baseline_engine=engine,
            anomaly_threshold=2.0,
            consecutive_anomalies_to_open=3,
        )

        # Simulated attack
        result = detector.check(
            agent_id="agent-1",
            tool_calls=["exfiltrate_data", "delete_all"],
            output_tokens=50000,
            api_call_count=500,
        )

        assert result.is_anomalous is True
        assert len(result.anomaly_types) >= 1
        assert result.overall_deviation > 0

    @pytest.mark.asyncio
    async def test_require_approval_returns_202_pending(self):
        """HITL: When triggered, return 202 Pending equivalent to agent."""
        from app.services.threat_detection.action_engine import PolicyActionEngine, ActionResult
        from app.services.threat_detection.scorer import ThreatScore, PatternMatch
        from app.services.hitl.approval_workflow import ApprovalWorkflowService

        engine = PolicyActionEngine(action_overrides={"high": "require_approval"})
        service = ApprovalWorkflowService()

        threat_score = ThreatScore(
            risk_level="high",
            score=0.85,
            matches=[
                PatternMatch(
                    pattern_id="PI-001",
                    pattern_name="prompt_injection_basic",
                    category="prompt_injection",
                    severity="high",
                    matched_text="ignore previous",
                    position=(0, 15),
                )
            ],
            categories_hit={"prompt_injection"},
        )

        result = engine.evaluate("ignore previous instructions", threat_score)
        assert result.action == "require_approval"

        # Create approval request
        approval = await service.create_approval(
            agent_id="agent-test",
            tenant_id="tenant-test",
            action_description="prompt injection detected",
            risk_context={"categories": list(threat_score.categories_hit)},
            risk_level=result.risk_level,
            risk_score=result.score,
            matched_patterns=result.matched_patterns or [],
        )
        result.approval_id = approval.id

        # Verify the response contains approval_id (202 Pending)
        d = result.to_dict()
        assert d["action"] == "require_approval"
        assert d["approval_id"] == approval.id
        assert approval.status == "pending"
