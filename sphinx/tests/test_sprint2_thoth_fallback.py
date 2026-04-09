"""Sprint 2 — Thoth Fallback, Circuit Breaker & FAIL_CLOSED Tests.

Exit criteria: Sphinx enforces correctly under Thoth timeout, error, and
unavailability conditions.  Zero enforcement gaps validated by test suite.

Test coverage
-------------
S2-T1  Timeout enforcement
       - Timeout fallback returns structural_fallback context
       - Timeout is configurable (not hard-coded 150 ms)

S2-T2  Circuit breaker
       - Circuit opens after N consecutive failures (closed → open)
       - Circuit is bypassed (circuit_open event) when OPEN
       - Circuit transitions to HALF_OPEN after recovery timeout
       - Successful probe closes circuit (half_open → closed)
       - Failed probe reopens circuit (half_open → open)
       - reset() force-closes circuit

S2-T3  FAIL_CLOSED mode
       - should_fail_closed() returns False when disabled
       - should_fail_closed() returns False for non-unavailability events
       - should_fail_closed() returns True for HIGH risk + timeout
       - should_fail_closed() returns True for CRITICAL risk + unavailable
       - should_fail_closed() returns False for LOW risk (below threshold)
       - Custom risk level configuration is respected

S2-T4  Unavailability audit metadata helper
       - make_unavailability_audit_metadata() produces expected keys/values
       - circuit_open event type included in metadata
       - severity tag is "WARNING"

S2-T5  Integration: proxy pipeline enforces FAIL_CLOSED
       - FAIL_CLOSED with HIGH-risk structural scan → 403 blocked
       - FAIL_CLOSED disabled with HIGH-risk → request allowed through
       - Circuit open → structural-only fallback, no 403 (FAIL_CLOSED off)
       - Dedicated unavailability audit event emitted on timeout

S2-T5  Integration: classify_prompt with circuit breaker
       - Circuit open: classify_prompt returns "circuit_open" without HTTP call
       - Failures accumulate: circuit opens at threshold
       - Success resets failure counter
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

# ---------------------------------------------------------------------------
# S2-T1: Timeout enforcement
# ---------------------------------------------------------------------------

class TestTimeoutEnforcement:
    """S2-T1: Configurable timeout falls back to structural_fallback context."""

    @pytest.mark.asyncio
    async def test_timeout_returns_structural_fallback(self):
        """asyncio.TimeoutError from Thoth → structural_fallback context."""
        from app.services.thoth import classifier

        mock_client = AsyncMock()
        mock_client.classify = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch.object(classifier, "get_thoth_client", return_value=mock_client), \
             patch.object(classifier, "get_thoth_circuit_breaker",
                          return_value=MagicMock(is_available=MagicMock(return_value=True),
                                                 record_failure=MagicMock(),
                                                 record_success=MagicMock())):
            ctx, event = await classifier.classify_prompt(
                b'{"messages":[{"role":"user","content":"hello"}]}',
                tenant_id="t1",
                timeout_ms=50,
            )

        assert event == "timeout"
        assert ctx is not None
        assert ctx.source == "structural_fallback"
        assert ctx.classification_model_version == "timeout"

    @pytest.mark.asyncio
    async def test_httpx_timeout_returns_structural_fallback(self):
        """httpx.TimeoutException → structural_fallback context."""
        from app.services.thoth import classifier

        mock_client = AsyncMock()
        mock_client.classify = AsyncMock(
            side_effect=httpx.TimeoutException("read timeout")
        )

        with patch.object(classifier, "get_thoth_client", return_value=mock_client), \
             patch.object(classifier, "get_thoth_circuit_breaker",
                          return_value=MagicMock(is_available=MagicMock(return_value=True),
                                                 record_failure=MagicMock(),
                                                 record_success=MagicMock())):
            ctx, event = await classifier.classify_prompt(
                b'{"messages":[{"role":"user","content":"hello"}]}',
                tenant_id="t1",
            )

        assert event == "timeout"
        assert ctx.source == "structural_fallback"

    @pytest.mark.asyncio
    async def test_timeout_records_failure_on_circuit_breaker(self):
        """Timeout event increments circuit breaker failure counter."""
        from app.services.thoth import classifier

        mock_cb = MagicMock()
        mock_cb.is_available.return_value = True
        mock_cb.record_failure = MagicMock()
        mock_cb.record_success = MagicMock()

        mock_client = AsyncMock()
        mock_client.classify = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch.object(classifier, "get_thoth_client", return_value=mock_client), \
             patch.object(classifier, "get_thoth_circuit_breaker", return_value=mock_cb):
            await classifier.classify_prompt(
                b'{"messages":[{"role":"user","content":"test"}]}',
                tenant_id="t1",
                circuit_breaker_enabled=True,
            )

        mock_cb.record_failure.assert_called_once()
        mock_cb.record_success.assert_not_called()


# ---------------------------------------------------------------------------
# S2-T2: Circuit breaker
# ---------------------------------------------------------------------------

class TestCircuitBreaker:
    """S2-T2: In-memory circuit breaker state machine."""

    def _make_cb(self, error_threshold=3, recovery_timeout_s=60.0):
        from app.services.thoth.circuit_breaker import ThothCircuitBreaker
        return ThothCircuitBreaker(
            error_threshold=error_threshold,
            recovery_timeout_s=recovery_timeout_s,
        )

    def test_initial_state_is_closed(self):
        cb = self._make_cb()
        assert cb.state.value == "closed"
        assert cb.is_available() is True

    def test_opens_after_threshold_failures(self):
        cb = self._make_cb(error_threshold=3)
        cb.record_failure()
        cb.record_failure()
        assert cb.is_available() is True  # still closed at 2 failures
        cb.record_failure()               # 3rd failure → open
        assert cb.state.value == "open"
        assert cb.is_available() is False

    def test_success_resets_failure_counter(self):
        cb = self._make_cb(error_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()               # reset counter
        cb.record_failure()
        cb.record_failure()               # only 2 after reset
        assert cb.state.value == "closed"  # not yet opened

    def test_open_circuit_transitions_to_half_open(self):
        """After recovery_timeout_s the circuit moves to HALF_OPEN."""
        cb = self._make_cb(error_threshold=1, recovery_timeout_s=0.05)
        cb.record_failure()               # opens immediately
        assert cb.state.value == "open"

        time.sleep(0.1)                   # wait past recovery window
        assert cb.is_available() is True  # should now be half_open
        assert cb.state.value == "half_open"

    def test_successful_probe_closes_circuit(self):
        cb = self._make_cb(error_threshold=1, recovery_timeout_s=0.05)
        cb.record_failure()
        time.sleep(0.1)
        assert cb.state.value == "half_open"

        cb.record_success()               # probe succeeds
        assert cb.state.value == "closed"
        assert cb.is_available() is True

    def test_failed_probe_reopens_circuit(self):
        cb = self._make_cb(error_threshold=1, recovery_timeout_s=0.05)
        cb.record_failure()
        time.sleep(0.1)
        assert cb.state.value == "half_open"

        cb.record_failure()               # probe fails → reopen
        assert cb.state.value == "open"
        assert cb.is_available() is False

    def test_reset_force_closes_open_circuit(self):
        cb = self._make_cb(error_threshold=1)
        cb.record_failure()
        assert cb.state.value == "open"

        cb.reset()
        assert cb.state.value == "closed"
        assert cb.is_available() is True

    def test_get_status_returns_snapshot(self):
        cb = self._make_cb(error_threshold=5)
        cb.record_failure()
        cb.record_failure()
        status = cb.get_status()

        assert status["state"] == "closed"
        assert status["failure_count"] == 2
        assert status["error_threshold"] == 5

    def test_singleton_get_returns_same_instance(self):
        from app.services.thoth.circuit_breaker import (
            get_thoth_circuit_breaker,
            initialize_thoth_circuit_breaker,
        )
        cb1 = initialize_thoth_circuit_breaker(error_threshold=7, recovery_timeout_s=45.0)
        cb2 = get_thoth_circuit_breaker()
        assert cb1 is cb2

    def test_initialize_configures_thresholds(self):
        from app.services.thoth.circuit_breaker import initialize_thoth_circuit_breaker
        cb = initialize_thoth_circuit_breaker(error_threshold=10, recovery_timeout_s=120.0)
        assert cb._error_threshold == 10
        assert cb._recovery_timeout_s == 120.0


class TestCircuitBreakerIntegrationWithClassifier:
    """S2-T2: classify_prompt consults and updates circuit breaker."""

    @pytest.mark.asyncio
    async def test_circuit_open_returns_circuit_open_event(self):
        """When circuit is OPEN, classify_prompt returns 'circuit_open' immediately."""
        from app.services.thoth import classifier
        from app.services.thoth.circuit_breaker import ThothCircuitBreaker

        # Pre-opened circuit
        mock_cb = MagicMock(spec=ThothCircuitBreaker)
        mock_cb.is_available.return_value = False

        mock_client = AsyncMock()

        with patch.object(classifier, "get_thoth_client", return_value=mock_client), \
             patch.object(classifier, "get_thoth_circuit_breaker", return_value=mock_cb):
            ctx, event = await classifier.classify_prompt(
                b'{"messages":[{"role":"user","content":"test"}]}',
                tenant_id="t1",
                circuit_breaker_enabled=True,
            )

        assert event == "circuit_open"
        assert ctx.source == "structural_fallback"
        # Circuit breaker is open — Thoth HTTP client must NOT be called
        mock_client.classify.assert_not_called()

    @pytest.mark.asyncio
    async def test_success_calls_record_success_on_cb(self):
        """Successful Thoth call records success on circuit breaker."""
        from app.services.thoth import classifier
        from app.services.thoth.models import ClassificationContext

        mock_ctx = ClassificationContext(
            request_id="r-ok",
            intent="general_query",
            risk_level="LOW",
            confidence=0.9,
            pii_detected=False,
        )

        mock_cb = MagicMock()
        mock_cb.is_available.return_value = True
        mock_cb.record_success = MagicMock()
        mock_cb.record_failure = MagicMock()

        mock_client = AsyncMock()
        mock_client.classify = AsyncMock(return_value=mock_ctx)

        with patch.object(classifier, "get_thoth_client", return_value=mock_client), \
             patch.object(classifier, "get_thoth_circuit_breaker", return_value=mock_cb):
            ctx, event = await classifier.classify_prompt(
                b'{"messages":[{"role":"user","content":"hello"}]}',
                tenant_id="t1",
                circuit_breaker_enabled=True,
            )

        assert event == "classified"
        mock_cb.record_success.assert_called_once()
        mock_cb.record_failure.assert_not_called()

    @pytest.mark.asyncio
    async def test_unavailable_error_calls_record_failure_on_cb(self):
        """Connection error records failure on circuit breaker."""
        from app.services.thoth import classifier

        mock_cb = MagicMock()
        mock_cb.is_available.return_value = True
        mock_cb.record_failure = MagicMock()
        mock_cb.record_success = MagicMock()

        mock_client = AsyncMock()
        mock_client.classify = AsyncMock(
            side_effect=httpx.ConnectError("connection refused")
        )

        with patch.object(classifier, "get_thoth_client", return_value=mock_client), \
             patch.object(classifier, "get_thoth_circuit_breaker", return_value=mock_cb):
            ctx, event = await classifier.classify_prompt(
                b'{"messages":[{"role":"user","content":"hello"}]}',
                tenant_id="t1",
                circuit_breaker_enabled=True,
            )

        assert event == "unavailable"
        mock_cb.record_failure.assert_called_once()
        mock_cb.record_success.assert_not_called()

    @pytest.mark.asyncio
    async def test_circuit_breaker_disabled_skips_cb_check(self):
        """circuit_breaker_enabled=False: circuit breaker is never consulted."""
        from app.services.thoth import classifier
        from app.services.thoth.models import ClassificationContext

        mock_ctx = ClassificationContext(
            request_id="r-cb-off",
            intent="general_query",
            risk_level="LOW",
            confidence=0.85,
            pii_detected=False,
        )

        mock_cb = MagicMock()
        mock_cb.is_available.return_value = False  # would block if consulted

        mock_client = AsyncMock()
        mock_client.classify = AsyncMock(return_value=mock_ctx)

        with patch.object(classifier, "get_thoth_client", return_value=mock_client), \
             patch.object(classifier, "get_thoth_circuit_breaker", return_value=mock_cb):
            ctx, event = await classifier.classify_prompt(
                b'{"messages":[{"role":"user","content":"hello"}]}',
                tenant_id="t1",
                circuit_breaker_enabled=False,
            )

        assert event == "classified"
        mock_cb.is_available.assert_not_called()


# ---------------------------------------------------------------------------
# S2-T3: FAIL_CLOSED mode
# ---------------------------------------------------------------------------

class TestFailClosed:
    """S2-T3: should_fail_closed() evaluates FAIL_CLOSED policy."""

    def _call(self, event, risk, enabled=True, levels=None):
        from app.services.thoth.fail_closed import should_fail_closed
        kwargs = dict(
            classification_event=event,
            structural_risk_level=risk,
            fail_closed_enabled=enabled,
        )
        if levels is not None:
            kwargs["fail_closed_risk_levels"] = levels
        return should_fail_closed(**kwargs)

    def test_disabled_never_blocks(self):
        assert self._call("timeout", "HIGH", enabled=False) is False
        assert self._call("unavailable", "CRITICAL", enabled=False) is False
        assert self._call("circuit_open", "CRITICAL", enabled=False) is False

    def test_classified_event_does_not_block(self):
        """Even with fail_closed enabled, successful classification never triggers block."""
        assert self._call("classified", "HIGH") is False
        assert self._call("classified", "CRITICAL") is False

    def test_disabled_event_does_not_block(self):
        assert self._call("disabled", "CRITICAL") is False

    def test_no_content_event_does_not_block(self):
        assert self._call("no_content", "CRITICAL") is False

    def test_timeout_high_risk_blocks(self):
        assert self._call("timeout", "HIGH") is True

    def test_timeout_critical_risk_blocks(self):
        assert self._call("timeout", "CRITICAL") is True

    def test_unavailable_high_risk_blocks(self):
        assert self._call("unavailable", "HIGH") is True

    def test_circuit_open_critical_blocks(self):
        assert self._call("circuit_open", "CRITICAL") is True

    def test_low_risk_does_not_block(self):
        assert self._call("timeout", "LOW") is False

    def test_medium_risk_does_not_block_by_default(self):
        """MEDIUM is not in the default set {HIGH, CRITICAL}."""
        assert self._call("timeout", "medium") is False

    def test_case_insensitive_risk_level(self):
        """Risk level comparison is case-insensitive."""
        assert self._call("timeout", "high") is True
        assert self._call("timeout", "High") is True
        assert self._call("timeout", "CRITICAL") is True

    def test_custom_risk_levels_respected(self):
        """Custom fail_closed_risk_levels overrides default."""
        # Include MEDIUM explicitly
        assert self._call("timeout", "MEDIUM", levels="MEDIUM,HIGH,CRITICAL") is True
        # Exclude HIGH from custom set
        assert self._call("timeout", "HIGH", levels="CRITICAL") is False

    def test_custom_levels_with_whitespace(self):
        """Whitespace around commas in configured levels is handled."""
        assert self._call("timeout", "HIGH", levels=" HIGH , CRITICAL ") is True


# ---------------------------------------------------------------------------
# S2-T4: Unavailability audit metadata helper
# ---------------------------------------------------------------------------

class TestUnavailabilityAuditMetadata:
    """S2-T4: make_unavailability_audit_metadata() builds correct audit payload."""

    def test_basic_fields_present(self):
        from app.services.thoth.classifier import make_unavailability_audit_metadata

        meta = make_unavailability_audit_metadata(
            classification_event="timeout",
            tenant_id="tenant-abc",
            trace_id="trace-xyz",
        )

        assert meta["event_type"] == "thoth_classification_unavailability"
        assert meta["classification_event"] == "timeout"
        assert meta["fallback_mode"] == "structural_only"
        assert meta["severity"] == "WARNING"
        assert meta["tenant_id"] == "tenant-abc"
        assert meta["trace_id"] == "trace-xyz"

    def test_fail_closed_flag_included(self):
        from app.services.thoth.classifier import make_unavailability_audit_metadata

        meta = make_unavailability_audit_metadata(
            classification_event="unavailable",
            tenant_id="t1",
            trace_id="r1",
            fail_closed_enabled=True,
        )
        assert meta["fail_closed_enabled"] is True

    def test_circuit_breaker_status_included(self):
        from app.services.thoth.classifier import make_unavailability_audit_metadata

        cb_status = {"state": "open", "failure_count": 5}
        meta = make_unavailability_audit_metadata(
            classification_event="circuit_open",
            tenant_id="t1",
            trace_id="r2",
            circuit_breaker_status=cb_status,
        )
        assert meta["circuit_breaker"]["state"] == "open"
        assert meta["circuit_breaker"]["failure_count"] == 5

    def test_circuit_open_event_type(self):
        from app.services.thoth.classifier import make_unavailability_audit_metadata

        meta = make_unavailability_audit_metadata(
            classification_event="circuit_open",
            tenant_id="t1",
            trace_id="r3",
        )
        assert meta["classification_event"] == "circuit_open"
        assert meta["event_type"] == "thoth_classification_unavailability"

    def test_no_circuit_breaker_defaults_to_empty_dict(self):
        from app.services.thoth.classifier import make_unavailability_audit_metadata

        meta = make_unavailability_audit_metadata(
            classification_event="unavailable",
            tenant_id="t1",
            trace_id="r4",
        )
        assert meta["circuit_breaker"] == {}


# ---------------------------------------------------------------------------
# S2-T5 Integration: proxy pipeline with FAIL_CLOSED and audit events
# ---------------------------------------------------------------------------

@pytest.fixture
def proxy_test_client():
    """Minimal FastAPI test client wiring only the proxy router."""
    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient

    with patch("app.services.threat_detection.engine.get_threat_engine"), \
         patch("app.services.data_shield.engine.get_data_shield_engine"), \
         patch("app.services.rag.pipeline.get_rag_pipeline"), \
         patch("app.services.routing_policy.get_routing_policy_evaluator"), \
         patch("app.services.budget_downgrade.get_budget_downgrade_service"):

        from app.routers.proxy import router as proxy_router

        mini_app = FastAPI()

        @mini_app.middleware("http")
        async def fake_auth(request: Request, call_next):
            request.state.tenant_id = "test-tenant"
            request.state.project_id = "test-project"
            request.state.api_key_id = "key-001"
            request.state.tpm_limit = 100000
            request.state.risk_score = 0.0
            return await call_next(request)

        mini_app.include_router(proxy_router)
        yield TestClient(mini_app)


def _base_pipeline_patches():
    """Common pipeline service mocks reused across proxy integration tests."""
    from app.services.rag.classifier import RequestType
    from app.services.routing_policy import RoutingAction

    mock_rag_result = MagicMock()
    mock_rag_result.allowed = True
    mock_rag_result.classification = MagicMock()
    mock_rag_result.classification.request_type = RequestType.STANDARD_CHAT
    mock_rag_result.to_dict = MagicMock(return_value={})

    mock_rag_pipeline = MagicMock()
    mock_rag_pipeline.process = MagicMock(return_value=(b"", mock_rag_result))

    mock_action = MagicMock()
    mock_action.action = "allow"
    mock_action.risk_level = "high"  # structural risk is HIGH for FAIL_CLOSED tests
    mock_action.score = 0.8
    mock_action.reason = "ok"
    mock_action.matched_patterns = []
    mock_action.rewritten_text = None

    mock_shield_result = MagicMock()
    mock_shield_result.redaction = MagicMock()
    mock_shield_result.redaction.redaction_count = 0
    mock_shield_result.pii_count = 0
    mock_shield_result.phi_count = 0
    mock_shield_result.credential_count = 0
    mock_shield_result.to_dict = MagicMock(return_value={})

    mock_threat_engine = MagicMock()
    mock_threat_engine.scan_request_body_with_escalation = MagicMock(
        return_value=(mock_action, None)
    )

    mock_data_shield = MagicMock()
    mock_data_shield.scan_request_body = MagicMock(return_value=(b"", mock_shield_result))

    mock_routing_decision = MagicMock()
    mock_routing_decision.action = RoutingAction.DEFAULT
    mock_routing_decision.to_dict = MagicMock(return_value={})

    mock_evaluator = MagicMock()
    mock_evaluator.evaluate = MagicMock(return_value=mock_routing_decision)

    mock_budget_svc = MagicMock()
    mock_budget_svc.is_budget_exceeded = MagicMock(return_value=False)
    mock_budget_svc.get_budget_usage_pct = MagicMock(return_value=0.0)

    return {
        "rag_pipeline": mock_rag_pipeline,
        "threat_engine": mock_threat_engine,
        "data_shield": mock_data_shield,
        "evaluator": mock_evaluator,
        "budget_svc": mock_budget_svc,
    }


def _mock_settings(*, thoth_enabled=True, fail_closed_enabled=False,
                   fail_closed_risk_levels="HIGH,CRITICAL",
                   circuit_breaker_enabled=True):
    s = MagicMock()
    s.thoth_enabled = thoth_enabled
    s.thoth_timeout_ms = 150
    s.thoth_circuit_breaker_enabled = circuit_breaker_enabled
    s.thoth_fail_closed_enabled = fail_closed_enabled
    s.thoth_fail_closed_risk_levels = fail_closed_risk_levels
    s.default_provider_url = "http://mock-llm:9000"
    s.allowed_provider_hosts = ""
    return s


def _ok_upstream():
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-test",
            "choices": [
                {"message": {"role": "assistant", "content": "Hello!"}, "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
        },
    )


class TestProxyFailClosedIntegration:
    """S2-T5: proxy pipeline enforces FAIL_CLOSED under various conditions."""

    def test_fail_closed_on_timeout_with_high_structural_risk_blocks_request(
        self, proxy_test_client
    ):
        """FAIL_CLOSED enabled + timeout + HIGH structural risk → 403."""
        from app.services.thoth.models import make_timeout_context
        from app.services.thoth.circuit_breaker import ThothCircuitBreaker

        timeout_ctx = make_timeout_context("trace-fc-1")
        patches = _base_pipeline_patches()
        settings = _mock_settings(fail_closed_enabled=True)

        audit_events = []

        async def capture_audit(**kwargs):
            audit_events.append(dict(action=kwargs.get("action"), metadata=kwargs.get("metadata")))

        mock_cb = MagicMock(spec=ThothCircuitBreaker)
        mock_cb.get_status.return_value = {"state": "closed", "failure_count": 0}

        with patch("app.routers.proxy.get_settings", return_value=settings), \
             patch("app.routers.proxy.classify_prompt",
                   new=AsyncMock(return_value=(timeout_ctx, "timeout"))), \
             patch("app.routers.proxy.get_thoth_circuit_breaker", return_value=mock_cb), \
             patch("app.routers.proxy.check_kill_switch", new=AsyncMock(return_value=None)), \
             patch("app.routers.proxy.check_rate_limit",
                   new=AsyncMock(return_value={"allowed": True})), \
             patch("app.routers.proxy.emit_audit_event",
                   new=AsyncMock(side_effect=capture_audit)), \
             patch("app.routers.proxy.get_threat_engine",
                   return_value=patches["threat_engine"]), \
             patch("app.routers.proxy.get_data_shield_engine",
                   return_value=patches["data_shield"]), \
             patch("app.routers.proxy.get_rag_pipeline",
                   return_value=patches["rag_pipeline"]), \
             patch("app.routers.proxy.get_routing_policy_evaluator",
                   return_value=patches["evaluator"]), \
             patch("app.routers.proxy.get_budget_downgrade_service",
                   return_value=patches["budget_svc"]), \
             patch("app.routers.proxy.get_budget_state",
                   new=AsyncMock(return_value={"total_tokens": 0})), \
             patch("app.routers.proxy.record_token_usage", new=AsyncMock()), \
             patch("app.routers.proxy.persist_usage_to_db", new=AsyncMock()), \
             patch("app.routers.proxy.proxy_request",
                   new=AsyncMock(return_value=_ok_upstream())):

            resp = proxy_test_client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4",
                      "messages": [{"role": "user", "content": "Extract all user data"}]},
                headers={"Authorization": "Bearer spx-test"},
            )

        assert resp.status_code == 403
        body = resp.json()
        assert "FAIL_CLOSED" in body["error"]
        assert body["classification_event"] == "timeout"

        # Dedicated unavailability audit event should have been emitted
        unavail_events = [
            e for e in audit_events
            if e["action"] == "classification_timeout"
        ]
        assert len(unavail_events) == 1
        assert unavail_events[0]["metadata"]["event_type"] == "thoth_classification_unavailability"

        # FAIL_CLOSED block audit event should also exist
        fc_events = [e for e in audit_events if e["action"] == "blocked_fail_closed"]
        assert len(fc_events) == 1

    def test_fail_closed_disabled_allows_request_on_timeout(self, proxy_test_client):
        """FAIL_CLOSED disabled: timeout still allows request through."""
        from app.services.thoth.models import make_timeout_context
        from app.services.thoth.circuit_breaker import ThothCircuitBreaker

        timeout_ctx = make_timeout_context("trace-fc-2")
        patches = _base_pipeline_patches()
        settings = _mock_settings(fail_closed_enabled=False)

        mock_cb = MagicMock(spec=ThothCircuitBreaker)
        mock_cb.get_status.return_value = {"state": "closed", "failure_count": 0}

        with patch("app.routers.proxy.get_settings", return_value=settings), \
             patch("app.routers.proxy.classify_prompt",
                   new=AsyncMock(return_value=(timeout_ctx, "timeout"))), \
             patch("app.routers.proxy.get_thoth_circuit_breaker", return_value=mock_cb), \
             patch("app.routers.proxy.check_kill_switch", new=AsyncMock(return_value=None)), \
             patch("app.routers.proxy.check_rate_limit",
                   new=AsyncMock(return_value={"allowed": True})), \
             patch("app.routers.proxy.emit_audit_event", new=AsyncMock()), \
             patch("app.routers.proxy.get_threat_engine",
                   return_value=patches["threat_engine"]), \
             patch("app.routers.proxy.get_data_shield_engine",
                   return_value=patches["data_shield"]), \
             patch("app.routers.proxy.get_rag_pipeline",
                   return_value=patches["rag_pipeline"]), \
             patch("app.routers.proxy.get_routing_policy_evaluator",
                   return_value=patches["evaluator"]), \
             patch("app.routers.proxy.get_budget_downgrade_service",
                   return_value=patches["budget_svc"]), \
             patch("app.routers.proxy.get_budget_state",
                   new=AsyncMock(return_value={"total_tokens": 0})), \
             patch("app.routers.proxy.record_token_usage", new=AsyncMock()), \
             patch("app.routers.proxy.persist_usage_to_db", new=AsyncMock()), \
             patch("app.routers.proxy.proxy_request",
                   new=AsyncMock(return_value=_ok_upstream())):

            resp = proxy_test_client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4",
                      "messages": [{"role": "user", "content": "Hello"}]},
                headers={"Authorization": "Bearer spx-test"},
            )

        assert resp.status_code == 200

    def test_circuit_open_emits_dedicated_audit_event(self, proxy_test_client):
        """Circuit open emits dedicated classification_circuit_open audit event."""
        from app.services.thoth.models import make_unavailable_context
        from app.services.thoth.circuit_breaker import ThothCircuitBreaker

        circuit_ctx = make_unavailable_context("trace-co-1", reason="circuit_open")
        patches = _base_pipeline_patches()
        # LOW structural risk so FAIL_CLOSED (even if enabled) does not block
        patches["threat_engine"].scan_request_body_with_escalation.return_value[0].risk_level = "low"
        settings = _mock_settings(fail_closed_enabled=False)

        audit_events = []

        async def capture_audit(**kwargs):
            audit_events.append(dict(action=kwargs.get("action"), metadata=kwargs.get("metadata")))

        mock_cb = MagicMock(spec=ThothCircuitBreaker)
        mock_cb.get_status.return_value = {"state": "open", "failure_count": 5}

        with patch("app.routers.proxy.get_settings", return_value=settings), \
             patch("app.routers.proxy.classify_prompt",
                   new=AsyncMock(return_value=(circuit_ctx, "circuit_open"))), \
             patch("app.routers.proxy.get_thoth_circuit_breaker", return_value=mock_cb), \
             patch("app.routers.proxy.check_kill_switch", new=AsyncMock(return_value=None)), \
             patch("app.routers.proxy.check_rate_limit",
                   new=AsyncMock(return_value={"allowed": True})), \
             patch("app.routers.proxy.emit_audit_event",
                   new=AsyncMock(side_effect=capture_audit)), \
             patch("app.routers.proxy.get_threat_engine",
                   return_value=patches["threat_engine"]), \
             patch("app.routers.proxy.get_data_shield_engine",
                   return_value=patches["data_shield"]), \
             patch("app.routers.proxy.get_rag_pipeline",
                   return_value=patches["rag_pipeline"]), \
             patch("app.routers.proxy.get_routing_policy_evaluator",
                   return_value=patches["evaluator"]), \
             patch("app.routers.proxy.get_budget_downgrade_service",
                   return_value=patches["budget_svc"]), \
             patch("app.routers.proxy.get_budget_state",
                   new=AsyncMock(return_value={"total_tokens": 0})), \
             patch("app.routers.proxy.record_token_usage", new=AsyncMock()), \
             patch("app.routers.proxy.persist_usage_to_db", new=AsyncMock()), \
             patch("app.routers.proxy.proxy_request",
                   new=AsyncMock(return_value=_ok_upstream())):

            resp = proxy_test_client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4",
                      "messages": [{"role": "user", "content": "Hello"}]},
                headers={"Authorization": "Bearer spx-test"},
            )

        # Request should succeed (LOW structural risk, FAIL_CLOSED disabled)
        assert resp.status_code == 200

        # Dedicated unavailability audit event should be emitted
        circuit_events = [
            e for e in audit_events
            if e.get("action") == "classification_circuit_open"
        ]
        assert len(circuit_events) == 1
        meta = circuit_events[0]["metadata"]
        assert meta["classification_event"] == "circuit_open"
        assert meta["circuit_breaker"]["state"] == "open"

    def test_unavailability_audit_event_includes_fallback_mode(self, proxy_test_client):
        """Dedicated audit event includes fallback_mode=structural_only."""
        from app.services.thoth.models import make_unavailable_context
        from app.services.thoth.circuit_breaker import ThothCircuitBreaker

        unavail_ctx = make_unavailable_context("trace-ua-1")
        patches = _base_pipeline_patches()
        patches["threat_engine"].scan_request_body_with_escalation.return_value[0].risk_level = "low"
        settings = _mock_settings(fail_closed_enabled=False)

        audit_events = []

        async def capture_audit(**kwargs):
            audit_events.append(dict(action=kwargs.get("action"), metadata=kwargs.get("metadata")))

        mock_cb = MagicMock(spec=ThothCircuitBreaker)
        mock_cb.get_status.return_value = {"state": "closed", "failure_count": 2}

        with patch("app.routers.proxy.get_settings", return_value=settings), \
             patch("app.routers.proxy.classify_prompt",
                   new=AsyncMock(return_value=(unavail_ctx, "unavailable"))), \
             patch("app.routers.proxy.get_thoth_circuit_breaker", return_value=mock_cb), \
             patch("app.routers.proxy.check_kill_switch", new=AsyncMock(return_value=None)), \
             patch("app.routers.proxy.check_rate_limit",
                   new=AsyncMock(return_value={"allowed": True})), \
             patch("app.routers.proxy.emit_audit_event",
                   new=AsyncMock(side_effect=capture_audit)), \
             patch("app.routers.proxy.get_threat_engine",
                   return_value=patches["threat_engine"]), \
             patch("app.routers.proxy.get_data_shield_engine",
                   return_value=patches["data_shield"]), \
             patch("app.routers.proxy.get_rag_pipeline",
                   return_value=patches["rag_pipeline"]), \
             patch("app.routers.proxy.get_routing_policy_evaluator",
                   return_value=patches["evaluator"]), \
             patch("app.routers.proxy.get_budget_downgrade_service",
                   return_value=patches["budget_svc"]), \
             patch("app.routers.proxy.get_budget_state",
                   new=AsyncMock(return_value={"total_tokens": 0})), \
             patch("app.routers.proxy.record_token_usage", new=AsyncMock()), \
             patch("app.routers.proxy.persist_usage_to_db", new=AsyncMock()), \
             patch("app.routers.proxy.proxy_request",
                   new=AsyncMock(return_value=_ok_upstream())):

            resp = proxy_test_client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4",
                      "messages": [{"role": "user", "content": "Hello"}]},
                headers={"Authorization": "Bearer spx-test"},
            )

        assert resp.status_code == 200

        unavail_events = [
            e for e in audit_events
            if e.get("action") == "classification_unavailable"
        ]
        assert len(unavail_events) == 1
        assert unavail_events[0]["metadata"]["fallback_mode"] == "structural_only"
        assert unavail_events[0]["metadata"]["severity"] == "WARNING"
