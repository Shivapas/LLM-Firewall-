"""Sprint 13 tests — Provider Health Monitoring, Circuit Breaker, Failover & Cost Tracking.

Acceptance criteria:
- Provider health probe detects simulated error rate spike and fires alert within 60 seconds
- Circuit breaker opens on 5 consecutive failures; closes after successful probe with no traffic lost
- Cost dashboard shows accurate per-provider, per-tenant token consumption in real time
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ── Health Probe Tests ───────────────────────────────────────────────────


class TestProviderHealthProbe:
    """Provider health probe detects latency spikes, errors, and outages."""

    @pytest.mark.asyncio
    async def test_probe_healthy_provider(self):
        """Health probe returns healthy status for responsive provider."""
        from app.services.health_probe import ProviderHealthProbe

        probe = ProviderHealthProbe(AsyncMock(), interval=30)
        # Mock a successful HTTP response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        probe._client = AsyncMock()
        probe._client.get = AsyncMock(return_value=mock_resp)

        result = await probe.probe_provider("openai", "https://api.openai.com")

        assert result["provider_name"] == "openai"
        assert result["is_healthy"] is True
        assert result["status_code"] == 200
        assert result["latency_ms"] >= 0

    @pytest.mark.asyncio
    async def test_probe_unhealthy_provider(self):
        """Health probe detects server error (500+)."""
        from app.services.health_probe import ProviderHealthProbe

        probe = ProviderHealthProbe(AsyncMock(), interval=30)
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        probe._client = AsyncMock()
        probe._client.get = AsyncMock(return_value=mock_resp)

        result = await probe.probe_provider("openai", "https://api.openai.com")

        assert result["is_healthy"] is False
        assert result["status_code"] == 503
        assert "503" in result["error_message"]

    @pytest.mark.asyncio
    async def test_probe_timeout(self):
        """Health probe handles timeout gracefully."""
        import httpx
        from app.services.health_probe import ProviderHealthProbe

        probe = ProviderHealthProbe(AsyncMock(), interval=30)
        probe._client = AsyncMock()
        probe._client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        result = await probe.probe_provider("anthropic", "https://api.anthropic.com")

        assert result["is_healthy"] is False
        assert "Timeout" in result["error_message"]

    @pytest.mark.asyncio
    async def test_compute_error_rate(self):
        """Error rate computation over time window."""
        from app.services.health_probe import ProviderHealthProbe

        probe = ProviderHealthProbe(AsyncMock(), interval=30)
        mock_db = AsyncMock()

        # Simulate: 2 total checks, 1 failure
        total_result = MagicMock()
        total_result.scalar.return_value = 10
        error_result = MagicMock()
        error_result.scalar.return_value = 3

        mock_db.execute = AsyncMock(side_effect=[total_result, error_result])
        rate = await probe.compute_error_rate(mock_db, "openai", window_seconds=60)
        assert rate == pytest.approx(0.3, abs=0.01)

    @pytest.mark.asyncio
    async def test_fire_alert_on_error_spike(self):
        """Alert fires when error rate exceeds threshold."""
        from app.services.health_probe import ProviderHealthProbe

        probe = ProviderHealthProbe(AsyncMock(), interval=30)
        mock_redis = AsyncMock()

        with patch("app.services.health_probe.get_redis", return_value=mock_redis):
            await probe.fire_alert("openai", 0.75, "Error rate spike detected: 75%")

        mock_redis.publish.assert_called_once()
        call_args = mock_redis.publish.call_args
        assert call_args[0][0] == "sphinx:provider:alerts"
        payload = json.loads(call_args[0][1])
        assert payload["provider_name"] == "openai"
        assert payload["error_rate"] == 0.75


# ── Circuit Breaker Tests ────────────────────────────────────────────────


class TestCircuitBreaker:
    """Per-provider circuit breaker: open on failures, half-open probe, close on recovery."""

    @pytest.mark.asyncio
    async def test_initial_state_is_closed(self):
        """Circuit breaker starts in closed state."""
        from app.services.circuit_breaker import CircuitBreaker

        cb = CircuitBreaker("openai", failure_threshold=5, recovery_timeout=60)
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)

        state = await cb.get_state(mock_db)
        assert state["state"] == "closed"
        assert state["failure_count"] == 0

    @pytest.mark.asyncio
    async def test_opens_on_consecutive_failures(self):
        """Circuit breaker opens after 5 consecutive failures."""
        from app.services.circuit_breaker import CircuitBreaker, _cb_states

        cb = CircuitBreaker("test-provider", failure_threshold=5, recovery_timeout=60)
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()

        # Clear any stale state
        _cb_states.pop("test-provider", None)

        with patch("app.services.circuit_breaker.get_redis", return_value=AsyncMock()):
            # Record 5 consecutive failures
            for i in range(5):
                state = await cb.record_failure(mock_db)

            assert state["state"] == "open"
            assert state["failure_count"] == 5
            assert state["opened_at"] is not None

    @pytest.mark.asyncio
    async def test_half_open_after_recovery_timeout(self):
        """Circuit breaker transitions to half_open after recovery timeout."""
        from app.services.circuit_breaker import CircuitBreaker, _cb_states
        from datetime import timedelta

        cb = CircuitBreaker("timeout-test", failure_threshold=5, recovery_timeout=1)

        # Set opened_at to 2 seconds ago (past recovery timeout)
        past = (datetime.now(timezone.utc) - timedelta(seconds=2)).isoformat()
        _cb_states["timeout-test"] = {
            "provider_name": "timeout-test",
            "state": "open",
            "failure_count": 5,
            "success_count": 0,
            "last_failure_at": past,
            "last_success_at": None,
            "opened_at": past,
            "half_open_at": None,
            "failure_threshold": 5,
            "recovery_timeout_seconds": 1,
        }

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()

        with patch("app.services.circuit_breaker.get_redis", return_value=AsyncMock()):
            allowed = await cb.is_request_allowed(mock_db)

        assert allowed is True
        assert _cb_states["timeout-test"]["state"] == "half_open"

    @pytest.mark.asyncio
    async def test_closes_on_successful_probe(self):
        """Circuit breaker closes after successful probe in half_open state."""
        from app.services.circuit_breaker import CircuitBreaker, _cb_states

        cb = CircuitBreaker("recovery-test", failure_threshold=5, recovery_timeout=60)

        _cb_states["recovery-test"] = {
            "provider_name": "recovery-test",
            "state": "half_open",
            "failure_count": 5,
            "success_count": 0,
            "last_failure_at": None,
            "last_success_at": None,
            "opened_at": datetime.now(timezone.utc).isoformat(),
            "half_open_at": datetime.now(timezone.utc).isoformat(),
            "failure_threshold": 5,
            "recovery_timeout_seconds": 60,
        }

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()

        with patch("app.services.circuit_breaker.get_redis", return_value=AsyncMock()):
            state = await cb.record_success(mock_db)

        assert state["state"] == "closed"
        assert state["failure_count"] == 0

    @pytest.mark.asyncio
    async def test_reopens_on_failed_probe(self):
        """Circuit breaker reopens when probe fails in half_open state."""
        from app.services.circuit_breaker import CircuitBreaker, _cb_states

        cb = CircuitBreaker("reopen-test", failure_threshold=5, recovery_timeout=60)

        _cb_states["reopen-test"] = {
            "provider_name": "reopen-test",
            "state": "half_open",
            "failure_count": 5,
            "success_count": 0,
            "last_failure_at": None,
            "last_success_at": None,
            "opened_at": datetime.now(timezone.utc).isoformat(),
            "half_open_at": datetime.now(timezone.utc).isoformat(),
            "failure_threshold": 5,
            "recovery_timeout_seconds": 60,
        }

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()

        with patch("app.services.circuit_breaker.get_redis", return_value=AsyncMock()):
            state = await cb.record_failure(mock_db)

        assert state["state"] == "open"

    @pytest.mark.asyncio
    async def test_request_blocked_when_open(self):
        """Requests are blocked when circuit breaker is open."""
        from app.services.circuit_breaker import CircuitBreaker, _cb_states

        cb = CircuitBreaker("blocked-test", failure_threshold=5, recovery_timeout=3600)

        _cb_states["blocked-test"] = {
            "provider_name": "blocked-test",
            "state": "open",
            "failure_count": 5,
            "success_count": 0,
            "last_failure_at": None,
            "last_success_at": None,
            "opened_at": datetime.now(timezone.utc).isoformat(),
            "half_open_at": None,
            "failure_threshold": 5,
            "recovery_timeout_seconds": 3600,
        }

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()

        with patch("app.services.circuit_breaker.get_redis", return_value=AsyncMock()):
            allowed = await cb.is_request_allowed(mock_db)

        assert allowed is False


# ── Cost Tracking Tests ──────────────────────────────────────────────────


class TestCostTracker:
    """Cost tracking per provider per tenant with real-time counters."""

    def test_estimate_cost_known_model(self):
        """Cost estimation uses model-specific pricing."""
        from app.services.cost_tracker import estimate_cost

        cost = estimate_cost("gpt-4", prompt_tokens=1000, completion_tokens=500)
        # gpt-4: prompt=$0.03/1K, completion=$0.06/1K
        expected = (1000 / 1000) * 0.03 + (500 / 1000) * 0.06
        assert cost == pytest.approx(expected, abs=0.0001)

    def test_estimate_cost_unknown_model(self):
        """Cost estimation uses default pricing for unknown models."""
        from app.services.cost_tracker import estimate_cost

        cost = estimate_cost("unknown-model-v1", prompt_tokens=2000, completion_tokens=1000)
        # Default: prompt=$0.001/1K, completion=$0.002/1K
        expected = (2000 / 1000) * 0.001 + (1000 / 1000) * 0.002
        assert cost == pytest.approx(expected, abs=0.0001)

    @pytest.mark.asyncio
    async def test_record_cost_persists(self):
        """Cost record is persisted to DB and Redis counters."""
        from app.services.cost_tracker import record_cost

        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        mock_redis = AsyncMock()
        mock_pipe = AsyncMock()
        mock_pipe.execute = AsyncMock(return_value=[])
        mock_redis.pipeline.return_value = mock_pipe

        with patch("app.services.cost_tracker.get_redis", return_value=mock_redis):
            result = await record_cost(
                mock_db,
                provider_name="openai",
                tenant_id="tenant-1",
                model="gpt-4",
                prompt_tokens=500,
                completion_tokens=200,
            )

        assert result["provider_name"] == "openai"
        assert result["tenant_id"] == "tenant-1"
        assert result["total_tokens"] == 700
        assert result["estimated_cost_usd"] > 0
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_realtime_cost_from_redis(self):
        """Real-time cost data is fetched from Redis counters."""
        from app.services.cost_tracker import get_realtime_cost

        mock_redis = AsyncMock()
        mock_redis.hgetall = AsyncMock(return_value={
            b"prompt_tokens": b"1000",
            b"completion_tokens": b"500",
            b"total_tokens": b"1500",
            b"cost_microdollars": b"45000",  # $0.045
        })

        with patch("app.services.cost_tracker.get_redis", return_value=mock_redis):
            result = await get_realtime_cost("openai", "tenant-1")

        assert result is not None
        assert result["prompt_tokens"] == 1000
        assert result["completion_tokens"] == 500
        assert result["estimated_cost_usd"] == pytest.approx(0.045, abs=0.001)


# ── Failover Policy Tests ───────────────────────────────────────────────


class TestFailoverPolicy:
    """Automatic failover: error rate exceeds threshold -> kill-switch reroute."""

    @pytest.mark.asyncio
    async def test_evaluate_triggers_failover(self):
        """Failover triggers when error rate exceeds threshold."""
        from app.services.failover_policy import FailoverPolicyEngine

        engine = FailoverPolicyEngine(AsyncMock(), evaluation_interval=15)

        mock_policy = MagicMock()
        mock_policy.provider_name = "openai"
        mock_policy.error_rate_threshold = 0.5
        mock_policy.evaluation_window_seconds = 60
        mock_policy.fallback_provider = "anthropic"
        mock_policy.auto_failover = True
        mock_policy.require_confirmation = False

        mock_db = AsyncMock()

        # Mock health probe to return high error rate
        mock_probe = MagicMock()
        mock_probe.compute_error_rate = AsyncMock(return_value=0.8)

        # Mock circuit breaker state as closed
        mock_cb = MagicMock()
        mock_cb.get_state = AsyncMock(return_value={"state": "closed", "failure_count": 0})

        with patch("app.services.health_probe.get_health_probe", return_value=mock_probe), \
             patch("app.services.failover_policy.get_circuit_breaker", return_value=mock_cb):
            action = await engine.evaluate_provider(mock_db, mock_policy)

        assert action is not None
        assert action["provider_name"] == "openai"
        assert action["fallback_provider"] == "anthropic"
        assert action["error_rate"] == 0.8
        assert "error_rate" in action["reason"]

    @pytest.mark.asyncio
    async def test_no_failover_below_threshold(self):
        """No failover when error rate is below threshold."""
        from app.services.failover_policy import FailoverPolicyEngine

        engine = FailoverPolicyEngine(AsyncMock(), evaluation_interval=15)

        mock_policy = MagicMock()
        mock_policy.provider_name = "openai"
        mock_policy.error_rate_threshold = 0.5
        mock_policy.evaluation_window_seconds = 60
        mock_policy.fallback_provider = "anthropic"

        mock_db = AsyncMock()
        mock_probe = MagicMock()
        mock_probe.compute_error_rate = AsyncMock(return_value=0.1)
        mock_cb = MagicMock()
        mock_cb.get_state = AsyncMock(return_value={"state": "closed", "failure_count": 0})

        with patch("app.services.health_probe.get_health_probe", return_value=mock_probe), \
             patch("app.services.failover_policy.get_circuit_breaker", return_value=mock_cb):
            action = await engine.evaluate_provider(mock_db, mock_policy)

        assert action is None

    @pytest.mark.asyncio
    async def test_failover_triggered_by_open_circuit_breaker(self):
        """Failover triggers when circuit breaker is open."""
        from app.services.failover_policy import FailoverPolicyEngine

        engine = FailoverPolicyEngine(AsyncMock(), evaluation_interval=15)

        mock_policy = MagicMock()
        mock_policy.provider_name = "openai"
        mock_policy.error_rate_threshold = 0.5
        mock_policy.evaluation_window_seconds = 60
        mock_policy.fallback_provider = "anthropic"
        mock_policy.auto_failover = True
        mock_policy.require_confirmation = False

        mock_db = AsyncMock()
        mock_probe = MagicMock()
        mock_probe.compute_error_rate = AsyncMock(return_value=0.1)  # Low error rate
        mock_cb = MagicMock()
        mock_cb.get_state = AsyncMock(return_value={"state": "open", "failure_count": 5})

        with patch("app.services.health_probe.get_health_probe", return_value=mock_probe), \
             patch("app.services.failover_policy.get_circuit_breaker", return_value=mock_cb):
            action = await engine.evaluate_provider(mock_db, mock_policy)

        assert action is not None
        assert "circuit_breaker=open" in action["reason"]

    @pytest.mark.asyncio
    async def test_confirmation_required(self):
        """Failover requires human confirmation when configured."""
        from app.services.failover_policy import FailoverPolicyEngine

        engine = FailoverPolicyEngine(AsyncMock(), evaluation_interval=15)

        action = {
            "provider_name": "openai",
            "fallback_provider": "anthropic",
            "reason": "test",
            "error_rate": 0.8,
            "circuit_breaker_state": "open",
            "auto_failover": False,
            "require_confirmation": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        mock_redis = AsyncMock()
        with patch("app.services.failover_policy.get_redis", return_value=mock_redis):
            conf_id = await engine.request_confirmation(action)

        assert conf_id is not None
        assert len(conf_id) == 8
        assert conf_id in engine._pending_confirmations


# ── Admin API Endpoint Tests ─────────────────────────────────────────────


class TestAdminEndpoints:
    """Test Sprint 13 admin API endpoints."""

    def _get_client(self, mock_redis):
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()

        async def mock_get_db():
            yield mock_db

        with patch("app.services.redis_client.get_redis", return_value=mock_redis):
            with patch("app.middleware.auth.validate_api_key", return_value=None):
                with patch("app.middleware.auth.validate_api_key_from_db", return_value=None):
                    from app.main import app
                    from app.services.database import get_db
                    app.dependency_overrides[get_db] = mock_get_db
                    client = TestClient(app)
                    return client, app

    def test_get_provider_health(self):
        """GET /admin/provider-health returns health data."""
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.ping = AsyncMock()

        with patch("app.services.health_probe.get_provider_health_status", return_value=[]):
            client, app = self._get_client(mock_redis)
            resp = client.get("/admin/provider-health")
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        assert "provider_health" in data

    def test_get_circuit_breakers(self):
        """GET /admin/circuit-breakers returns circuit breaker states."""
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.ping = AsyncMock()

        with patch("app.services.circuit_breaker.get_all_circuit_breaker_states", return_value=[]):
            client, app = self._get_client(mock_redis)
            resp = client.get("/admin/circuit-breakers")
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        assert "circuit_breakers" in resp.json()

    def test_get_provider_costs(self):
        """GET /admin/provider-costs returns cost data."""
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.ping = AsyncMock()

        with patch("app.services.cost_tracker.get_cost_summary", return_value=[]):
            client, app = self._get_client(mock_redis)
            resp = client.get("/admin/provider-costs")
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        assert "cost_summary" in resp.json()

    def test_get_failover_policies(self):
        """GET /admin/failover-policies returns failover policies."""
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.ping = AsyncMock()

        with patch("app.services.failover_policy.list_failover_policies", return_value=[]):
            client, app = self._get_client(mock_redis)
            resp = client.get("/admin/failover-policies")
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        assert "failover_policies" in resp.json()

    def test_multi_model_dashboard(self):
        """GET /admin/multi-model-dashboard returns aggregated data."""
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.ping = AsyncMock()

        with patch("app.services.health_probe.get_provider_health_status", return_value=[]), \
             patch("app.services.circuit_breaker.get_all_circuit_breaker_states", return_value=[]), \
             patch("app.services.cost_tracker.get_provider_cost_totals", return_value=[]), \
             patch("app.services.kill_switch.list_kill_switches", return_value=[]):
            client, app = self._get_client(mock_redis)
            resp = client.get("/admin/multi-model-dashboard")
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        assert "model_registry" in data
        assert "provider_health" in data
        assert "circuit_breakers" in data
        assert "cost_totals_24h" in data
        assert "active_kill_switches" in data
        assert "routing_rules" in data
