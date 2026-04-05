"""Sprint 3 integration tests for multi-provider routing and audit events."""

import json
import pytest
from unittest.mock import AsyncMock, patch

AUTH_HEADER = {"Authorization": "Bearer spx-test-key"}


class TestMultiProviderProxy:
    def test_proxy_with_default_provider(self, authed_client):
        """Requests with unknown models fall back to default provider."""
        with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=None):
            with patch("app.routers.proxy.check_rate_limit", new_callable=AsyncMock, return_value={"allowed": True, "current_usage": 0}):
                with patch("app.routers.proxy.resolve_provider", return_value=None):
                    with patch("app.routers.proxy.proxy_request", new_callable=AsyncMock) as mock_proxy:
                        from starlette.responses import Response
                        mock_proxy.return_value = Response(
                            content=json.dumps({"choices": [], "usage": {}}).encode(),
                            status_code=200,
                            media_type="application/json",
                        )
                        with patch("app.routers.proxy.emit_audit_event", new_callable=AsyncMock):
                            resp = authed_client.post(
                                "/v1/chat/completions",
                                json={"model": "unknown-model", "messages": [{"role": "user", "content": "hi"}]},
                                headers=AUTH_HEADER,
                            )
                            assert resp.status_code == 200
                            mock_proxy.assert_called_once()

    def test_kill_switch_emits_audit_event(self, authed_client):
        """Kill-switch blocks should emit audit events."""
        ks_data = {"action": "block", "reason": "testing"}
        with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=ks_data):
            with patch("app.routers.proxy.emit_audit_event", new_callable=AsyncMock) as mock_audit:
                resp = authed_client.post(
                    "/v1/chat/completions",
                    json={"model": "blocked-model", "messages": [{"role": "user", "content": "test"}]},
                    headers=AUTH_HEADER,
                )
                assert resp.status_code == 503
                mock_audit.assert_called_once()
                call_kwargs = mock_audit.call_args.kwargs
                assert call_kwargs["action"] == "blocked"
                assert call_kwargs["status_code"] == 503

    def test_rate_limit_emits_audit_event(self, authed_client):
        """Rate-limited requests should emit audit events."""
        with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=None):
            with patch(
                "app.routers.proxy.check_rate_limit",
                new_callable=AsyncMock,
                return_value={"allowed": False, "current_usage": 100001, "retry_after": 30},
            ):
                with patch("app.routers.proxy.emit_audit_event", new_callable=AsyncMock) as mock_audit:
                    resp = authed_client.post(
                        "/v1/chat/completions",
                        json={"model": "gpt-4", "messages": [{"role": "user", "content": "test"}]},
                        headers=AUTH_HEADER,
                    )
                    assert resp.status_code == 429
                    mock_audit.assert_called_once()
                    call_kwargs = mock_audit.call_args.kwargs
                    assert call_kwargs["action"] == "rate_limited"

    def test_reroute_sets_audit_action(self, authed_client):
        """Kill-switch reroute should set audit_action to 'rerouted'."""
        ks_data = {"action": "reroute", "fallback_model": "gpt-3.5-turbo", "reason": "cost"}
        with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=ks_data):
            with patch("app.routers.proxy.check_rate_limit", new_callable=AsyncMock, return_value={"allowed": True, "current_usage": 0}):
                with patch("app.routers.proxy.resolve_provider", return_value=None):
                    with patch("app.routers.proxy.proxy_request", new_callable=AsyncMock) as mock_proxy:
                        from starlette.responses import Response
                        mock_proxy.return_value = Response(
                            content=json.dumps({"choices": [], "usage": {}}).encode(),
                            status_code=200,
                            media_type="application/json",
                        )
                        with patch("app.routers.proxy.emit_audit_event", new_callable=AsyncMock) as mock_audit:
                            resp = authed_client.post(
                                "/v1/chat/completions",
                                json={"model": "gpt-4", "messages": [{"role": "user", "content": "test"}]},
                                headers=AUTH_HEADER,
                            )
                            assert resp.status_code == 200
                            # The last audit call should have action='rerouted'
                            last_call = mock_audit.call_args_list[-1]
                            assert last_call.kwargs["action"] == "rerouted"


class TestAuditEventIntegration:
    def test_successful_request_emits_audit(self, authed_client):
        """Successful proxied requests emit audit events with action='allowed'."""
        with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=None):
            with patch("app.routers.proxy.check_rate_limit", new_callable=AsyncMock, return_value={"allowed": True, "current_usage": 0}):
                with patch("app.routers.proxy.resolve_provider", return_value=None):
                    with patch("app.routers.proxy.proxy_request", new_callable=AsyncMock) as mock_proxy:
                        from starlette.responses import Response
                        mock_proxy.return_value = Response(
                            content=json.dumps({"choices": [], "usage": {}}).encode(),
                            status_code=200,
                            media_type="application/json",
                        )
                        with patch("app.routers.proxy.emit_audit_event", new_callable=AsyncMock) as mock_audit:
                            resp = authed_client.post(
                                "/v1/chat/completions",
                                json={"model": "mock-model", "messages": [{"role": "user", "content": "hi"}]},
                                headers=AUTH_HEADER,
                            )
                            assert resp.status_code == 200
                            mock_audit.assert_called()
                            last_call = mock_audit.call_args_list[-1]
                            assert last_call.kwargs["action"] == "allowed"
