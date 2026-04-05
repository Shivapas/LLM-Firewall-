"""Sprint 2 proxy integration tests — rate limiting, kill-switch, token tracking at proxy level."""

import json
from unittest.mock import patch, AsyncMock

import httpx


def test_rate_limit_returns_429(authed_client):
    """When rate limit is exceeded, proxy should return 429 with Retry-After."""
    rate_result = {
        "allowed": False,
        "current_usage": 100000,
        "limit": 100000,
        "retry_after": 30,
    }

    with patch("app.routers.proxy.check_rate_limit", new_callable=AsyncMock, return_value=rate_result):
        with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=None):
            response = authed_client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]},
                headers={"Authorization": "Bearer spx-test-key"},
            )

    assert response.status_code == 429
    assert "Retry-After" in response.headers or "retry-after" in response.headers
    data = response.json()
    assert "Rate limit exceeded" in data["error"]


def test_rate_limit_allows_within_limit(authed_client):
    """When rate limit is within bounds, proxy should forward request."""
    rate_result = {
        "allowed": True,
        "current_usage": 50,
        "limit": 100000,
        "retry_after": None,
    }

    mock_upstream = httpx.Response(
        200,
        json={
            "id": "chatcmpl-test",
            "choices": [{"message": {"role": "assistant", "content": "Hi!"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
        },
    )

    with patch("app.routers.proxy.check_rate_limit", new_callable=AsyncMock, return_value=rate_result):
        with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=None):
            with patch("app.services.proxy.get_http_client") as mock_client_fn:
                mock_client = AsyncMock()
                mock_client.request = AsyncMock(return_value=mock_upstream)
                mock_client_fn.return_value = mock_client

                with patch("app.routers.proxy.record_token_usage", new_callable=AsyncMock):
                    with patch("app.routers.proxy.persist_usage_to_db", new_callable=AsyncMock):
                        response = authed_client.post(
                            "/v1/chat/completions",
                            json={"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]},
                            headers={"Authorization": "Bearer spx-test-key"},
                        )

    assert response.status_code == 200


def test_kill_switch_reroutes_model(authed_client):
    """Kill-switch with reroute should change the model and proxy successfully."""
    ks_data = {
        "model_name": "gpt-4",
        "action": "reroute",
        "fallback_model": "gpt-3.5-turbo",
        "reason": "Cost optimization",
        "is_active": True,
    }

    rate_result = {"allowed": True, "current_usage": 0, "limit": 100000, "retry_after": None}

    mock_upstream = httpx.Response(
        200,
        json={
            "id": "chatcmpl-test",
            "choices": [{"message": {"role": "assistant", "content": "Hi!"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
            "model": "gpt-3.5-turbo",
        },
    )

    with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=ks_data):
        with patch("app.routers.proxy.check_rate_limit", new_callable=AsyncMock, return_value=rate_result):
            with patch("app.services.proxy.get_http_client") as mock_client_fn:
                mock_client = AsyncMock()
                mock_client.request = AsyncMock(return_value=mock_upstream)
                mock_client_fn.return_value = mock_client

                with patch("app.routers.proxy.record_token_usage", new_callable=AsyncMock):
                    with patch("app.routers.proxy.persist_usage_to_db", new_callable=AsyncMock):
                        response = authed_client.post(
                            "/v1/chat/completions",
                            json={"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]},
                            headers={"Authorization": "Bearer spx-test-key"},
                        )

    assert response.status_code == 200
