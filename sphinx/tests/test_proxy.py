import json
from unittest.mock import patch, AsyncMock

import httpx


def test_proxy_forwards_to_provider(authed_client):
    """Test that authenticated requests are proxied to the LLM provider."""
    mock_upstream = httpx.Response(
        200,
        json={
            "id": "chatcmpl-test",
            "choices": [
                {"message": {"role": "assistant", "content": "Hello!"}, "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
        },
    )

    with patch("app.services.proxy.get_http_client") as mock_client_fn:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_upstream)
        mock_client_fn.return_value = mock_client

        response = authed_client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Hello"}],
            },
            headers={"Authorization": "Bearer spx-test-key"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "choices" in data


def test_proxy_models_endpoint(authed_client):
    """Test that GET /v1/models is proxied."""
    mock_upstream = httpx.Response(
        200,
        json={"object": "list", "data": [{"id": "gpt-4", "object": "model"}]},
    )

    with patch("app.services.proxy.get_http_client") as mock_client_fn:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_upstream)
        mock_client_fn.return_value = mock_client

        response = authed_client.get(
            "/v1/models",
            headers={"Authorization": "Bearer spx-test-key"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["object"] == "list"
