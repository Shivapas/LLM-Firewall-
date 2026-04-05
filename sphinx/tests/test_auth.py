from unittest.mock import patch, AsyncMock


def test_missing_auth_header(client):
    response = client.post("/v1/chat/completions", json={"model": "gpt-4"})
    assert response.status_code == 401
    assert "Authorization" in response.json()["error"]


def test_invalid_bearer_format(client):
    response = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4"},
        headers={"Authorization": "Basic abc123"},
    )
    assert response.status_code == 401


def test_invalid_api_key(client):
    response = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4"},
        headers={"Authorization": "Bearer spx-invalid-key"},
    )
    assert response.status_code == 401
    assert "Invalid" in response.json()["error"]


def test_valid_api_key_passes_auth(authed_client):
    """With a valid key, the request should pass auth and reach the proxy."""
    rate_result = {"allowed": True, "current_usage": 0, "limit": 100000, "retry_after": None}

    with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=None):
        with patch("app.routers.proxy.check_rate_limit", new_callable=AsyncMock, return_value=rate_result):
            with patch("app.routers.proxy.proxy_request") as mock_proxy:
                from starlette.responses import JSONResponse
                mock_proxy.return_value = JSONResponse(content={"choices": []})

                response = authed_client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                    headers={"Authorization": "Bearer spx-valid-key"},
                )
                assert response.status_code == 200
                mock_proxy.assert_called_once()
