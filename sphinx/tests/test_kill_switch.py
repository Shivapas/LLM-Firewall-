"""Tests for the kill-switch service."""

import json
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timezone


@pytest.mark.asyncio
async def test_check_kill_switch_active():
    """Should return kill-switch data when active in cache."""
    ks_data = {
        "model_name": "gpt-4",
        "action": "block",
        "fallback_model": None,
        "reason": "Security incident",
        "is_active": True,
    }
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=json.dumps(ks_data))

    with patch("app.services.kill_switch.get_redis", return_value=mock_redis):
        from app.services.kill_switch import check_kill_switch
        result = await check_kill_switch("gpt-4")

    assert result is not None
    assert result["action"] == "block"
    assert result["is_active"] is True


@pytest.mark.asyncio
async def test_check_kill_switch_inactive():
    """Should return None when kill-switch is inactive."""
    ks_data = {"is_active": False, "action": "block"}
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=json.dumps(ks_data))

    with patch("app.services.kill_switch.get_redis", return_value=mock_redis):
        from app.services.kill_switch import check_kill_switch
        result = await check_kill_switch("gpt-4")

    assert result is None


@pytest.mark.asyncio
async def test_check_kill_switch_not_found():
    """Should return None when no kill-switch exists."""
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)

    with patch("app.services.kill_switch.get_redis", return_value=mock_redis):
        from app.services.kill_switch import check_kill_switch
        result = await check_kill_switch("gpt-4")

    assert result is None


@pytest.mark.asyncio
async def test_check_kill_switch_reroute():
    """Should return reroute data with fallback model."""
    ks_data = {
        "model_name": "gpt-4",
        "action": "reroute",
        "fallback_model": "gpt-3.5-turbo",
        "reason": "Cost optimization",
        "is_active": True,
    }
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=json.dumps(ks_data))

    with patch("app.services.kill_switch.get_redis", return_value=mock_redis):
        from app.services.kill_switch import check_kill_switch
        result = await check_kill_switch("gpt-4")

    assert result["action"] == "reroute"
    assert result["fallback_model"] == "gpt-3.5-turbo"


def test_kill_switch_block_returns_503(authed_client):
    """Kill-switch block should return 503 at the proxy level."""
    ks_data = {
        "model_name": "gpt-4",
        "action": "block",
        "fallback_model": None,
        "reason": "Security incident",
        "is_active": True,
    }

    with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=ks_data):
        response = authed_client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]},
            headers={"Authorization": "Bearer spx-test-key"},
        )

    assert response.status_code == 503
    data = response.json()
    assert "temporarily unavailable" in data["error"]


def test_kill_switch_admin_activate(client):
    """Test activating a kill-switch via admin API."""
    ks_result = {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "model_name": "gpt-4",
        "action": "block",
        "fallback_model": None,
        "activated_by": "admin",
        "reason": "test",
        "is_active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    with patch("app.routers.admin.activate_kill_switch", new_callable=AsyncMock, return_value=ks_result):
        response = client.post(
            "/admin/kill-switches",
            json={
                "model_name": "gpt-4",
                "action": "block",
                "activated_by": "admin",
                "reason": "test",
            },
        )

    assert response.status_code == 200
    data = response.json()
    assert data["model_name"] == "gpt-4"
    assert data["is_active"] is True


def test_kill_switch_admin_deactivate(client):
    """Test deactivating a kill-switch via admin API."""
    with patch("app.routers.admin.deactivate_kill_switch", new_callable=AsyncMock, return_value=True):
        response = client.delete("/admin/kill-switches/gpt-4")

    assert response.status_code == 200
    assert response.json()["status"] == "deactivated"


def test_kill_switch_admin_deactivate_not_found(client):
    """Test deactivating a nonexistent kill-switch returns 404."""
    with patch("app.routers.admin.deactivate_kill_switch", new_callable=AsyncMock, return_value=False):
        response = client.delete("/admin/kill-switches/nonexistent")

    assert response.status_code == 404
