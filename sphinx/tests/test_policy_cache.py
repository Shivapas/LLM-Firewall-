"""Tests for the policy cache loader."""

import json
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timezone


def test_get_policy_returns_none_when_empty():
    """Empty cache returns None."""
    from app.services.policy_cache import get_policy, _policy_cache
    # Clear cache
    _policy_cache.clear()
    assert get_policy("nonexistent") is None


def test_get_all_policies_empty():
    """Empty cache returns empty dict."""
    from app.services.policy_cache import get_all_policies, _policy_cache
    _policy_cache.clear()
    assert get_all_policies() == {}


def test_get_policies_by_type():
    """Should filter policies by type."""
    import app.services.policy_cache as pc
    pc._policy_cache = {
        "rate-rule-1": {"name": "rate-rule-1", "policy_type": "rate_limit"},
        "access-rule-1": {"name": "access-rule-1", "policy_type": "access_control"},
        "rate-rule-2": {"name": "rate-rule-2", "policy_type": "rate_limit"},
    }
    result = pc.get_policies_by_type("rate_limit")
    assert len(result) == 2
    assert all(p["policy_type"] == "rate_limit" for p in result)

    # Cleanup
    pc._policy_cache.clear()


@pytest.mark.asyncio
async def test_load_policies_from_db():
    """Should load active policies into in-memory cache."""
    mock_rule = MagicMock()
    mock_rule.name = "test-policy"
    mock_rule.id = "550e8400-e29b-41d4-a716-446655440000"
    mock_rule.description = "Test policy"
    mock_rule.policy_type = "rate_limit"
    mock_rule.rules_json = json.dumps({"max_tpm": 1000})
    mock_rule.version = 1
    mock_rule.is_active = True

    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [mock_rule]
    mock_db.execute = AsyncMock(return_value=mock_result)

    from app.services.policy_cache import load_policies, get_policy
    count = await load_policies(mock_db)

    assert count == 1
    policy = get_policy("test-policy")
    assert policy is not None
    assert policy["policy_type"] == "rate_limit"
    assert policy["rules"]["max_tpm"] == 1000


def test_policy_admin_create(client):
    """Test creating a policy via admin API."""
    import uuid as _uuid
    from datetime import datetime, timezone

    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()

    # When refresh is called, leave the object's attributes intact
    async def noop_refresh(obj):
        # Ensure the object has all required fields after "refresh"
        if not hasattr(obj, 'is_active') or obj.is_active is None:
            obj.is_active = True
        if not hasattr(obj, 'version') or obj.version is None:
            obj.version = 1
        if not hasattr(obj, 'created_at') or obj.created_at is None:
            obj.created_at = datetime.now(timezone.utc)

    mock_db.refresh = noop_refresh

    from app.main import app
    from app.services.database import get_db

    async def override_get_db():
        yield mock_db

    app.dependency_overrides[get_db] = override_get_db

    with patch("app.routers.admin.force_refresh", new_callable=AsyncMock, return_value=1):
        response = client.post(
            "/admin/policies",
            json={
                "name": "test-policy",
                "description": "A test policy",
                "policy_type": "rate_limit",
                "rules": {"max_tpm": 5000},
            },
        )

    app.dependency_overrides.clear()
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "test-policy"
    assert data["policy_type"] == "rate_limit"


def test_policy_cache_refresh_endpoint(client):
    """Test the force-refresh cache endpoint."""
    with patch("app.routers.admin.force_refresh", new_callable=AsyncMock, return_value=3):
        response = client.post("/admin/policies/refresh")

    assert response.status_code == 200
    assert response.json()["policies_loaded"] == 3
