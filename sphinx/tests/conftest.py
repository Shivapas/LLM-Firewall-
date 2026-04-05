import asyncio
import json
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    r = AsyncMock()
    r.get = AsyncMock(return_value=None)
    r.setex = AsyncMock()
    r.delete = AsyncMock()
    r.ping = AsyncMock()
    r.hgetall = AsyncMock(return_value={})
    r.pipeline.return_value = AsyncMock()
    r.pipeline.return_value.execute = AsyncMock(return_value=[])
    r.pipeline.return_value.hincrby = AsyncMock()
    r.pipeline.return_value.expire = AsyncMock()
    r.pipeline.return_value.zremrangebyscore = AsyncMock()
    r.eval = AsyncMock(return_value=[1, 0, 0])  # Default: rate limit allows
    r.zrange = AsyncMock(return_value=[])
    r.zremrangebyscore = AsyncMock()
    return r


@pytest.fixture
def valid_key_data():
    return {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "tenant_id": "tenant-1",
        "project_id": "project-1",
        "allowed_models": ["gpt-4", "claude-3"],
        "tpm_limit": 100000,
        "risk_score": 0.0,
        "is_active": True,
        "expires_at": None,
    }


@pytest.fixture
def client(mock_redis, valid_key_data):
    """Test client with mocked Redis and DB."""
    with patch("app.services.redis_client.get_redis", return_value=mock_redis):
        with patch("app.middleware.auth.validate_api_key", return_value=None):
            with patch("app.middleware.auth.validate_api_key_from_db", return_value=None):
                from app.main import app
                yield TestClient(app)


@pytest.fixture
def authed_client(mock_redis, valid_key_data):
    """Test client with a valid API key."""
    with patch("app.services.redis_client.get_redis", return_value=mock_redis):
        with patch("app.middleware.auth.validate_api_key", return_value=valid_key_data):
            from app.main import app
            yield TestClient(app)
