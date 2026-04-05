"""Tests for token budget tracking service."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_record_token_usage():
    """Should increment token counters in Redis."""
    mock_redis = MagicMock()
    mock_pipe = MagicMock()
    mock_pipe.hincrby = MagicMock()
    mock_pipe.expire = MagicMock()
    mock_pipe.execute = AsyncMock(return_value=[100, 50, 150, 5])
    mock_redis.pipeline.return_value = mock_pipe

    with patch("app.services.token_budget.get_redis", new_callable=AsyncMock, return_value=mock_redis):
        from app.services.token_budget import record_token_usage
        result = await record_token_usage(
            api_key_id="key-123",
            model="gpt-4",
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
        )

    assert result["prompt_tokens"] == 100
    assert result["completion_tokens"] == 50
    assert result["total_tokens"] == 150
    assert result["request_count"] == 5


@pytest.mark.asyncio
async def test_get_budget_state_with_data():
    """Should return budget state from Redis hash."""
    mock_redis = AsyncMock()
    mock_redis.hgetall = AsyncMock(return_value={
        "prompt_tokens": "200",
        "completion_tokens": "100",
        "total_tokens": "300",
        "request_count": "10",
    })

    with patch("app.services.token_budget.get_redis", return_value=mock_redis):
        from app.services.token_budget import get_budget_state
        result = await get_budget_state("key-123")

    assert result["total_tokens"] == 300
    assert result["request_count"] == 10


@pytest.mark.asyncio
async def test_get_budget_state_empty():
    """Should return zeros when no data exists."""
    mock_redis = AsyncMock()
    mock_redis.hgetall = AsyncMock(return_value={})

    with patch("app.services.token_budget.get_redis", return_value=mock_redis):
        from app.services.token_budget import get_budget_state
        result = await get_budget_state("key-123")

    assert result["total_tokens"] == 0
    assert result["request_count"] == 0
