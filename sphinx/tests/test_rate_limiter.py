"""Tests for the Redis-backed sliding window rate limiter."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock


def _make_mock_redis(**overrides):
    """Create a mock Redis that correctly handles sync pipeline() and async eval()."""
    mock_redis = MagicMock()
    # Async methods
    mock_redis.eval = AsyncMock(return_value=overrides.get("eval_result", [1, 0, 0]))
    mock_redis.zrange = AsyncMock(return_value=overrides.get("zrange_result", []))
    mock_redis.zremrangebyscore = AsyncMock()

    # pipeline() is sync in redis.asyncio, returns an object with async execute()
    mock_pipe = MagicMock()
    mock_pipe.zremrangebyscore = MagicMock()
    mock_pipe.execute = AsyncMock(return_value=[])
    mock_redis.pipeline.return_value = mock_pipe

    return mock_redis


@pytest.mark.asyncio
async def test_rate_limit_allows_within_limit():
    """Requests within TPM limit should be allowed."""
    mock_redis = _make_mock_redis(eval_result=[1, 10, 0])

    with patch("app.services.rate_limiter.get_redis", new_callable=AsyncMock, return_value=mock_redis):
        from app.services.rate_limiter import check_rate_limit
        result = await check_rate_limit("key-123", tpm_limit=1000, token_count=10)

    assert result["allowed"] is True
    assert result["current_usage"] == 10
    assert result["limit"] == 1000
    assert result["retry_after"] is None


@pytest.mark.asyncio
async def test_rate_limit_blocks_when_exceeded():
    """Requests exceeding TPM limit should be blocked with retry_after."""
    import time

    mock_redis = _make_mock_redis(
        eval_result=[0, 1000, -1],
        zrange_result=[("oldest_entry:5", time.time() - 30)],
    )

    with patch("app.services.rate_limiter.get_redis", new_callable=AsyncMock, return_value=mock_redis):
        from app.services.rate_limiter import check_rate_limit
        result = await check_rate_limit("key-123", tpm_limit=1000, token_count=100)

    assert result["allowed"] is False
    assert result["retry_after"] is not None
    assert result["retry_after"] > 0


@pytest.mark.asyncio
async def test_get_current_usage():
    """Should sum token counts from sorted set members."""
    mock_redis = AsyncMock()
    mock_redis.zremrangebyscore = AsyncMock()
    mock_redis.zrange = AsyncMock(return_value=["1234.5:10", "1234.6:20", "1234.7:30"])

    with patch("app.services.rate_limiter.get_redis", return_value=mock_redis):
        from app.services.rate_limiter import get_current_usage
        usage = await get_current_usage("key-123")

    assert usage == 60
