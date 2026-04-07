"""Redis-backed sliding window rate limiter keyed by API key."""

import logging
import time
import uuid

from app.services.redis_client import get_redis

logger = logging.getLogger("sphinx.rate_limiter")

# Sliding window duration in seconds
WINDOW_SIZE = 60  # 1 minute for TPM (tokens per minute)

# Lua script for atomic check-and-add with retry_after calculation
_RATE_LIMIT_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local token_count = tonumber(ARGV[4])
local member = ARGV[5]

-- Remove expired entries
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

-- Sum current usage: each member name is "timestamp:tokens:uuid", parse token part
local members = redis.call('ZRANGE', key, 0, -1)
local current_usage = 0
for _, m in ipairs(members) do
    local tokens = tonumber(string.match(m, ':(%d+):'))
    if tokens then
        current_usage = current_usage + tokens
    end
end

-- Check if adding token_count would exceed limit
if current_usage + token_count > limit then
    -- Calculate retry_after from oldest entry
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = window
    if #oldest >= 2 then
        retry_after = math.max(1, math.ceil((tonumber(oldest[2]) + window) - now) + 1)
    end
    return {0, current_usage, retry_after}
end

-- Add this request
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, window + 1)

return {1, current_usage + token_count, 0}
"""


async def check_rate_limit(api_key_id: str, tpm_limit: int, token_count: int = 1) -> dict:
    """Check and enforce TPM rate limit using a Redis sliding window.

    Returns dict with:
        allowed: bool - whether the request is within limits
        current_usage: int - tokens used in current window
        limit: int - the TPM limit
        retry_after: int|None - seconds to wait if rate limited
    """
    r = await get_redis()
    now = time.time()
    window_key = f"ratelimit:{api_key_id}"

    # Use a unique suffix to prevent member collisions in the sorted set
    unique_id = uuid.uuid4().hex[:8]
    member = f"{now}:{token_count}:{unique_id}"

    result = await r.eval(
        _RATE_LIMIT_LUA, 1, window_key,
        str(now), str(WINDOW_SIZE), str(tpm_limit), str(token_count), member,
    )

    allowed = bool(result[0])
    current_usage = int(result[1])
    retry_after = int(result[2]) if not allowed else None

    if not allowed:
        logger.warning(
            "Rate limit exceeded key=%s usage=%d limit=%d retry_after=%s",
            api_key_id, current_usage, tpm_limit, retry_after,
        )

    return {
        "allowed": allowed,
        "current_usage": current_usage,
        "limit": tpm_limit,
        "retry_after": retry_after,
    }


async def get_current_usage(api_key_id: str) -> int:
    """Get current token usage in the sliding window."""
    r = await get_redis()
    now = time.time()
    window_key = f"ratelimit:{api_key_id}"

    # Remove expired
    await r.zremrangebyscore(window_key, 0, now - WINDOW_SIZE)

    members = await r.zrange(window_key, 0, -1)
    usage = 0
    for m in members:
        # Member format: "timestamp:token_count:uuid"
        parts = m.split(":")
        if len(parts) >= 2:
            try:
                usage += int(parts[1])
            except ValueError:
                pass
    return usage
