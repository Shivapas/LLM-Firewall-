"""Redis-backed sliding window rate limiter keyed by API key."""

import logging
import time

from app.services.redis_client import get_redis

logger = logging.getLogger("sphinx.rate_limiter")

# Sliding window duration in seconds
WINDOW_SIZE = 60  # 1 minute for TPM (tokens per minute)


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

    pipe = r.pipeline()

    # Remove entries outside the sliding window
    pipe.zremrangebyscore(window_key, 0, now - WINDOW_SIZE)

    # Get current token count in window
    # Each member stores its token_count in the score-adjacent approach;
    # we use ZRANGEBYSCORE to sum up. Instead, we store each request as a
    # member with score=timestamp, and use a naming scheme that encodes token count.
    # Simpler: store token_count as part of the member value, sum via Lua script.

    await pipe.execute()

    # Use Lua script for atomic check-and-add
    lua_script = """
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local limit = tonumber(ARGV[3])
    local token_count = tonumber(ARGV[4])
    local member = ARGV[5]

    -- Remove expired entries
    redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

    -- Sum current usage: each member name is "timestamp:tokens", parse token part
    local members = redis.call('ZRANGE', key, 0, -1)
    local current_usage = 0
    for _, m in ipairs(members) do
        local tokens = tonumber(string.match(m, ':(%d+)$'))
        if tokens then
            current_usage = current_usage + tokens
        end
    end

    -- Check if adding token_count would exceed limit
    if current_usage + token_count > limit then
        return {0, current_usage, -1}
    end

    -- Add this request
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, window + 1)

    return {1, current_usage + token_count, 0}
    """

    member = f"{now}:{token_count}"
    result = await r.eval(lua_script, 1, window_key, str(now), str(WINDOW_SIZE), str(tpm_limit), str(token_count), member)

    allowed = bool(result[0])
    current_usage = int(result[1])

    retry_after = None
    if not allowed:
        # Calculate when the oldest entry in the window expires
        oldest = await r.zrange(window_key, 0, 0, withscores=True)
        if oldest:
            oldest_time = oldest[0][1]
            retry_after = max(1, int((oldest_time + WINDOW_SIZE) - now) + 1)
        else:
            retry_after = WINDOW_SIZE

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
        parts = m.rsplit(":", 1)
        if len(parts) == 2:
            try:
                usage += int(parts[1])
            except ValueError:
                pass
    return usage
