import asyncio

import redis.asyncio as redis

from app.config import get_settings

redis_pool: redis.Redis | None = None
_redis_lock = asyncio.Lock()


async def get_redis() -> redis.Redis:
    global redis_pool
    if redis_pool is not None:
        return redis_pool
    async with _redis_lock:
        if redis_pool is None:
            settings = get_settings()
            redis_pool = redis.from_url(settings.redis_url, decode_responses=True)
    return redis_pool


async def close_redis() -> None:
    global redis_pool
    async with _redis_lock:
        if redis_pool is not None:
            await redis_pool.aclose()
            redis_pool = None
