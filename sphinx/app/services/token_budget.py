"""Token budget tracking — cumulative consumption per API key per period.

Serves budget state from Redis; persists to Postgres asynchronously.
"""

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import TokenUsage
from app.services.redis_client import get_redis

logger = logging.getLogger("sphinx.token_budget")

BUDGET_KEY_PREFIX = "budget:"
BUDGET_TTL = 3600  # 1 hour TTL for budget counters in Redis


async def record_token_usage(
    api_key_id: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
) -> dict:
    """Record token usage in Redis. Returns updated budget state."""
    r = await get_redis()
    budget_key = f"{BUDGET_KEY_PREFIX}{api_key_id}"

    # Atomically increment counters in a Redis hash
    pipe = r.pipeline()
    pipe.hincrby(budget_key, "prompt_tokens", prompt_tokens)
    pipe.hincrby(budget_key, "completion_tokens", completion_tokens)
    pipe.hincrby(budget_key, "total_tokens", total_tokens)
    pipe.hincrby(budget_key, "request_count", 1)
    pipe.expire(budget_key, BUDGET_TTL)
    results = await pipe.execute()

    return {
        "api_key_id": api_key_id,
        "prompt_tokens": int(results[0]),
        "completion_tokens": int(results[1]),
        "total_tokens": int(results[2]),
        "request_count": int(results[3]),
    }


async def get_budget_state(api_key_id: str) -> dict:
    """Get current budget state from Redis."""
    r = await get_redis()
    budget_key = f"{BUDGET_KEY_PREFIX}{api_key_id}"

    data = await r.hgetall(budget_key)
    if not data:
        return {
            "api_key_id": api_key_id,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "request_count": 0,
        }

    return {
        "api_key_id": api_key_id,
        "prompt_tokens": int(data.get("prompt_tokens", 0)),
        "completion_tokens": int(data.get("completion_tokens", 0)),
        "total_tokens": int(data.get("total_tokens", 0)),
        "request_count": int(data.get("request_count", 0)),
    }


async def persist_usage_to_db(
    db: AsyncSession,
    api_key_id: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
) -> None:
    """Persist a token usage record to Postgres for long-term tracking."""
    import uuid

    record = TokenUsage(
        id=uuid.uuid4(),
        api_key_id=uuid.UUID(api_key_id),
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
    )
    db.add(record)
    await db.commit()
    logger.debug(
        "Persisted usage key=%s model=%s tokens=%d",
        api_key_id, model, total_tokens,
    )


async def get_usage_summary(db: AsyncSession, api_key_id: str) -> dict:
    """Get cumulative usage from Postgres."""
    from sqlalchemy import func
    import uuid

    result = await db.execute(
        select(
            func.coalesce(func.sum(TokenUsage.prompt_tokens), 0),
            func.coalesce(func.sum(TokenUsage.completion_tokens), 0),
            func.coalesce(func.sum(TokenUsage.total_tokens), 0),
            func.count(TokenUsage.id),
        ).where(TokenUsage.api_key_id == uuid.UUID(api_key_id))
    )
    row = result.one()
    return {
        "api_key_id": api_key_id,
        "prompt_tokens": int(row[0]),
        "completion_tokens": int(row[1]),
        "total_tokens": int(row[2]),
        "request_count": int(row[3]),
    }
