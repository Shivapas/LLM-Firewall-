"""Cost tracking per provider per tenant — track token consumption and estimated cost.

Exposes cost data via dashboard and API. Supports real-time aggregation
using Redis counters with periodic DB persistence.
"""

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, func as sa_func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import ProviderCostRecord
from app.services.redis_client import get_redis

logger = logging.getLogger("sphinx.cost_tracker")

COST_COUNTER_PREFIX = "cost:"
COST_COUNTER_TTL = 3600  # 1 hour

# Pricing per 1K tokens (approximate, in USD)
MODEL_PRICING: dict[str, dict[str, float]] = {
    # OpenAI
    "gpt-4": {"prompt": 0.03, "completion": 0.06},
    "gpt-4-turbo": {"prompt": 0.01, "completion": 0.03},
    "gpt-4o": {"prompt": 0.005, "completion": 0.015},
    "gpt-4o-mini": {"prompt": 0.00015, "completion": 0.0006},
    "gpt-3.5-turbo": {"prompt": 0.0005, "completion": 0.0015},
    # Anthropic
    "claude-3-opus-20240229": {"prompt": 0.015, "completion": 0.075},
    "claude-3-sonnet-20240229": {"prompt": 0.003, "completion": 0.015},
    "claude-3-haiku-20240307": {"prompt": 0.00025, "completion": 0.00125},
    "claude-3.5-sonnet-20241022": {"prompt": 0.003, "completion": 0.015},
    # Gemini
    "gemini-1.5-pro": {"prompt": 0.00125, "completion": 0.005},
    "gemini-1.5-flash": {"prompt": 0.000075, "completion": 0.0003},
    "gemini-2.0-flash": {"prompt": 0.0001, "completion": 0.0004},
    # Default fallback
    "_default": {"prompt": 0.001, "completion": 0.002},
}


def estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Estimate cost in USD for a given model and token counts."""
    pricing = MODEL_PRICING.get(model, MODEL_PRICING["_default"])
    cost = (prompt_tokens / 1000.0) * pricing["prompt"] + \
           (completion_tokens / 1000.0) * pricing["completion"]
    return round(cost, 6)


async def record_cost(
    db: AsyncSession,
    provider_name: str,
    tenant_id: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
) -> dict:
    """Record a cost event — persist to DB and increment Redis counters."""
    total_tokens = prompt_tokens + completion_tokens
    cost_usd = estimate_cost(model, prompt_tokens, completion_tokens)

    record = ProviderCostRecord(
        id=uuid.uuid4(),
        provider_name=provider_name,
        tenant_id=tenant_id,
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        estimated_cost_usd=cost_usd,
    )
    db.add(record)
    await db.commit()

    # Increment Redis counters for real-time dashboard
    try:
        r = await get_redis()
        day_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        counter_key = f"{COST_COUNTER_PREFIX}{provider_name}:{tenant_id}:{day_key}"
        pipe = r.pipeline()
        pipe.hincrby(counter_key, "prompt_tokens", prompt_tokens)
        pipe.hincrby(counter_key, "completion_tokens", completion_tokens)
        pipe.hincrby(counter_key, "total_tokens", total_tokens)
        # Store cost as integer microdollars to avoid float issues
        pipe.hincrby(counter_key, "cost_microdollars", int(cost_usd * 1_000_000))
        pipe.expire(counter_key, COST_COUNTER_TTL)
        await pipe.execute()
    except Exception:
        logger.debug("Failed to increment cost counters in Redis", exc_info=True)

    return {
        "provider_name": provider_name,
        "tenant_id": tenant_id,
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "estimated_cost_usd": cost_usd,
    }


async def get_cost_summary(
    db: AsyncSession,
    provider_name: Optional[str] = None,
    tenant_id: Optional[str] = None,
    hours: int = 24,
) -> list[dict]:
    """Get aggregated cost summary grouped by provider and tenant."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    filters = [ProviderCostRecord.created_at >= cutoff]
    if provider_name:
        filters.append(ProviderCostRecord.provider_name == provider_name)
    if tenant_id:
        filters.append(ProviderCostRecord.tenant_id == tenant_id)

    q = await db.execute(
        select(
            ProviderCostRecord.provider_name,
            ProviderCostRecord.tenant_id,
            ProviderCostRecord.model,
            sa_func.sum(ProviderCostRecord.prompt_tokens).label("total_prompt_tokens"),
            sa_func.sum(ProviderCostRecord.completion_tokens).label("total_completion_tokens"),
            sa_func.sum(ProviderCostRecord.total_tokens).label("total_tokens"),
            sa_func.sum(ProviderCostRecord.estimated_cost_usd).label("total_cost_usd"),
            sa_func.count(ProviderCostRecord.id).label("request_count"),
        )
        .where(and_(*filters))
        .group_by(
            ProviderCostRecord.provider_name,
            ProviderCostRecord.tenant_id,
            ProviderCostRecord.model,
        )
        .order_by(sa_func.sum(ProviderCostRecord.estimated_cost_usd).desc())
    )

    rows = q.fetchall()
    return [
        {
            "provider_name": row.provider_name,
            "tenant_id": row.tenant_id,
            "model": row.model,
            "total_prompt_tokens": row.total_prompt_tokens or 0,
            "total_completion_tokens": row.total_completion_tokens or 0,
            "total_tokens": row.total_tokens or 0,
            "total_cost_usd": round(row.total_cost_usd or 0, 6),
            "request_count": row.request_count or 0,
        }
        for row in rows
    ]


async def get_provider_cost_totals(db: AsyncSession, hours: int = 24) -> list[dict]:
    """Get cost totals per provider (no tenant breakdown)."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    q = await db.execute(
        select(
            ProviderCostRecord.provider_name,
            sa_func.sum(ProviderCostRecord.prompt_tokens).label("total_prompt_tokens"),
            sa_func.sum(ProviderCostRecord.completion_tokens).label("total_completion_tokens"),
            sa_func.sum(ProviderCostRecord.total_tokens).label("total_tokens"),
            sa_func.sum(ProviderCostRecord.estimated_cost_usd).label("total_cost_usd"),
            sa_func.count(ProviderCostRecord.id).label("request_count"),
        )
        .where(ProviderCostRecord.created_at >= cutoff)
        .group_by(ProviderCostRecord.provider_name)
        .order_by(sa_func.sum(ProviderCostRecord.estimated_cost_usd).desc())
    )

    rows = q.fetchall()
    return [
        {
            "provider_name": row.provider_name,
            "total_prompt_tokens": row.total_prompt_tokens or 0,
            "total_completion_tokens": row.total_completion_tokens or 0,
            "total_tokens": row.total_tokens or 0,
            "total_cost_usd": round(row.total_cost_usd or 0, 6),
            "request_count": row.request_count or 0,
        }
        for row in rows
    ]


async def get_realtime_cost(provider_name: str, tenant_id: str) -> Optional[dict]:
    """Get real-time cost from Redis counters (current day)."""
    try:
        r = await get_redis()
        day_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        counter_key = f"{COST_COUNTER_PREFIX}{provider_name}:{tenant_id}:{day_key}"
        data = await r.hgetall(counter_key)
        if not data:
            return None
        return {
            "provider_name": provider_name,
            "tenant_id": tenant_id,
            "date": day_key,
            "prompt_tokens": int(data.get(b"prompt_tokens", data.get("prompt_tokens", 0))),
            "completion_tokens": int(data.get(b"completion_tokens", data.get("completion_tokens", 0))),
            "total_tokens": int(data.get(b"total_tokens", data.get("total_tokens", 0))),
            "estimated_cost_usd": int(data.get(b"cost_microdollars", data.get("cost_microdollars", 0))) / 1_000_000,
        }
    except Exception:
        logger.debug("Failed to get realtime cost from Redis", exc_info=True)
        return None
