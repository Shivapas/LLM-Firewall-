"""Kill-switch service — per-model blocking/rerouting at ingress.

Checks cached kill-switch state; returns 503 or reroutes to fallback model.
"""

import json
import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import KillSwitch
from app.services.redis_client import get_redis

logger = logging.getLogger("sphinx.kill_switch")

CACHE_KEY_PREFIX = "killswitch:"
CACHE_TTL = 30  # 30 seconds — propagates within 5s requirement via push + short TTL


async def check_kill_switch(model_name: str) -> Optional[dict]:
    """Check if a kill-switch is active for the given model.

    Returns None if no active kill-switch, otherwise returns:
        action: "block" or "reroute"
        fallback_model: model to reroute to (if action is reroute)
        reason: human-readable reason
    """
    r = await get_redis()
    cache_key = f"{CACHE_KEY_PREFIX}{model_name}"

    cached = await r.get(cache_key)
    if cached is not None:
        data = json.loads(cached)
        if not data.get("is_active"):
            return None
        return data

    # Not in cache — no kill-switch active (cache is populated on activation)
    return None


async def activate_kill_switch(
    db: AsyncSession,
    model_name: str,
    action: str,
    activated_by: str,
    reason: str = "",
    fallback_model: str | None = None,
) -> dict:
    """Activate a kill-switch for a model. Persists to DB and pushes to Redis cache."""
    import uuid

    if action not in ("block", "reroute"):
        raise ValueError("action must be 'block' or 'reroute'")
    if action == "reroute" and not fallback_model:
        raise ValueError("fallback_model required when action is 'reroute'")

    # Upsert in database
    result = await db.execute(
        select(KillSwitch).where(KillSwitch.model_name == model_name)
    )
    ks = result.scalar_one_or_none()

    if ks is None:
        ks = KillSwitch(
            id=uuid.uuid4(),
            model_name=model_name,
            action=action,
            fallback_model=fallback_model,
            activated_by=activated_by,
            reason=reason,
            is_active=True,
        )
        db.add(ks)
    else:
        ks.action = action
        ks.fallback_model = fallback_model
        ks.activated_by = activated_by
        ks.reason = reason
        ks.is_active = True

    await db.commit()
    await db.refresh(ks)

    # Push to Redis cache for fast ingress check
    data = _serialize_kill_switch(ks)
    r = await get_redis()
    await r.setex(f"{CACHE_KEY_PREFIX}{model_name}", CACHE_TTL, json.dumps(data))

    logger.warning(
        "Kill-switch ACTIVATED model=%s action=%s fallback=%s by=%s reason=%s",
        model_name, action, fallback_model, activated_by, reason,
    )
    return data


async def deactivate_kill_switch(db: AsyncSession, model_name: str) -> bool:
    """Deactivate a kill-switch for a model."""
    result = await db.execute(
        select(KillSwitch).where(KillSwitch.model_name == model_name)
    )
    ks = result.scalar_one_or_none()
    if ks is None:
        return False

    ks.is_active = False
    await db.commit()

    # Remove from cache
    r = await get_redis()
    await r.delete(f"{CACHE_KEY_PREFIX}{model_name}")

    logger.info("Kill-switch DEACTIVATED model=%s", model_name)
    return True


async def list_kill_switches(db: AsyncSession) -> list[dict]:
    """List all kill-switches."""
    result = await db.execute(select(KillSwitch).order_by(KillSwitch.created_at.desc()))
    switches = result.scalars().all()
    return [_serialize_kill_switch(ks) for ks in switches]


async def sync_kill_switches_to_cache(db: AsyncSession) -> int:
    """Load all active kill-switches from DB into Redis cache. Returns count synced."""
    result = await db.execute(
        select(KillSwitch).where(KillSwitch.is_active == True)
    )
    switches = result.scalars().all()

    r = await get_redis()
    count = 0
    for ks in switches:
        data = _serialize_kill_switch(ks)
        await r.setex(f"{CACHE_KEY_PREFIX}{ks.model_name}", CACHE_TTL, json.dumps(data))
        count += 1

    logger.info("Synced %d active kill-switches to cache", count)
    return count


def _serialize_kill_switch(ks: KillSwitch) -> dict:
    return {
        "id": str(ks.id),
        "model_name": ks.model_name,
        "action": ks.action,
        "fallback_model": ks.fallback_model,
        "activated_by": ks.activated_by,
        "reason": ks.reason,
        "is_active": ks.is_active,
        "created_at": ks.created_at.isoformat() if ks.created_at else None,
    }
