"""Kill-switch service — per-model blocking/rerouting at ingress.

Checks cached kill-switch state; returns 503 or reroutes to fallback model.
Supports Redis pub/sub for sub-5-second propagation across gateway instances.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import KillSwitch, KillSwitchAuditLog
from app.services.redis_client import get_redis

logger = logging.getLogger("sphinx.kill_switch")

CACHE_KEY_PREFIX = "killswitch:"
CACHE_TTL = 30  # seconds
PUBSUB_CHANNEL = "sphinx:killswitch:updates"

# Local in-memory state updated via pub/sub subscriber
_local_kill_switch_state: dict[str, dict] = {}
_subscriber_task: Optional[asyncio.Task] = None


async def check_kill_switch(model_name: str) -> Optional[dict]:
    """Check if a kill-switch is active for the given model.

    Checks local in-memory state first (updated via pub/sub), then falls back
    to Redis cache. Returns None if no active kill-switch.
    """
    # Fast path: check local state (updated by pub/sub subscriber)
    local = _local_kill_switch_state.get(model_name)
    if local is not None:
        if not local.get("is_active"):
            return None
        return local

    # Fallback: check Redis cache directly
    r = await get_redis()
    cache_key = f"{CACHE_KEY_PREFIX}{model_name}"
    cached = await r.get(cache_key)
    if cached is not None:
        data = json.loads(cached)
        if not data.get("is_active"):
            return None
        # Populate local state
        _local_kill_switch_state[model_name] = data
        return data

    return None


async def activate_kill_switch(
    db: AsyncSession,
    model_name: str,
    action: str,
    activated_by: str,
    reason: str = "",
    fallback_model: str | None = None,
    error_message: str | None = None,
) -> dict:
    """Activate a kill-switch for a model. Persists to DB, pushes to Redis cache, and publishes via pub/sub."""
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
            error_message=error_message or "Model temporarily unavailable",
            is_active=True,
        )
        db.add(ks)
    else:
        ks.action = action
        ks.fallback_model = fallback_model
        ks.activated_by = activated_by
        ks.reason = reason
        ks.error_message = error_message or "Model temporarily unavailable"
        ks.is_active = True

    await db.commit()
    await db.refresh(ks)

    # Write immutable audit log
    audit_entry = KillSwitchAuditLog(
        id=uuid.uuid4(),
        model_name=model_name,
        action=action,
        fallback_model=fallback_model,
        activated_by=activated_by,
        reason=reason,
        event_type="activated",
    )
    db.add(audit_entry)
    await db.commit()

    # Push to Redis cache and publish change notification
    data = _serialize_kill_switch(ks)
    r = await get_redis()
    await r.setex(f"{CACHE_KEY_PREFIX}{model_name}", CACHE_TTL, json.dumps(data))

    # Publish to pub/sub channel for all gateway subscribers
    await _publish_kill_switch_update(r, model_name, data)

    # Update local state immediately
    _local_kill_switch_state[model_name] = data

    logger.warning(
        "Kill-switch ACTIVATED model=%s action=%s fallback=%s by=%s reason=%s",
        model_name, action, fallback_model, activated_by, reason,
    )
    return data


async def deactivate_kill_switch(db: AsyncSession, model_name: str) -> bool:
    """Deactivate a kill-switch for a model."""
    import uuid

    result = await db.execute(
        select(KillSwitch).where(KillSwitch.model_name == model_name)
    )
    ks = result.scalar_one_or_none()
    if ks is None:
        return False

    ks.is_active = False
    await db.commit()

    # Write immutable audit log
    audit_entry = KillSwitchAuditLog(
        id=uuid.uuid4(),
        model_name=model_name,
        action=ks.action,
        fallback_model=ks.fallback_model,
        activated_by=ks.activated_by,
        reason=ks.reason,
        event_type="deactivated",
    )
    db.add(audit_entry)
    await db.commit()

    # Remove from cache and publish deactivation
    r = await get_redis()
    await r.delete(f"{CACHE_KEY_PREFIX}{model_name}")

    deactivation_data = {"model_name": model_name, "is_active": False}
    await _publish_kill_switch_update(r, model_name, deactivation_data)

    # Remove from local state
    _local_kill_switch_state.pop(model_name, None)

    logger.info("Kill-switch DEACTIVATED model=%s", model_name)
    return True


async def list_kill_switches(db: AsyncSession) -> list[dict]:
    """List all kill-switches."""
    result = await db.execute(select(KillSwitch).order_by(KillSwitch.created_at.desc()))
    switches = result.scalars().all()
    return [_serialize_kill_switch(ks) for ks in switches]


async def get_kill_switch_audit_log(db: AsyncSession, model_name: Optional[str] = None) -> list[dict]:
    """Get immutable kill-switch audit log. Cannot be deleted via API."""
    query = select(KillSwitchAuditLog).order_by(KillSwitchAuditLog.created_at.desc())
    if model_name:
        query = query.where(KillSwitchAuditLog.model_name == model_name)
    result = await db.execute(query)
    logs = result.scalars().all()
    return [
        {
            "id": str(log.id),
            "model_name": log.model_name,
            "action": log.action,
            "fallback_model": log.fallback_model,
            "activated_by": log.activated_by,
            "reason": log.reason,
            "event_type": log.event_type,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in logs
    ]


async def sync_kill_switches_to_cache(db: AsyncSession) -> int:
    """Load all active kill-switches from DB into Redis cache and local state. Returns count synced."""
    result = await db.execute(
        select(KillSwitch).where(KillSwitch.is_active == True)
    )
    switches = result.scalars().all()

    r = await get_redis()
    count = 0
    for ks in switches:
        data = _serialize_kill_switch(ks)
        await r.setex(f"{CACHE_KEY_PREFIX}{ks.model_name}", CACHE_TTL, json.dumps(data))
        _local_kill_switch_state[ks.model_name] = data
        count += 1

    logger.info("Synced %d active kill-switches to cache", count)
    return count


# ── Pub/Sub ──────────────────────────────────────────────────────────────


async def _publish_kill_switch_update(r, model_name: str, data: dict) -> None:
    """Publish kill-switch state change to Redis pub/sub channel."""
    message = json.dumps({"model_name": model_name, "data": data})
    try:
        await r.publish(PUBSUB_CHANNEL, message)
        logger.debug("Published kill-switch update for model=%s", model_name)
    except Exception:
        logger.warning("Failed to publish kill-switch update", exc_info=True)


async def start_kill_switch_subscriber() -> None:
    """Start a background task that subscribes to kill-switch pub/sub updates."""
    global _subscriber_task
    if _subscriber_task is not None:
        return

    _subscriber_task = asyncio.create_task(_kill_switch_subscriber_loop())
    logger.info("Kill-switch pub/sub subscriber started")


async def stop_kill_switch_subscriber() -> None:
    """Stop the kill-switch pub/sub subscriber."""
    global _subscriber_task
    if _subscriber_task is not None:
        _subscriber_task.cancel()
        try:
            await _subscriber_task
        except asyncio.CancelledError:
            pass
        _subscriber_task = None
        logger.info("Kill-switch pub/sub subscriber stopped")


async def _kill_switch_subscriber_loop() -> None:
    """Subscribe to Redis pub/sub and update local kill-switch state."""
    try:
        r = await get_redis()
        pubsub = r.pubsub()
        await pubsub.subscribe(PUBSUB_CHANNEL)
        logger.info("Subscribed to channel=%s", PUBSUB_CHANNEL)

        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                payload = json.loads(message["data"])
                model_name = payload["model_name"]
                data = payload["data"]

                if data.get("is_active", False):
                    _local_kill_switch_state[model_name] = data
                    logger.info("Pub/sub: kill-switch ACTIVATED model=%s", model_name)
                else:
                    _local_kill_switch_state.pop(model_name, None)
                    logger.info("Pub/sub: kill-switch DEACTIVATED model=%s", model_name)
            except Exception:
                logger.warning("Failed to process pub/sub message", exc_info=True)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.error("Kill-switch subscriber loop error", exc_info=True)


def _serialize_kill_switch(ks: KillSwitch) -> dict:
    return {
        "id": str(ks.id),
        "model_name": ks.model_name,
        "action": ks.action,
        "fallback_model": ks.fallback_model,
        "activated_by": ks.activated_by,
        "reason": ks.reason,
        "error_message": ks.error_message if hasattr(ks, 'error_message') and ks.error_message else "Model temporarily unavailable",
        "is_active": ks.is_active,
        "created_at": ks.created_at.isoformat() if ks.created_at else None,
        "updated_at": ks.updated_at.isoformat() if ks.updated_at else None,
    }
