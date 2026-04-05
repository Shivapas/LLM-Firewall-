"""Policy cache loader — pulls compiled policy objects from DB on startup and refresh.

Maintains an in-memory policy cache with TTL-based refresh for sub-millisecond lookups.
Also supports forced refresh via push notification.
"""

import asyncio
import json
import logging
import time
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import PolicyRule

logger = logging.getLogger("sphinx.policy_cache")

# In-memory cache for sub-millisecond access
_policy_cache: dict[str, dict] = {}
_cache_loaded_at: float = 0
CACHE_TTL = 60  # Refresh every 60 seconds
_refresh_task: Optional[asyncio.Task] = None


def get_policy(name: str) -> Optional[dict]:
    """Get a cached policy by name. Returns None if not found. O(1) lookup."""
    return _policy_cache.get(name)


def get_all_policies() -> dict[str, dict]:
    """Get all cached policies. Returns a copy of the cache."""
    return dict(_policy_cache)


def get_policies_by_type(policy_type: str) -> list[dict]:
    """Get all cached policies of a given type."""
    return [p for p in _policy_cache.values() if p.get("policy_type") == policy_type]


async def load_policies(db: AsyncSession) -> int:
    """Load all active policies from DB into in-memory cache. Returns count loaded."""
    global _policy_cache, _cache_loaded_at

    result = await db.execute(
        select(PolicyRule).where(PolicyRule.is_active == True)
    )
    rules = result.scalars().all()

    new_cache = {}
    for rule in rules:
        new_cache[rule.name] = {
            "id": str(rule.id),
            "name": rule.name,
            "description": rule.description,
            "policy_type": rule.policy_type,
            "rules": json.loads(rule.rules_json) if rule.rules_json else {},
            "version": rule.version,
            "is_active": rule.is_active,
        }

    _policy_cache = new_cache
    _cache_loaded_at = time.monotonic()

    logger.info("Loaded %d active policies into cache", len(new_cache))
    return len(new_cache)


async def refresh_if_stale(db: AsyncSession) -> bool:
    """Refresh cache if TTL has elapsed. Returns True if refreshed."""
    global _cache_loaded_at
    if time.monotonic() - _cache_loaded_at > CACHE_TTL:
        await load_policies(db)
        return True
    return False


async def force_refresh(db: AsyncSession) -> int:
    """Force a cache refresh regardless of TTL. Returns count loaded."""
    return await load_policies(db)


async def _background_refresh_loop(session_factory) -> None:
    """Background task that periodically refreshes the policy cache."""
    while True:
        try:
            await asyncio.sleep(CACHE_TTL)
            async with session_factory() as db:
                await load_policies(db)
        except asyncio.CancelledError:
            logger.info("Policy cache refresh loop cancelled")
            break
        except Exception:
            logger.exception("Error refreshing policy cache")
            await asyncio.sleep(5)


def start_background_refresh(session_factory) -> asyncio.Task:
    """Start the background policy cache refresh loop."""
    global _refresh_task
    _refresh_task = asyncio.create_task(_background_refresh_loop(session_factory))
    logger.info("Started policy cache background refresh (TTL=%ds)", CACHE_TTL)
    return _refresh_task


def stop_background_refresh() -> None:
    """Stop the background refresh task."""
    global _refresh_task
    if _refresh_task is not None:
        _refresh_task.cancel()
        _refresh_task = None
        logger.info("Stopped policy cache background refresh")
