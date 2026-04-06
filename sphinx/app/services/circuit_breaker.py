"""Circuit breaker per provider — open on consecutive failures, half-open probe, close on recovery.

States:
  - closed: normal operation, requests pass through
  - open: provider is failing, requests blocked/rerouted
  - half_open: probe requests allowed to test recovery

State transitions:
  closed -> open: failure_count >= failure_threshold
  open -> half_open: recovery_timeout_seconds elapsed
  half_open -> closed: probe succeeds
  half_open -> open: probe fails
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import CircuitBreakerState
from app.services.redis_client import get_redis

logger = logging.getLogger("sphinx.circuit_breaker")

CB_CACHE_PREFIX = "circuit_breaker:"
CB_CACHE_TTL = 30
CB_PUBSUB_CHANNEL = "sphinx:circuit_breaker:updates"

# In-memory cache of circuit breaker states
_cb_states: dict[str, dict] = {}


class CircuitBreaker:
    """Per-provider circuit breaker with open/half-open/closed states."""

    def __init__(self, provider_name: str, failure_threshold: int = 5,
                 recovery_timeout: int = 60, half_open_max: int = 1):
        self.provider_name = provider_name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max = half_open_max

    async def get_state(self, db: AsyncSession) -> dict:
        """Get current circuit breaker state for this provider."""
        # Check in-memory cache first
        if self.provider_name in _cb_states:
            state = _cb_states[self.provider_name]
            # Check if open state should transition to half_open
            if state["state"] == "open" and state.get("opened_at"):
                opened_dt = datetime.fromisoformat(state["opened_at"]) if isinstance(state["opened_at"], str) else state["opened_at"]
                elapsed = (datetime.now(timezone.utc) - opened_dt).total_seconds()
                if elapsed >= self.recovery_timeout:
                    state["state"] = "half_open"
                    state["half_open_at"] = datetime.now(timezone.utc).isoformat()
                    _cb_states[self.provider_name] = state
                    await self._persist_state(db, state)
                    await self._publish_update(state)
            return state

        # Load from DB
        result = await db.execute(
            select(CircuitBreakerState).where(CircuitBreakerState.provider_name == self.provider_name)
        )
        cb = result.scalar_one_or_none()
        if cb is None:
            state = self._default_state()
            _cb_states[self.provider_name] = state
            return state

        state = self._serialize(cb)
        _cb_states[self.provider_name] = state
        return state

    async def record_success(self, db: AsyncSession) -> dict:
        """Record a successful request. Transition half_open -> closed."""
        state = await self.get_state(db)
        now = datetime.now(timezone.utc)

        state["success_count"] = state.get("success_count", 0) + 1
        state["last_success_at"] = now.isoformat()

        if state["state"] == "half_open":
            # Successful probe — close the circuit
            state["state"] = "closed"
            state["failure_count"] = 0
            state["opened_at"] = None
            state["half_open_at"] = None
            logger.info("Circuit breaker CLOSED for provider=%s (recovered)", self.provider_name)

        _cb_states[self.provider_name] = state
        await self._persist_state(db, state)
        await self._publish_update(state)
        return state

    async def record_failure(self, db: AsyncSession) -> dict:
        """Record a failed request. Transition closed -> open or half_open -> open."""
        state = await self.get_state(db)
        now = datetime.now(timezone.utc)

        state["failure_count"] = state.get("failure_count", 0) + 1
        state["last_failure_at"] = now.isoformat()

        if state["state"] == "half_open":
            # Failed probe — reopen circuit
            state["state"] = "open"
            state["opened_at"] = now.isoformat()
            state["half_open_at"] = None
            logger.warning("Circuit breaker RE-OPENED for provider=%s (probe failed)", self.provider_name)

        elif state["state"] == "closed" and state["failure_count"] >= self.failure_threshold:
            # Threshold exceeded — open circuit
            state["state"] = "open"
            state["opened_at"] = now.isoformat()
            logger.warning(
                "Circuit breaker OPENED for provider=%s (failures=%d >= threshold=%d)",
                self.provider_name, state["failure_count"], self.failure_threshold,
            )

        _cb_states[self.provider_name] = state
        await self._persist_state(db, state)
        await self._publish_update(state)
        return state

    async def force_state(self, db: AsyncSession, new_state: str) -> dict:
        """Manually force a circuit breaker state (admin override)."""
        state = await self.get_state(db)
        now = datetime.now(timezone.utc)
        state["state"] = new_state

        if new_state == "open":
            state["opened_at"] = now.isoformat()
        elif new_state == "half_open":
            state["half_open_at"] = now.isoformat()
        elif new_state == "closed":
            state["failure_count"] = 0
            state["opened_at"] = None
            state["half_open_at"] = None

        _cb_states[self.provider_name] = state
        await self._persist_state(db, state)
        await self._publish_update(state)
        logger.info("Circuit breaker FORCED to %s for provider=%s", new_state, self.provider_name)
        return state

    async def is_request_allowed(self, db: AsyncSession) -> bool:
        """Check if a request should be allowed through for this provider."""
        state = await self.get_state(db)

        if state["state"] == "closed":
            return True
        elif state["state"] == "open":
            # Check if we should transition to half_open
            if state.get("opened_at"):
                opened_dt = datetime.fromisoformat(state["opened_at"]) if isinstance(state["opened_at"], str) else state["opened_at"]
                elapsed = (datetime.now(timezone.utc) - opened_dt).total_seconds()
                if elapsed >= self.recovery_timeout:
                    state["state"] = "half_open"
                    state["half_open_at"] = datetime.now(timezone.utc).isoformat()
                    _cb_states[self.provider_name] = state
                    await self._persist_state(db, state)
                    await self._publish_update(state)
                    return True  # Allow probe request
            return False
        elif state["state"] == "half_open":
            return True  # Allow probe requests
        return False

    async def _persist_state(self, db: AsyncSession, state: dict) -> None:
        """Persist circuit breaker state to DB and Redis."""
        result = await db.execute(
            select(CircuitBreakerState).where(CircuitBreakerState.provider_name == self.provider_name)
        )
        cb = result.scalar_one_or_none()
        now = datetime.now(timezone.utc)

        if cb is None:
            cb = CircuitBreakerState(
                id=uuid.uuid4(),
                provider_name=self.provider_name,
                state=state["state"],
                failure_count=state.get("failure_count", 0),
                success_count=state.get("success_count", 0),
                last_failure_at=_parse_dt(state.get("last_failure_at")),
                last_success_at=_parse_dt(state.get("last_success_at")),
                opened_at=_parse_dt(state.get("opened_at")),
                half_open_at=_parse_dt(state.get("half_open_at")),
                failure_threshold=self.failure_threshold,
                recovery_timeout_seconds=self.recovery_timeout,
                half_open_max_requests=self.half_open_max,
            )
            db.add(cb)
        else:
            cb.state = state["state"]
            cb.failure_count = state.get("failure_count", 0)
            cb.success_count = state.get("success_count", 0)
            cb.last_failure_at = _parse_dt(state.get("last_failure_at"))
            cb.last_success_at = _parse_dt(state.get("last_success_at"))
            cb.opened_at = _parse_dt(state.get("opened_at"))
            cb.half_open_at = _parse_dt(state.get("half_open_at"))

        await db.commit()

        # Cache in Redis
        try:
            r = await get_redis()
            cache_key = f"{CB_CACHE_PREFIX}{self.provider_name}"
            await r.setex(cache_key, CB_CACHE_TTL, json.dumps(state))
        except Exception:
            logger.debug("Failed to cache circuit breaker state", exc_info=True)

    async def _publish_update(self, state: dict) -> None:
        """Publish circuit breaker state change via Redis pub/sub."""
        try:
            r = await get_redis()
            msg = json.dumps({"provider_name": self.provider_name, "state": state})
            await r.publish(CB_PUBSUB_CHANNEL, msg)
        except Exception:
            logger.debug("Failed to publish circuit breaker update", exc_info=True)

    def _default_state(self) -> dict:
        return {
            "provider_name": self.provider_name,
            "state": "closed",
            "failure_count": 0,
            "success_count": 0,
            "last_failure_at": None,
            "last_success_at": None,
            "opened_at": None,
            "half_open_at": None,
            "failure_threshold": self.failure_threshold,
            "recovery_timeout_seconds": self.recovery_timeout,
        }

    @staticmethod
    def _serialize(cb: CircuitBreakerState) -> dict:
        return {
            "id": str(cb.id),
            "provider_name": cb.provider_name,
            "state": cb.state,
            "failure_count": cb.failure_count,
            "success_count": cb.success_count,
            "last_failure_at": cb.last_failure_at.isoformat() if cb.last_failure_at else None,
            "last_success_at": cb.last_success_at.isoformat() if cb.last_success_at else None,
            "opened_at": cb.opened_at.isoformat() if cb.opened_at else None,
            "half_open_at": cb.half_open_at.isoformat() if cb.half_open_at else None,
            "failure_threshold": cb.failure_threshold,
            "recovery_timeout_seconds": cb.recovery_timeout_seconds,
            "created_at": cb.created_at.isoformat() if cb.created_at else None,
            "updated_at": cb.updated_at.isoformat() if cb.updated_at else None,
        }


def _parse_dt(val) -> Optional[datetime]:
    """Parse a datetime from string or return as-is."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val
    return datetime.fromisoformat(val)


# ── Convenience functions ────────────────────────────────────────────────

_breakers: dict[str, CircuitBreaker] = {}


def get_circuit_breaker(provider_name: str, failure_threshold: int = 5,
                        recovery_timeout: int = 60) -> CircuitBreaker:
    """Get or create a circuit breaker for a provider."""
    if provider_name not in _breakers:
        _breakers[provider_name] = CircuitBreaker(
            provider_name, failure_threshold, recovery_timeout
        )
    return _breakers[provider_name]


async def get_all_circuit_breaker_states(db: AsyncSession) -> list[dict]:
    """Get all circuit breaker states from DB."""
    result = await db.execute(
        select(CircuitBreakerState).order_by(CircuitBreakerState.provider_name)
    )
    states = result.scalars().all()
    return [CircuitBreaker._serialize(s) for s in states]


async def sync_circuit_breakers_from_db(db: AsyncSession) -> int:
    """Load all circuit breaker states from DB into memory on startup."""
    result = await db.execute(select(CircuitBreakerState))
    states = result.scalars().all()
    count = 0
    for cb in states:
        state = CircuitBreaker._serialize(cb)
        _cb_states[cb.provider_name] = state
        _breakers[cb.provider_name] = CircuitBreaker(
            cb.provider_name, cb.failure_threshold, cb.recovery_timeout_seconds
        )
        count += 1
    logger.info("Synced %d circuit breaker states from DB", count)
    return count
