"""Automatic failover policy — if provider error rate exceeds threshold,
automatically activate kill-switch reroute to fallback provider.

Supports configurable thresholds, evaluation windows, and optional
human confirmation requirement.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import FailoverPolicy, ProviderCredential
from app.services.redis_client import get_redis
from app.services.circuit_breaker import get_circuit_breaker

logger = logging.getLogger("sphinx.failover_policy")

FAILOVER_ALERT_CHANNEL = "sphinx:failover:alerts"
CONFIRMATION_PREFIX = "failover_confirm:"

_failover_task: Optional[asyncio.Task] = None


class FailoverPolicyEngine:
    """Evaluates provider health against failover policies and triggers reroute."""

    def __init__(self, session_factory, evaluation_interval: int = 15):
        self._session_factory = session_factory
        self._evaluation_interval = evaluation_interval
        self._running = False
        self._pending_confirmations: dict[str, dict] = {}

    async def evaluate_provider(self, db: AsyncSession, policy: FailoverPolicy) -> Optional[dict]:
        """Evaluate a single provider against its failover policy.

        Returns an action dict if failover should trigger, None otherwise.
        """
        from app.services.health_probe import get_health_probe

        probe = get_health_probe()
        error_rate = await probe.compute_error_rate(
            db, policy.provider_name, window_seconds=policy.evaluation_window_seconds
        )

        # Check circuit breaker state
        cb = get_circuit_breaker(policy.provider_name)
        cb_state = await cb.get_state(db)

        should_failover = False
        reason_parts = []

        if error_rate >= policy.error_rate_threshold:
            should_failover = True
            reason_parts.append(f"error_rate={error_rate:.2%} >= threshold={policy.error_rate_threshold:.2%}")

        if cb_state["state"] == "open":
            should_failover = True
            reason_parts.append(f"circuit_breaker=open (failures={cb_state['failure_count']})")

        if not should_failover:
            return None

        reason = "; ".join(reason_parts)

        action = {
            "provider_name": policy.provider_name,
            "fallback_provider": policy.fallback_provider,
            "reason": reason,
            "error_rate": error_rate,
            "circuit_breaker_state": cb_state["state"],
            "auto_failover": policy.auto_failover,
            "require_confirmation": policy.require_confirmation,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        return action

    async def execute_failover(self, db: AsyncSession, action: dict) -> dict:
        """Execute automatic failover by activating kill-switch reroute.

        Routes traffic from the failing provider's models to the fallback provider.
        """
        from app.services.kill_switch import activate_kill_switch
        from app.services.providers.registry import MODEL_PROVIDER_MAP

        provider_name = action["provider_name"]
        fallback_provider = action["fallback_provider"]

        # Find all models served by the failing provider
        models_to_reroute = [
            model for model, prov in MODEL_PROVIDER_MAP.items()
            if prov == provider_name
        ]

        # Find a fallback model from the fallback provider
        fallback_models = [
            model for model, prov in MODEL_PROVIDER_MAP.items()
            if prov == fallback_provider
        ]
        fallback_model = fallback_models[0] if fallback_models else None

        results = []
        for model in models_to_reroute:
            try:
                ks_result = await activate_kill_switch(
                    db=db,
                    model_name=model,
                    action="reroute",
                    activated_by="failover_policy",
                    reason=f"Auto-failover: {action['reason']}",
                    fallback_model=fallback_model,
                )
                results.append({"model": model, "status": "rerouted", "fallback": fallback_model})
                logger.warning(
                    "FAILOVER: model=%s rerouted to %s (provider=%s -> %s)",
                    model, fallback_model, provider_name, fallback_provider,
                )
            except Exception as exc:
                results.append({"model": model, "status": "error", "error": str(exc)})
                logger.error("FAILOVER failed for model=%s: %s", model, exc)

        # Publish failover alert
        await self._publish_alert(action, results)

        return {
            "provider": provider_name,
            "fallback": fallback_provider,
            "models_rerouted": results,
            "timestamp": action["timestamp"],
        }

    async def request_confirmation(self, action: dict) -> str:
        """Store pending failover for human confirmation."""
        confirmation_id = str(uuid.uuid4())[:8]
        self._pending_confirmations[confirmation_id] = action

        try:
            r = await get_redis()
            await r.setex(
                f"{CONFIRMATION_PREFIX}{confirmation_id}",
                300,  # 5 min TTL
                json.dumps(action),
            )
        except Exception:
            pass

        await self._publish_alert(action, [{"status": "pending_confirmation", "confirmation_id": confirmation_id}])
        logger.info("Failover pending confirmation: id=%s provider=%s", confirmation_id, action["provider_name"])
        return confirmation_id

    async def confirm_failover(self, db: AsyncSession, confirmation_id: str) -> Optional[dict]:
        """Confirm a pending failover action."""
        action = self._pending_confirmations.pop(confirmation_id, None)
        if action is None:
            try:
                r = await get_redis()
                cached = await r.get(f"{CONFIRMATION_PREFIX}{confirmation_id}")
                if cached:
                    action = json.loads(cached)
                    await r.delete(f"{CONFIRMATION_PREFIX}{confirmation_id}")
            except Exception:
                pass

        if action is None:
            return None

        return await self.execute_failover(db, action)

    async def evaluate_all(self) -> list[dict]:
        """Evaluate all active failover policies and trigger actions."""
        actions = []
        async with self._session_factory() as db:
            q = await db.execute(
                select(FailoverPolicy).where(FailoverPolicy.is_active == True)
            )
            policies = q.scalars().all()

            for policy in policies:
                action = await self.evaluate_provider(db, policy)
                if action is None:
                    continue

                if policy.require_confirmation and not policy.auto_failover:
                    conf_id = await self.request_confirmation(action)
                    actions.append({"action": "pending_confirmation", "confirmation_id": conf_id, **action})
                elif policy.auto_failover:
                    result = await self.execute_failover(db, action)
                    actions.append({"action": "failover_executed", **result})
                else:
                    # Alert only
                    await self._publish_alert(action, [{"status": "alert_only"}])
                    actions.append({"action": "alert_only", **action})

        return actions

    async def _evaluation_loop(self) -> None:
        """Background loop evaluating failover policies."""
        self._running = True
        while self._running:
            try:
                await self.evaluate_all()
            except Exception:
                logger.error("Failover evaluation cycle failed", exc_info=True)
            await asyncio.sleep(self._evaluation_interval)

    async def start(self) -> None:
        """Start the background failover evaluation loop."""
        global _failover_task
        if _failover_task is not None:
            return
        _failover_task = asyncio.create_task(self._evaluation_loop())
        logger.info("Failover policy engine started (interval=%ds)", self._evaluation_interval)

    async def stop(self) -> None:
        """Stop the background failover evaluation loop."""
        global _failover_task
        self._running = False
        if _failover_task is not None:
            _failover_task.cancel()
            try:
                await _failover_task
            except asyncio.CancelledError:
                pass
            _failover_task = None
        logger.info("Failover policy engine stopped")

    async def _publish_alert(self, action: dict, results: list[dict]) -> None:
        try:
            r = await get_redis()
            alert = {"action": action, "results": results}
            await r.publish(FAILOVER_ALERT_CHANNEL, json.dumps(alert))
        except Exception:
            logger.debug("Failed to publish failover alert", exc_info=True)


# Singleton
_engine: Optional[FailoverPolicyEngine] = None


def get_failover_engine(session_factory=None, interval: int = 15) -> FailoverPolicyEngine:
    global _engine
    if _engine is None:
        if session_factory is None:
            from app.services.database import async_session
            session_factory = async_session
        _engine = FailoverPolicyEngine(session_factory, interval)
    return _engine


# CRUD helpers

async def create_failover_policy(db: AsyncSession, **kwargs) -> dict:
    policy = FailoverPolicy(id=uuid.uuid4(), **kwargs)
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return _serialize(policy)


async def get_failover_policy(db: AsyncSession, provider_name: str) -> Optional[dict]:
    result = await db.execute(
        select(FailoverPolicy).where(FailoverPolicy.provider_name == provider_name)
    )
    p = result.scalar_one_or_none()
    return _serialize(p) if p else None


async def list_failover_policies(db: AsyncSession) -> list[dict]:
    result = await db.execute(select(FailoverPolicy).order_by(FailoverPolicy.provider_name))
    return [_serialize(p) for p in result.scalars().all()]


async def update_failover_policy(db: AsyncSession, provider_name: str, **kwargs) -> Optional[dict]:
    result = await db.execute(
        select(FailoverPolicy).where(FailoverPolicy.provider_name == provider_name)
    )
    p = result.scalar_one_or_none()
    if p is None:
        return None
    for k, v in kwargs.items():
        if hasattr(p, k) and v is not None:
            setattr(p, k, v)
    await db.commit()
    await db.refresh(p)
    return _serialize(p)


async def delete_failover_policy(db: AsyncSession, provider_name: str) -> bool:
    result = await db.execute(
        select(FailoverPolicy).where(FailoverPolicy.provider_name == provider_name)
    )
    p = result.scalar_one_or_none()
    if p is None:
        return False
    await db.delete(p)
    await db.commit()
    return True


def _serialize(p: FailoverPolicy) -> dict:
    return {
        "id": str(p.id),
        "provider_name": p.provider_name,
        "error_rate_threshold": p.error_rate_threshold,
        "latency_threshold_ms": p.latency_threshold_ms,
        "evaluation_window_seconds": p.evaluation_window_seconds,
        "fallback_provider": p.fallback_provider,
        "auto_failover": p.auto_failover,
        "require_confirmation": p.require_confirmation,
        "is_active": p.is_active,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }
