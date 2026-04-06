"""Provider health probe — periodic health checks for registered providers.

Detects latency spikes, error rate increases, and provider outages.
Fires alerts when error rate exceeds threshold within evaluation window.
"""

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy import select, func as sa_func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import ProviderHealthCheck, ProviderCredential
from app.services.redis_client import get_redis

logger = logging.getLogger("sphinx.health_probe")

ALERT_CHANNEL = "sphinx:provider:alerts"
HEALTH_CACHE_PREFIX = "provider_health:"
HEALTH_CACHE_TTL = 30  # seconds

_probe_task: Optional[asyncio.Task] = None
_probe_interval: int = 30  # seconds between probes


class ProviderHealthProbe:
    """Periodic health checker for all registered providers."""

    def __init__(self, session_factory, interval: int = 30):
        self._session_factory = session_factory
        self._interval = interval
        self._client = httpx.AsyncClient(timeout=10.0)
        self._running = False

    async def probe_provider(self, provider_name: str, base_url: str) -> dict:
        """Send a lightweight health check request to a provider."""
        start = time.monotonic()
        result = {
            "provider_name": provider_name,
            "is_healthy": False,
            "latency_ms": 0.0,
            "status_code": 0,
            "error_message": "",
            "error_rate": 0.0,
        }

        try:
            # Use a lightweight endpoint — most providers respond to GET on base URL
            # or a models endpoint
            url = base_url.rstrip("/")
            if "openai" in provider_name or "azure" in provider_name:
                url += "/models"
            elif "anthropic" in provider_name:
                url += "/v1/models"
            else:
                url += "/health"

            resp = await self._client.get(url, headers={"Accept": "application/json"})
            elapsed_ms = (time.monotonic() - start) * 1000.0

            result["status_code"] = resp.status_code
            result["latency_ms"] = round(elapsed_ms, 2)
            result["is_healthy"] = resp.status_code < 500

            if resp.status_code >= 500:
                result["error_message"] = f"HTTP {resp.status_code}"

        except httpx.TimeoutException:
            elapsed_ms = (time.monotonic() - start) * 1000.0
            result["latency_ms"] = round(elapsed_ms, 2)
            result["error_message"] = "Timeout"
        except httpx.ConnectError as exc:
            elapsed_ms = (time.monotonic() - start) * 1000.0
            result["latency_ms"] = round(elapsed_ms, 2)
            result["error_message"] = f"Connection error: {exc}"
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000.0
            result["latency_ms"] = round(elapsed_ms, 2)
            result["error_message"] = str(exc)

        return result

    async def compute_error_rate(self, db: AsyncSession, provider_name: str, window_seconds: int = 60) -> float:
        """Compute error rate for a provider over the last window_seconds."""
        cutoff = datetime.now(timezone.utc).timestamp() - window_seconds
        from sqlalchemy import and_

        total_q = await db.execute(
            select(sa_func.count(ProviderHealthCheck.id)).where(
                and_(
                    ProviderHealthCheck.provider_name == provider_name,
                    ProviderHealthCheck.checked_at >= datetime.fromtimestamp(cutoff, tz=timezone.utc),
                )
            )
        )
        total = total_q.scalar() or 0
        if total == 0:
            return 0.0

        error_q = await db.execute(
            select(sa_func.count(ProviderHealthCheck.id)).where(
                and_(
                    ProviderHealthCheck.provider_name == provider_name,
                    ProviderHealthCheck.checked_at >= datetime.fromtimestamp(cutoff, tz=timezone.utc),
                    ProviderHealthCheck.is_healthy == False,
                )
            )
        )
        errors = error_q.scalar() or 0
        return errors / total

    async def record_check(self, db: AsyncSession, result: dict) -> None:
        """Persist a health check result to the database and cache."""
        record = ProviderHealthCheck(
            id=uuid.uuid4(),
            provider_name=result["provider_name"],
            is_healthy=result["is_healthy"],
            latency_ms=result["latency_ms"],
            status_code=result["status_code"],
            error_message=result["error_message"],
            error_rate=result["error_rate"],
        )
        db.add(record)
        await db.commit()

        # Cache latest health status in Redis
        try:
            import json
            r = await get_redis()
            cache_key = f"{HEALTH_CACHE_PREFIX}{result['provider_name']}"
            await r.setex(cache_key, HEALTH_CACHE_TTL, json.dumps(result))
        except Exception:
            logger.debug("Failed to cache health check result", exc_info=True)

    async def fire_alert(self, provider_name: str, error_rate: float, message: str) -> None:
        """Publish a provider health alert via Redis pub/sub."""
        import json
        try:
            r = await get_redis()
            alert = {
                "provider_name": provider_name,
                "error_rate": error_rate,
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            await r.publish(ALERT_CHANNEL, json.dumps(alert))
            logger.warning("ALERT: provider=%s error_rate=%.2f msg=%s", provider_name, error_rate, message)
        except Exception:
            logger.error("Failed to publish provider alert", exc_info=True)

    async def run_probe_cycle(self) -> list[dict]:
        """Run one complete probe cycle for all registered providers."""
        results = []
        async with self._session_factory() as db:
            # Get all enabled providers
            q = await db.execute(
                select(ProviderCredential).where(ProviderCredential.is_enabled == True)
            )
            providers = q.scalars().all()

            for provider in providers:
                result = await self.probe_provider(provider.provider_name, provider.base_url)

                # Compute error rate over the last 60s
                error_rate = await self.compute_error_rate(db, provider.provider_name, window_seconds=60)
                result["error_rate"] = round(error_rate, 4)

                await self.record_check(db, result)
                results.append(result)

                # Fire alert if error rate is elevated
                if error_rate > 0.5:
                    await self.fire_alert(
                        provider.provider_name,
                        error_rate,
                        f"Error rate spike detected: {error_rate:.0%}",
                    )

        return results

    async def _probe_loop(self) -> None:
        """Background loop that periodically probes all providers."""
        self._running = True
        while self._running:
            try:
                await self.run_probe_cycle()
            except Exception:
                logger.error("Health probe cycle failed", exc_info=True)
            await asyncio.sleep(self._interval)

    async def start(self) -> None:
        """Start the background health probe loop."""
        global _probe_task
        if _probe_task is not None:
            return
        _probe_task = asyncio.create_task(self._probe_loop())
        logger.info("Provider health probe started (interval=%ds)", self._interval)

    async def stop(self) -> None:
        """Stop the background health probe loop."""
        global _probe_task
        self._running = False
        if _probe_task is not None:
            _probe_task.cancel()
            try:
                await _probe_task
            except asyncio.CancelledError:
                pass
            _probe_task = None
        await self._client.aclose()
        logger.info("Provider health probe stopped")

    async def close(self) -> None:
        await self.stop()


# Singleton
_health_probe: Optional[ProviderHealthProbe] = None


def get_health_probe(session_factory=None, interval: int = 30) -> ProviderHealthProbe:
    global _health_probe
    if _health_probe is None:
        if session_factory is None:
            from app.services.database import async_session
            session_factory = async_session
        _health_probe = ProviderHealthProbe(session_factory, interval)
    return _health_probe


async def get_provider_health_status(db: AsyncSession, provider_name: Optional[str] = None) -> list[dict]:
    """Get latest health status for providers from cache or DB."""
    import json

    # Try cache first
    try:
        r = await get_redis()
        if provider_name:
            cached = await r.get(f"{HEALTH_CACHE_PREFIX}{provider_name}")
            if cached:
                return [json.loads(cached)]
        else:
            # Get all providers and check cache for each
            q = await db.execute(
                select(ProviderCredential.provider_name).where(ProviderCredential.is_enabled == True)
            )
            names = [row[0] for row in q.fetchall()]
            results = []
            for name in names:
                cached = await r.get(f"{HEALTH_CACHE_PREFIX}{name}")
                if cached:
                    results.append(json.loads(cached))
            if results:
                return results
    except Exception:
        pass

    # Fallback: latest check per provider from DB
    from sqlalchemy import distinct
    if provider_name:
        q = await db.execute(
            select(ProviderHealthCheck)
            .where(ProviderHealthCheck.provider_name == provider_name)
            .order_by(ProviderHealthCheck.checked_at.desc())
            .limit(1)
        )
    else:
        # Get latest check for each provider using a subquery
        subq = (
            select(
                ProviderHealthCheck.provider_name,
                sa_func.max(ProviderHealthCheck.checked_at).label("max_checked"),
            )
            .group_by(ProviderHealthCheck.provider_name)
            .subquery()
        )
        q = await db.execute(
            select(ProviderHealthCheck).join(
                subq,
                (ProviderHealthCheck.provider_name == subq.c.provider_name)
                & (ProviderHealthCheck.checked_at == subq.c.max_checked),
            )
        )

    checks = q.scalars().all()
    return [
        {
            "provider_name": c.provider_name,
            "is_healthy": c.is_healthy,
            "latency_ms": c.latency_ms,
            "status_code": c.status_code,
            "error_message": c.error_message,
            "error_rate": c.error_rate,
            "checked_at": c.checked_at.isoformat() if c.checked_at else None,
        }
        for c in checks
    ]
