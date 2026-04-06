import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.middleware.auth import APIKeyAuthMiddleware
from app.routers import health, proxy, admin
from app.services.redis_client import close_redis
from app.services.proxy import close_http_client
from app.services.database import async_session
from app.services.policy_cache import load_policies, start_background_refresh, stop_background_refresh
from app.services.kill_switch import sync_kill_switches_to_cache, start_kill_switch_subscriber, stop_kill_switch_subscriber
from app.services.routing import initialize_registry
from app.services.credential_store import list_providers, get_provider_credential
from app.services.audit import get_audit_writer, get_audit_consumer
from app.services.threat_detection.engine import get_threat_engine, reset_threat_engine
from app.services.threat_detection.tier2_scanner import get_tier2_scanner
from app.services.health_probe import get_health_probe
from app.services.circuit_breaker import sync_circuit_breakers_from_db
from app.services.failover_policy import get_failover_engine

logger = logging.getLogger("sphinx.main")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: load policy cache, sync kill-switches, init providers, start audit
    try:
        async with async_session() as db:
            await load_policies(db)
            await sync_kill_switches_to_cache(db)

            # Initialize provider registry from stored credentials
            providers = []
            provider_list = await list_providers(db)
            for p in provider_list:
                if p.get("is_enabled"):
                    cred = await get_provider_credential(db, p["provider_name"])
                    if cred:
                        providers.append(cred)
            if providers:
                await initialize_registry(providers)
                logger.info("Provider registry initialized with %d providers", len(providers))

        start_background_refresh(async_session)

        # Initialize audit writer (Kafka producer)
        audit_writer = get_audit_writer()
        await audit_writer.initialize()

        # Start audit consumer (Kafka -> Postgres)
        audit_consumer = get_audit_consumer()
        await audit_consumer.start(async_session)

        # Initialize Tier 1 Threat Detection Engine
        threat_engine = get_threat_engine()
        logger.info(
            "Threat detection engine initialized: %d patterns loaded",
            threat_engine.library.count(),
        )

        # Load custom security rules from DB into threat engine
        from app.models.api_key import SecurityRule
        try:
            async with async_session() as db:
                from sqlalchemy import select
                result = await db.execute(
                    select(SecurityRule).where(SecurityRule.is_active == True)
                )
                custom_rules = result.scalars().all()
                if custom_rules:
                    import json as _json
                    rule_dicts = [
                        {
                            "id": f"custom-{r.id}",
                            "name": r.name,
                            "category": r.category,
                            "severity": r.severity,
                            "pattern": r.pattern,
                            "description": r.description,
                            "tags": _json.loads(r.tags_json) if r.tags_json else [],
                        }
                        for r in custom_rules
                    ]
                    threat_engine.load_policy_rules(rule_dicts)
                    logger.info("Loaded %d custom security rules from DB", len(custom_rules))
        except Exception:
            logger.warning("Failed to load custom security rules (table may not exist)", exc_info=True)

        # Initialize Tier 2 ML semantic scanner
        tier2_scanner = get_tier2_scanner()
        logger.info(
            "Tier 2 semantic scanner initialized: %d threat embeddings in index",
            tier2_scanner.index_size,
        )

        # Start kill-switch pub/sub subscriber for sub-5s propagation
        await start_kill_switch_subscriber()

        # Sprint 13: Initialize provider health monitoring & failover
        async with async_session() as db:
            await sync_circuit_breakers_from_db(db)

        health_probe = get_health_probe(async_session)
        await health_probe.start()

        failover_engine = get_failover_engine(async_session)
        await failover_engine.start()

        logger.info("Startup complete: policy cache loaded, kill-switches synced, pub/sub active, audit system ready, health probe active")
    except Exception:
        logger.warning("Startup cache loading failed (DB may not be ready)", exc_info=True)

    yield

    # Shutdown
    await stop_kill_switch_subscriber()
    stop_background_refresh()

    # Stop Sprint 13 services
    try:
        health_probe = get_health_probe()
        await health_probe.stop()
        failover_engine = get_failover_engine()
        await failover_engine.stop()
    except Exception:
        logger.warning("Error shutting down health probe / failover engine", exc_info=True)

    # Close audit system
    try:
        audit_writer = get_audit_writer()
        await audit_writer.close()
        audit_consumer = get_audit_consumer()
        await audit_consumer.stop()
    except Exception:
        logger.warning("Error shutting down audit system", exc_info=True)

    await close_redis()
    await close_http_client()


app = FastAPI(
    title="Sphinx AI Mesh Firewall",
    description="Gateway proxy for LLM provider traffic with multi-provider routing and audit",
    version="0.8.0",
    lifespan=lifespan,
)

# Middleware
app.add_middleware(APIKeyAuthMiddleware)

# Routers
app.include_router(health.router)
app.include_router(proxy.router)
app.include_router(admin.router)
