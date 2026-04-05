import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.middleware.auth import APIKeyAuthMiddleware
from app.routers import health, proxy, admin
from app.services.redis_client import close_redis
from app.services.proxy import close_http_client
from app.services.database import async_session
from app.services.policy_cache import load_policies, start_background_refresh, stop_background_refresh
from app.services.kill_switch import sync_kill_switches_to_cache
from app.services.routing import initialize_registry
from app.services.credential_store import list_providers, get_provider_credential
from app.services.audit import get_audit_writer, get_audit_consumer

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

        logger.info("Startup complete: policy cache loaded, kill-switches synced, audit system ready")
    except Exception:
        logger.warning("Startup cache loading failed (DB may not be ready)", exc_info=True)

    yield

    # Shutdown
    stop_background_refresh()

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
    version="0.3.0",
    lifespan=lifespan,
)

# Middleware
app.add_middleware(APIKeyAuthMiddleware)

# Routers
app.include_router(health.router)
app.include_router(proxy.router)
app.include_router(admin.router)
