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

logger = logging.getLogger("sphinx.main")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: load policy cache and sync kill-switches
    try:
        async with async_session() as db:
            await load_policies(db)
            await sync_kill_switches_to_cache(db)
        start_background_refresh(async_session)
        logger.info("Startup complete: policy cache loaded, kill-switches synced")
    except Exception:
        logger.warning("Startup cache loading failed (DB may not be ready)", exc_info=True)

    yield

    # Shutdown
    stop_background_refresh()
    await close_redis()
    await close_http_client()


app = FastAPI(
    title="Sphinx AI Mesh Firewall",
    description="Gateway proxy for LLM provider traffic with API key auth and tenant isolation",
    version="0.1.0",
    lifespan=lifespan,
)

# Middleware
app.add_middleware(APIKeyAuthMiddleware)

# Routers
app.include_router(health.router)
app.include_router(proxy.router)
app.include_router(admin.router)
