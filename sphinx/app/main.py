import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.middleware.auth import APIKeyAuthMiddleware
from app.routers import health, proxy, admin
from app.services.redis_client import close_redis
from app.services.proxy import close_http_client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
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
