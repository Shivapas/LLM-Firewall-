import logging

from fastapi import APIRouter
from starlette.responses import JSONResponse

from app.services.redis_client import get_redis
from app.services.database import engine

logger = logging.getLogger("sphinx.health")

router = APIRouter()


@router.get("/health")
async def health_check():
    """Basic liveness probe for load balancers and Kubernetes."""
    return {"status": "ok"}


@router.get("/ready")
async def readiness_check():
    """Readiness probe: checks Redis and PostgreSQL connectivity."""
    checks = {"redis": False, "postgres": False}

    try:
        r = await get_redis()
        await r.ping()
        checks["redis"] = True
    except Exception as e:
        logger.error("Redis readiness check failed: %s", e)

    try:
        async with engine.connect() as conn:
            await conn.execute(
                __import__("sqlalchemy").text("SELECT 1")
            )
        checks["postgres"] = True
    except Exception as e:
        logger.error("Postgres readiness check failed: %s", e)

    all_ready = all(checks.values())
    return JSONResponse(
        status_code=200 if all_ready else 503,
        content={"status": "ready" if all_ready else "not_ready", "checks": checks},
    )
