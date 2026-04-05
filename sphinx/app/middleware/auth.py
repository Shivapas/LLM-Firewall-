import logging
import time

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.services.key_service import validate_api_key, validate_api_key_from_db
from app.services.database import async_session

logger = logging.getLogger("sphinx.auth")

# Paths that skip authentication
PUBLIC_PATHS = {"/health", "/ready", "/docs", "/openapi.json", "/redoc"}


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip auth for public endpoints
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        # Skip auth for control plane admin endpoints (they use separate auth)
        if request.url.path.startswith("/admin/"):
            return await call_next(request)

        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"error": "Missing or invalid Authorization header"},
            )

        raw_key = auth_header[7:]  # Strip "Bearer "

        start = time.monotonic()

        # Try Redis cache first
        key_data = await validate_api_key(raw_key)

        # Fall back to database
        if key_data is None:
            async with async_session() as db:
                key_data = await validate_api_key_from_db(raw_key, db)

        elapsed_ms = (time.monotonic() - start) * 1000

        if key_data is None:
            logger.warning("Invalid API key attempt, prefix=%s", raw_key[:8] if len(raw_key) >= 8 else "???")
            return JSONResponse(
                status_code=401,
                content={"error": "Invalid or expired API key"},
            )

        # Inject tenant context into request state
        request.state.tenant_id = key_data["tenant_id"]
        request.state.project_id = key_data["project_id"]
        request.state.api_key_id = key_data["id"]
        request.state.allowed_models = key_data["allowed_models"]
        request.state.tpm_limit = key_data["tpm_limit"]

        logger.info(
            "Authenticated request tenant=%s project=%s key_id=%s validation_ms=%.1f",
            key_data["tenant_id"],
            key_data["project_id"],
            key_data["id"],
            elapsed_ms,
        )

        response = await call_next(request)
        return response
