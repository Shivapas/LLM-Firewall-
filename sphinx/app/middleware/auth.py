import logging
import time

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.services.key_service import validate_api_key, validate_api_key_from_db
from app.services.database import async_session

logger = logging.getLogger("sphinx.auth")

# Paths that skip authentication
PUBLIC_PATHS = {"/health", "/ready", "/docs", "/openapi.json", "/redoc"}

# Maximum allowed API key length to prevent abuse
MAX_API_KEY_LENGTH = 256

# Admin endpoints require a separate admin token (set via ADMIN_API_TOKEN env var)
ADMIN_PATH_PREFIX = "/admin/"


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Normalize path: strip trailing slashes for consistent matching
        path = request.url.path.rstrip("/") or "/"

        # Skip auth for public endpoints
        if path in PUBLIC_PATHS:
            return await call_next(request)

        # Admin endpoints: require admin bearer token
        if path.startswith(ADMIN_PATH_PREFIX) or path == "/admin":
            return await self._authenticate_admin(request, call_next)

        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"error": "Missing or invalid Authorization header"},
            )

        raw_key = auth_header[7:]  # Strip "Bearer "

        # Validate key length to prevent abuse
        if not raw_key or len(raw_key) > MAX_API_KEY_LENGTH:
            return JSONResponse(
                status_code=401,
                content={"error": "Invalid API key format"},
            )

        start = time.monotonic()

        # Try Redis cache first
        key_data = await validate_api_key(raw_key)

        # Fall back to database
        if key_data is None:
            async with async_session() as db:
                key_data = await validate_api_key_from_db(raw_key, db)

        elapsed_ms = (time.monotonic() - start) * 1000

        if key_data is None:
            logger.warning(
                "Invalid API key attempt, prefix=%s",
                raw_key[:4] + "..." if len(raw_key) >= 4 else "???"
            )
            return JSONResponse(
                status_code=401,
                content={"error": "Invalid or expired API key"},
            )

        # Inject tenant context into request state
        try:
            request.state.tenant_id = key_data["tenant_id"]
            request.state.project_id = key_data["project_id"]
            request.state.api_key_id = key_data["id"]
            request.state.allowed_models = key_data["allowed_models"]
            request.state.tpm_limit = key_data["tpm_limit"]
        except KeyError as e:
            logger.error("Malformed key_data missing field: %s", e)
            return JSONResponse(
                status_code=500,
                content={"error": "Internal authentication error"},
            )

        logger.info(
            "Authenticated request tenant=%s project=%s key_id=%s validation_ms=%.1f",
            key_data["tenant_id"],
            key_data["project_id"],
            key_data["id"],
            elapsed_ms,
        )

        response = await call_next(request)
        return response

    async def _authenticate_admin(self, request: Request, call_next):
        """Authenticate admin endpoints using a separate admin API token."""
        from app.config import get_settings

        settings = get_settings()
        admin_token = getattr(settings, "admin_api_token", "")

        if not admin_token:
            # If no admin token is configured, block all admin access
            logger.error("Admin API access attempted but ADMIN_API_TOKEN is not configured")
            return JSONResponse(
                status_code=403,
                content={"error": "Admin API is not configured. Set ADMIN_API_TOKEN."},
            )

        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"error": "Missing or invalid Authorization header for admin endpoint"},
            )

        provided_token = auth_header[7:]
        if provided_token != admin_token:
            logger.warning("Invalid admin token attempt from %s", request.client.host if request.client else "unknown")
            return JSONResponse(
                status_code=403,
                content={"error": "Invalid admin credentials"},
            )

        return await call_next(request)
