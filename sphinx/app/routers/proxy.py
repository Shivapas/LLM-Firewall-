import logging

from fastapi import APIRouter, Request
from starlette.responses import Response

from app.services.proxy import proxy_request
from app.config import get_settings

logger = logging.getLogger("sphinx.proxy")

router = APIRouter()


@router.api_route(
    "/v1/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
async def gateway_proxy(request: Request, path: str) -> Response:
    """Main gateway proxy endpoint. Forwards authenticated requests to LLM providers."""
    settings = get_settings()
    target_url = settings.default_provider_url

    tenant_id = getattr(request.state, "tenant_id", "unknown")
    project_id = getattr(request.state, "project_id", "unknown")

    logger.info(
        "Proxying request path=/v1/%s tenant=%s project=%s method=%s",
        path,
        tenant_id,
        project_id,
        request.method,
    )

    response = await proxy_request(request, target_url)
    return response
