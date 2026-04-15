"""Sprint 33 — Canary Token Module router.

Endpoints:
  POST /v1/canary/inject         — inject canary into system prompt for a session
  POST /v1/canary/scan           — scan a response for canary leakage
  GET  /v1/canary/health         — health / readiness check
  GET  /v1/canary/metrics        — 30-day rolling leakage stats (dashboard badge)
  GET  /v1/canary/config         — current canary configuration
  PUT  /v1/canary/config         — update canary toggle per policy (SP-335)
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.canary.generator import get_canary_generator
from app.services.canary.injector import get_canary_injector
from app.services.canary.scanner import CanaryScanResult, get_canary_scanner
from app.services.canary.threat_event import (
    CanaryThreatEvent,
    get_canary_threat_emitter,
)
from app.services.canary.metrics import CanaryMetricsStore

logger = logging.getLogger("sphinx.routers.canary")

router = APIRouter(prefix="/v1/canary", tags=["Canary Token"])

# Module-level metrics store instance
_metrics_store = CanaryMetricsStore()


def get_canary_metrics_store() -> CanaryMetricsStore:
    return _metrics_store


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CanaryInjectRequest(BaseModel):
    """Request to inject a canary token into a system prompt."""
    system_prompt: str = Field(..., description="Original system prompt text")
    session_id: str = Field(..., description="Unique session identifier")
    ttl_seconds: Optional[float] = Field(None, description="Token TTL override")


class CanaryInjectResponse(BaseModel):
    """Response after canary injection."""
    modified_prompt: str
    session_id: str
    canary_active: bool = True
    ttl_seconds: float = 0.0


class CanaryScanRequest(BaseModel):
    """Request to scan a response for canary leakage."""
    response_text: str = Field(..., description="LLM response text to scan")
    session_id: str = Field(..., description="Session to check canary for")
    turn_index: int = Field(0, description="Conversation turn index")
    tenant_id: str = Field("", description="Tenant ID for threat event")
    policy_id: str = Field("", description="Policy ID for threat event")


class CanaryScanResponse(BaseModel):
    """Response from canary scan."""
    detected: bool = False
    session_id: str = ""
    turn_index: int = 0
    scan_time_ms: float = 0.0
    extraction_confidence: float = 0.0
    threat_event_emitted: bool = False


class CanaryHealthResponse(BaseModel):
    """Canary module health check."""
    status: str = "ok"
    enabled: bool = True
    active_sessions: int = 0
    total_generated: int = 0
    total_scans: int = 0
    total_detections: int = 0


class CanaryMetricsResponse(BaseModel):
    """SP-335: 30-day rolling leakage metrics for dashboard badge."""
    rolling_leakage_count: int = 0
    total_scans: int = 0
    total_detections: int = 0
    total_sessions_protected: int = 0
    window_days: int = 30
    detection_rate: float = 0.0


class CanaryConfigResponse(BaseModel):
    """Current canary configuration."""
    canary_token_enabled: bool = True
    active_sessions: int = 0
    total_generated: int = 0
    total_injections: int = 0
    emitter_connected: bool = False
    emitter_emitted_count: int = 0


class CanaryConfigUpdateRequest(BaseModel):
    """SP-335: Runtime canary configuration update (per policy toggle)."""
    canary_token_enabled: Optional[bool] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/inject", response_model=CanaryInjectResponse)
async def inject_canary(req: CanaryInjectRequest) -> CanaryInjectResponse:
    """Inject a canary token into a system prompt for a session.

    SP-331: Prepends invisible canary comment to system prompt.
    """
    try:
        injector = get_canary_injector()
        modified_prompt, canary = injector.inject(
            system_prompt=req.system_prompt,
            session_id=req.session_id,
            ttl_seconds=req.ttl_seconds,
        )
        _metrics_store.record_session_protected()
        return CanaryInjectResponse(
            modified_prompt=modified_prompt,
            session_id=req.session_id,
            canary_active=True,
            ttl_seconds=canary.expires_at - canary.created_at,
        )
    except Exception:
        logger.exception("Canary injection failed")
        raise HTTPException(status_code=500, detail="Canary injection error")


@router.post("/scan", response_model=CanaryScanResponse)
async def scan_response(req: CanaryScanRequest) -> CanaryScanResponse:
    """Scan an LLM response for canary token leakage.

    SP-332: Regex match per response turn against active session canary.
    SP-333: Emits CRITICAL threat event on detection.
    """
    try:
        scanner = get_canary_scanner()
        result = scanner.scan_response(
            response_text=req.response_text,
            session_id=req.session_id,
            turn_index=req.turn_index,
        )

        _metrics_store.record_scan(
            detected=result.detected,
            session_id=req.session_id,
        )

        threat_emitted = False
        if result.detected:
            # SP-333: Emit CRITICAL threat event
            try:
                emitter = get_canary_threat_emitter()
                token_hash = ""
                if result.token_found:
                    token_hash = hashlib.sha256(
                        result.token_found.encode("utf-8")
                    ).hexdigest()[:16]

                event = CanaryThreatEvent(
                    session_id=req.session_id,
                    turn_index=req.turn_index,
                    detection_timestamp=result.scan_time_ms,
                    tenant_id=req.tenant_id,
                    policy_id=req.policy_id,
                    token_hash=token_hash,
                    match_position=result.match_position,
                )
                await emitter.emit(event)
                threat_emitted = True
            except Exception:
                logger.warning("Failed to emit canary threat event", exc_info=True)

        return CanaryScanResponse(
            detected=result.detected,
            session_id=req.session_id,
            turn_index=req.turn_index,
            scan_time_ms=result.scan_time_ms,
            extraction_confidence=result.extraction_confidence,
            threat_event_emitted=threat_emitted,
        )
    except Exception:
        logger.exception("Canary scan failed")
        raise HTTPException(status_code=500, detail="Canary scan error")


@router.get("/health", response_model=CanaryHealthResponse)
async def canary_health() -> CanaryHealthResponse:
    """Canary module health and readiness check."""
    try:
        generator = get_canary_generator()
        injector = get_canary_injector()
        scanner = get_canary_scanner()
        return CanaryHealthResponse(
            status="ok",
            enabled=injector.enabled,
            active_sessions=generator.active_count,
            total_generated=generator.total_generated,
            total_scans=scanner.total_scans,
            total_detections=scanner.total_detections,
        )
    except Exception:
        logger.exception("Canary health check failed")
        raise HTTPException(status_code=503, detail="Canary module unavailable")


@router.get("/metrics", response_model=CanaryMetricsResponse)
async def canary_metrics() -> CanaryMetricsResponse:
    """SP-335: 30-day rolling leakage statistics for dashboard badge.

    Badge updates within 30s of new detection.
    """
    try:
        stats = _metrics_store.get_rolling_stats()
        return CanaryMetricsResponse(**stats)
    except Exception:
        logger.exception("Canary metrics failed")
        raise HTTPException(status_code=500, detail="Canary metrics unavailable")


@router.get("/config", response_model=CanaryConfigResponse)
async def canary_config() -> CanaryConfigResponse:
    """Return current canary module configuration."""
    try:
        generator = get_canary_generator()
        injector = get_canary_injector()
        emitter = get_canary_threat_emitter()
        return CanaryConfigResponse(
            canary_token_enabled=injector.enabled,
            active_sessions=generator.active_count,
            total_generated=generator.total_generated,
            total_injections=injector.total_injections,
            emitter_connected=emitter._initialized,
            emitter_emitted_count=emitter.emitted_count,
        )
    except Exception:
        logger.exception("Canary config read failed")
        raise HTTPException(status_code=500, detail="Canary config unavailable")


@router.put("/config", response_model=CanaryConfigResponse)
async def update_canary_config(
    req: CanaryConfigUpdateRequest,
) -> CanaryConfigResponse:
    """SP-335: Update canary toggle per policy at runtime.

    Toggle applies per policy; dashboard badge updates within 30s.
    """
    try:
        injector = get_canary_injector()
        if req.canary_token_enabled is not None:
            injector.enabled = req.canary_token_enabled
            logger.info("Canary token enabled set to %s", req.canary_token_enabled)
        return await canary_config()
    except Exception:
        logger.exception("Canary config update failed")
        raise HTTPException(status_code=500, detail="Canary config update failed")
