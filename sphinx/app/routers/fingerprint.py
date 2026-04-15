"""Sprint 34 -- Model Fingerprinting Admin API router.

Endpoints (SP-343):
  GET  /v1/fingerprint/profile   -- export current baseline profile (JSON)
  POST /v1/fingerprint/profile   -- import a baseline profile
  POST /v1/fingerprint/reset     -- reset profiler and trigger re-warm-up
  GET  /v1/fingerprint/health    -- module health / readiness
  GET  /v1/fingerprint/config    -- current configuration
  PUT  /v1/fingerprint/config    -- update configuration at runtime
  POST /v1/fingerprint/score     -- score a response against the baseline

SP-343 acceptance criteria:
  - All 3 primary endpoints respond correctly
  - Import/export round-trip produces identical profile
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.fingerprint.feature_extractor import (
    FEATURE_COUNT,
    FEATURE_NAMES,
    get_feature_extractor,
)
from app.services.fingerprint.baseline_profiler import (
    BaselineProfile,
    BaselineProfiler,
    get_baseline_profiler,
)
from app.services.fingerprint.deviation_scorer import (
    DeviationScorer,
    get_deviation_scorer,
)

logger = logging.getLogger("sphinx.routers.fingerprint")

router = APIRouter(prefix="/v1/fingerprint", tags=["Model Fingerprint"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class FingerprintProfileResponse(BaseModel):
    """Serialised baseline profile."""
    version: str = "1.0"
    feature_count: int = FEATURE_COUNT
    feature_names: list[str] = Field(default_factory=lambda: list(FEATURE_NAMES))
    means: list[float] = Field(default_factory=list)
    stds: list[float] = Field(default_factory=list)
    sample_count: int = 0
    created_at: float = 0.0
    profile_hash: str = ""
    model_id: str = ""


class FingerprintProfileImportRequest(BaseModel):
    """Request to import a baseline profile."""
    means: list[float] = Field(..., description="Per-feature mean values")
    stds: list[float] = Field(..., description="Per-feature standard deviations")
    sample_count: int = Field(..., description="Number of samples used")
    created_at: float = Field(..., description="Unix timestamp of profile creation")
    profile_hash: str = Field("", description="SHA-256 integrity hash")
    model_id: str = Field("", description="Inference model identifier")


class FingerprintResetResponse(BaseModel):
    """Response after profiler reset."""
    status: str = "reset"
    message: str = "Profiler reset for re-warm-up"


class FingerprintScoreRequest(BaseModel):
    """Request to score a response against the baseline."""
    response_text: str = Field(..., description="LLM response text to score")


class FingerprintScoreResponse(BaseModel):
    """Deviation scoring result."""
    z_scores: list[float] = Field(default_factory=list)
    feature_names: list[str] = Field(default_factory=lambda: list(FEATURE_NAMES))
    aggregate_deviation: float = 0.0
    alert_triggered: bool = False
    threshold: float = 2.5
    max_z_score: float = 0.0
    max_z_feature: str = ""
    scoring_time_ms: float = 0.0


class FingerprintHealthResponse(BaseModel):
    """Fingerprint module health check."""
    status: str = "ok"
    enabled: bool = False
    profile_loaded: bool = False
    warm_up_collected: int = 0
    warm_up_target: int = 50
    warm_up_complete: bool = False
    warm_up_duration_ms: Optional[float] = None
    model_id: str = ""


class FingerprintConfigResponse(BaseModel):
    """Current fingerprint module configuration."""
    fingerprint_enabled: bool = False
    warm_up_count: int = 50
    alert_threshold: float = 2.5
    model_id: str = ""
    profile_loaded: bool = False
    profile_hash: str = ""
    profile_sample_count: int = 0


class FingerprintConfigUpdateRequest(BaseModel):
    """Runtime configuration update."""
    fingerprint_enabled: Optional[bool] = None
    alert_threshold: Optional[float] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/profile", response_model=FingerprintProfileResponse)
async def export_profile() -> FingerprintProfileResponse:
    """GET /v1/fingerprint/profile -- export current baseline profile.

    SP-343: Returns the full baseline profile as JSON.
    """
    try:
        profiler = get_baseline_profiler()
        profile = profiler.profile
        if profile is None:
            raise HTTPException(
                status_code=404,
                detail="No baseline profile available. Run warm-up or import a profile.",
            )
        data = profile.to_dict()
        return FingerprintProfileResponse(**data)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to export fingerprint profile")
        raise HTTPException(status_code=500, detail="Profile export error")


@router.post("/profile", response_model=FingerprintProfileResponse)
async def import_profile(
    req: FingerprintProfileImportRequest,
) -> FingerprintProfileResponse:
    """POST /v1/fingerprint/profile -- import a baseline profile.

    SP-343: Replaces the current baseline with the provided profile.
    Import/export round-trip must produce identical profile.
    """
    try:
        if len(req.means) != FEATURE_COUNT:
            raise HTTPException(
                status_code=400,
                detail=f"means must have {FEATURE_COUNT} elements, got {len(req.means)}",
            )
        if len(req.stds) != FEATURE_COUNT:
            raise HTTPException(
                status_code=400,
                detail=f"stds must have {FEATURE_COUNT} elements, got {len(req.stds)}",
            )

        profile = BaselineProfile(
            means=req.means,
            stds=req.stds,
            sample_count=req.sample_count,
            created_at=req.created_at,
            profile_hash=req.profile_hash,
            model_id=req.model_id,
        )

        profiler = get_baseline_profiler()
        profiler.import_profile(profile)

        data = profile.to_dict()
        return FingerprintProfileResponse(**data)
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("Failed to import fingerprint profile")
        raise HTTPException(status_code=500, detail="Profile import error")


@router.post("/reset", response_model=FingerprintResetResponse)
async def reset_profiler() -> FingerprintResetResponse:
    """POST /v1/fingerprint/reset -- reset profiler for re-warm-up.

    SP-343: Clears all warm-up data and the current profile.
    """
    try:
        profiler = get_baseline_profiler()
        profiler.reset()
        return FingerprintResetResponse(
            status="reset",
            message="Profiler reset for re-warm-up",
        )
    except Exception:
        logger.exception("Failed to reset fingerprint profiler")
        raise HTTPException(status_code=500, detail="Profiler reset error")


@router.post("/score", response_model=FingerprintScoreResponse)
async def score_response(req: FingerprintScoreRequest) -> FingerprintScoreResponse:
    """Score an LLM response against the current baseline profile.

    Returns per-feature z-scores and aggregate deviation index.
    """
    try:
        profiler = get_baseline_profiler()
        profile = profiler.profile
        if profile is None:
            raise HTTPException(
                status_code=404,
                detail="No baseline profile available. Run warm-up or import a profile.",
            )

        scorer = get_deviation_scorer()
        result = scorer.score_response(req.response_text, profile)

        return FingerprintScoreResponse(
            z_scores=result.z_scores,
            feature_names=result.feature_names,
            aggregate_deviation=result.aggregate_deviation,
            alert_triggered=result.alert_triggered,
            threshold=result.threshold,
            max_z_score=result.max_z_score,
            max_z_feature=result.max_z_feature,
            scoring_time_ms=result.scoring_time_ms,
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to score response")
        raise HTTPException(status_code=500, detail="Scoring error")


@router.get("/health", response_model=FingerprintHealthResponse)
async def fingerprint_health() -> FingerprintHealthResponse:
    """Fingerprint module health and readiness check."""
    try:
        profiler = get_baseline_profiler()
        profile = profiler.profile
        return FingerprintHealthResponse(
            status="ok",
            enabled=True,
            profile_loaded=profile is not None,
            warm_up_collected=profiler.collected,
            warm_up_target=profiler.warm_up_count,
            warm_up_complete=profiler.is_warm_up_complete,
            warm_up_duration_ms=profiler.warm_up_duration_ms,
            model_id=profile.model_id if profile else "",
        )
    except Exception:
        logger.exception("Fingerprint health check failed")
        raise HTTPException(status_code=503, detail="Fingerprint module unavailable")


@router.get("/config", response_model=FingerprintConfigResponse)
async def fingerprint_config() -> FingerprintConfigResponse:
    """Return current fingerprint module configuration."""
    try:
        profiler = get_baseline_profiler()
        scorer = get_deviation_scorer()
        profile = profiler.profile
        return FingerprintConfigResponse(
            fingerprint_enabled=True,
            warm_up_count=profiler.warm_up_count,
            alert_threshold=scorer.alert_threshold,
            model_id=profile.model_id if profile else "",
            profile_loaded=profile is not None,
            profile_hash=profile.profile_hash if profile else "",
            profile_sample_count=profile.sample_count if profile else 0,
        )
    except Exception:
        logger.exception("Fingerprint config read failed")
        raise HTTPException(status_code=500, detail="Config unavailable")


@router.put("/config", response_model=FingerprintConfigResponse)
async def update_fingerprint_config(
    req: FingerprintConfigUpdateRequest,
) -> FingerprintConfigResponse:
    """Update fingerprint configuration at runtime."""
    try:
        scorer = get_deviation_scorer()
        if req.alert_threshold is not None:
            scorer.alert_threshold = req.alert_threshold
            logger.info("Fingerprint alert threshold set to %.2f", req.alert_threshold)
        return await fingerprint_config()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("Fingerprint config update failed")
        raise HTTPException(status_code=500, detail="Config update failed")
