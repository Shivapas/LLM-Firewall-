"""Sprint 35 -- Supply Chain Integrity + Inference Endpoint Monitoring router.

Endpoints:
  GET  /v1/supply-chain/status       -- model alignment status badge (SP-353)
  GET  /v1/supply-chain/dashboard    -- full inference health dashboard (SP-353)
  GET  /v1/supply-chain/deviation    -- rolling 24h deviation chart (SP-353)
  GET  /v1/supply-chain/drift        -- per-feature drift chart (SP-353)
  GET  /v1/supply-chain/monitor      -- monitor summary (SP-350)
  PUT  /v1/supply-chain/config       -- update monitor config at runtime
  GET  /v1/supply-chain/dpdpa        -- DPDPA compliance report (SP-355)
  POST /v1/supply-chain/score        -- score a response and record in monitor
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.fingerprint.supply_chain_monitor import (
    get_supply_chain_monitor,
)
from app.services.fingerprint.output_scanner_integration import (
    get_fingerprint_output_integration,
)
from app.services.fingerprint.dashboard import (
    get_inference_health_dashboard,
)
from app.services.fingerprint.dpdpa_compliance import (
    get_dpdpa_validator,
)
from app.services.fingerprint.baseline_profiler import get_baseline_profiler
from app.services.fingerprint.deviation_scorer import get_deviation_scorer

logger = logging.getLogger("sphinx.routers.supply_chain")

router = APIRouter(prefix="/v1/supply-chain", tags=["Supply Chain Integrity"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class StatusBadgeResponse(BaseModel):
    """Model alignment status badge."""
    status: str = "ALIGNED"
    color: str = "green"
    consecutive_breaches: int = 0
    threshold: int = 5
    model_id: str = ""
    profile_loaded: bool = False
    warm_up_complete: bool = False
    alert_threshold_sigma: float = 2.5


class MonitorSummaryResponse(BaseModel):
    """Supply chain monitor summary."""
    alignment_status: str = "ALIGNED"
    consecutive_breaches: int = 0
    consecutive_threshold: int = 5
    alert_active: bool = False
    total_alerts: int = 0
    total_responses_scored: int = 0
    model_id: str = ""
    baseline_version: str = ""
    last_alert: Optional[dict] = None


class SupplyChainConfigUpdateRequest(BaseModel):
    """Runtime configuration update for the supply chain monitor."""
    consecutive_threshold: Optional[int] = Field(
        None, ge=1, description="Consecutive breach count before alert"
    )
    fingerprint_enabled: Optional[bool] = Field(
        None, description="Enable/disable fingerprint scoring"
    )
    alert_threshold: Optional[float] = Field(
        None, gt=0, description="Deviation alert threshold (sigma)"
    )


class SupplyChainScoreRequest(BaseModel):
    """Request to score a response through the supply chain pipeline."""
    response_text: str = Field(..., description="LLM response text to score")


class SupplyChainScoreResponse(BaseModel):
    """Result of scoring a response through the supply chain pipeline."""
    scored: bool = False
    deviation_score: float = 0.0
    alert_triggered: bool = False
    alignment_status: str = "ALIGNED"
    max_z_feature: str = ""
    max_z_score: float = 0.0
    scoring_time_ms: float = 0.0
    supply_chain_alert_emitted: bool = False
    warm_up_in_progress: bool = False


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/status", response_model=StatusBadgeResponse)
async def get_status_badge() -> StatusBadgeResponse:
    """GET /v1/supply-chain/status -- model alignment status badge.

    SP-353: status badge transitions correctly (ALIGNED / DRIFTING / SWAPPED).
    """
    try:
        dashboard = get_inference_health_dashboard()
        badge = dashboard.get_status_badge()
        return StatusBadgeResponse(**badge)
    except Exception:
        logger.exception("Failed to get status badge")
        raise HTTPException(status_code=500, detail="Status badge unavailable")


@router.get("/dashboard")
async def get_full_dashboard() -> dict:
    """GET /v1/supply-chain/dashboard -- full inference health dashboard.

    SP-353: rolling 24h deviation score chart, per-feature drift chart,
    current model alignment status badge.
    """
    try:
        dashboard = get_inference_health_dashboard()
        return dashboard.get_full_dashboard()
    except Exception:
        logger.exception("Failed to get dashboard data")
        raise HTTPException(status_code=500, detail="Dashboard unavailable")


@router.get("/deviation")
async def get_deviation_chart() -> dict:
    """GET /v1/supply-chain/deviation -- rolling 24h deviation chart data."""
    try:
        dashboard = get_inference_health_dashboard()
        return dashboard.get_deviation_chart()
    except Exception:
        logger.exception("Failed to get deviation chart")
        raise HTTPException(status_code=500, detail="Deviation chart unavailable")


@router.get("/drift")
async def get_drift_chart() -> dict:
    """GET /v1/supply-chain/drift -- per-feature drift chart data."""
    try:
        dashboard = get_inference_health_dashboard()
        return dashboard.get_drift_chart()
    except Exception:
        logger.exception("Failed to get drift chart")
        raise HTTPException(status_code=500, detail="Drift chart unavailable")


@router.get("/monitor", response_model=MonitorSummaryResponse)
async def get_monitor_summary() -> MonitorSummaryResponse:
    """GET /v1/supply-chain/monitor -- supply chain monitor summary."""
    try:
        monitor = get_supply_chain_monitor()
        summary = monitor.get_summary()
        return MonitorSummaryResponse(**summary)
    except Exception:
        logger.exception("Failed to get monitor summary")
        raise HTTPException(status_code=500, detail="Monitor summary unavailable")


@router.put("/config")
async def update_config(req: SupplyChainConfigUpdateRequest) -> dict:
    """PUT /v1/supply-chain/config -- update supply chain config at runtime."""
    try:
        monitor = get_supply_chain_monitor()
        integration = get_fingerprint_output_integration()
        scorer = get_deviation_scorer()

        changes = {}
        if req.consecutive_threshold is not None:
            monitor.consecutive_threshold = req.consecutive_threshold
            changes["consecutive_threshold"] = req.consecutive_threshold
        if req.fingerprint_enabled is not None:
            integration.enabled = req.fingerprint_enabled
            changes["fingerprint_enabled"] = req.fingerprint_enabled
        if req.alert_threshold is not None:
            scorer.alert_threshold = req.alert_threshold
            changes["alert_threshold"] = req.alert_threshold

        logger.info("Supply chain config updated: %s", changes)
        return {"status": "updated", "changes": changes}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("Failed to update supply chain config")
        raise HTTPException(status_code=500, detail="Config update failed")


@router.post("/score", response_model=SupplyChainScoreResponse)
async def score_response(req: SupplyChainScoreRequest) -> SupplyChainScoreResponse:
    """POST /v1/supply-chain/score -- score a response through the pipeline.

    SP-351: scores response and writes deviation to metadata.
    SP-350: records in supply chain monitor for consecutive alerting.
    """
    try:
        integration = get_fingerprint_output_integration()
        result = integration.scan_response(req.response_text)
        return SupplyChainScoreResponse(
            scored=result.scored,
            deviation_score=result.deviation_score,
            alert_triggered=result.alert_triggered,
            alignment_status=result.alignment_status,
            max_z_feature=result.max_z_feature,
            max_z_score=result.max_z_score,
            scoring_time_ms=result.scoring_time_ms,
            supply_chain_alert_emitted=result.supply_chain_alert is not None,
            warm_up_in_progress=result.warm_up_in_progress,
        )
    except Exception:
        logger.exception("Failed to score response")
        raise HTTPException(status_code=500, detail="Scoring error")


@router.get("/dpdpa")
async def get_dpdpa_compliance() -> dict:
    """GET /v1/supply-chain/dpdpa -- DPDPA compliance report.

    SP-355: confirms feature vectors contain no PII.
    """
    try:
        validator = get_dpdpa_validator()
        profiler = get_baseline_profiler()
        profile = profiler.profile

        report = {
            "trustdlp_integration_note": validator.generate_trustdlp_integration_note(),
        }

        # Validate current baseline profile if available
        if profile:
            profile_report = validator.validate_baseline_profile(profile.to_dict())
            report["baseline_profile_validation"] = profile_report

        # Validate a sample feature vector
        from app.services.fingerprint.feature_extractor import get_feature_extractor
        extractor = get_feature_extractor()
        sample_vec = extractor.extract("Sample text for validation.")
        vec_report = validator.validate_feature_vector(sample_vec)
        report["feature_vector_validation"] = vec_report

        return report
    except Exception:
        logger.exception("Failed to generate DPDPA compliance report")
        raise HTTPException(status_code=500, detail="DPDPA report generation failed")
