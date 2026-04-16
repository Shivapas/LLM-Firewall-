"""Sprint 36 -- OWASP LLM Top 10 v2025 Compliance Matrix router.

Endpoints:
  GET  /v1/owasp/registry          -- tag registry summary (SP-360)
  GET  /v1/owasp/coverage          -- per-category coverage scores (SP-361)
  POST /v1/owasp/coverage          -- coverage with custom config (SP-361)
  GET  /v1/owasp/gaps              -- gap analysis (SP-362)
  POST /v1/owasp/gaps              -- gap analysis with custom config (SP-362)
  GET  /v1/owasp/dashboard         -- full compliance dashboard (SP-363)
  POST /v1/owasp/dashboard         -- dashboard with custom config (SP-363)
  GET  /v1/owasp/export/json       -- JSON compliance export (SP-365)
  POST /v1/owasp/export/json       -- JSON export with custom config (SP-365)
  GET  /v1/owasp/export/pdf        -- PDF compliance report (SP-364)
  POST /v1/owasp/export/pdf        -- PDF report with custom config (SP-364)
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from app.services.owasp.tag_registry import get_tag_registry
from app.services.owasp.coverage_engine import get_owasp_coverage_engine
from app.services.owasp.gap_analysis import get_gap_analysis_engine
from app.services.owasp.dashboard import get_owasp_dashboard
from app.services.owasp.compliance_export import get_compliance_export_engine

logger = logging.getLogger("sphinx.routers.owasp")

router = APIRouter(prefix="/v1/owasp", tags=["OWASP LLM Top 10 v2025"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ConfigOverrideRequest(BaseModel):
    """Custom configuration for OWASP scoring."""
    config: dict[str, bool] = Field(
        ...,
        description="Map of config_key -> enabled (True/False)",
        json_schema_extra={
            "example": {
                "ipia_enabled": True,
                "canary_token_enabled": True,
                "fingerprint_enabled": True,
            }
        },
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/registry")
async def get_registry() -> dict:
    """GET /v1/owasp/registry -- OWASP tag registry summary.

    SP-360: Tag registry covers all 30 v2.0 modules + 3 new modules.
    """
    try:
        registry = get_tag_registry()
        return registry.to_dict()
    except Exception:
        logger.exception("Failed to load tag registry")
        raise HTTPException(status_code=500, detail="Tag registry unavailable")


@router.get("/coverage")
async def get_coverage() -> dict:
    """GET /v1/owasp/coverage -- per-category coverage scores (default config).

    SP-361: Coverage scores computed for LLM01-LLM10.
    """
    try:
        engine = get_owasp_coverage_engine()
        result = engine.compute_coverage()
        return result.to_dict()
    except Exception:
        logger.exception("Failed to compute coverage")
        raise HTTPException(status_code=500, detail="Coverage computation failed")


@router.post("/coverage")
async def compute_coverage(req: ConfigOverrideRequest) -> dict:
    """POST /v1/owasp/coverage -- coverage with custom config.

    SP-361: Re-score on config change in < 500ms.
    """
    try:
        engine = get_owasp_coverage_engine()
        result = engine.compute_coverage(req.config)
        return result.to_dict()
    except Exception:
        logger.exception("Failed to compute custom coverage")
        raise HTTPException(status_code=500, detail="Coverage computation failed")


@router.get("/gaps")
async def get_gaps() -> dict:
    """GET /v1/owasp/gaps -- gap analysis (default config).

    SP-362: Gap analysis with remediation recommendations.
    """
    try:
        engine = get_gap_analysis_engine()
        result = engine.analyse()
        return result.to_dict()
    except Exception:
        logger.exception("Failed to run gap analysis")
        raise HTTPException(status_code=500, detail="Gap analysis failed")


@router.post("/gaps")
async def compute_gaps(req: ConfigOverrideRequest) -> dict:
    """POST /v1/owasp/gaps -- gap analysis with custom config.

    SP-362: Gap analysis generates for config with 2 modules disabled.
    """
    try:
        engine = get_gap_analysis_engine()
        result = engine.analyse(req.config)
        return result.to_dict()
    except Exception:
        logger.exception("Failed to run custom gap analysis")
        raise HTTPException(status_code=500, detail="Gap analysis failed")


@router.get("/dashboard")
async def get_dashboard() -> dict:
    """GET /v1/owasp/dashboard -- full compliance dashboard (default config).

    SP-363: Radar chart, Shield Score, top 3 gaps.
    """
    try:
        dashboard = get_owasp_dashboard()
        return dashboard.get_full_dashboard()
    except Exception:
        logger.exception("Failed to build dashboard")
        raise HTTPException(status_code=500, detail="Dashboard unavailable")


@router.post("/dashboard")
async def compute_dashboard(req: ConfigOverrideRequest) -> dict:
    """POST /v1/owasp/dashboard -- dashboard with custom config.

    SP-363: Shield Score >= 85 for default Roadmap v1 configuration.
    """
    try:
        dashboard = get_owasp_dashboard()
        return dashboard.get_full_dashboard(req.config)
    except Exception:
        logger.exception("Failed to build custom dashboard")
        raise HTTPException(status_code=500, detail="Dashboard unavailable")


@router.get("/export/json")
async def export_json() -> dict:
    """GET /v1/owasp/export/json -- JSON compliance export (default config).

    SP-365: Machine-readable compliance export.
    """
    try:
        engine = get_compliance_export_engine()
        export = engine.export_json()
        return export.to_dict()
    except Exception:
        logger.exception("Failed to generate JSON export")
        raise HTTPException(status_code=500, detail="JSON export failed")


@router.post("/export/json")
async def compute_json_export(req: ConfigOverrideRequest) -> dict:
    """POST /v1/owasp/export/json -- JSON export with custom config.

    SP-365: Validates against schema spec; importable into SIEM.
    """
    try:
        engine = get_compliance_export_engine()
        export = engine.export_json(req.config)
        return export.to_dict()
    except Exception:
        logger.exception("Failed to generate custom JSON export")
        raise HTTPException(status_code=500, detail="JSON export failed")


@router.get("/export/pdf")
async def export_pdf() -> dict:
    """GET /v1/owasp/export/pdf -- PDF compliance report data (default config).

    SP-364: Branded TrustFabric report with scores, gaps, and remediation.
    Returns structured data; use render_text() for plain text, or pipe to
    a PDF renderer in production.
    """
    try:
        engine = get_compliance_export_engine()
        report = engine.export_pdf()
        return report.to_dict()
    except Exception:
        logger.exception("Failed to generate PDF report")
        raise HTTPException(status_code=500, detail="PDF export failed")


@router.post("/export/pdf")
async def compute_pdf_export(req: ConfigOverrideRequest) -> dict:
    """POST /v1/owasp/export/pdf -- PDF report with custom config.

    SP-364: Per-category score table, gap analysis, remediation guidance.
    """
    try:
        engine = get_compliance_export_engine()
        report = engine.export_pdf(req.config)
        return report.to_dict()
    except Exception:
        logger.exception("Failed to generate custom PDF report")
        raise HTTPException(status_code=500, detail="PDF export failed")


@router.get("/export/pdf/text", response_class=PlainTextResponse)
async def export_pdf_text() -> str:
    """GET /v1/owasp/export/pdf/text -- Plain text rendering of the PDF report.

    Useful for testing and terminal-based review.
    """
    try:
        engine = get_compliance_export_engine()
        report = engine.export_pdf()
        return report.render_text()
    except Exception:
        logger.exception("Failed to render PDF text")
        raise HTTPException(status_code=500, detail="Text export failed")
