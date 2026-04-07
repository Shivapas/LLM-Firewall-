"""Sprint 29/30 — Model Security, Session Security, AI-SPM, Semantic Cache Router.

Endpoints:
- POST /models/scan                        — Scan a model artifact
- GET  /models/scan/history                — Get scan history
- POST /models/registry                    — Register an approved model
- POST /models/registry/verify             — Verify a model against the registry
- GET  /models/registry                    — List registered models
- POST /sessions/{session_id}/turn         — Record a turn + evaluate risk
- GET  /sessions/{session_id}              — Get session context
- GET  /sessions                           — List active sessions
- GET  /ai-spm/assets                      — List AI assets
- POST /ai-spm/assets                      — Discover/register an AI asset
- GET  /ai-spm/ungoverned                  — List ungoverned assets
- POST /ai-spm/enroll                      — Request enrollment
- POST /ai-spm/enroll/{id}/approve         — Approve enrollment
- GET  /ai-spm/dashboard                   — AI-SPM dashboard summary
- POST /cache/lookup                       — Semantic cache lookup
- POST /cache/store                        — Store in semantic cache
- GET  /cache/stats                        — Cache statistics
- POST /cache/invalidate                   — Invalidate cache for tenant
- GET  /cache/audit                        — Cache audit log
- GET  /release/checklist                  — v2.0 release checklist
- POST /release/checklist/{id}             — Update checklist item
- GET  /release/status                     — Release readiness status
- POST /release/benchmark                  — Record performance benchmark
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.services.model_scanner.artifact_scanner import get_model_artifact_scanner
from app.services.model_scanner.provenance_registry import get_model_provenance_registry
from app.services.session_security.context_store import get_session_context_store
from app.services.session_security.cross_turn_risk import get_cross_turn_risk_accumulator
from app.services.ai_spm.discovery import get_ai_spm_service
from app.services.semantic_cache.cache_layer import get_semantic_cache_layer
from app.services.semantic_cache.cache_security import get_cache_security_controller
from app.services.semantic_cache.cache_audit import get_cache_audit_logger
from app.services.release.v2_checklist import get_v2_release_checklist

logger = logging.getLogger("sphinx.routers.model_security")

router = APIRouter(prefix="/admin", tags=["model-security"])


# ── Request/Response Models ──────────────────────────────────────────────


class ModelScanRequest(BaseModel):
    filename: str = "model.bin"
    data_b64: str = ""  # base64-encoded model data (for API; in practice use upload)
    data_hex: str = ""  # hex-encoded model data (for testing)


class ModelRegisterRequest(BaseModel):
    model_name: str
    model_version: str
    file_hash: str
    file_size: int = 0
    model_format: str = ""
    source: str = ""
    registered_by: str = "admin"
    scan_id: str = ""


class ModelVerifyRequest(BaseModel):
    model_name: str
    file_hash: str


class TurnRequest(BaseModel):
    risk_score: float = 0.0
    risk_level: str = "none"
    matched_patterns: list[str] = []
    input_preview: str = ""
    tenant_id: str = ""
    agent_id: str = ""


class AssetDiscoverRequest(BaseModel):
    name: str
    asset_type: str = "llm_api"
    provider: str = ""
    endpoint: str = ""
    tenant_id: str = ""
    team: str = ""
    discovery_source: str = "manual"
    risk_level: str = "medium"


class EnrollmentRequest(BaseModel):
    asset_id: str
    requested_by: str = "admin"
    routing_policy: str = "default"


class EnrollmentApproveRequest(BaseModel):
    resolution_note: str = ""


class CacheLookupRequest(BaseModel):
    tenant_id: str
    query_text: str
    model: str = ""
    policy_version: str = ""


class CacheStoreRequest(BaseModel):
    tenant_id: str
    query_text: str
    response_text: str
    model: str = ""
    policy_version: str = ""


class CacheInvalidateRequest(BaseModel):
    tenant_id: str
    policy_version: str = ""


class ChecklistUpdateRequest(BaseModel):
    status: str
    checked_by: str = ""
    evidence: str = ""


class BenchmarkRequest(BaseModel):
    check_name: str
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float = 0.0
    sample_count: int = 0
    threshold_ms: float = 50.0


# ── Model Scanner Endpoints ─────────────────────────────────────────────


@router.post("/models/scan")
async def scan_model(req: ModelScanRequest):
    """Scan a model artifact for security threats."""
    import base64
    scanner = get_model_artifact_scanner()

    if req.data_hex:
        data = bytes.fromhex(req.data_hex)
    elif req.data_b64:
        data = base64.b64decode(req.data_b64)
    else:
        raise HTTPException(400, "Provide data_b64 or data_hex")

    result = scanner.scan(data, req.filename)
    return result.to_dict()


@router.get("/models/scan/history")
async def get_scan_history(limit: int = Query(50, ge=1, le=200)):
    scanner = get_model_artifact_scanner()
    return [r.to_dict() for r in scanner.get_scan_history(limit)]


@router.get("/models/scan/stats")
async def get_scan_stats():
    scanner = get_model_artifact_scanner()
    return scanner.get_stats()


# ── Model Provenance Registry ────────────────────────────────────────────


@router.post("/models/registry")
async def register_model(req: ModelRegisterRequest):
    registry = get_model_provenance_registry()
    reg = registry.register(
        model_name=req.model_name,
        model_version=req.model_version,
        file_hash=req.file_hash,
        file_size=req.file_size,
        model_format=req.model_format,
        source=req.source,
        registered_by=req.registered_by,
        scan_id=req.scan_id,
    )
    return reg.to_dict()


@router.post("/models/registry/verify")
async def verify_model(req: ModelVerifyRequest):
    registry = get_model_provenance_registry()
    check = registry.verify(req.model_name, req.file_hash)
    return check.to_dict()


@router.get("/models/registry")
async def list_registrations(model_name: str = Query("", description="Filter by model name")):
    registry = get_model_provenance_registry()
    return [r.to_dict() for r in registry.list_registrations(model_name)]


# ── Session Security ────────────────────────────────────────────────────


@router.post("/sessions/{session_id}/turn")
async def record_turn(session_id: str, req: TurnRequest):
    accumulator = get_cross_turn_risk_accumulator()
    result = accumulator.evaluate_turn(
        session_id=session_id,
        risk_score=req.risk_score,
        risk_level=req.risk_level,
        matched_patterns=req.matched_patterns,
        input_preview=req.input_preview,
        tenant_id=req.tenant_id,
        agent_id=req.agent_id,
    )
    return result


@router.get("/sessions")
async def list_sessions(
    tenant_id: str = Query(""),
    active_only: bool = Query(True),
):
    store = get_session_context_store()
    sessions = store.list_sessions(tenant_id, active_only)
    return [s.to_dict() for s in sessions]


@router.get("/sessions/escalations")
async def list_escalations(limit: int = Query(50, ge=1, le=200)):
    accumulator = get_cross_turn_risk_accumulator()
    return [e.to_dict() for e in accumulator.get_escalation_events(limit)]


@router.get("/sessions/{session_id}")
async def get_session(session_id: str):
    store = get_session_context_store()
    session = store.get_session(session_id)
    if session is None:
        raise HTTPException(404, "Session not found")
    return session.to_dict()


# ── AI-SPM ──────────────────────────────────────────────────────────────


@router.post("/ai-spm/assets")
async def discover_asset(req: AssetDiscoverRequest):
    svc = get_ai_spm_service()
    asset = svc.discover_asset(
        name=req.name,
        asset_type=req.asset_type,
        provider=req.provider,
        endpoint=req.endpoint,
        tenant_id=req.tenant_id,
        team=req.team,
        discovery_source=req.discovery_source,
        risk_level=req.risk_level,
    )
    return asset.to_dict()


@router.get("/ai-spm/assets")
async def list_assets(
    status: str = Query(""),
    tenant_id: str = Query(""),
    asset_type: str = Query(""),
):
    svc = get_ai_spm_service()
    return [a.to_dict() for a in svc.list_assets(status, tenant_id, asset_type)]


@router.get("/ai-spm/ungoverned")
async def list_ungoverned(tenant_id: str = Query("")):
    svc = get_ai_spm_service()
    return [a.to_dict() for a in svc.list_ungoverned(tenant_id)]


@router.post("/ai-spm/enroll")
async def request_enrollment(req: EnrollmentRequest):
    svc = get_ai_spm_service()
    enrollment = svc.request_enrollment(req.asset_id, req.requested_by, req.routing_policy)
    if enrollment is None:
        raise HTTPException(400, "Asset not found or not eligible for enrollment")
    return enrollment.to_dict()


@router.post("/ai-spm/enroll/{request_id}/approve")
async def approve_enrollment(request_id: str, req: EnrollmentApproveRequest):
    svc = get_ai_spm_service()
    ok = svc.approve_enrollment(request_id, req.resolution_note)
    if not ok:
        raise HTTPException(400, "Enrollment request not found or already resolved")
    return {"status": "approved"}


@router.get("/ai-spm/dashboard")
async def ai_spm_dashboard():
    svc = get_ai_spm_service()
    return svc.get_dashboard_summary()


# ── Semantic Cache ──────────────────────────────────────────────────────


@router.post("/cache/lookup")
async def cache_lookup(req: CacheLookupRequest):
    cache = get_semantic_cache_layer()
    audit = get_cache_audit_logger()
    security = get_cache_security_controller(cache=cache)

    # Verify namespace isolation
    iso_check = security.verify_namespace_isolation(req.tenant_id, req.tenant_id)

    result = cache.lookup(req.tenant_id, req.query_text, req.model, req.policy_version)

    if result.is_hit:
        # Scan for poisoning
        poison = security.scan_for_poisoning(result.entry)
        if poison.is_poisoned:
            # Don't serve poisoned cache entries
            audit.log_cache_miss(
                tenant_id=req.tenant_id,
                query_hash=result.entry.query_hash if result.entry else "",
                policy_version=req.policy_version,
                model=req.model,
                lookup_time_ms=result.lookup_time_ms,
                metadata={"blocked_reason": "cache_poisoning_detected"},
            )
            return {"is_hit": False, "reason": "cache_entry_blocked_poisoning", "poison_detection": poison.to_dict()}

        audit.log_cache_hit(
            tenant_id=req.tenant_id,
            query_hash=result.entry.query_hash,
            cache_key=result.cache_key,
            similarity_score=result.similarity_score,
            policy_version=req.policy_version,
            model=req.model,
            lookup_time_ms=result.lookup_time_ms,
        )
    else:
        audit.log_cache_miss(
            tenant_id=req.tenant_id,
            query_hash="",
            best_similarity=result.similarity_score,
            policy_version=req.policy_version,
            model=req.model,
            lookup_time_ms=result.lookup_time_ms,
        )

    return result.to_dict()


@router.post("/cache/store")
async def cache_store(req: CacheStoreRequest):
    cache = get_semantic_cache_layer()
    security = get_cache_security_controller(cache=cache)

    entry = cache.store(
        tenant_id=req.tenant_id,
        query_text=req.query_text,
        response_text=req.response_text,
        model=req.model,
        policy_version=req.policy_version,
    )

    # Scan for poisoning on store
    poison = security.scan_for_poisoning(entry)
    result = entry.to_dict()
    if poison.is_poisoned:
        result["poison_warning"] = poison.to_dict()

    return result


@router.get("/cache/stats")
async def cache_stats():
    cache = get_semantic_cache_layer()
    return cache.get_stats()


@router.post("/cache/invalidate")
async def cache_invalidate(req: CacheInvalidateRequest):
    cache = get_semantic_cache_layer()
    security = get_cache_security_controller(cache=cache)

    if req.policy_version:
        count = cache.invalidate_policy_version(req.tenant_id, req.policy_version)
    else:
        count = security.on_policy_change(req.tenant_id, "manual")

    return {"invalidated": count}


@router.get("/cache/audit")
async def cache_audit(
    tenant_id: str = Query(""),
    response_source: str = Query(""),
    limit: int = Query(100, ge=1, le=500),
):
    audit = get_cache_audit_logger()
    return [e.to_dict() for e in audit.get_entries(tenant_id, response_source, limit)]


@router.get("/cache/audit/stats")
async def cache_audit_stats():
    audit = get_cache_audit_logger()
    return audit.get_stats()


# ── v2.0 Release Checklist ──────────────────────────────────────────────


@router.get("/release/checklist")
async def get_checklist(
    category: str = Query(""),
    status: str = Query(""),
):
    checklist = get_v2_release_checklist()
    return [i.to_dict() for i in checklist.get_items(category, status)]


@router.post("/release/checklist/{item_id}")
async def update_checklist_item(item_id: str, req: ChecklistUpdateRequest):
    checklist = get_v2_release_checklist()
    item = checklist.update_item_status(item_id, req.status, req.checked_by, req.evidence)
    if item is None:
        raise HTTPException(404, "Checklist item not found")
    return item.to_dict()


@router.get("/release/status")
async def release_status():
    checklist = get_v2_release_checklist()
    return checklist.is_release_ready()


@router.post("/release/benchmark")
async def record_benchmark(req: BenchmarkRequest):
    checklist = get_v2_release_checklist()
    benchmark = checklist.record_benchmark(
        check_name=req.check_name,
        p50_ms=req.p50_ms,
        p95_ms=req.p95_ms,
        p99_ms=req.p99_ms,
        max_ms=req.max_ms,
        sample_count=req.sample_count,
        threshold_ms=req.threshold_ms,
    )
    return benchmark.to_dict()


@router.get("/release/benchmarks")
async def list_benchmarks():
    checklist = get_v2_release_checklist()
    return [b.to_dict() for b in checklist.get_benchmarks()]
