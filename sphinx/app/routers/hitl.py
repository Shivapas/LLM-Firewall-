"""Sprint 28 — HITL Enforcement Checkpoints + Cascading Failure Detection Router.

Endpoints:
- GET  /approvals                         — List pending approval requests
- GET  /approvals/{id}                    — Get approval request details
- POST /approvals/{id}/approve            — Approve a pending request
- POST /approvals/{id}/reject             — Reject a pending request
- GET  /agents/{agent_id}/baseline        — Get agent behavioral baseline
- GET  /agents/{agent_id}/circuit-breaker — Get agent circuit breaker state
- POST /agents/{agent_id}/circuit-breaker — Force circuit breaker state
- POST /agents/{agent_id}/check           — Check agent behavior against baseline
- GET  /anomalies                         — List recent anomaly events
- GET  /circuit-breakers                  — List all agent circuit breakers
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.services.hitl.approval_workflow import get_approval_workflow_service
from app.services.hitl.baseline_engine import get_baseline_engine
from app.services.hitl.anomaly_detector import get_anomaly_detector

logger = logging.getLogger("sphinx.routers.hitl")

router = APIRouter(prefix="/admin", tags=["hitl"])


# ── Request/Response Models ───────────────────────────────────────────


class ApprovalDecisionRequest(BaseModel):
    decided_by: str
    reason: str = ""


class ForceCircuitBreakerRequest(BaseModel):
    state: str  # closed, open, half_open


class BehaviorCheckRequest(BaseModel):
    tool_calls: list[str] | None = None
    output_tokens: int = 0
    api_call_count: int = 1


class RecordEventRequest(BaseModel):
    tenant_id: str = "default"
    tool_calls: list[str] | None = None
    output_tokens: int = 0
    api_call_count: int = 1
    metadata: dict | None = None


# ── Approval Endpoints ────────────────────────────────────────────────


@router.get("/approvals")
async def list_pending_approvals(tenant_id: Optional[str] = Query(None)):
    """List all pending HITL approval requests."""
    service = get_approval_workflow_service()
    pending = await service.list_pending(tenant_id=tenant_id)
    return {
        "approvals": [service.to_dict(r) for r in pending],
        "total": len(pending),
    }


@router.get("/approvals/{approval_id}")
async def get_approval(approval_id: str):
    """Get a specific approval request by ID."""
    service = get_approval_workflow_service()
    req = await service.get_approval(approval_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return service.to_dict(req)


@router.post("/approvals/{approval_id}/approve")
async def approve_request(approval_id: str, body: ApprovalDecisionRequest):
    """Approve a pending approval request. Approved action resumes within 5s."""
    service = get_approval_workflow_service()
    req = await service.approve(
        approval_id=approval_id,
        decided_by=body.decided_by,
        reason=body.reason,
    )
    if not req:
        raise HTTPException(
            status_code=404,
            detail="Approval request not found or already decided",
        )
    return {
        "status": "approved",
        "approval": service.to_dict(req),
    }


@router.post("/approvals/{approval_id}/reject")
async def reject_request(approval_id: str, body: ApprovalDecisionRequest):
    """Reject a pending approval request."""
    service = get_approval_workflow_service()
    req = await service.reject(
        approval_id=approval_id,
        decided_by=body.decided_by,
        reason=body.reason,
    )
    if not req:
        raise HTTPException(
            status_code=404,
            detail="Approval request not found or already decided",
        )
    return {
        "status": "rejected",
        "approval": service.to_dict(req),
    }


# ── Agent Baseline Endpoints ─────────────────────────────────────────


@router.get("/agents/{agent_id}/baseline")
async def get_agent_baseline(agent_id: str):
    """Get the behavioral baseline for an agent."""
    engine = get_baseline_engine()
    baseline = engine.get_baseline(agent_id)
    if not baseline:
        all_baselines = engine.get_all_baselines()
        if agent_id in all_baselines:
            b = all_baselines[agent_id]
            return {
                "agent_id": agent_id,
                "is_ready": False,
                "total_observations": engine.event_count(agent_id),
                "observation_start": b.observation_start.isoformat(),
                "message": "Baseline not yet ready; still in observation period",
            }
        raise HTTPException(status_code=404, detail="No baseline data for this agent")
    return engine.baseline_to_dict(baseline)


@router.post("/agents/{agent_id}/events")
async def record_behavioral_event(agent_id: str, body: RecordEventRequest):
    """Record a behavioral event for baseline computation."""
    engine = get_baseline_engine()
    engine.record_event(
        agent_id=agent_id,
        tenant_id=body.tenant_id,
        tool_calls=body.tool_calls,
        output_tokens=body.output_tokens,
        api_call_count=body.api_call_count,
        metadata=body.metadata,
    )
    return {
        "agent_id": agent_id,
        "total_events": engine.event_count(agent_id),
        "baseline_ready": engine.is_baseline_ready(agent_id),
    }


# ── Circuit Breaker Endpoints ────────────────────────────────────────


@router.get("/hitl/agents/{agent_id}/circuit-breaker")
async def get_hitl_agent_circuit_breaker(agent_id: str):
    """Get the HITL circuit breaker state for an agent."""
    detector = get_anomaly_detector()
    state = detector.get_circuit_state(agent_id)
    breakers = detector.get_all_breakers()
    breaker_info = breakers.get(agent_id, {
        "agent_id": agent_id,
        "state": state,
        "consecutive_anomalies": 0,
        "total_anomalies": 0,
        "total_checks": 0,
    })
    return breaker_info


@router.post("/hitl/agents/{agent_id}/circuit-breaker")
async def force_hitl_agent_circuit_breaker(agent_id: str, body: ForceCircuitBreakerRequest):
    """Admin override: force an agent's HITL circuit breaker state."""
    valid_states = {"closed", "open", "half_open"}
    if body.state not in valid_states:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid state. Must be one of: {valid_states}",
        )
    detector = get_anomaly_detector()
    detector.force_circuit_state(agent_id, body.state)
    return {
        "agent_id": agent_id,
        "state": body.state,
        "message": f"Circuit breaker forced to {body.state}",
    }


@router.post("/agents/{agent_id}/check")
async def check_agent_behavior(agent_id: str, body: BehaviorCheckRequest):
    """Check agent behavior against its baseline (anomaly detection)."""
    detector = get_anomaly_detector()
    result = detector.check(
        agent_id=agent_id,
        tool_calls=body.tool_calls,
        output_tokens=body.output_tokens,
        api_call_count=body.api_call_count,
    )
    return {
        "agent_id": agent_id,
        "is_anomalous": result.is_anomalous,
        "anomaly_types": result.anomaly_types,
        "deviation_scores": result.deviation_scores,
        "overall_deviation": round(result.overall_deviation, 4),
        "circuit_state": result.circuit_state,
        "action": result.action,
        "details": result.details,
    }


# ── Global Views ──────────────────────────────────────────────────────


@router.get("/hitl/circuit-breakers")
async def list_all_hitl_circuit_breakers():
    """List all agent HITL circuit breaker states."""
    detector = get_anomaly_detector()
    breakers = detector.get_all_breakers()
    return {
        "circuit_breakers": breakers,
        "total": len(breakers),
    }


@router.get("/hitl/anomalies")
async def list_hitl_anomalies(limit: int = Query(100, ge=1, le=1000)):
    """List recent HITL anomaly events."""
    detector = get_anomaly_detector()
    history = detector.get_anomaly_history(limit=limit)
    return {
        "anomalies": history,
        "total": len(history),
    }
