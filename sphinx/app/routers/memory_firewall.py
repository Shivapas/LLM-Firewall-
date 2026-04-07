"""Admin API for Agent Memory Store Firewall — Sprints 25–26.

Sprint 25 endpoints:
- Intercepting memory writes (POST /admin/memory-firewall/intercept)
- Policy CRUD (GET/POST/PUT/DELETE /admin/memory-firewall/policies)
- Audit log queries (GET /admin/memory-firewall/audit)
- Stats and quarantine management

Sprint 26 endpoints:
- Read anomaly detection (POST /admin/memory-firewall/read-check)
- Memory lifecycle cap management (GET/POST /admin/memory-firewall/lifecycle)
- Integrity verification (POST /admin/memory-firewall/integrity/verify)
- Cross-agent isolation (POST /admin/memory-firewall/isolation/check)
- Memory store dashboard (GET /admin/memory-firewall/dashboard)
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.memory_firewall.proxy import (
    get_memory_store_proxy,
    MemoryWriteRequest,
)
from app.services.memory_firewall.policy import WritePolicy
from app.services.memory_firewall.read_anomaly import (
    get_read_anomaly_detector,
    MemoryReadRequest,
)
from app.services.memory_firewall.lifecycle import get_memory_lifecycle_manager
from app.services.memory_firewall.integrity import get_memory_integrity_verifier
from app.services.memory_firewall.isolation import get_memory_isolation_enforcer

router = APIRouter(prefix="/admin/memory-firewall", tags=["memory-firewall"])


# ── Request / Response Models ────────────────────────────────────────────


class InterceptWriteRequest(BaseModel):
    agent_id: str
    session_id: str = ""
    content: str
    content_key: str = ""
    backend: str = "redis"
    framework: str = "langchain"
    namespace: str = ""
    metadata: dict = {}


class SetPolicyRequest(BaseModel):
    agent_id: str
    policy: str  # allow_all | scan_and_allow | scan_and_block | require_approval
    allowed_backends: list[str] = []
    allowed_namespaces: list[str] = []
    max_content_length: int = 0
    custom_threshold: float = 0.0


# ── Endpoints ────────────────────────────────────────────────────────────


@router.post("/intercept")
async def intercept_memory_write(req: InterceptWriteRequest):
    """Intercept an agent memory write through the firewall proxy."""
    proxy = get_memory_store_proxy()
    write_req = MemoryWriteRequest(
        agent_id=req.agent_id,
        session_id=req.session_id,
        content=req.content,
        content_key=req.content_key,
        backend=req.backend,
        framework=req.framework,
        namespace=req.namespace,
        metadata=req.metadata,
    )
    result = proxy.intercept_write(write_req)
    return result.to_dict()


@router.get("/policies")
async def list_policies():
    """List all per-agent memory write policies."""
    proxy = get_memory_store_proxy()
    policies = proxy.policy_store.list_policies()
    return [p.to_dict() for p in policies]


@router.get("/policies/{agent_id}")
async def get_policy(agent_id: str):
    """Get policy configuration for a specific agent."""
    proxy = get_memory_store_proxy()
    config = proxy.policy_store.get_policy_config(agent_id)
    if not config:
        return {"agent_id": agent_id, "policy": proxy.policy_store.default_policy.value, "source": "default"}
    return config.to_dict()


@router.post("/policies")
async def set_policy(req: SetPolicyRequest):
    """Create or update a per-agent memory write policy."""
    try:
        WritePolicy(req.policy)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid policy: {req.policy}. Must be one of: {[p.value for p in WritePolicy]}",
        )

    proxy = get_memory_store_proxy()
    config = proxy.policy_store.set_policy(
        agent_id=req.agent_id,
        policy=req.policy,
        allowed_backends=req.allowed_backends,
        allowed_namespaces=req.allowed_namespaces,
        max_content_length=req.max_content_length,
        custom_threshold=req.custom_threshold,
    )
    return config.to_dict()


@router.delete("/policies/{agent_id}")
async def delete_policy(agent_id: str):
    """Delete a per-agent policy (reverts to default)."""
    proxy = get_memory_store_proxy()
    deleted = proxy.policy_store.delete_policy(agent_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"No policy found for agent: {agent_id}")
    return {"deleted": True, "agent_id": agent_id}


@router.get("/audit")
async def query_audit_log(
    agent_id: Optional[str] = None,
    action_taken: Optional[str] = None,
    limit: int = 100,
):
    """Query memory write audit records."""
    proxy = get_memory_store_proxy()
    records = proxy.audit_log.get_records(
        agent_id=agent_id,
        action_taken=action_taken,
        limit=limit,
    )
    return [r.to_dict() for r in records]


@router.get("/audit/verify")
async def verify_audit_chain():
    """Verify the integrity of the memory write audit hash chain."""
    proxy = get_memory_store_proxy()
    is_valid, message = proxy.audit_log.verify_chain_integrity()
    return {"is_valid": is_valid, "message": message}


@router.get("/stats")
async def get_stats():
    """Get memory firewall proxy statistics."""
    proxy = get_memory_store_proxy()
    return {
        "proxy_stats": proxy.get_stats(),
        "audit_count": proxy.audit_log.count(),
        "audit_by_action": proxy.audit_log.count_by_action(),
        "audit_by_agent": proxy.audit_log.count_by_agent(),
        "policy_count": proxy.policy_store.count(),
        "quarantine_size": len(proxy.get_quarantine()),
        "scanner_patterns": proxy.scanner.pattern_count,
    }


@router.get("/quarantine")
async def list_quarantine():
    """List quarantined memory write requests."""
    proxy = get_memory_store_proxy()
    items = proxy.get_quarantine()
    return [
        {
            "agent_id": item.agent_id,
            "session_id": item.session_id,
            "content_key": item.content_key,
            "backend": item.backend,
            "framework": item.framework,
            "namespace": item.namespace,
            "content_hash": item.content_hash(),
        }
        for item in items
    ]


@router.delete("/quarantine")
async def clear_quarantine():
    """Clear all quarantined write requests."""
    proxy = get_memory_store_proxy()
    count = proxy.clear_quarantine()
    return {"cleared": count}


# ── Sprint 26: Request / Response Models ──────────────────────────────────


class ReadCheckRequest(BaseModel):
    reader_agent_id: str
    content_key: str
    namespace: str = ""
    backend: str = "redis"
    framework: str = "langchain"
    session_id: str = ""


class RegisterChunkRequest(BaseModel):
    content_key: str
    writer_agent_id: str
    namespace: str = ""
    token_count: int = 0
    content_hash: str = ""


class SetCapRequest(BaseModel):
    agent_id: str
    max_tokens: int = 20000


class AddEntryRequest(BaseModel):
    agent_id: str
    content_key: str
    token_count: int
    namespace: str = ""
    content_hash: str = ""


class AddIntegrityRecordRequest(BaseModel):
    agent_id: str
    content_key: str
    content_hash: str
    namespace: str = ""


class GrantPermissionRequest(BaseModel):
    reader_agent_id: str
    writer_agent_id: str
    namespaces: list[str] = []
    granted_by: str = "admin"


class IsolationCheckRequest(BaseModel):
    reader_agent_id: str
    writer_agent_id: str
    content_key: str = ""
    namespace: str = ""


# ── Sprint 26: Read Anomaly Detection ────────────────────────────────────


@router.post("/read-check")
async def check_memory_read(req: ReadCheckRequest):
    """Check a memory read for anomalies (cross-agent, stale access)."""
    detector = get_read_anomaly_detector()
    enforcer = get_memory_isolation_enforcer()

    # Get permitted cross-agent writers for isolation-aware anomaly detection
    permitted = enforcer.get_permitted_writers(req.reader_agent_id)

    read_req = MemoryReadRequest(
        reader_agent_id=req.reader_agent_id,
        content_key=req.content_key,
        namespace=req.namespace,
        backend=req.backend,
        framework=req.framework,
        session_id=req.session_id,
    )
    alerts = detector.check_read(read_req, permitted_cross_agents=permitted)
    return {
        "reader_agent_id": req.reader_agent_id,
        "content_key": req.content_key,
        "anomalies_found": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }


@router.post("/chunks")
async def register_chunk(req: RegisterChunkRequest):
    """Register a memory chunk for read anomaly tracking."""
    detector = get_read_anomaly_detector()
    chunk = detector.register_chunk(
        content_key=req.content_key,
        writer_agent_id=req.writer_agent_id,
        namespace=req.namespace,
        token_count=req.token_count,
        content_hash=req.content_hash,
    )
    return chunk.to_dict()


@router.get("/read-anomalies")
async def list_read_anomalies(
    anomaly_type: Optional[str] = None,
    agent_id: Optional[str] = None,
    limit: int = 100,
):
    """List read anomaly alerts."""
    detector = get_read_anomaly_detector()
    alerts = detector.get_alerts(anomaly_type=anomaly_type, agent_id=agent_id, limit=limit)
    return [a.to_dict() for a in alerts]


# ── Sprint 26: Memory Lifecycle Cap ──────────────────────────────────────


@router.post("/lifecycle/cap")
async def set_memory_cap(req: SetCapRequest):
    """Set the token cap for an agent's long-term memory."""
    manager = get_memory_lifecycle_manager()
    cap = manager.set_cap(req.agent_id, req.max_tokens)
    return cap.to_dict()


@router.get("/lifecycle/cap/{agent_id}")
async def get_memory_cap(agent_id: str):
    """Get the token cap and usage for an agent."""
    manager = get_memory_lifecycle_manager()
    return manager.get_agent_token_usage(agent_id)


@router.post("/lifecycle/entry")
async def add_memory_entry(req: AddEntryRequest):
    """Add a memory entry with lifecycle cap enforcement."""
    manager = get_memory_lifecycle_manager()
    entry, evictions = manager.add_entry(
        agent_id=req.agent_id,
        content_key=req.content_key,
        token_count=req.token_count,
        namespace=req.namespace,
        content_hash=req.content_hash,
    )
    return {
        "entry": entry.to_dict(),
        "evictions": [e.to_dict() for e in evictions],
        "eviction_count": len(evictions),
    }


@router.get("/lifecycle/evictions")
async def list_evictions(agent_id: Optional[str] = None, limit: int = 100):
    """List memory eviction events."""
    manager = get_memory_lifecycle_manager()
    events = manager.get_eviction_log(agent_id=agent_id, limit=limit)
    return [e.to_dict() for e in events]


# ── Sprint 26: Memory Integrity Verification ─────────────────────────────


@router.post("/integrity/record")
async def add_integrity_record(req: AddIntegrityRecordRequest):
    """Add a memory record to the integrity chain."""
    verifier = get_memory_integrity_verifier()
    record = verifier.add_record(
        agent_id=req.agent_id,
        content_key=req.content_key,
        content_hash=req.content_hash,
        namespace=req.namespace,
    )
    return record.to_dict()


@router.post("/integrity/verify")
async def verify_memory_integrity():
    """Run integrity verification over all stored memory records."""
    verifier = get_memory_integrity_verifier()
    result = verifier.verify_integrity()
    return result.to_dict()


@router.get("/integrity/alerts")
async def list_integrity_alerts(limit: int = 100):
    """List memory integrity alerts."""
    verifier = get_memory_integrity_verifier()
    alerts = verifier.get_alerts(limit=limit)
    return [a.to_dict() for a in alerts]


@router.get("/integrity/history")
async def integrity_verification_history(limit: int = 20):
    """Get integrity verification run history."""
    verifier = get_memory_integrity_verifier()
    history = verifier.get_verification_history(limit=limit)
    return [r.to_dict() for r in history]


# ── Sprint 26: Cross-Agent Memory Isolation ──────────────────────────────


@router.post("/isolation/permission")
async def grant_cross_agent_permission(req: GrantPermissionRequest):
    """Grant an agent permission to read another agent's memory."""
    enforcer = get_memory_isolation_enforcer()
    perm = enforcer.grant_permission(
        reader_agent_id=req.reader_agent_id,
        writer_agent_id=req.writer_agent_id,
        namespaces=req.namespaces,
        granted_by=req.granted_by,
    )
    return perm.to_dict()


@router.delete("/isolation/permission")
async def revoke_cross_agent_permission(
    reader_agent_id: str,
    writer_agent_id: str,
):
    """Revoke a cross-agent read permission."""
    enforcer = get_memory_isolation_enforcer()
    revoked = enforcer.revoke_permission(reader_agent_id, writer_agent_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="Permission not found")
    return {"revoked": True}


@router.post("/isolation/check")
async def check_isolation(req: IsolationCheckRequest):
    """Check whether a cross-agent read is permitted."""
    enforcer = get_memory_isolation_enforcer()
    result = enforcer.check_read(
        reader_agent_id=req.reader_agent_id,
        writer_agent_id=req.writer_agent_id,
        content_key=req.content_key,
        namespace=req.namespace,
    )
    return result.to_dict()


@router.get("/isolation/permissions")
async def list_isolation_permissions(agent_id: Optional[str] = None):
    """List all cross-agent read permissions."""
    enforcer = get_memory_isolation_enforcer()
    perms = enforcer.list_permissions(agent_id=agent_id)
    return [p.to_dict() for p in perms]


@router.get("/isolation/audit")
async def list_isolation_audit(
    reader_agent_id: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 100,
):
    """Query cross-agent isolation audit log."""
    enforcer = get_memory_isolation_enforcer()
    records = enforcer.get_audit(reader_agent_id=reader_agent_id, action=action, limit=limit)
    return [r.to_dict() for r in records]


# ── Sprint 26: Memory Store Dashboard ────────────────────────────────────


@router.get("/dashboard")
async def memory_store_dashboard():
    """Admin dashboard: per-agent memory size, write velocity, blocked writes,
    anomaly flags, integrity status."""
    proxy = get_memory_store_proxy()
    detector = get_read_anomaly_detector()
    manager = get_memory_lifecycle_manager()
    verifier = get_memory_integrity_verifier()
    enforcer = get_memory_isolation_enforcer()

    # Per-agent memory summary
    agent_summaries = []
    for cap in manager.list_caps():
        agent_id = cap.agent_id
        usage = manager.get_agent_token_usage(agent_id)
        write_audit = proxy.audit_log.count_by_agent()
        agent_summaries.append({
            "agent_id": agent_id,
            "memory_tokens": usage["current_tokens"],
            "max_tokens": usage["max_tokens"],
            "utilization_pct": usage["utilization_pct"],
            "entry_count": usage["entry_count"],
            "write_count": write_audit.get(agent_id, 0),
        })

    # Latest integrity check
    integrity_history = verifier.get_verification_history(limit=1)
    latest_integrity = integrity_history[0].to_dict() if integrity_history else None

    return {
        "proxy_stats": proxy.get_stats(),
        "write_audit": {
            "total_records": proxy.audit_log.count(),
            "by_action": proxy.audit_log.count_by_action(),
            "by_agent": proxy.audit_log.count_by_agent(),
        },
        "read_anomaly_stats": detector.get_stats(),
        "read_anomaly_count": detector.alert_count(),
        "lifecycle_stats": manager.get_stats(),
        "integrity_stats": verifier.get_stats(),
        "latest_integrity_check": latest_integrity,
        "isolation_stats": enforcer.get_stats(),
        "isolation_permission_count": enforcer.permission_count(),
        "agent_summaries": agent_summaries,
        "policy_count": proxy.policy_store.count(),
        "quarantine_size": len(proxy.get_quarantine()),
        "scanner_patterns": proxy.scanner.pattern_count,
    }
