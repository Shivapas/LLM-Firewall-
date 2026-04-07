"""Admin API for Agent Memory Store Firewall — Sprint 25.

Endpoints for:
- Intercepting memory writes (POST /admin/memory-firewall/intercept)
- Policy CRUD (GET/POST/PUT/DELETE /admin/memory-firewall/policies)
- Audit log queries (GET /admin/memory-firewall/audit)
- Stats and quarantine management
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
