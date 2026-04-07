"""Admin API for Inter-Agent A2A Protocol Firewall — Sprint 27.

Endpoints:
- Agent registration (POST/GET/DELETE /admin/a2a/agents)
- Token issuance and revocation (POST /admin/a2a/tokens)
- Message interception (POST /admin/a2a/intercept)
- Certificate management (POST/GET/DELETE /admin/a2a/certificates)
- mTLS policy management (POST/GET /admin/a2a/mtls-policies)
- Audit log queries (GET /admin/a2a/audit)
- Dashboard stats (GET /admin/a2a/stats)
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.a2a.interceptor import (
    get_a2a_interceptor,
    A2AMessage,
)
from app.services.a2a.token_issuer import get_token_issuer
from app.services.a2a.signature import get_signature_verifier
from app.services.a2a.mtls import get_mtls_enforcer
from app.services.a2a.audit import get_a2a_audit_log

router = APIRouter(prefix="/admin/a2a", tags=["a2a-firewall"])


# ── Request / Response Models ────────────────────────────────────────────


class RegisterAgentRequest(BaseModel):
    agent_id: str
    display_name: str = ""
    allowed_downstream: list[str] = []
    permission_scope: list[str] = ["read", "write"]
    token_ttl_seconds: int = 3600


class IssueTokenRequest(BaseModel):
    agent_id: str


class RevokeTokenRequest(BaseModel):
    jti: str


class InterceptMessageRequest(BaseModel):
    sender_agent_id: str
    receiver_agent_id: str
    content: str = ""
    message_type: str = "task"
    framework: str = "langgraph"
    session_id: str = ""
    correlation_id: str = ""
    jwt_token: str = ""
    signature: str = ""
    nonce: str = ""
    timestamp: float = 0.0
    mtls_verified: bool = False
    sender_cert_fingerprint: str = ""


class IssueCertificateRequest(BaseModel):
    agent_id: str
    spiffe_id: str = ""
    ttl_seconds: int = 86400


class AddMTLSPolicyRequest(BaseModel):
    workflow_id: str
    agent_pairs: list[list[str]] = []
    framework: str = "langgraph"
    required: bool = True


class SetGlobalMTLSRequest(BaseModel):
    required: bool


# ── Agent Registration ────────────────────────────────────────────────────


@router.post("/agents")
async def register_agent(req: RegisterAgentRequest):
    """Register an agent service account for A2A communication."""
    issuer = get_token_issuer()
    verifier = get_signature_verifier()

    reg = issuer.register_agent(
        agent_id=req.agent_id,
        display_name=req.display_name,
        allowed_downstream=req.allowed_downstream,
        permission_scope=req.permission_scope,
        token_ttl_seconds=req.token_ttl_seconds,
    )

    # Register signing secret with signature verifier
    verifier.register_secret(req.agent_id, reg.signing_secret)

    # Wire up interceptor components
    interceptor = get_a2a_interceptor()
    interceptor.set_token_issuer(issuer)
    interceptor.set_signature_verifier(verifier)
    interceptor.set_audit_log(get_a2a_audit_log())

    return {"status": "registered", "agent": reg.to_dict()}


@router.get("/agents")
async def list_agents():
    """List all registered agent service accounts."""
    issuer = get_token_issuer()
    return {"agents": issuer.list_agents()}


@router.get("/agents/{agent_id}")
async def get_agent(agent_id: str):
    """Get a specific registered agent."""
    issuer = get_token_issuer()
    agent = issuer.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent": agent.to_dict()}


@router.delete("/agents/{agent_id}")
async def unregister_agent(agent_id: str):
    """Unregister an agent service account."""
    issuer = get_token_issuer()
    verifier = get_signature_verifier()

    if not issuer.unregister_agent(agent_id):
        raise HTTPException(status_code=404, detail="Agent not found")
    verifier.remove_secret(agent_id)
    return {"status": "unregistered", "agent_id": agent_id}


# ── Token Issuance ────────────────────────────────────────────────────────


@router.post("/tokens/issue")
async def issue_token(req: IssueTokenRequest):
    """Issue a signed JWT token for a registered agent."""
    issuer = get_token_issuer()
    try:
        token = issuer.issue_token(req.agent_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "issued", "token": token.to_dict()}


@router.post("/tokens/revoke")
async def revoke_token(req: RevokeTokenRequest):
    """Revoke a JWT token by its JTI."""
    issuer = get_token_issuer()
    issuer.revoke_token(req.jti)
    return {"status": "revoked", "jti": req.jti}


@router.post("/tokens/validate")
async def validate_token(agent_id: str = "", token: str = ""):
    """Validate a JWT token."""
    issuer = get_token_issuer()
    result = issuer.validate_token(token, agent_id)
    return result


# ── Message Interception ──────────────────────────────────────────────────


@router.post("/intercept")
async def intercept_message(req: InterceptMessageRequest):
    """Intercept and validate an A2A message through all security checks."""
    interceptor = get_a2a_interceptor()

    message = A2AMessage(
        sender_agent_id=req.sender_agent_id,
        receiver_agent_id=req.receiver_agent_id,
        content=req.content,
        message_type=req.message_type,
        framework=req.framework,
        session_id=req.session_id,
        correlation_id=req.correlation_id,
        jwt_token=req.jwt_token,
        signature=req.signature,
        nonce=req.nonce,
        timestamp=req.timestamp,
        mtls_verified=req.mtls_verified,
        sender_cert_fingerprint=req.sender_cert_fingerprint,
    )

    result = interceptor.intercept(message)
    return result.to_dict()


# ── Certificate Management ────────────────────────────────────────────────


@router.post("/certificates")
async def issue_certificate(req: IssueCertificateRequest):
    """Issue an mTLS certificate for an agent."""
    enforcer = get_mtls_enforcer()
    cert = enforcer.issue_certificate(
        agent_id=req.agent_id,
        spiffe_id=req.spiffe_id,
        ttl_seconds=req.ttl_seconds,
    )
    return {"status": "issued", "certificate": cert.to_dict()}


@router.get("/certificates")
async def list_certificates():
    """List all agent certificates."""
    enforcer = get_mtls_enforcer()
    return {"certificates": enforcer.list_certificates()}


@router.get("/certificates/{agent_id}")
async def get_certificate(agent_id: str):
    """Get certificate for a specific agent."""
    enforcer = get_mtls_enforcer()
    cert = enforcer.get_certificate(agent_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return {"certificate": cert.to_dict()}


@router.delete("/certificates/{agent_id}")
async def revoke_certificate(agent_id: str):
    """Revoke an agent's mTLS certificate."""
    enforcer = get_mtls_enforcer()
    if not enforcer.revoke_certificate(agent_id):
        raise HTTPException(status_code=404, detail="Certificate not found")
    return {"status": "revoked", "agent_id": agent_id}


# ── mTLS Policy Management ───────────────────────────────────────────────


@router.post("/mtls-policies")
async def add_mtls_policy(req: AddMTLSPolicyRequest):
    """Add an mTLS enforcement policy for a workflow."""
    enforcer = get_mtls_enforcer()

    # Wire up interceptor
    interceptor = get_a2a_interceptor()
    interceptor.set_mtls_enforcer(enforcer)

    # Convert list[list[str]] to list[tuple[str, str]]
    pairs = [(p[0], p[1]) for p in req.agent_pairs if len(p) == 2]

    policy = enforcer.add_policy(
        workflow_id=req.workflow_id,
        agent_pairs=pairs,
        framework=req.framework,
        required=req.required,
    )
    return {"status": "created", "policy": policy.to_dict()}


@router.get("/mtls-policies")
async def list_mtls_policies():
    """List all mTLS policies."""
    enforcer = get_mtls_enforcer()
    return {"policies": enforcer.list_policies()}


@router.post("/mtls-policies/global")
async def set_global_mtls(req: SetGlobalMTLSRequest):
    """Enable or disable global mTLS requirement."""
    enforcer = get_mtls_enforcer()
    enforcer.set_global_mtls_required(req.required)
    return {"status": "updated", "global_mtls_required": req.required}


# ── Audit Log ─────────────────────────────────────────────────────────────


@router.get("/audit")
async def query_audit_log(
    sender_agent_id: str = "",
    receiver_agent_id: str = "",
    action: str = "",
    limit: int = 100,
):
    """Query A2A audit log records."""
    audit = get_a2a_audit_log()
    records = audit.get_records(
        sender_agent_id=sender_agent_id,
        receiver_agent_id=receiver_agent_id,
        action=action,
        limit=limit,
    )
    return {"records": [r.to_dict() for r in records], "total": len(records)}


@router.get("/audit/{record_id}")
async def get_audit_record(record_id: str):
    """Get a specific audit record."""
    audit = get_a2a_audit_log()
    record = audit.get_record_by_id(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Audit record not found")
    return {"record": record.to_dict()}


@router.get("/audit/chain/verify")
async def verify_audit_chain():
    """Verify the integrity of the A2A audit chain."""
    audit = get_a2a_audit_log()
    return audit.verify_chain_integrity()


# ── Dashboard / Stats ─────────────────────────────────────────────────────


@router.get("/stats")
async def get_a2a_stats():
    """Get A2A firewall statistics."""
    interceptor = get_a2a_interceptor()
    issuer = get_token_issuer()
    verifier = get_signature_verifier()
    enforcer = get_mtls_enforcer()
    audit = get_a2a_audit_log()

    return {
        "interceptor": interceptor.get_stats(),
        "token_issuer": issuer.get_stats(),
        "signature_verifier": verifier.get_stats(),
        "mtls_enforcer": enforcer.get_stats(),
        "audit": audit.get_stats(),
    }
