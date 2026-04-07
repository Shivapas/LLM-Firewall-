"""Control plane admin API for API key management, kill-switches, and policies."""

import json
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import APIKey, KillSwitch, PolicyRule, SecurityRule, RAGPolicyConfig, PolicyVersionSnapshot, VectorCollectionPolicy, Incident, CollectionAuditLogRecord, RoutingRule, BudgetTier, AlertRule, AlertEvent, SecurityIncident, OnboardingProgress, RedTeamCampaign, RedTeamProbeResult
from app.services.database import get_db
from app.services.key_service import create_api_key, revoke_api_key, hash_key
from app.services.kill_switch import (
    activate_kill_switch,
    deactivate_kill_switch,
    list_kill_switches,
    get_kill_switch_audit_log,
)
from app.services.policy_cache import force_refresh, get_all_policies
from app.services.threat_detection.engine import get_threat_engine
from app.services.threat_detection.pattern_library import ThreatPattern

router = APIRouter(prefix="/admin", tags=["admin"])


class CreateKeyRequest(BaseModel):
    tenant_id: str
    project_id: str
    allowed_models: list[str] = []
    tpm_limit: int = 100000
    expires_at: Optional[datetime] = None


class CreateKeyResponse(BaseModel):
    raw_key: str
    key_id: str
    key_prefix: str
    tenant_id: str
    project_id: str


class KeyInfo(BaseModel):
    id: str
    key_prefix: str
    tenant_id: str
    project_id: str
    allowed_models: list[str]
    tpm_limit: int
    risk_score: float
    is_active: bool
    expires_at: Optional[datetime]
    created_at: datetime


@router.post("/keys", response_model=CreateKeyResponse)
async def create_key(body: CreateKeyRequest, db: AsyncSession = Depends(get_db)):
    """Create a new API key."""
    raw_key, api_key = await create_api_key(
        db=db,
        tenant_id=body.tenant_id,
        project_id=body.project_id,
        allowed_models=body.allowed_models,
        tpm_limit=body.tpm_limit,
        expires_at=body.expires_at,
    )
    return CreateKeyResponse(
        raw_key=raw_key,
        key_id=str(api_key.id),
        key_prefix=api_key.key_prefix,
        tenant_id=api_key.tenant_id,
        project_id=api_key.project_id,
    )


@router.get("/keys", response_model=list[KeyInfo])
async def list_keys(db: AsyncSession = Depends(get_db)):
    """List all API keys."""
    result = await db.execute(select(APIKey).order_by(APIKey.created_at.desc()))
    keys = result.scalars().all()
    return [
        KeyInfo(
            id=str(k.id),
            key_prefix=k.key_prefix,
            tenant_id=k.tenant_id,
            project_id=k.project_id,
            allowed_models=k.allowed_models or [],
            tpm_limit=k.tpm_limit,
            risk_score=k.risk_score,
            is_active=k.is_active,
            expires_at=k.expires_at,
            created_at=k.created_at,
        )
        for k in keys
    ]


@router.get("/keys/{key_id}", response_model=KeyInfo)
async def get_key(key_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Get a specific API key by ID."""
    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    key = result.scalar_one_or_none()
    if key is None:
        raise HTTPException(status_code=404, detail="API key not found")
    return KeyInfo(
        id=str(key.id),
        key_prefix=key.key_prefix,
        tenant_id=key.tenant_id,
        project_id=key.project_id,
        allowed_models=key.allowed_models or [],
        tpm_limit=key.tpm_limit,
        risk_score=key.risk_score,
        is_active=key.is_active,
        expires_at=key.expires_at,
        created_at=key.created_at,
    )


class UpdateKeyRequest(BaseModel):
    allowed_models: Optional[list[str]] = None
    tpm_limit: Optional[int] = None
    is_active: Optional[bool] = None


@router.patch("/keys/{key_id}", response_model=KeyInfo)
async def update_key(
    key_id: uuid.UUID, body: UpdateKeyRequest, db: AsyncSession = Depends(get_db)
):
    """Update an existing API key."""
    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    key = result.scalar_one_or_none()
    if key is None:
        raise HTTPException(status_code=404, detail="API key not found")

    if body.allowed_models is not None:
        key.allowed_models = body.allowed_models
    if body.tpm_limit is not None:
        key.tpm_limit = body.tpm_limit
    if body.is_active is not None:
        key.is_active = body.is_active

    await db.commit()
    await db.refresh(key)

    return KeyInfo(
        id=str(key.id),
        key_prefix=key.key_prefix,
        tenant_id=key.tenant_id,
        project_id=key.project_id,
        allowed_models=key.allowed_models or [],
        tpm_limit=key.tpm_limit,
        risk_score=key.risk_score,
        is_active=key.is_active,
        expires_at=key.expires_at,
        created_at=key.created_at,
    )


@router.delete("/keys/{key_id}")
async def delete_key(key_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Revoke (soft-delete) an API key."""
    success = await revoke_api_key(db, key_id)
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"status": "revoked", "key_id": str(key_id)}


# ── Kill-Switch Endpoints ──────────────────────────────────────────────


class ActivateKillSwitchRequest(BaseModel):
    model_name: str
    action: str = "block"  # block | reroute
    fallback_model: Optional[str] = None
    activated_by: str
    reason: str = ""
    error_message: Optional[str] = None


class KillSwitchInfo(BaseModel):
    id: str
    model_name: str
    action: str
    fallback_model: Optional[str]
    activated_by: str
    reason: str
    error_message: Optional[str] = "Model temporarily unavailable"
    is_active: bool
    created_at: Optional[datetime]
    updated_at: Optional[datetime] = None


class KillSwitchAuditEntry(BaseModel):
    id: str
    model_name: str
    action: str
    fallback_model: Optional[str]
    activated_by: str
    reason: str
    event_type: str
    created_at: Optional[datetime]


@router.post("/kill-switches", response_model=KillSwitchInfo)
async def activate_kill_switch_endpoint(
    body: ActivateKillSwitchRequest, db: AsyncSession = Depends(get_db)
):
    """Activate a kill-switch for a model."""
    try:
        data = await activate_kill_switch(
            db=db,
            model_name=body.model_name,
            action=body.action,
            activated_by=body.activated_by,
            reason=body.reason,
            fallback_model=body.fallback_model,
            error_message=body.error_message,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return KillSwitchInfo(**data)


@router.get("/kill-switches", response_model=list[KillSwitchInfo])
async def list_kill_switches_endpoint(db: AsyncSession = Depends(get_db)):
    """List all kill-switches."""
    switches = await list_kill_switches(db)
    return [KillSwitchInfo(**s) for s in switches]


@router.get("/kill-switches/audit", response_model=list[KillSwitchAuditEntry])
async def get_kill_switch_audit_endpoint(
    model_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Get immutable kill-switch audit log. Records cannot be deleted."""
    logs = await get_kill_switch_audit_log(db, model_name=model_name)
    return [KillSwitchAuditEntry(**log) for log in logs]


@router.delete("/kill-switches/{model_name}")
async def deactivate_kill_switch_endpoint(
    model_name: str, db: AsyncSession = Depends(get_db)
):
    """Deactivate a kill-switch for a model."""
    success = await deactivate_kill_switch(db, model_name)
    if not success:
        raise HTTPException(status_code=404, detail="Kill-switch not found")
    return {"status": "deactivated", "model_name": model_name}


# ── Policy Endpoints ───────────────────────────────────────────────────


class CreatePolicyRequest(BaseModel):
    name: str
    description: str = ""
    policy_type: str
    rules: dict = {}


class PolicyInfo(BaseModel):
    id: str
    name: str
    description: str
    policy_type: str
    rules: dict
    is_active: bool
    version: int
    created_at: Optional[datetime]


@router.post("/policies", response_model=PolicyInfo)
async def create_policy(body: CreatePolicyRequest, db: AsyncSession = Depends(get_db)):
    """Create a new policy rule."""
    from app.services.policy_versioning import create_policy_snapshot

    policy = PolicyRule(
        id=uuid.uuid4(),
        name=body.name,
        description=body.description,
        policy_type=body.policy_type,
        rules_json=json.dumps(body.rules),
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    # Create initial version snapshot
    await create_policy_snapshot(
        db, policy.id, policy.rules_json,
        description="Initial version",
    )

    # Refresh the in-memory policy cache
    await force_refresh(db)

    return PolicyInfo(
        id=str(policy.id),
        name=policy.name,
        description=policy.description,
        policy_type=policy.policy_type,
        rules=json.loads(policy.rules_json),
        is_active=policy.is_active,
        version=policy.version,
        created_at=policy.created_at,
    )


@router.get("/policies", response_model=list[PolicyInfo])
async def list_policies(db: AsyncSession = Depends(get_db)):
    """List all policy rules."""
    result = await db.execute(select(PolicyRule).order_by(PolicyRule.created_at.desc()))
    rules = result.scalars().all()
    return [
        PolicyInfo(
            id=str(r.id),
            name=r.name,
            description=r.description,
            policy_type=r.policy_type,
            rules=json.loads(r.rules_json) if r.rules_json else {},
            is_active=r.is_active,
            version=r.version,
            created_at=r.created_at,
        )
        for r in rules
    ]


@router.get("/policies/{policy_id}", response_model=PolicyInfo)
async def get_policy_endpoint(policy_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Get a specific policy by ID."""
    result = await db.execute(select(PolicyRule).where(PolicyRule.id == policy_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return PolicyInfo(
        id=str(rule.id),
        name=rule.name,
        description=rule.description,
        policy_type=rule.policy_type,
        rules=json.loads(rule.rules_json) if rule.rules_json else {},
        is_active=rule.is_active,
        version=rule.version,
        created_at=rule.created_at,
    )


class UpdatePolicyRequest(BaseModel):
    description: Optional[str] = None
    rules: Optional[dict] = None
    is_active: Optional[bool] = None


@router.patch("/policies/{policy_id}", response_model=PolicyInfo)
async def update_policy(
    policy_id: uuid.UUID, body: UpdatePolicyRequest, db: AsyncSession = Depends(get_db)
):
    """Update a policy rule."""
    from app.services.policy_versioning import create_policy_snapshot

    result = await db.execute(select(PolicyRule).where(PolicyRule.id == policy_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Policy not found")

    if body.description is not None:
        rule.description = body.description
    if body.rules is not None:
        rule.rules_json = json.dumps(body.rules)
        rule.version += 1
    if body.is_active is not None:
        rule.is_active = body.is_active

    await db.commit()
    await db.refresh(rule)

    # Create version snapshot on rules change
    if body.rules is not None:
        await create_policy_snapshot(
            db, policy_id, rule.rules_json,
            description=f"Updated to version {rule.version}",
        )

    await force_refresh(db)

    return PolicyInfo(
        id=str(rule.id),
        name=rule.name,
        description=rule.description,
        policy_type=rule.policy_type,
        rules=json.loads(rule.rules_json) if rule.rules_json else {},
        is_active=rule.is_active,
        version=rule.version,
        created_at=rule.created_at,
    )


@router.post("/policies/refresh")
async def refresh_policy_cache(db: AsyncSession = Depends(get_db)):
    """Force refresh the in-memory policy cache."""
    count = await force_refresh(db)
    return {"status": "refreshed", "policies_loaded": count}


@router.get("/policies/cache/status")
async def policy_cache_status():
    """Get current state of the in-memory policy cache."""
    policies = get_all_policies()
    return {
        "cached_policies": len(policies),
        "policy_names": list(policies.keys()),
    }


# ── Security Rule Endpoints (Sprint 4 — Threat Detection) ────────────


class CreateSecurityRuleRequest(BaseModel):
    name: str
    description: str = ""
    category: str = "prompt_injection"
    severity: str = "medium"
    pattern: str
    action: str = "block"
    rewrite_template: Optional[str] = None
    tags: list[str] = []
    stage: str = "input"


class SecurityRuleInfo(BaseModel):
    id: str
    name: str
    description: str
    category: str
    severity: str
    pattern: str
    action: str
    rewrite_template: Optional[str]
    tags: list[str]
    is_active: bool
    stage: str
    created_at: Optional[datetime]


@router.post("/security-rules", response_model=SecurityRuleInfo)
async def create_security_rule(
    body: CreateSecurityRuleRequest, db: AsyncSession = Depends(get_db)
):
    """Create a new security rule for threat detection."""
    import re as re_module
    # Validate regex pattern
    try:
        re_module.compile(body.pattern)
    except re_module.error as e:
        raise HTTPException(status_code=400, detail=f"Invalid regex pattern: {e}")

    valid_actions = {"allow", "block", "rewrite", "downgrade"}
    if body.action not in valid_actions:
        raise HTTPException(status_code=400, detail=f"Invalid action. Must be one of: {valid_actions}")

    valid_severities = {"critical", "high", "medium", "low"}
    if body.severity not in valid_severities:
        raise HTTPException(status_code=400, detail=f"Invalid severity. Must be one of: {valid_severities}")

    rule = SecurityRule(
        id=uuid.uuid4(),
        name=body.name,
        description=body.description,
        category=body.category,
        severity=body.severity,
        pattern=body.pattern,
        action=body.action,
        rewrite_template=body.rewrite_template,
        tags_json=json.dumps(body.tags),
        stage=body.stage,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    # Load into the threat engine immediately
    engine = get_threat_engine()
    engine.load_policy_rules([{
        "id": f"custom-{rule.id}",
        "name": rule.name,
        "category": rule.category,
        "severity": rule.severity,
        "pattern": rule.pattern,
        "description": rule.description,
        "tags": body.tags,
    }])

    return SecurityRuleInfo(
        id=str(rule.id),
        name=rule.name,
        description=rule.description,
        category=rule.category,
        severity=rule.severity,
        pattern=rule.pattern,
        action=rule.action,
        rewrite_template=rule.rewrite_template,
        tags=json.loads(rule.tags_json),
        is_active=rule.is_active,
        stage=rule.stage,
        created_at=rule.created_at,
    )


@router.get("/security-rules", response_model=list[SecurityRuleInfo])
async def list_security_rules(db: AsyncSession = Depends(get_db)):
    """List all security rules."""
    result = await db.execute(
        select(SecurityRule).order_by(SecurityRule.created_at.desc())
    )
    rules = result.scalars().all()
    return [
        SecurityRuleInfo(
            id=str(r.id),
            name=r.name,
            description=r.description,
            category=r.category,
            severity=r.severity,
            pattern=r.pattern,
            action=r.action,
            rewrite_template=r.rewrite_template,
            tags=json.loads(r.tags_json) if r.tags_json else [],
            is_active=r.is_active,
            stage=r.stage,
            created_at=r.created_at,
        )
        for r in rules
    ]


@router.get("/security-rules/{rule_id}", response_model=SecurityRuleInfo)
async def get_security_rule(rule_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Get a specific security rule by ID."""
    result = await db.execute(select(SecurityRule).where(SecurityRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Security rule not found")
    return SecurityRuleInfo(
        id=str(rule.id),
        name=rule.name,
        description=rule.description,
        category=rule.category,
        severity=rule.severity,
        pattern=rule.pattern,
        action=rule.action,
        rewrite_template=rule.rewrite_template,
        tags=json.loads(rule.tags_json) if rule.tags_json else [],
        is_active=rule.is_active,
        stage=rule.stage,
        created_at=rule.created_at,
    )


class UpdateSecurityRuleRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    pattern: Optional[str] = None
    action: Optional[str] = None
    rewrite_template: Optional[str] = None
    tags: Optional[list[str]] = None
    is_active: Optional[bool] = None
    stage: Optional[str] = None


@router.patch("/security-rules/{rule_id}", response_model=SecurityRuleInfo)
async def update_security_rule(
    rule_id: uuid.UUID, body: UpdateSecurityRuleRequest, db: AsyncSession = Depends(get_db)
):
    """Update a security rule."""
    import re as re_module

    result = await db.execute(select(SecurityRule).where(SecurityRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Security rule not found")

    if body.pattern is not None:
        try:
            re_module.compile(body.pattern)
        except re_module.error as e:
            raise HTTPException(status_code=400, detail=f"Invalid regex pattern: {e}")
        rule.pattern = body.pattern

    if body.name is not None:
        rule.name = body.name
    if body.description is not None:
        rule.description = body.description
    if body.category is not None:
        rule.category = body.category
    if body.severity is not None:
        rule.severity = body.severity
    if body.action is not None:
        rule.action = body.action
    if body.rewrite_template is not None:
        rule.rewrite_template = body.rewrite_template
    if body.tags is not None:
        rule.tags_json = json.dumps(body.tags)
    if body.is_active is not None:
        rule.is_active = body.is_active
    if body.stage is not None:
        rule.stage = body.stage

    await db.commit()
    await db.refresh(rule)

    return SecurityRuleInfo(
        id=str(rule.id),
        name=rule.name,
        description=rule.description,
        category=rule.category,
        severity=rule.severity,
        pattern=rule.pattern,
        action=rule.action,
        rewrite_template=rule.rewrite_template,
        tags=json.loads(rule.tags_json) if rule.tags_json else [],
        is_active=rule.is_active,
        stage=rule.stage,
        created_at=rule.created_at,
    )


@router.delete("/security-rules/{rule_id}")
async def delete_security_rule(rule_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Delete a security rule."""
    result = await db.execute(select(SecurityRule).where(SecurityRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Security rule not found")

    # Remove from threat engine
    engine = get_threat_engine()
    engine.library.remove_pattern(f"custom-{rule_id}")

    await db.delete(rule)
    await db.commit()
    return {"status": "deleted", "rule_id": str(rule_id)}


# ── Threat Detection Status & Test Endpoints ─────────────────────────


@router.get("/threat-engine/status")
async def threat_engine_status():
    """Get threat detection engine status and statistics."""
    engine = get_threat_engine()
    return engine.get_stats()


class ScanTestRequest(BaseModel):
    text: str


@router.post("/threat-engine/scan")
async def scan_test(body: ScanTestRequest):
    """Test the threat detection engine against sample text."""
    engine = get_threat_engine()
    threat_score = engine.scan(body.text)
    action_result = engine.action_engine.evaluate(body.text, threat_score)
    return {
        "threat_score": threat_score.to_dict(),
        "action": action_result.to_dict(),
    }


# ── RAG Pipeline Endpoints (Sprint 6) ─────────────────────────────────

from app.services.rag.classifier import get_rag_classifier
from app.services.rag.query_firewall import get_query_firewall
from app.services.rag.intent_classifier import get_intent_classifier
from app.services.rag.pipeline import get_rag_pipeline


class CreateRAGPolicyRequest(BaseModel):
    name: str
    description: str = ""
    query_stage_enabled: bool = True
    retrieval_stage_enabled: bool = True
    generator_stage_enabled: bool = True
    query_threat_detection: bool = True
    query_pii_redaction: bool = True
    query_intent_classification: bool = True
    block_high_risk_intents: bool = False
    max_chunks: int = 10
    max_tokens_per_chunk: int = 512
    scan_retrieved_chunks: bool = True
    generator_pii_redaction: bool = True
    generator_threat_detection: bool = True
    rules: dict = {}
    tenant_id: str = "*"


class RAGPolicyInfo(BaseModel):
    id: str
    name: str
    description: str
    query_stage_enabled: bool
    retrieval_stage_enabled: bool
    generator_stage_enabled: bool
    query_threat_detection: bool
    query_pii_redaction: bool
    query_intent_classification: bool
    block_high_risk_intents: bool
    max_chunks: int
    max_tokens_per_chunk: int
    scan_retrieved_chunks: bool
    generator_pii_redaction: bool
    generator_threat_detection: bool
    rules: dict
    is_active: bool
    tenant_id: str
    created_at: Optional[datetime]


@router.post("/rag-policies", response_model=RAGPolicyInfo)
async def create_rag_policy(body: CreateRAGPolicyRequest, db: AsyncSession = Depends(get_db)):
    """Create a new RAG pipeline policy configuration."""
    policy = RAGPolicyConfig(
        id=uuid.uuid4(),
        name=body.name,
        description=body.description,
        query_stage_enabled=body.query_stage_enabled,
        retrieval_stage_enabled=body.retrieval_stage_enabled,
        generator_stage_enabled=body.generator_stage_enabled,
        query_threat_detection=body.query_threat_detection,
        query_pii_redaction=body.query_pii_redaction,
        query_intent_classification=body.query_intent_classification,
        block_high_risk_intents=body.block_high_risk_intents,
        max_chunks=body.max_chunks,
        max_tokens_per_chunk=body.max_tokens_per_chunk,
        scan_retrieved_chunks=body.scan_retrieved_chunks,
        generator_pii_redaction=body.generator_pii_redaction,
        generator_threat_detection=body.generator_threat_detection,
        rules_json=json.dumps(body.rules),
        tenant_id=body.tenant_id,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    return _rag_policy_to_info(policy)


@router.get("/rag-policies", response_model=list[RAGPolicyInfo])
async def list_rag_policies(db: AsyncSession = Depends(get_db)):
    """List all RAG pipeline policy configurations."""
    result = await db.execute(
        select(RAGPolicyConfig).order_by(RAGPolicyConfig.created_at.desc())
    )
    policies = result.scalars().all()
    return [_rag_policy_to_info(p) for p in policies]


@router.get("/rag-policies/{policy_id}", response_model=RAGPolicyInfo)
async def get_rag_policy(policy_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Get a specific RAG policy by ID."""
    result = await db.execute(
        select(RAGPolicyConfig).where(RAGPolicyConfig.id == policy_id)
    )
    policy = result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(status_code=404, detail="RAG policy not found")
    return _rag_policy_to_info(policy)


class UpdateRAGPolicyRequest(BaseModel):
    description: Optional[str] = None
    query_stage_enabled: Optional[bool] = None
    retrieval_stage_enabled: Optional[bool] = None
    generator_stage_enabled: Optional[bool] = None
    query_threat_detection: Optional[bool] = None
    query_pii_redaction: Optional[bool] = None
    query_intent_classification: Optional[bool] = None
    block_high_risk_intents: Optional[bool] = None
    max_chunks: Optional[int] = None
    max_tokens_per_chunk: Optional[int] = None
    scan_retrieved_chunks: Optional[bool] = None
    generator_pii_redaction: Optional[bool] = None
    generator_threat_detection: Optional[bool] = None
    rules: Optional[dict] = None
    is_active: Optional[bool] = None


@router.patch("/rag-policies/{policy_id}", response_model=RAGPolicyInfo)
async def update_rag_policy(
    policy_id: uuid.UUID, body: UpdateRAGPolicyRequest, db: AsyncSession = Depends(get_db)
):
    """Update a RAG pipeline policy."""
    result = await db.execute(
        select(RAGPolicyConfig).where(RAGPolicyConfig.id == policy_id)
    )
    policy = result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(status_code=404, detail="RAG policy not found")

    for field_name in (
        "description", "query_stage_enabled", "retrieval_stage_enabled",
        "generator_stage_enabled", "query_threat_detection", "query_pii_redaction",
        "query_intent_classification", "block_high_risk_intents", "max_chunks",
        "max_tokens_per_chunk", "scan_retrieved_chunks", "generator_pii_redaction",
        "generator_threat_detection", "is_active",
    ):
        val = getattr(body, field_name, None)
        if val is not None:
            setattr(policy, field_name, val)

    if body.rules is not None:
        policy.rules_json = json.dumps(body.rules)

    await db.commit()
    await db.refresh(policy)
    return _rag_policy_to_info(policy)


@router.delete("/rag-policies/{policy_id}")
async def delete_rag_policy(policy_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Delete a RAG pipeline policy."""
    result = await db.execute(
        select(RAGPolicyConfig).where(RAGPolicyConfig.id == policy_id)
    )
    policy = result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(status_code=404, detail="RAG policy not found")
    await db.delete(policy)
    await db.commit()
    return {"status": "deleted", "policy_id": str(policy_id)}


def _rag_policy_to_info(policy: RAGPolicyConfig) -> RAGPolicyInfo:
    return RAGPolicyInfo(
        id=str(policy.id),
        name=policy.name,
        description=policy.description,
        query_stage_enabled=policy.query_stage_enabled,
        retrieval_stage_enabled=policy.retrieval_stage_enabled,
        generator_stage_enabled=policy.generator_stage_enabled,
        query_threat_detection=policy.query_threat_detection,
        query_pii_redaction=policy.query_pii_redaction,
        query_intent_classification=policy.query_intent_classification,
        block_high_risk_intents=policy.block_high_risk_intents,
        max_chunks=policy.max_chunks,
        max_tokens_per_chunk=policy.max_tokens_per_chunk,
        scan_retrieved_chunks=policy.scan_retrieved_chunks,
        generator_pii_redaction=policy.generator_pii_redaction,
        generator_threat_detection=policy.generator_threat_detection,
        rules=json.loads(policy.rules_json) if policy.rules_json else {},
        is_active=policy.is_active,
        tenant_id=policy.tenant_id,
        created_at=policy.created_at,
    )


# ── RAG Pipeline Test Endpoints ────────────────────────────────────────


class RAGClassifyRequest(BaseModel):
    body: dict


@router.post("/rag-pipeline/classify")
async def rag_classify_test(req: RAGClassifyRequest):
    """Test the RAG request classifier against a sample payload."""
    classifier = get_rag_classifier()
    body_bytes = json.dumps(req.body).encode()
    result = classifier.classify(body_bytes)
    return result.to_dict()


class RAGQueryScanRequest(BaseModel):
    query: str
    tenant_id: str = ""


@router.post("/rag-pipeline/scan-query")
async def rag_scan_query_test(req: RAGQueryScanRequest):
    """Test the RAG query firewall against a sample query."""
    firewall = get_query_firewall()
    result = firewall.scan_query(req.query, tenant_id=req.tenant_id)
    return result.to_dict()


class RAGIntentRequest(BaseModel):
    query: str


@router.post("/rag-pipeline/classify-intent")
async def rag_intent_test(req: RAGIntentRequest):
    """Test the intent classifier against a sample query."""
    classifier = get_intent_classifier()
    result = classifier.classify(req.query)
    return result.to_dict()


@router.post("/rag-pipeline/process")
async def rag_pipeline_test(req: RAGClassifyRequest):
    """Test the full RAG pipeline against a sample payload."""
    pipeline = get_rag_pipeline()
    body_bytes = json.dumps(req.body).encode()
    _, result = pipeline.process(body_bytes, tenant_id="test")
    return result.to_dict()


# ── Sprint 7: Policy Version Management ──────────────────────────────

from app.services.policy_versioning import (
    list_policy_versions,
    get_policy_version,
    diff_policy_versions,
    rollback_policy,
    simulate_policy,
)
from app.services.threat_detection.tier2_scanner import get_tier2_scanner
from app.services.threat_detection.escalation_gate import get_escalation_gate


class PolicyVersionInfo(BaseModel):
    id: str
    policy_id: str
    version: int
    name: str
    description: str
    policy_type: str
    rules: dict
    created_by: str
    created_at: Optional[str]


@router.get("/policies/{policy_id}/versions", response_model=list[PolicyVersionInfo])
async def list_versions(policy_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """List all version snapshots for a policy."""
    versions = await list_policy_versions(db, policy_id)
    return [PolicyVersionInfo(**v) for v in versions]


@router.get("/policies/{policy_id}/versions/{version}", response_model=PolicyVersionInfo)
async def get_version(
    policy_id: uuid.UUID, version: int, db: AsyncSession = Depends(get_db)
):
    """Get a specific version snapshot."""
    ver = await get_policy_version(db, policy_id, version)
    if not ver:
        raise HTTPException(status_code=404, detail=f"Version {version} not found")
    return PolicyVersionInfo(**ver)


class PolicyDiffRequest(BaseModel):
    version_a: int
    version_b: int


@router.post("/policies/{policy_id}/diff")
async def diff_versions(
    policy_id: uuid.UUID, body: PolicyDiffRequest, db: AsyncSession = Depends(get_db)
):
    """Compute diff between two policy versions."""
    try:
        diff = await diff_policy_versions(db, policy_id, body.version_a, body.version_b)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return diff


class PolicyRollbackRequest(BaseModel):
    target_version: int
    rolled_back_by: str = "admin"


@router.post("/policies/{policy_id}/rollback")
async def rollback_version(
    policy_id: uuid.UUID, body: PolicyRollbackRequest, db: AsyncSession = Depends(get_db)
):
    """Rollback a policy to a previous version. Propagates to gateway in < 5s."""
    try:
        result = await rollback_policy(
            db, policy_id, body.target_version, body.rolled_back_by,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return result


class PolicySimulationRequest(BaseModel):
    rules: dict
    limit: int = 100


@router.post("/policies/{policy_id}/simulate")
async def simulate_policy_endpoint(
    policy_id: uuid.UUID, body: PolicySimulationRequest, db: AsyncSession = Depends(get_db)
):
    """Simulate a policy against recent request log (dry-run).

    Preview which requests would be blocked/rewritten before activation.
    """
    try:
        result = await simulate_policy(db, policy_id, body.rules, body.limit)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return result


# ── Sprint 7: Tier 2 ML Scanner Endpoints ────────────────────────────


@router.post("/threat-engine/scan-tier2")
async def scan_test_tier2(body: ScanTestRequest):
    """Test the Tier 2 ML semantic scanner against sample text."""
    tier2 = get_tier2_scanner()
    result = tier2.scan(body.text)
    return result.to_dict()


@router.post("/threat-engine/scan-escalation")
async def scan_test_escalation(body: ScanTestRequest):
    """Test full Tier 1 + Tier 2 escalation pipeline against sample text."""
    engine = get_threat_engine()
    action_result, escalation = engine.evaluate_with_escalation(body.text)
    result = {
        "action": action_result.to_dict(),
    }
    if escalation:
        result["escalation"] = escalation.to_dict()
    return result


@router.get("/threat-engine/tier2-status")
async def tier2_status():
    """Get Tier 2 ML semantic scanner status."""
    tier2 = get_tier2_scanner()
    engine = get_threat_engine()
    return {
        "tier2_enabled": engine.tier2_enabled,
        "index_size": tier2.index_size,
    }


# ── Sprint 8: Vector DB Proxy & Namespace Isolation ────────────────────

from app.services.vectordb.proxy import (
    get_vectordb_proxy,
    CollectionPolicy,
    VectorDBProvider,
    VectorOperation,
    ProxyAction,
    ProxyRequest,
)
from app.services.vectordb.namespace_isolator import get_namespace_isolator


class CreateVectorCollectionRequest(BaseModel):
    collection_name: str
    provider: str = "chromadb"
    default_action: str = "deny"
    allowed_operations: list[str] = []
    sensitive_fields: list[str] = []
    namespace_field: str = "tenant_id"
    max_results: int = 10
    tenant_id: str = "*"
    # Sprint 9 fields
    block_sensitive_documents: bool = False
    sensitive_field_patterns: list[str] = []
    anomaly_distance_threshold: float = 0.0
    scan_chunks_for_injection: bool = True
    max_tokens_per_chunk: int = 512


class VectorCollectionInfo(BaseModel):
    id: str
    collection_name: str
    provider: str
    default_action: str
    allowed_operations: list[str]
    sensitive_fields: list[str]
    namespace_field: str
    max_results: int
    is_active: bool
    tenant_id: str
    created_at: Optional[datetime]
    # Sprint 9 fields
    block_sensitive_documents: bool = False
    sensitive_field_patterns: list[str] = []
    anomaly_distance_threshold: float = 0.0
    scan_chunks_for_injection: bool = True
    max_tokens_per_chunk: int = 512


class UpdateVectorCollectionRequest(BaseModel):
    default_action: Optional[str] = None
    allowed_operations: Optional[list[str]] = None
    sensitive_fields: Optional[list[str]] = None
    namespace_field: Optional[str] = None
    max_results: Optional[int] = None
    is_active: Optional[bool] = None
    # Sprint 9 fields
    block_sensitive_documents: Optional[bool] = None
    sensitive_field_patterns: Optional[list[str]] = None
    anomaly_distance_threshold: Optional[float] = None
    scan_chunks_for_injection: Optional[bool] = None
    max_tokens_per_chunk: Optional[int] = None


@router.post("/vector-collections", response_model=VectorCollectionInfo)
async def create_vector_collection(
    body: CreateVectorCollectionRequest, db: AsyncSession = Depends(get_db)
):
    """Register a new vector collection with per-collection access policy."""
    valid_providers = {"chromadb", "pinecone", "milvus"}
    if body.provider not in valid_providers:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid provider. Must be one of: {valid_providers}",
        )

    valid_actions = {"deny", "allow", "monitor"}
    if body.default_action not in valid_actions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid default_action. Must be one of: {valid_actions}",
        )

    valid_ops = {"query", "insert", "update", "delete"}
    for op in body.allowed_operations:
        if op not in valid_ops:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid operation '{op}'. Must be one of: {valid_ops}",
            )

    if body.max_results < 1 or body.max_results > 100:
        raise HTTPException(
            status_code=400, detail="max_results must be between 1 and 100"
        )

    # Check uniqueness
    existing = await db.execute(
        select(VectorCollectionPolicy).where(
            VectorCollectionPolicy.collection_name == body.collection_name
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=409,
            detail=f"Collection '{body.collection_name}' already registered",
        )

    policy = VectorCollectionPolicy(
        id=uuid.uuid4(),
        collection_name=body.collection_name,
        provider=body.provider,
        default_action=body.default_action,
        allowed_operations=body.allowed_operations,
        sensitive_fields=body.sensitive_fields,
        namespace_field=body.namespace_field,
        max_results=body.max_results,
        tenant_id=body.tenant_id,
        block_sensitive_documents=body.block_sensitive_documents,
        sensitive_field_patterns=body.sensitive_field_patterns,
        anomaly_distance_threshold=body.anomaly_distance_threshold,
        scan_chunks_for_injection=body.scan_chunks_for_injection,
        max_tokens_per_chunk=body.max_tokens_per_chunk,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    # Register in the in-memory proxy
    _sync_policy_to_proxy(policy)

    return _vector_collection_to_info(policy)


@router.get("/vector-collections", response_model=list[VectorCollectionInfo])
async def list_vector_collections(db: AsyncSession = Depends(get_db)):
    """List all registered vector collection policies."""
    result = await db.execute(
        select(VectorCollectionPolicy).order_by(
            VectorCollectionPolicy.created_at.desc()
        )
    )
    policies = result.scalars().all()
    return [_vector_collection_to_info(p) for p in policies]


@router.get("/vector-collections/{collection_id}", response_model=VectorCollectionInfo)
async def get_vector_collection(
    collection_id: uuid.UUID, db: AsyncSession = Depends(get_db)
):
    """Get a specific vector collection policy by ID."""
    result = await db.execute(
        select(VectorCollectionPolicy).where(
            VectorCollectionPolicy.id == collection_id
        )
    )
    policy = result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(status_code=404, detail="Vector collection policy not found")
    return _vector_collection_to_info(policy)


@router.patch("/vector-collections/{collection_id}", response_model=VectorCollectionInfo)
async def update_vector_collection(
    collection_id: uuid.UUID,
    body: UpdateVectorCollectionRequest,
    db: AsyncSession = Depends(get_db),
):
    """Update a vector collection policy."""
    result = await db.execute(
        select(VectorCollectionPolicy).where(
            VectorCollectionPolicy.id == collection_id
        )
    )
    policy = result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(status_code=404, detail="Vector collection policy not found")

    if body.default_action is not None:
        valid_actions = {"deny", "allow", "monitor"}
        if body.default_action not in valid_actions:
            raise HTTPException(status_code=400, detail=f"Invalid default_action. Must be one of: {valid_actions}")
        policy.default_action = body.default_action

    if body.allowed_operations is not None:
        valid_ops = {"query", "insert", "update", "delete"}
        for op in body.allowed_operations:
            if op not in valid_ops:
                raise HTTPException(status_code=400, detail=f"Invalid operation '{op}'.")
        policy.allowed_operations = body.allowed_operations

    if body.sensitive_fields is not None:
        policy.sensitive_fields = body.sensitive_fields
    if body.namespace_field is not None:
        policy.namespace_field = body.namespace_field
    if body.max_results is not None:
        if body.max_results < 1 or body.max_results > 100:
            raise HTTPException(status_code=400, detail="max_results must be between 1 and 100")
        policy.max_results = body.max_results
    if body.is_active is not None:
        policy.is_active = body.is_active
    # Sprint 9 fields
    if body.block_sensitive_documents is not None:
        policy.block_sensitive_documents = body.block_sensitive_documents
    if body.sensitive_field_patterns is not None:
        policy.sensitive_field_patterns = body.sensitive_field_patterns
    if body.anomaly_distance_threshold is not None:
        policy.anomaly_distance_threshold = body.anomaly_distance_threshold
    if body.scan_chunks_for_injection is not None:
        policy.scan_chunks_for_injection = body.scan_chunks_for_injection
    if body.max_tokens_per_chunk is not None:
        policy.max_tokens_per_chunk = body.max_tokens_per_chunk

    await db.commit()
    await db.refresh(policy)

    # Update in-memory proxy
    _sync_policy_to_proxy(policy)

    return _vector_collection_to_info(policy)


@router.delete("/vector-collections/{collection_id}")
async def delete_vector_collection(
    collection_id: uuid.UUID, db: AsyncSession = Depends(get_db)
):
    """Delete a vector collection policy."""
    result = await db.execute(
        select(VectorCollectionPolicy).where(
            VectorCollectionPolicy.id == collection_id
        )
    )
    policy = result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(status_code=404, detail="Vector collection policy not found")

    # Remove from in-memory proxy
    proxy = get_vectordb_proxy()
    proxy.remove_policy(policy.collection_name)

    await db.delete(policy)
    await db.commit()
    return {"status": "deleted", "collection_id": str(collection_id)}


class VectorDBProxyTestRequest(BaseModel):
    collection_name: str
    operation: str = "query"
    tenant_id: str = "test-tenant"
    top_k: int = 10
    filters: dict = {}


@router.post("/vector-proxy/test")
async def vector_proxy_test(body: VectorDBProxyTestRequest):
    """Test the vector DB proxy enforcement against a sample request."""
    try:
        op = VectorOperation(body.operation)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid operation. Must be one of: query, insert, update, delete",
        )

    proxy = get_vectordb_proxy()
    request = ProxyRequest(
        collection_name=body.collection_name,
        operation=op,
        tenant_id=body.tenant_id,
        top_k=body.top_k,
        filters=body.filters,
    )
    result = proxy.process(request)
    return result.to_dict()


@router.get("/vector-proxy/status")
async def vector_proxy_status():
    """Get vector DB proxy status and statistics."""
    proxy = get_vectordb_proxy()
    policies = proxy.list_policies()
    return {
        "stats": proxy.get_stats(),
        "registered_collections": len(policies),
        "collections": [
            {
                "collection_name": p.collection_name,
                "provider": p.provider.value if isinstance(p.provider, VectorDBProvider) else p.provider,
                "default_action": p.default_action.value if isinstance(p.default_action, ProxyAction) else p.default_action,
                "is_active": p.is_active,
            }
            for p in policies
        ],
    }


def _vector_collection_to_info(policy: VectorCollectionPolicy) -> VectorCollectionInfo:
    return VectorCollectionInfo(
        id=str(policy.id),
        collection_name=policy.collection_name,
        provider=policy.provider,
        default_action=policy.default_action,
        allowed_operations=policy.allowed_operations or [],
        sensitive_fields=policy.sensitive_fields or [],
        namespace_field=policy.namespace_field,
        max_results=policy.max_results,
        is_active=policy.is_active,
        tenant_id=policy.tenant_id,
        created_at=policy.created_at,
        block_sensitive_documents=policy.block_sensitive_documents,
        sensitive_field_patterns=policy.sensitive_field_patterns or [],
        anomaly_distance_threshold=policy.anomaly_distance_threshold,
        scan_chunks_for_injection=policy.scan_chunks_for_injection,
        max_tokens_per_chunk=policy.max_tokens_per_chunk,
    )


def _sync_policy_to_proxy(db_policy: VectorCollectionPolicy) -> None:
    """Sync a DB policy record to the in-memory vector DB proxy."""
    proxy = get_vectordb_proxy()
    try:
        provider = VectorDBProvider(db_policy.provider)
    except ValueError:
        provider = VectorDBProvider.CHROMADB

    try:
        default_action = ProxyAction(db_policy.default_action)
    except ValueError:
        default_action = ProxyAction.DENY

    ops = []
    for op_str in (db_policy.allowed_operations or []):
        try:
            ops.append(VectorOperation(op_str))
        except ValueError:
            pass

    policy = CollectionPolicy(
        collection_name=db_policy.collection_name,
        provider=provider,
        default_action=default_action,
        allowed_operations=ops,
        sensitive_fields=db_policy.sensitive_fields or [],
        namespace_field=db_policy.namespace_field,
        max_results=db_policy.max_results,
        is_active=db_policy.is_active,
        tenant_id=db_policy.tenant_id,
        scan_chunks_for_injection=db_policy.scan_chunks_for_injection,
        block_sensitive_documents=db_policy.block_sensitive_documents,
        sensitive_field_patterns=db_policy.sensitive_field_patterns or [],
        anomaly_distance_threshold=db_policy.anomaly_distance_threshold,
        max_tokens_per_chunk=db_policy.max_tokens_per_chunk,
    )
    proxy.register_policy(policy)


# ── Sprint 9: Incident Endpoints ─────────────────────────────────────────


class IncidentInfo(BaseModel):
    id: str
    incident_type: str
    tenant_id: str
    collection_name: str
    chunk_content_hash: str
    chunk_id: str
    matched_patterns: str
    risk_level: str
    score: float
    action_taken: str
    metadata_json: str
    created_at: Optional[datetime]


@router.get("/incidents", response_model=list[IncidentInfo])
async def list_incidents(
    tenant_id: Optional[str] = None,
    collection_name: Optional[str] = None,
    incident_type: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """List recorded incidents (indirect injection, sensitive field blocks, anomalies)."""
    query = select(Incident).order_by(Incident.created_at.desc()).limit(min(limit, 200))
    if tenant_id:
        query = query.where(Incident.tenant_id == tenant_id)
    if collection_name:
        query = query.where(Incident.collection_name == collection_name)
    if incident_type:
        query = query.where(Incident.incident_type == incident_type)

    result = await db.execute(query)
    incidents = result.scalars().all()
    return [
        IncidentInfo(
            id=str(i.id),
            incident_type=i.incident_type,
            tenant_id=i.tenant_id,
            collection_name=i.collection_name,
            chunk_content_hash=i.chunk_content_hash,
            chunk_id=i.chunk_id,
            matched_patterns=i.matched_patterns,
            risk_level=i.risk_level,
            score=i.score,
            action_taken=i.action_taken,
            metadata_json=i.metadata_json,
            created_at=i.created_at,
        )
        for i in incidents
    ]


@router.get("/incidents/{incident_id}", response_model=IncidentInfo)
async def get_incident(incident_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Get a specific incident by ID."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return IncidentInfo(
        id=str(incident.id),
        incident_type=incident.incident_type,
        tenant_id=incident.tenant_id,
        collection_name=incident.collection_name,
        chunk_content_hash=incident.chunk_content_hash,
        chunk_id=incident.chunk_id,
        matched_patterns=incident.matched_patterns,
        risk_level=incident.risk_level,
        score=incident.score,
        action_taken=incident.action_taken,
        metadata_json=incident.metadata_json,
        created_at=incident.created_at,
    )


@router.get("/chunk-scan/status")
async def chunk_scan_status():
    """Get chunk scanner status and recent incident summary."""
    from app.services.vectordb.chunk_scanner import get_chunk_scanner, get_incident_logger

    scanner = get_chunk_scanner()
    incident_logger = get_incident_logger()
    pending = incident_logger.get_pending()
    return {
        "scanner_active": True,
        "pending_incidents": len(pending),
    }


# ── Sprint 10: Collection Audit Log Endpoints ──────────────────────────


@router.get("/collection-audit")
async def list_collection_audit_entries(
    collection_name: Optional[str] = None,
    tenant_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
):
    """List collection-level audit log entries."""
    from app.services.vectordb.collection_audit import get_collection_audit_log

    audit_log = get_collection_audit_log()
    entries = audit_log.get_entries(
        collection_name=collection_name,
        tenant_id=tenant_id,
        limit=min(limit, 200),
        offset=offset,
    )
    return [e.to_dict() for e in entries]


@router.get("/collection-audit/stats")
async def collection_audit_stats(collection_name: Optional[str] = None):
    """Get aggregated collection audit statistics."""
    from app.services.vectordb.collection_audit import get_collection_audit_log

    audit_log = get_collection_audit_log()
    stats = audit_log.get_collection_stats(collection_name)
    return {
        "total_buffered": audit_log.buffer_size,
        "total_entries": audit_log.total_entries,
        "collections": stats,
    }


@router.get("/collection-audit/tenant-stats/{collection_name}")
async def collection_tenant_stats(collection_name: str):
    """Get per-tenant query volume for a collection."""
    from app.services.vectordb.collection_audit import get_collection_audit_log

    audit_log = get_collection_audit_log()
    return audit_log.get_tenant_stats(collection_name)


@router.get("/collection-audit/anomaly-timeline")
async def collection_anomaly_timeline(
    collection_name: Optional[str] = None,
    limit: int = 100,
):
    """Get timeline of anomaly events across collections."""
    from app.services.vectordb.collection_audit import get_collection_audit_log

    audit_log = get_collection_audit_log()
    return audit_log.get_anomaly_timeline(collection_name, limit=min(limit, 500))


# ── Sprint 10: Vector DB Dashboard Endpoint ────────────────────────────


@router.get("/vectordb-dashboard")
async def vectordb_dashboard(db: AsyncSession = Depends(get_db)):
    """Dashboard data: collection policy health, query volume, blocked counts, anomaly timeline."""
    from app.services.vectordb.collection_audit import get_collection_audit_log
    from app.services.vectordb.proxy import get_vectordb_proxy

    proxy = get_vectordb_proxy()
    audit_log = get_collection_audit_log()

    # Proxy stats
    proxy_stats = proxy.get_stats()
    policies = proxy.list_policies()

    # Collection policy health
    collection_health = []
    for p in policies:
        provider_val = p.provider.value if isinstance(p.provider, VectorDBProvider) else str(p.provider)
        action_val = p.default_action.value if isinstance(p.default_action, ProxyAction) else str(p.default_action)
        cstats = audit_log.get_collection_stats(p.collection_name)
        cs = cstats.get(p.collection_name, {})
        collection_health.append({
            "collection_name": p.collection_name,
            "provider": provider_val,
            "default_action": action_val,
            "is_active": p.is_active,
            "total_queries": cs.get("total_queries", 0),
            "total_blocked": cs.get("total_blocked", 0),
            "total_chunks_returned": cs.get("total_chunks_returned", 0),
            "total_chunks_blocked": cs.get("total_chunks_blocked", 0),
            "total_anomalies": cs.get("total_anomalies", 0),
            "total_injection_blocks": cs.get("total_injection_blocks", 0),
            "avg_latency_ms": round(cs.get("avg_latency_ms", 0.0), 2),
            "unique_tenants": cs.get("unique_tenants", 0),
        })

    # Anomaly timeline (last 50)
    anomaly_timeline = audit_log.get_anomaly_timeline(limit=50)

    # Overall summary
    all_stats = audit_log.get_collection_stats()
    total_queries = sum(s.get("total_queries", 0) for s in all_stats.values())
    total_blocked = sum(s.get("total_blocked", 0) for s in all_stats.values())
    total_anomalies = sum(s.get("total_anomalies", 0) for s in all_stats.values())

    return {
        "proxy_stats": proxy_stats,
        "registered_collections": len(policies),
        "collection_health": collection_health,
        "anomaly_timeline": anomaly_timeline,
        "summary": {
            "total_queries": total_queries,
            "total_blocked": total_blocked,
            "total_anomalies": total_anomalies,
            "audit_buffer_size": audit_log.buffer_size,
        },
    }


# ── Sprint 10: Milvus Proxy Status Endpoint ───────────────────────────


@router.get("/milvus-proxy/status")
async def milvus_proxy_status():
    """Get Milvus gRPC proxy status and health."""
    from app.services.vectordb.milvus_proxy import get_milvus_proxy

    proxy = get_milvus_proxy()
    return {
        "stats": proxy.stats,
        "health": proxy.health_check(),
    }


# ── Sprint 10: Compliance Tagging Status ───────────────────────────────


@router.get("/compliance-tagger/status")
async def compliance_tagger_status():
    """Get compliance tagger configuration status."""
    from app.services.vectordb.compliance_tagger import get_compliance_tagger

    tagger = get_compliance_tagger()
    return {
        "active": True,
        "scan_content": tagger._policy.scan_content,
        "scan_metadata": tagger._policy.scan_metadata,
        "pii_patterns": len(tagger._policy.pii_content_patterns),
        "phi_patterns": len(tagger._policy.phi_content_patterns),
        "ip_patterns": len(tagger._policy.ip_content_patterns),
    }


# ── Sprint 11: Routing Rules & Budget Tiers ────────────────────────────


class CreateRoutingRuleRequest(BaseModel):
    name: str
    description: str = ""
    priority: int = 100
    condition_type: str = "sensitivity"
    condition_json: str = "{}"
    target_model: str = ""
    target_provider: str = ""
    action: str = "route"
    tenant_id: str = "*"
    is_active: bool = True


class UpdateRoutingRuleRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[int] = None
    condition_type: Optional[str] = None
    condition_json: Optional[str] = None
    target_model: Optional[str] = None
    target_provider: Optional[str] = None
    action: Optional[str] = None
    tenant_id: Optional[str] = None
    is_active: Optional[bool] = None


@router.get("/routing-rules")
async def list_routing_rules(db: AsyncSession = Depends(get_db)):
    """List all routing rules ordered by priority."""
    result = await db.execute(
        select(RoutingRule).order_by(RoutingRule.priority, RoutingRule.created_at)
    )
    rules = result.scalars().all()
    return {
        "rules": [
            {
                "id": str(r.id),
                "name": r.name,
                "description": r.description,
                "priority": r.priority,
                "condition_type": r.condition_type,
                "condition_json": r.condition_json,
                "target_model": r.target_model,
                "target_provider": r.target_provider,
                "action": r.action,
                "tenant_id": r.tenant_id,
                "is_active": r.is_active,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            }
            for r in rules
        ],
        "total": len(rules),
    }


@router.post("/routing-rules", status_code=201)
async def create_routing_rule(
    req: CreateRoutingRuleRequest, db: AsyncSession = Depends(get_db)
):
    """Create a new routing rule."""
    # Validate condition JSON
    try:
        json.loads(req.condition_json)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid condition_json")

    rule = RoutingRule(
        name=req.name,
        description=req.description,
        priority=req.priority,
        condition_type=req.condition_type,
        condition_json=req.condition_json,
        target_model=req.target_model,
        target_provider=req.target_provider,
        action=req.action,
        tenant_id=req.tenant_id,
        is_active=req.is_active,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    # Reload rules into the evaluator
    await _reload_routing_rules(db)

    return {
        "id": str(rule.id),
        "name": rule.name,
        "priority": rule.priority,
        "action": rule.action,
        "target_model": rule.target_model,
        "created": True,
    }


@router.put("/routing-rules/{rule_id}")
async def update_routing_rule(
    rule_id: str, req: UpdateRoutingRuleRequest, db: AsyncSession = Depends(get_db)
):
    """Update an existing routing rule."""
    result = await db.execute(
        select(RoutingRule).where(RoutingRule.id == uuid.UUID(rule_id))
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Routing rule not found")

    for field_name, value in req.model_dump(exclude_unset=True).items():
        if field_name == "condition_json" and value is not None:
            try:
                json.loads(value)
            except (json.JSONDecodeError, TypeError):
                raise HTTPException(status_code=400, detail="Invalid condition_json")
        setattr(rule, field_name, value)

    await db.commit()
    await db.refresh(rule)
    await _reload_routing_rules(db)

    return {"id": str(rule.id), "name": rule.name, "updated": True}


@router.delete("/routing-rules/{rule_id}")
async def delete_routing_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a routing rule."""
    result = await db.execute(
        select(RoutingRule).where(RoutingRule.id == uuid.UUID(rule_id))
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Routing rule not found")

    await db.delete(rule)
    await db.commit()
    await _reload_routing_rules(db)

    return {"id": rule_id, "deleted": True}


class CreateBudgetTierRequest(BaseModel):
    model_name: str
    tier_name: str = "standard"
    token_budget: int = 1000000
    downgrade_model: str = ""
    budget_window_seconds: int = 3600
    tenant_id: str = "*"
    is_active: bool = True


@router.get("/budget-tiers")
async def list_budget_tiers(db: AsyncSession = Depends(get_db)):
    """List all budget tier configurations."""
    result = await db.execute(
        select(BudgetTier).order_by(BudgetTier.model_name, BudgetTier.tier_name)
    )
    tiers = result.scalars().all()
    return {
        "tiers": [
            {
                "id": str(t.id),
                "model_name": t.model_name,
                "tier_name": t.tier_name,
                "token_budget": t.token_budget,
                "downgrade_model": t.downgrade_model,
                "budget_window_seconds": t.budget_window_seconds,
                "tenant_id": t.tenant_id,
                "is_active": t.is_active,
                "created_at": t.created_at.isoformat() if t.created_at else None,
            }
            for t in tiers
        ],
        "total": len(tiers),
    }


@router.post("/budget-tiers", status_code=201)
async def create_budget_tier(
    req: CreateBudgetTierRequest, db: AsyncSession = Depends(get_db)
):
    """Create a new budget tier configuration."""
    tier = BudgetTier(
        model_name=req.model_name,
        tier_name=req.tier_name,
        token_budget=req.token_budget,
        downgrade_model=req.downgrade_model,
        budget_window_seconds=req.budget_window_seconds,
        tenant_id=req.tenant_id,
        is_active=req.is_active,
    )
    db.add(tier)
    await db.commit()
    await db.refresh(tier)
    await _reload_budget_tiers(db)

    return {
        "id": str(tier.id),
        "model_name": tier.model_name,
        "tier_name": tier.tier_name,
        "downgrade_model": tier.downgrade_model,
        "created": True,
    }


@router.delete("/budget-tiers/{tier_id}")
async def delete_budget_tier(tier_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a budget tier configuration."""
    result = await db.execute(
        select(BudgetTier).where(BudgetTier.id == uuid.UUID(tier_id))
    )
    tier = result.scalar_one_or_none()
    if not tier:
        raise HTTPException(status_code=404, detail="Budget tier not found")

    await db.delete(tier)
    await db.commit()
    await _reload_budget_tiers(db)

    return {"id": tier_id, "deleted": True}


@router.get("/routing-policy/status")
async def routing_policy_status():
    """Get current routing policy evaluator status."""
    from app.services.routing_policy import get_routing_policy_evaluator
    from app.services.budget_downgrade import get_budget_downgrade_service

    evaluator = get_routing_policy_evaluator()
    budget_svc = get_budget_downgrade_service()

    return {
        "routing_rules_loaded": len(evaluator._rules),
        "budget_tiers_loaded": sum(len(v) for v in budget_svc._tiers.values()),
        "private_model": evaluator._private_model,
        "private_provider": evaluator._private_provider,
        "public_model": evaluator._public_model,
        "public_provider": evaluator._public_provider,
    }


async def _reload_routing_rules(db: AsyncSession) -> None:
    """Reload routing rules from DB into the evaluator."""
    from app.services.routing_policy import get_routing_policy_evaluator

    result = await db.execute(
        select(RoutingRule).where(RoutingRule.is_active == True).order_by(RoutingRule.priority)
    )
    rules = result.scalars().all()
    evaluator = get_routing_policy_evaluator()
    evaluator.load_rules([
        {
            "id": str(r.id),
            "name": r.name,
            "priority": r.priority,
            "condition_type": r.condition_type,
            "condition_json": r.condition_json,
            "target_model": r.target_model,
            "target_provider": r.target_provider,
            "action": r.action,
            "tenant_id": r.tenant_id,
            "is_active": r.is_active,
        }
        for r in rules
    ])


async def _reload_budget_tiers(db: AsyncSession) -> None:
    """Reload budget tiers from DB into the downgrade service."""
    from app.services.budget_downgrade import get_budget_downgrade_service

    result = await db.execute(
        select(BudgetTier).where(BudgetTier.is_active == True)
    )
    tiers = result.scalars().all()
    svc = get_budget_downgrade_service()
    svc.load_tiers([
        {
            "model_name": t.model_name,
            "tier_name": t.tier_name,
            "token_budget": t.token_budget,
            "downgrade_model": t.downgrade_model,
            "budget_window_seconds": t.budget_window_seconds,
            "tenant_id": t.tenant_id,
        }
        for t in tiers
    ])


# ── Sprint 13: Provider Health Monitoring & Failover ─────────────────────


# -- Provider Health Probe endpoints --

@router.get("/provider-health")
async def get_provider_health(
    provider_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Get latest health status for providers."""
    from app.services.health_probe import get_provider_health_status
    statuses = await get_provider_health_status(db, provider_name)
    return {"provider_health": statuses}


@router.post("/provider-health/probe")
async def trigger_health_probe(db: AsyncSession = Depends(get_db)):
    """Manually trigger a health probe cycle."""
    from app.services.health_probe import get_health_probe
    probe = get_health_probe()
    results = await probe.run_probe_cycle()
    return {"results": results}


# -- Circuit Breaker endpoints --

class CircuitBreakerForceRequest(BaseModel):
    provider_name: str
    state: str  # closed, open, half_open


@router.get("/circuit-breakers")
async def list_circuit_breakers(db: AsyncSession = Depends(get_db)):
    """Get all circuit breaker states."""
    from app.services.circuit_breaker import get_all_circuit_breaker_states
    states = await get_all_circuit_breaker_states(db)
    return {"circuit_breakers": states}


@router.get("/circuit-breakers/{provider_name}")
async def get_circuit_breaker_state(provider_name: str, db: AsyncSession = Depends(get_db)):
    """Get circuit breaker state for a specific provider."""
    from app.services.circuit_breaker import get_circuit_breaker
    cb = get_circuit_breaker(provider_name)
    state = await cb.get_state(db)
    return state


@router.post("/circuit-breakers/force")
async def force_circuit_breaker(body: CircuitBreakerForceRequest, db: AsyncSession = Depends(get_db)):
    """Manually force a circuit breaker state (admin override)."""
    if body.state not in ("closed", "open", "half_open"):
        raise HTTPException(status_code=400, detail="state must be closed, open, or half_open")
    from app.services.circuit_breaker import get_circuit_breaker
    cb = get_circuit_breaker(body.provider_name)
    state = await cb.force_state(db, body.state)
    return state


# -- Failover Policy endpoints --

class FailoverPolicyRequest(BaseModel):
    provider_name: str
    error_rate_threshold: float = 0.5
    latency_threshold_ms: float = 5000.0
    evaluation_window_seconds: int = 60
    fallback_provider: str = ""
    auto_failover: bool = True
    require_confirmation: bool = False
    is_active: bool = True


class FailoverPolicyUpdateRequest(BaseModel):
    error_rate_threshold: Optional[float] = None
    latency_threshold_ms: Optional[float] = None
    evaluation_window_seconds: Optional[int] = None
    fallback_provider: Optional[str] = None
    auto_failover: Optional[bool] = None
    require_confirmation: Optional[bool] = None
    is_active: Optional[bool] = None


@router.get("/failover-policies")
async def list_failover_policies_endpoint(db: AsyncSession = Depends(get_db)):
    """List all failover policies."""
    from app.services.failover_policy import list_failover_policies
    policies = await list_failover_policies(db)
    return {"failover_policies": policies}


@router.get("/failover-policies/{provider_name}")
async def get_failover_policy_endpoint(provider_name: str, db: AsyncSession = Depends(get_db)):
    """Get failover policy for a specific provider."""
    from app.services.failover_policy import get_failover_policy
    policy = await get_failover_policy(db, provider_name)
    if policy is None:
        raise HTTPException(status_code=404, detail="Failover policy not found")
    return policy


@router.post("/failover-policies", status_code=201)
async def create_failover_policy_endpoint(body: FailoverPolicyRequest, db: AsyncSession = Depends(get_db)):
    """Create a new failover policy."""
    from app.services.failover_policy import create_failover_policy
    policy = await create_failover_policy(
        db,
        provider_name=body.provider_name,
        error_rate_threshold=body.error_rate_threshold,
        latency_threshold_ms=body.latency_threshold_ms,
        evaluation_window_seconds=body.evaluation_window_seconds,
        fallback_provider=body.fallback_provider,
        auto_failover=body.auto_failover,
        require_confirmation=body.require_confirmation,
        is_active=body.is_active,
    )
    return policy


@router.put("/failover-policies/{provider_name}")
async def update_failover_policy_endpoint(
    provider_name: str, body: FailoverPolicyUpdateRequest, db: AsyncSession = Depends(get_db)
):
    """Update a failover policy."""
    from app.services.failover_policy import update_failover_policy
    policy = await update_failover_policy(db, provider_name, **body.model_dump(exclude_none=True))
    if policy is None:
        raise HTTPException(status_code=404, detail="Failover policy not found")
    return policy


@router.delete("/failover-policies/{provider_name}")
async def delete_failover_policy_endpoint(provider_name: str, db: AsyncSession = Depends(get_db)):
    """Delete a failover policy."""
    from app.services.failover_policy import delete_failover_policy
    ok = await delete_failover_policy(db, provider_name)
    if not ok:
        raise HTTPException(status_code=404, detail="Failover policy not found")
    return {"status": "deleted", "provider_name": provider_name}


@router.post("/failover-policies/evaluate")
async def evaluate_failover_policies(db: AsyncSession = Depends(get_db)):
    """Manually trigger failover policy evaluation."""
    from app.services.failover_policy import get_failover_engine
    engine = get_failover_engine()
    actions = await engine.evaluate_all()
    return {"actions": actions}


@router.post("/failover-policies/confirm/{confirmation_id}")
async def confirm_failover(confirmation_id: str, db: AsyncSession = Depends(get_db)):
    """Confirm a pending failover action."""
    from app.services.failover_policy import get_failover_engine
    engine = get_failover_engine()
    result = await engine.confirm_failover(db, confirmation_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Confirmation not found or expired")
    return result


# -- Cost Tracking endpoints --

@router.get("/provider-costs")
async def get_provider_costs(
    provider_name: Optional[str] = None,
    tenant_id: Optional[str] = None,
    hours: int = 24,
    db: AsyncSession = Depends(get_db),
):
    """Get cost summary per provider per tenant."""
    from app.services.cost_tracker import get_cost_summary
    summary = await get_cost_summary(db, provider_name, tenant_id, hours)
    return {"cost_summary": summary}


@router.get("/provider-costs/totals")
async def get_provider_cost_totals_endpoint(
    hours: int = 24,
    db: AsyncSession = Depends(get_db),
):
    """Get cost totals per provider (no tenant breakdown)."""
    from app.services.cost_tracker import get_provider_cost_totals
    totals = await get_provider_cost_totals(db, hours)
    return {"cost_totals": totals}


@router.get("/provider-costs/realtime/{provider_name}/{tenant_id}")
async def get_realtime_cost_endpoint(provider_name: str, tenant_id: str):
    """Get real-time cost from Redis counters."""
    from app.services.cost_tracker import get_realtime_cost
    data = await get_realtime_cost(provider_name, tenant_id)
    if data is None:
        return {"message": "No real-time data available"}
    return data


# -- Multi-Model Dashboard endpoint --

@router.get("/multi-model-dashboard")
async def multi_model_dashboard(db: AsyncSession = Depends(get_db)):
    """Aggregated dashboard: model registry, health, costs, kill-switches, routing."""
    from app.services.health_probe import get_provider_health_status
    from app.services.circuit_breaker import get_all_circuit_breaker_states
    from app.services.cost_tracker import get_provider_cost_totals
    from app.services.providers.registry import MODEL_PROVIDER_MAP

    health = await get_provider_health_status(db)
    cb_states = await get_all_circuit_breaker_states(db)
    costs = await get_provider_cost_totals(db, hours=24)
    kill_switches = await list_kill_switches(db)

    # Build model registry
    model_registry = {}
    for model, provider in MODEL_PROVIDER_MAP.items():
        if provider not in model_registry:
            model_registry[provider] = []
        model_registry[provider].append(model)

    # Get routing rules summary
    result = await db.execute(
        select(RoutingRule).where(RoutingRule.is_active == True).order_by(RoutingRule.priority)
    )
    routing_rules = result.scalars().all()
    routing_summary = [
        {
            "name": r.name,
            "priority": r.priority,
            "condition_type": r.condition_type,
            "target_model": r.target_model,
            "action": r.action,
        }
        for r in routing_rules
    ]

    return {
        "model_registry": model_registry,
        "provider_health": health,
        "circuit_breakers": cb_states,
        "cost_totals_24h": costs,
        "active_kill_switches": [ks for ks in kill_switches if ks.get("is_active")],
        "routing_rules": routing_summary,
    }


# ── Sprint 15: MCP Server Discovery & Risk Scoring ──────────────────────


class RegisterMCPServerRequest(BaseModel):
    server_name: str
    url: str
    protocol_version: str = "1.0"
    agent_id: str = ""


class DiscoverMCPServerRequest(BaseModel):
    server_name: str
    url: str
    agent_id: str = ""
    protocol_version: str = "1.0"


@router.post("/mcp/servers")
async def register_mcp_server(body: RegisterMCPServerRequest):
    """Register a new MCP server manually."""
    from app.services.mcp.discovery import get_mcp_discovery_service

    svc = get_mcp_discovery_service()
    record = svc.register_server_manual(
        server_name=body.server_name,
        url=body.url,
        protocol_version=body.protocol_version,
        agent_id=body.agent_id,
    )
    return record


@router.get("/mcp/servers")
async def list_mcp_servers():
    """List all registered MCP servers."""
    from app.services.mcp.discovery import get_mcp_discovery_service

    svc = get_mcp_discovery_service()
    return svc.list_servers()


@router.get("/mcp/servers/{server_name}")
async def get_mcp_server(server_name: str):
    """Get a specific MCP server by name."""
    from app.services.mcp.discovery import get_mcp_discovery_service

    svc = get_mcp_discovery_service()
    server = svc.get_server(server_name)
    if not server:
        raise HTTPException(status_code=404, detail="MCP server not found")
    return server


@router.get("/mcp/servers/{server_name}/capabilities")
async def get_mcp_server_capabilities(server_name: str):
    """Get scored capabilities for an MCP server."""
    from app.services.mcp.discovery import get_mcp_discovery_service

    svc = get_mcp_discovery_service()
    server = svc.get_server(server_name)
    if not server:
        raise HTTPException(status_code=404, detail="MCP server not found")
    return svc.get_capabilities(server_name)


@router.post("/mcp/servers/{server_name}/review")
async def mark_mcp_server_reviewed(server_name: str):
    """Mark an MCP server as reviewed by admin."""
    from app.services.mcp.discovery import get_mcp_discovery_service

    svc = get_mcp_discovery_service()
    if not svc.mark_reviewed(server_name):
        raise HTTPException(status_code=404, detail="MCP server not found")
    return {"status": "reviewed", "server_name": server_name}


@router.post("/mcp/servers/{server_name}/connect")
async def connect_agent_to_mcp(server_name: str, agent_id: str):
    """Record an agent connecting to an MCP server."""
    from app.services.mcp.discovery import get_mcp_discovery_service

    svc = get_mcp_discovery_service()
    if not svc.connect_agent(server_name, agent_id):
        raise HTTPException(status_code=404, detail="MCP server not found")
    return {"status": "connected", "server_name": server_name, "agent_id": agent_id}


@router.post("/mcp/discover")
async def discover_mcp_server(body: DiscoverMCPServerRequest):
    """Trigger capability discovery for an MCP server.

    Introspects the MCP server, discovers tools, scores risk, and generates alerts.
    """
    from app.services.mcp.discovery import get_mcp_discovery_service

    svc = get_mcp_discovery_service()
    result = await svc.discover_server(
        server_name=body.server_name,
        url=body.url,
        agent_id=body.agent_id,
        protocol_version=body.protocol_version,
    )
    if not result.success:
        raise HTTPException(status_code=502, detail=f"Discovery failed: {result.error}")

    return {
        "server_name": result.server_name,
        "url": result.url,
        "protocol_version": result.protocol_version,
        "tools_discovered": len(result.tools),
        "tools": [t.to_dict() for t in result.tools],
    }


@router.get("/mcp/alerts")
async def list_mcp_alerts(unacknowledged_only: bool = False):
    """List MCP risk alerts."""
    from app.services.mcp.discovery import get_mcp_discovery_service

    svc = get_mcp_discovery_service()
    return svc.list_alerts(unacknowledged_only=unacknowledged_only)


@router.post("/mcp/alerts/{alert_id}/acknowledge")
async def acknowledge_mcp_alert(alert_id: str, acknowledged_by: str = "admin"):
    """Acknowledge an MCP risk alert."""
    from app.services.mcp.discovery import get_mcp_discovery_service

    svc = get_mcp_discovery_service()
    if not svc.acknowledge_alert(alert_id, acknowledged_by=acknowledged_by):
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "acknowledged", "alert_id": alert_id}


# ── Sprint 16: Per-Agent Scope Enforcement ───────────────────────────────


class CreateAgentAccountRequest(BaseModel):
    agent_id: str
    display_name: str = ""
    description: str = ""
    allowed_mcp_servers: list[str] = []
    allowed_tools: list[str] = []
    context_scope: list[str] = []
    redact_fields: list[str] = []


class UpdateAgentAccountRequest(BaseModel):
    display_name: Optional[str] = None
    description: Optional[str] = None
    allowed_mcp_servers: Optional[list[str]] = None
    allowed_tools: Optional[list[str]] = None
    context_scope: Optional[list[str]] = None
    redact_fields: Optional[list[str]] = None
    is_active: Optional[bool] = None


class ToolCallValidationRequest(BaseModel):
    agent_id: str
    tool_name: str
    mcp_server: str = ""


@router.post("/agents")
async def create_agent_account(body: CreateAgentAccountRequest):
    """Create a new agent service account."""
    from app.services.mcp.agent_scope import get_agent_scope_service

    svc = get_agent_scope_service()
    try:
        account = svc.create_account(
            agent_id=body.agent_id,
            display_name=body.display_name,
            description=body.description,
            allowed_mcp_servers=body.allowed_mcp_servers,
            allowed_tools=body.allowed_tools,
            context_scope=body.context_scope,
            redact_fields=body.redact_fields,
        )
        return account.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.get("/agents")
async def list_agent_accounts():
    """List all agent service accounts."""
    from app.services.mcp.agent_scope import get_agent_scope_service

    svc = get_agent_scope_service()
    return [a.to_dict() for a in svc.list_accounts()]


@router.get("/agents/{agent_id}")
async def get_agent_account(agent_id: str):
    """Get a specific agent service account."""
    from app.services.mcp.agent_scope import get_agent_scope_service

    svc = get_agent_scope_service()
    account = svc.get_account(agent_id)
    if not account:
        raise HTTPException(status_code=404, detail="Agent account not found")
    return account.to_dict()


@router.put("/agents/{agent_id}")
async def update_agent_account(agent_id: str, body: UpdateAgentAccountRequest):
    """Update an agent service account."""
    from app.services.mcp.agent_scope import get_agent_scope_service

    svc = get_agent_scope_service()
    account = svc.update_account(
        agent_id=agent_id,
        display_name=body.display_name,
        description=body.description,
        allowed_mcp_servers=body.allowed_mcp_servers,
        allowed_tools=body.allowed_tools,
        context_scope=body.context_scope,
        redact_fields=body.redact_fields,
        is_active=body.is_active,
    )
    if not account:
        raise HTTPException(status_code=404, detail="Agent account not found")
    return account.to_dict()


@router.delete("/agents/{agent_id}")
async def delete_agent_account(agent_id: str):
    """Delete an agent service account."""
    from app.services.mcp.agent_scope import get_agent_scope_service

    svc = get_agent_scope_service()
    if not svc.delete_account(agent_id):
        raise HTTPException(status_code=404, detail="Agent account not found")
    return {"status": "deleted", "agent_id": agent_id}


@router.post("/agents/validate-tool-call")
async def validate_agent_tool_call(body: ToolCallValidationRequest):
    """Validate whether an agent is allowed to invoke a tool.

    Returns enforcement result: allowed or blocked with reason.
    """
    from app.services.mcp.agent_scope import get_agent_scope_service, ToolCallRequest

    svc = get_agent_scope_service()
    request = ToolCallRequest(
        agent_id=body.agent_id,
        tool_name=body.tool_name,
        mcp_server=body.mcp_server,
    )
    result = svc.enforce_tool_access(request)
    return {
        "allowed": result.allowed,
        "action": result.action,
        "reason": result.reason,
    }


@router.get("/agents/{agent_id}/violations")
async def list_agent_violations(
    agent_id: str,
    violation_type: Optional[str] = None,
    limit: int = 100,
):
    """List scope violations for an agent."""
    from app.services.mcp.agent_scope import get_agent_scope_service

    svc = get_agent_scope_service()
    violations = svc.list_violations(
        agent_id=agent_id,
        violation_type=violation_type,
        limit=limit,
    )
    return [v.to_dict() for v in violations]


@router.get("/agents/{agent_id}/violation-counts")
async def get_agent_violation_counts(agent_id: str):
    """Get violation counts by type for an agent."""
    from app.services.mcp.agent_scope import get_agent_scope_service

    svc = get_agent_scope_service()
    return svc.get_violation_counts(agent_id=agent_id)


# ── Sprint 17: MCP Guardrails Dashboard & Compliance Tagging ────────────


# ── Dashboard Endpoints ──────────────────────────────────────────────────


@router.get("/mcp/dashboard")
async def get_mcp_dashboard():
    """Get live MCP guardrails dashboard snapshot.

    Returns: per-agent connectivity, violation counts (24h),
    kill-switch events, tool call volume, risk scores.
    """
    from app.services.mcp.dashboard import get_guardrail_dashboard_service

    svc = get_guardrail_dashboard_service()
    snapshot = svc.get_snapshot()
    return snapshot.to_dict()


@router.get("/mcp/dashboard/agent/{agent_id}")
async def get_mcp_dashboard_agent_detail(agent_id: str):
    """Get detailed dashboard view for a specific agent."""
    from app.services.mcp.dashboard import get_guardrail_dashboard_service

    svc = get_guardrail_dashboard_service()
    detail = svc.get_agent_detail(agent_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Agent not found")
    return detail


# ── Tool Call Audit Endpoints ────────────────────────────────────────────


class RecordToolCallRequest(BaseModel):
    agent_id: str
    tool_name: str
    mcp_server: str
    input_data: Optional[dict] = None
    output_data: Optional[dict] = None
    action: str = "allowed"
    compliance_tags: list[str] = []
    latency_ms: float = 0.0
    metadata: Optional[dict] = None


@router.post("/mcp/tool-calls/audit")
async def record_tool_call(body: RecordToolCallRequest):
    """Record an MCP tool call in the audit log."""
    from app.services.mcp.tool_call_audit import get_tool_call_audit_service

    svc = get_tool_call_audit_service()
    record = svc.record_call(
        agent_id=body.agent_id,
        tool_name=body.tool_name,
        mcp_server=body.mcp_server,
        input_data=body.input_data,
        output_data=body.output_data,
        action=body.action,
        compliance_tags=body.compliance_tags,
        latency_ms=body.latency_ms,
        metadata=body.metadata,
    )
    return record.to_dict()


@router.get("/mcp/tool-calls/audit")
async def list_tool_call_audits(
    agent_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    mcp_server: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    """Query MCP tool call audit records."""
    from app.services.mcp.tool_call_audit import get_tool_call_audit_service

    svc = get_tool_call_audit_service()
    records = svc.list_records(
        agent_id=agent_id,
        tool_name=tool_name,
        mcp_server=mcp_server,
        action=action,
        limit=limit,
        offset=offset,
    )
    return [r.to_dict() for r in records]


@router.get("/mcp/tool-calls/volume")
async def get_tool_call_volume():
    """Get tool call volume grouped by agent."""
    from app.services.mcp.tool_call_audit import get_tool_call_audit_service

    svc = get_tool_call_audit_service()
    return svc.get_agent_tool_call_volume()


# ── Compliance Tagging Endpoints ─────────────────────────────────────────


class ComplianceScanRequest(BaseModel):
    content: str
    agent_id: str = ""
    tool_name: str = ""
    mcp_server: str = ""


class AddCompliancePatternRequest(BaseModel):
    label: str
    pattern: str


@router.post("/mcp/compliance/scan")
async def scan_for_compliance(body: ComplianceScanRequest):
    """Scan content for compliance tags (PII, PHI, FINANCIAL, etc.)."""
    from app.services.mcp.compliance_tagger import get_compliance_tagging_service

    svc = get_compliance_tagging_service()
    tagged = svc.tag_response(
        content=body.content,
        agent_id=body.agent_id,
        tool_name=body.tool_name,
        mcp_server=body.mcp_server,
    )
    return tagged.to_dict()


@router.post("/mcp/compliance/patterns")
async def add_compliance_pattern(body: AddCompliancePatternRequest):
    """Add a custom compliance detection pattern."""
    import re as re_module
    try:
        re_module.compile(body.pattern)
    except re_module.error as e:
        raise HTTPException(status_code=400, detail=f"Invalid regex pattern: {e}")

    from app.services.mcp.compliance_tagger import get_compliance_tagging_service

    svc = get_compliance_tagging_service()
    svc.add_custom_pattern(body.label, body.pattern)
    return {"status": "added", "label": body.label}


@router.get("/mcp/compliance/labels")
async def list_compliance_labels():
    """List all available compliance labels."""
    from app.services.mcp.compliance_tagger import get_compliance_tagging_service

    svc = get_compliance_tagging_service()
    return {"labels": svc.list_labels()}


# ── Agent Risk Score Endpoints ───────────────────────────────────────────


@router.get("/agents/{agent_id}/risk-score")
async def get_agent_risk_score(agent_id: str):
    """Get the current aggregate risk score for an agent."""
    from app.services.mcp.agent_risk_score import get_agent_risk_score_service

    svc = get_agent_risk_score_service()
    breakdown = svc.compute_risk_score(agent_id)
    return breakdown.to_dict()


@router.get("/agents/risk-scores")
async def get_all_agent_risk_scores():
    """Get risk scores for all agents."""
    from app.services.mcp.agent_risk_score import get_agent_risk_score_service
    from app.services.mcp.agent_scope import get_agent_scope_service

    scope_svc = get_agent_scope_service()
    risk_svc = get_agent_risk_score_service()

    agent_ids = [a.agent_id for a in scope_svc.list_accounts()]
    results = risk_svc.recompute_all(agent_ids)
    return {agent_id: bd.to_dict() for agent_id, bd in results.items()}


# ── Bulk Import Endpoints ────────────────────────────────────────────────


class BulkImportRequest(BaseModel):
    policies: list[dict]
    dry_run: bool = False
    update_existing: bool = True


class BulkImportYAMLRequest(BaseModel):
    yaml_content: str
    dry_run: bool = False
    update_existing: bool = True


@router.post("/agents/bulk-import")
async def bulk_import_agent_policies(body: BulkImportRequest):
    """Bulk import agent scope policies from JSON.

    Accepts a list of agent policy objects. Each must have agent_id
    and may include: display_name, description, allowed_mcp_servers,
    allowed_tools, context_scope, redact_fields.
    """
    from app.services.mcp.bulk_import import get_bulk_import_service

    svc = get_bulk_import_service()
    result = svc.import_policies(
        policies=body.policies,
        dry_run=body.dry_run,
        update_existing=body.update_existing,
    )
    return result.to_dict()


@router.post("/agents/bulk-import/yaml")
async def bulk_import_agent_policies_yaml(body: BulkImportYAMLRequest):
    """Bulk import agent scope policies from YAML content."""
    from app.services.mcp.bulk_import import get_bulk_import_service

    svc = get_bulk_import_service()
    try:
        policies = svc.parse_yaml(body.yaml_content)
    except (ValueError, ImportError) as e:
        raise HTTPException(status_code=400, detail=str(e))

    result = svc.import_policies(
        policies=policies,
        dry_run=body.dry_run,
        update_existing=body.update_existing,
    )
    return result.to_dict()


@router.post("/agents/bulk-import/validate")
async def validate_bulk_import(body: BulkImportRequest):
    """Validate agent scope policies without importing (dry run)."""
    from app.services.mcp.bulk_import import get_bulk_import_service

    svc = get_bulk_import_service()
    result = svc.import_policies(
        policies=body.policies,
        dry_run=True,
        update_existing=body.update_existing,
    )
    return result.to_dict()


# ── Sprint 18: Audit Trail Hardening & Compliance Reports ────────────────


@router.get("/audit/query")
async def query_audit_logs(
    tenant_id: Optional[str] = None,
    model: Optional[str] = None,
    action: Optional[str] = None,
    risk_level: Optional[str] = None,
    policy_version: Optional[str] = None,
    start_timestamp: Optional[float] = None,
    end_timestamp: Optional[float] = None,
    page: int = 1,
    page_size: int = 50,
):
    """Query audit logs with filtering and pagination."""
    from app.services.audit_query import get_audit_query_service, AuditQueryParams

    svc = get_audit_query_service()
    params = AuditQueryParams(
        tenant_id=tenant_id,
        model=model,
        action=action,
        risk_level=risk_level,
        policy_version=policy_version,
        start_timestamp=start_timestamp,
        end_timestamp=end_timestamp,
        page=page,
        page_size=page_size,
    )
    result = await svc.query(params)
    return result.model_dump()


@router.get("/audit/verify-chain")
async def verify_audit_chain(tenant_id: Optional[str] = None, limit: int = 10000):
    """Verify tamper-evident hash chain integrity on audit records."""
    from app.services.audit_hash_chain import get_hash_chain_service

    svc = get_hash_chain_service()
    result = await svc.verify_chain(tenant_id=tenant_id, limit=limit)
    return result


@router.post("/audit/validate-event")
async def validate_audit_event(body: dict):
    """Validate that an audit event has all required Sprint 18 fields."""
    from app.services.audit import AuditEvent

    event = AuditEvent(**body)
    missing = event.validate_required_fields()
    return {
        "valid": len(missing) == 0,
        "missing_fields": missing,
        "event_id": event.event_id,
    }


@router.post("/compliance/gdpr")
async def generate_gdpr_report(
    tenant_id: Optional[str] = None,
    days: int = 30,
    start_timestamp: Optional[float] = None,
    end_timestamp: Optional[float] = None,
):
    """Generate a GDPR compliance report."""
    from app.services.compliance_reports import get_compliance_report_service, ReportRequest

    svc = get_compliance_report_service()
    req = ReportRequest(
        tenant_id=tenant_id,
        days=days,
        start_timestamp=start_timestamp,
        end_timestamp=end_timestamp,
    )
    report = await svc.generate_gdpr_report(req)
    return report.model_dump()


@router.post("/compliance/hipaa")
async def generate_hipaa_report(
    tenant_id: Optional[str] = None,
    days: int = 30,
    start_timestamp: Optional[float] = None,
    end_timestamp: Optional[float] = None,
):
    """Generate a HIPAA compliance report."""
    from app.services.compliance_reports import get_compliance_report_service, ReportRequest

    svc = get_compliance_report_service()
    req = ReportRequest(
        tenant_id=tenant_id,
        days=days,
        start_timestamp=start_timestamp,
        end_timestamp=end_timestamp,
    )
    report = await svc.generate_hipaa_report(req)
    return report.model_dump()


@router.post("/compliance/soc2-pcidss")
async def generate_soc2_pcidss_report(
    tenant_id: Optional[str] = None,
    days: int = 30,
    start_timestamp: Optional[float] = None,
    end_timestamp: Optional[float] = None,
):
    """Generate a SOC 2 / PCI-DSS evidence export report."""
    from app.services.compliance_reports import get_compliance_report_service, ReportRequest

    svc = get_compliance_report_service()
    req = ReportRequest(
        tenant_id=tenant_id,
        days=days,
        start_timestamp=start_timestamp,
        end_timestamp=end_timestamp,
    )
    report = await svc.generate_soc2_pcidss_report(req)
    return report.model_dump()


@router.get("/compliance/evidence-export")
async def export_evidence_zip(
    tenant_id: Optional[str] = None,
    days: int = 30,
    start_timestamp: Optional[float] = None,
    end_timestamp: Optional[float] = None,
):
    """Download a ZIP archive containing GDPR, HIPAA, and SOC 2/PCI-DSS reports."""
    from fastapi.responses import Response
    from app.services.compliance_reports import get_compliance_report_service, ReportRequest

    svc = get_compliance_report_service()
    req = ReportRequest(
        tenant_id=tenant_id,
        days=days,
        start_timestamp=start_timestamp,
        end_timestamp=end_timestamp,
    )
    zip_bytes = await svc.export_evidence_zip(req)
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=compliance_evidence.zip"},
    )


# ── Sprint 19: Enterprise Dashboard & Alerting ──────────────────────────


# ── Security Operations Dashboard ──


@router.get("/dashboard/security-ops")
async def get_security_ops_dashboard(period_hours: int = 24):
    """Get the unified security operations dashboard."""
    from app.services.dashboard.security_ops import get_security_ops_dashboard as get_svc
    svc = get_svc()
    data = await svc.get_dashboard(period_hours=period_hours)
    return data.model_dump()


# ── Policy Coverage Map ──


@router.get("/dashboard/policy-coverage")
async def get_policy_coverage():
    """Get OWASP LLM Top 10 policy coverage map."""
    from app.services.dashboard.policy_coverage import get_policy_coverage_service
    svc = get_policy_coverage_service()
    data = await svc.get_coverage_map()
    return data.model_dump()


# ── Incident Management ──


class CreateIncidentBody(BaseModel):
    incident_type: str
    severity: str = "high"
    title: str = ""
    description: str = ""
    tenant_id: str = ""
    source_event_id: str = ""
    metadata: dict = {}


class UpdateIncidentBody(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None


@router.post("/incidents")
async def create_incident(body: CreateIncidentBody):
    """Create a new security incident."""
    from app.services.dashboard.incident_manager import (
        get_incident_management_service,
        CreateIncidentRequest,
    )
    svc = get_incident_management_service()
    req = CreateIncidentRequest(
        incident_type=body.incident_type,
        severity=body.severity,
        title=body.title,
        description=body.description,
        tenant_id=body.tenant_id,
        source_event_id=body.source_event_id,
        metadata=body.metadata,
    )
    record = await svc.create_incident(req)
    return record.model_dump()


@router.get("/incidents")
async def list_incidents(
    incident_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    tenant_id: Optional[str] = None,
    limit: int = 50,
):
    """List security incidents with optional filters."""
    from app.services.dashboard.incident_manager import get_incident_management_service
    svc = get_incident_management_service()
    records = await svc.list_incidents(
        incident_type=incident_type,
        severity=severity,
        status=status,
        tenant_id=tenant_id,
        limit=limit,
    )
    return [r.model_dump() for r in records]


@router.get("/incidents/stats")
async def get_incident_stats():
    """Get incident statistics."""
    from app.services.dashboard.incident_manager import get_incident_management_service
    svc = get_incident_management_service()
    stats = await svc.get_stats()
    return stats.model_dump()


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Get a specific incident."""
    from app.services.dashboard.incident_manager import get_incident_management_service
    svc = get_incident_management_service()
    record = await svc.get_incident(incident_id)
    if not record:
        raise HTTPException(status_code=404, detail="Incident not found")
    return record.model_dump()


@router.patch("/incidents/{incident_id}")
async def update_incident(incident_id: str, body: UpdateIncidentBody):
    """Update a security incident (status, assignment, resolution)."""
    from app.services.dashboard.incident_manager import (
        get_incident_management_service,
        UpdateIncidentRequest,
    )
    svc = get_incident_management_service()
    req = UpdateIncidentRequest(
        status=body.status,
        assigned_to=body.assigned_to,
        resolution_notes=body.resolution_notes,
    )
    record = await svc.update_incident(incident_id, req)
    if not record:
        raise HTTPException(status_code=404, detail="Incident not found")
    return record.model_dump()


# ── Alert Engine ──


class CreateAlertRuleBody(BaseModel):
    name: str
    description: str = ""
    condition_type: str
    condition_config: dict = {}
    delivery_channel: str = "webhook"
    delivery_target: str = ""
    cooldown_seconds: int = 300
    tenant_id: str = "*"


class UpdateAlertRuleBody(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    condition_type: Optional[str] = None
    condition_config: Optional[dict] = None
    delivery_channel: Optional[str] = None
    delivery_target: Optional[str] = None
    cooldown_seconds: Optional[int] = None
    is_active: Optional[bool] = None
    tenant_id: Optional[str] = None


@router.post("/alerts/rules")
async def create_alert_rule(body: CreateAlertRuleBody):
    """Create a new alert rule."""
    from app.services.dashboard.alert_engine import get_alert_engine_service, AlertRuleConfig
    svc = get_alert_engine_service()
    config = AlertRuleConfig(
        name=body.name,
        description=body.description,
        condition_type=body.condition_type,
        condition_config=body.condition_config,
        delivery_channel=body.delivery_channel,
        delivery_target=body.delivery_target,
        cooldown_seconds=body.cooldown_seconds,
        tenant_id=body.tenant_id,
    )
    return await svc.create_rule(config)


@router.get("/alerts/rules")
async def list_alert_rules(tenant_id: Optional[str] = None):
    """List all alert rules."""
    from app.services.dashboard.alert_engine import get_alert_engine_service
    svc = get_alert_engine_service()
    return await svc.list_rules(tenant_id=tenant_id)


@router.patch("/alerts/rules/{rule_id}")
async def update_alert_rule(rule_id: str, body: UpdateAlertRuleBody):
    """Update an alert rule."""
    from app.services.dashboard.alert_engine import get_alert_engine_service
    svc = get_alert_engine_service()
    updates = body.model_dump(exclude_none=True)
    result = await svc.update_rule(rule_id, updates)
    if not result:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    return result


@router.delete("/alerts/rules/{rule_id}")
async def delete_alert_rule(rule_id: str):
    """Delete an alert rule."""
    from app.services.dashboard.alert_engine import get_alert_engine_service
    svc = get_alert_engine_service()
    success = await svc.delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    return {"status": "deleted", "rule_id": rule_id}


@router.post("/alerts/evaluate")
async def evaluate_alerts():
    """Manually trigger evaluation of all active alert rules."""
    from app.services.dashboard.alert_engine import get_alert_engine_service
    svc = get_alert_engine_service()
    fired = await svc.evaluate_all_rules()
    return {"fired_count": len(fired), "events": [e.model_dump() for e in fired]}


@router.get("/alerts/events")
async def list_alert_events(limit: int = 50, tenant_id: Optional[str] = None):
    """List recent alert events."""
    from app.services.dashboard.alert_engine import get_alert_engine_service
    svc = get_alert_engine_service()
    events = await svc.list_events(limit=limit, tenant_id=tenant_id)
    return [e.model_dump() for e in events]


# ── Tenant Usage Dashboard ──


@router.get("/dashboard/tenant-usage/{tenant_id}")
async def get_tenant_usage(tenant_id: str, period_hours: int = 24):
    """Get per-tenant usage dashboard."""
    from app.services.dashboard.tenant_usage import get_tenant_usage_dashboard
    svc = get_tenant_usage_dashboard()
    data = await svc.get_tenant_usage(tenant_id, period_hours=period_hours)
    return data.model_dump()


@router.get("/dashboard/tenants-summary")
async def list_tenants_summary(period_hours: int = 24, limit: int = 50):
    """List usage summaries for all tenants."""
    from app.services.dashboard.tenant_usage import get_tenant_usage_dashboard
    svc = get_tenant_usage_dashboard()
    results = await svc.list_tenants_summary(period_hours=period_hours, limit=limit)
    return [r.model_dump() for r in results]


# ── Onboarding Wizard ──


@router.get("/onboarding/{tenant_id}")
async def get_onboarding_status(tenant_id: str):
    """Get onboarding wizard status for a tenant."""
    from app.services.dashboard.onboarding_wizard import get_onboarding_wizard_service
    svc = get_onboarding_wizard_service()
    status = await svc.get_status(tenant_id)
    return status.model_dump()


class CompleteStepBody(BaseModel):
    step_key: str


@router.post("/onboarding/{tenant_id}/complete-step")
async def complete_onboarding_step(tenant_id: str, body: CompleteStepBody):
    """Mark an onboarding step as complete."""
    from app.services.dashboard.onboarding_wizard import get_onboarding_wizard_service
    svc = get_onboarding_wizard_service()
    try:
        status = await svc.complete_step(tenant_id, body.step_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return status.model_dump()


@router.post("/onboarding/{tenant_id}/auto-detect")
async def auto_detect_onboarding(tenant_id: str):
    """Auto-detect onboarding progress by checking system state."""
    from app.services.dashboard.onboarding_wizard import get_onboarding_wizard_service
    svc = get_onboarding_wizard_service()
    status = await svc.auto_detect_progress(tenant_id)
    return status.model_dump()


@router.post("/onboarding/{tenant_id}/reset")
async def reset_onboarding(tenant_id: str):
    """Reset onboarding progress for a tenant."""
    from app.services.dashboard.onboarding_wizard import get_onboarding_wizard_service
    svc = get_onboarding_wizard_service()
    status = await svc.reset_progress(tenant_id)
    return status.model_dump()


# ── Sprint 20: Performance Profiling ──


@router.get("/profiling/memory")
async def get_memory_profile():
    """Get memory profiling report."""
    from app.services.performance.profiler import get_memory_profiler
    profiler = get_memory_profiler()
    return profiler.get_report()


@router.post("/profiling/memory/snapshot")
async def take_memory_snapshot():
    """Take a memory snapshot."""
    from app.services.performance.profiler import get_memory_profiler
    profiler = get_memory_profiler()
    snap = profiler.take_snapshot()
    return {
        "timestamp": snap.timestamp,
        "rss_mb": snap.rss_mb,
        "tracemalloc_current_mb": snap.tracemalloc_current_mb,
        "tracemalloc_peak_mb": snap.tracemalloc_peak_mb,
        "gc_objects": snap.gc_objects,
    }


@router.post("/profiling/memory/tracing/{action}")
async def memory_tracing(action: str):
    """Start or stop memory tracing. Action: 'start' or 'stop'."""
    from app.services.performance.profiler import get_memory_profiler
    profiler = get_memory_profiler()
    if action == "start":
        profiler.start_tracing()
        return {"status": "tracing_started"}
    elif action == "stop":
        profiler.stop_tracing()
        return {"status": "tracing_stopped"}
    raise HTTPException(status_code=400, detail="Action must be 'start' or 'stop'")


@router.get("/profiling/memory/leak-check")
async def check_memory_leak():
    """Run heuristic memory leak detection."""
    from app.services.performance.profiler import get_memory_profiler
    profiler = get_memory_profiler()
    result = profiler.detect_leak()
    return result or {"detected": False, "message": "Insufficient data for analysis"}


@router.get("/profiling/cpu")
async def get_cpu_profile():
    """Get CPU profiling hotspot report."""
    from app.services.performance.profiler import get_cpu_profiler
    profiler = get_cpu_profiler()
    return profiler.get_hotspot_report()


@router.post("/profiling/cpu/{action}")
async def cpu_profiling(action: str):
    """Enable or disable CPU profiling. Action: 'enable' or 'disable'."""
    from app.services.performance.profiler import get_cpu_profiler
    profiler = get_cpu_profiler()
    if action == "enable":
        profiler.enable()
        return {"status": "cpu_profiling_enabled"}
    elif action == "disable":
        profiler.disable()
        return {"status": "cpu_profiling_disabled"}
    raise HTTPException(status_code=400, detail="Action must be 'enable' or 'disable'")


@router.get("/profiling/regex-audit")
async def get_regex_audit():
    """Audit threat detection regex patterns for performance issues."""
    from app.services.performance.profiler import get_regex_auditor
    from app.services.threat_detection.engine import get_threat_engine
    auditor = get_regex_auditor()
    try:
        engine = get_threat_engine()
        patterns = [p.pattern for p in engine.library.patterns if hasattr(p, "pattern")]
        return auditor.audit_patterns(patterns)
    except Exception:
        return {"total_patterns": 0, "findings": [], "finding_count": 0, "avg_compilation_ms": 0}


@router.get("/profiling/cache")
async def get_cache_stats():
    """Get cache efficiency statistics."""
    from app.services.performance.profiler import get_cache_monitor
    monitor = get_cache_monitor()
    return monitor.get_report()


# ── Sprint 20: Security Penetration Test ──


@router.post("/security/pentest/run")
async def run_pentest():
    """Execute automated security penetration tests against the gateway."""
    from app.services.security.pentest import SecurityTestSuite
    suite = SecurityTestSuite()
    report = await suite.run_all()
    return {
        "scan_id": report.scan_id,
        "duration_seconds": report.duration_seconds,
        "total_tests": report.total_tests,
        "passed_tests": report.passed_tests,
        "failed_tests": report.failed_tests,
        "critical_count": report.critical_count,
        "high_count": report.high_count,
        "medium_count": report.medium_count,
        "low_count": report.low_count,
        "info_count": report.info_count,
        "unresolved_critical_high": report.unresolved_critical_high,
        "findings": [
            {
                "id": f.id,
                "test_name": f.test_name,
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
                "status": f.status,
                "cwe_id": f.cwe_id,
                "owasp_ref": f.owasp_ref,
            }
            for f in report.findings
        ],
    }


@router.get("/security/pentest/tests")
async def list_pentest_tests():
    """List all available security test definitions."""
    from app.services.security.pentest import SecurityTestSuite
    suite = SecurityTestSuite()
    return suite.get_all_test_definitions()


# ── Sprint 20: GA Release Checklist ──


@router.get("/ga-checklist")
async def get_ga_checklist():
    """Get GA release checklist status."""
    from app.services.security.ga_checklist import get_ga_checklist_service
    svc = get_ga_checklist_service()
    status = svc.get_status()
    return {
        "checklist_id": status.checklist_id,
        "version": status.version,
        "total_items": status.total_items,
        "signed_off_items": status.signed_off_items,
        "required_items": status.required_items,
        "required_signed_off": status.required_signed_off,
        "progress_percentage": status.progress_percentage,
        "ga_ready": status.ga_ready,
        "items": [
            {
                "id": i.id,
                "category": i.category,
                "title": i.title,
                "description": i.description,
                "required": i.required,
                "signoff_role": i.signoff_role,
                "signed_off": i.signed_off,
                "signed_off_by": i.signed_off_by,
                "signed_off_at": i.signed_off_at,
                "notes": i.notes,
            }
            for i in status.items
        ],
    }


class SignOffBody(BaseModel):
    signed_by: str
    notes: str = ""


@router.post("/ga-checklist/{item_id}/sign-off")
async def sign_off_checklist_item(item_id: str, body: SignOffBody):
    """Sign off a GA checklist item."""
    from app.services.security.ga_checklist import get_ga_checklist_service
    svc = get_ga_checklist_service()
    try:
        item = svc.sign_off_item(item_id, signed_by=body.signed_by, notes=body.notes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {
        "id": item.id,
        "signed_off": item.signed_off,
        "signed_off_by": item.signed_off_by,
        "signed_off_at": item.signed_off_at,
    }


@router.post("/ga-checklist/{item_id}/revoke")
async def revoke_checklist_signoff(item_id: str):
    """Revoke sign-off for a GA checklist item."""
    from app.services.security.ga_checklist import get_ga_checklist_service
    svc = get_ga_checklist_service()
    try:
        item = svc.revoke_signoff(item_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"id": item.id, "signed_off": item.signed_off}


@router.post("/ga-checklist/reset")
async def reset_ga_checklist():
    """Reset the entire GA checklist."""
    from app.services.security.ga_checklist import get_ga_checklist_service
    svc = get_ga_checklist_service()
    status = svc.reset()
    return {
        "checklist_id": status.checklist_id,
        "total_items": status.total_items,
        "signed_off_items": status.signed_off_items,
        "ga_ready": status.ga_ready,
    }


@router.get("/ga-checklist/category/{category}")
async def get_checklist_by_category(category: str):
    """Get GA checklist items by category."""
    from app.services.security.ga_checklist import get_ga_checklist_service
    svc = get_ga_checklist_service()
    items = svc.get_items_by_category(category)
    if not items:
        raise HTTPException(status_code=404, detail=f"No items found for category: {category}")
    return [
        {
            "id": i.id,
            "category": i.category,
            "title": i.title,
            "signed_off": i.signed_off,
            "signoff_role": i.signoff_role,
        }
        for i in items
    ]


@router.get("/ga-checklist/unsigned")
async def get_unsigned_checklist_items():
    """Get all unsigned GA checklist items."""
    from app.services.security.ga_checklist import get_ga_checklist_service
    svc = get_ga_checklist_service()
    items = svc.get_unsigned_items()
    return [
        {
            "id": i.id,
            "category": i.category,
            "title": i.title,
            "required": i.required,
            "signoff_role": i.signoff_role,
        }
        for i in items
    ]


# ── Sprint 21: Multilingual Threat Detection + EU AI Act Controls ─────────


@router.get("/multilingual/status")
async def get_multilingual_status():
    """Get multilingual threat detection system status."""
    from app.services.multilingual.unicode_normalizer import get_unicode_normalizer
    from app.services.multilingual.multilingual_detector import get_multilingual_detector
    from app.services.multilingual.language_detector import get_language_router

    normalizer = get_unicode_normalizer()
    detector = get_multilingual_detector()
    router_svc = get_language_router()

    return {
        "unicode_normalizer": normalizer.get_stats(),
        "multilingual_detector": detector.get_stats(),
        "supported_languages": router_svc.detector.get_supported_languages(),
    }


@router.post("/multilingual/scan")
async def multilingual_scan(body: dict):
    """Scan text with full multilingual pipeline: normalize -> detect language -> scan."""
    from app.services.multilingual.unicode_normalizer import get_unicode_normalizer
    from app.services.multilingual.multilingual_detector import get_multilingual_detector
    from app.services.multilingual.language_detector import get_language_router

    text = body.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="text field required")

    normalizer = get_unicode_normalizer()
    detector = get_multilingual_detector()
    lang_router = get_language_router()

    # Step 1: Normalize Unicode
    normalized = normalizer.normalize(text)
    obfuscation = normalizer.detect_obfuscation(text)

    # Step 2: Detect language and route
    lang_result, routing = lang_router.route(normalized)

    # Step 3: Run multilingual scan
    ml_result = detector.scan(normalized, detected_language=lang_result.language)

    return {
        "normalized_text": normalized,
        "obfuscation": obfuscation,
        "language_detection": lang_result.to_dict(),
        "routing_decision": routing.to_dict(),
        "multilingual_scan": ml_result.to_dict(),
    }


@router.post("/multilingual/normalize")
async def normalize_text(body: dict):
    """Normalize Unicode text and detect obfuscation techniques."""
    from app.services.multilingual.unicode_normalizer import get_unicode_normalizer

    text = body.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="text field required")

    normalizer = get_unicode_normalizer()
    return normalizer.detect_obfuscation(text)


@router.post("/multilingual/detect-language")
async def detect_language(body: dict):
    """Detect the language of input text."""
    from app.services.multilingual.language_detector import get_language_router

    text = body.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="text field required")

    lang_router = get_language_router()
    detection, routing = lang_router.route(text)
    return {
        "detection": detection.to_dict(),
        "routing": routing.to_dict(),
    }


@router.get("/eu-ai-act/dashboard")
async def get_eu_ai_act_dashboard():
    """Get EU AI Act risk classification dashboard."""
    from app.services.multilingual.eu_ai_act import get_eu_ai_act_service
    svc = get_eu_ai_act_service()
    return svc.get_dashboard().to_dict()


@router.post("/eu-ai-act/applications")
async def register_ai_application(body: dict):
    """Register a new AI application for EU AI Act classification."""
    from app.services.multilingual.eu_ai_act import get_eu_ai_act_service

    name = body.get("name", "")
    if not name:
        raise HTTPException(status_code=400, detail="name field required")

    svc = get_eu_ai_act_service()
    app = svc.register_application(
        name=name,
        description=body.get("description", ""),
        category=body.get("category", "general_assistant"),
        provider=body.get("provider", ""),
        model=body.get("model", ""),
        tenant_id=body.get("tenant_id", ""),
        compliance_notes=body.get("compliance_notes", ""),
    )
    return app.to_dict()


@router.get("/eu-ai-act/applications")
async def list_ai_applications(risk_tier: Optional[str] = None):
    """List registered AI applications, optionally filtered by risk tier."""
    from app.services.multilingual.eu_ai_act import get_eu_ai_act_service, EURiskTier

    svc = get_eu_ai_act_service()
    tier = None
    if risk_tier:
        try:
            tier = EURiskTier(risk_tier)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid risk tier: {risk_tier}")

    apps = svc.list_applications(risk_tier=tier)
    return [a.to_dict() for a in apps]


@router.get("/eu-ai-act/applications/{app_id}")
async def get_ai_application(app_id: str):
    """Get a registered AI application by ID."""
    from app.services.multilingual.eu_ai_act import get_eu_ai_act_service

    svc = get_eu_ai_act_service()
    app = svc.get_application(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    return app.to_dict()


@router.patch("/eu-ai-act/applications/{app_id}")
async def update_ai_application(app_id: str, body: dict):
    """Update an AI application's risk classification."""
    from app.services.multilingual.eu_ai_act import get_eu_ai_act_service

    svc = get_eu_ai_act_service()
    category = body.get("category")
    if not category:
        raise HTTPException(status_code=400, detail="category field required")

    app = svc.update_classification(app_id, category)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    return app.to_dict()


@router.delete("/eu-ai-act/applications/{app_id}")
async def remove_ai_application(app_id: str):
    """Remove a registered AI application."""
    from app.services.multilingual.eu_ai_act import get_eu_ai_act_service

    svc = get_eu_ai_act_service()
    if not svc.remove_application(app_id):
        raise HTTPException(status_code=404, detail="Application not found")
    return {"status": "removed", "app_id": app_id}


@router.get("/eu-ai-act/classification-rules")
async def get_classification_rules():
    """Get all EU AI Act risk classification rules."""
    from app.services.multilingual.eu_ai_act import get_eu_ai_act_service
    svc = get_eu_ai_act_service()
    return svc.get_classification_rules()


@router.post("/eu-ai-act/transparency-events")
async def log_transparency_event(body: dict):
    """Log a transparency event per EU AI Act Article 50."""
    from app.services.multilingual.eu_ai_act import get_eu_ai_act_service

    svc = get_eu_ai_act_service()
    event = svc.log_transparency_event(
        app_id=body.get("app_id", ""),
        tenant_id=body.get("tenant_id", ""),
        model=body.get("model", ""),
        provider=body.get("provider", ""),
        output_content=body.get("output_content", ""),
        input_content=body.get("input_content", ""),
        content_type=body.get("content_type", "text"),
        metadata=body.get("metadata"),
    )
    return event.to_dict()


@router.get("/eu-ai-act/transparency-events")
async def get_transparency_events(
    app_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    limit: int = 100,
):
    """Query transparency events."""
    from app.services.multilingual.eu_ai_act import get_eu_ai_act_service
    svc = get_eu_ai_act_service()
    events = svc.get_transparency_events(app_id=app_id, tenant_id=tenant_id, limit=limit)
    return [e.to_dict() for e in events]


@router.get("/eu-ai-act/stats")
async def get_eu_ai_act_stats():
    """Get EU AI Act service statistics."""
    from app.services.multilingual.eu_ai_act import get_eu_ai_act_service
    svc = get_eu_ai_act_service()
    return svc.get_stats()


# ──────────────────────────────────────────────────────────────────────────────
# Sprint 22 — Language Packs, Cross-Language Detection, EU AI Act Docs, Benchmark
# ──────────────────────────────────────────────────────────────────────────────


@router.get("/multilingual/language-packs")
async def get_language_packs():
    """Get available language-specific threat pattern packs."""
    from app.services.multilingual.language_packs import get_language_pack_scanner
    scanner = get_language_pack_scanner()
    return {
        "packs": [p.to_dict() for p in scanner.get_language_packs()],
        "stats": scanner.get_stats(),
    }


@router.get("/multilingual/coverage-matrix")
async def get_coverage_matrix():
    """Get language coverage matrix showing detection support for all languages."""
    from app.services.multilingual.language_packs import get_language_pack_scanner
    scanner = get_language_pack_scanner()
    return scanner.get_coverage_matrix()


@router.post("/multilingual/scan-with-packs")
async def scan_with_language_packs(body: dict):
    """Scan text with full pipeline including language pack patterns and cross-language detection."""
    from app.services.multilingual.unicode_normalizer import get_unicode_normalizer
    from app.services.multilingual.multilingual_detector import get_multilingual_detector
    from app.services.multilingual.language_detector import get_language_router
    from app.services.multilingual.language_packs import get_language_pack_scanner
    from app.services.multilingual.cross_language_detector import get_cross_language_detector

    text = body.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="text field required")

    normalizer = get_unicode_normalizer()
    detector = get_multilingual_detector()
    lang_router = get_language_router()
    pack_scanner = get_language_pack_scanner()
    cross_lang = get_cross_language_detector()

    # Step 1: Normalize Unicode
    normalized = normalizer.normalize(text)
    obfuscation = normalizer.detect_obfuscation(text)

    # Step 2: Detect language and route
    lang_result, routing = lang_router.route(normalized)

    # Step 3: Run multilingual embedding scan
    ml_result = detector.scan(normalized, detected_language=lang_result.language)

    # Step 4: Run language pack regex scan
    pack_matches = pack_scanner.scan(normalized, language_hint=lang_result.language)

    # Step 5: Run cross-language attack detection
    cross_lang_result = cross_lang.detect(normalized)

    return {
        "normalized_text": normalized,
        "obfuscation": obfuscation,
        "language_detection": lang_result.to_dict(),
        "routing_decision": routing.to_dict(),
        "multilingual_scan": ml_result.to_dict(),
        "language_pack_matches": [m.to_dict() for m in pack_matches],
        "cross_language_analysis": cross_lang_result.to_dict(),
    }


@router.post("/multilingual/cross-language-detect")
async def cross_language_detect(body: dict):
    """Detect cross-language attacks in mixed-language prompts."""
    from app.services.multilingual.cross_language_detector import get_cross_language_detector

    text = body.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="text field required")

    detector = get_cross_language_detector()
    result = detector.detect(text)
    return result.to_dict()


@router.post("/multilingual/benchmark/run")
async def run_multilingual_benchmark():
    """Run the multilingual detection latency benchmark. Returns p99 latencies per language."""
    from app.services.multilingual.benchmark import get_multilingual_benchmark
    benchmark = get_multilingual_benchmark()
    report = benchmark.run()
    return report.to_dict()


@router.get("/multilingual/benchmark/last")
async def get_last_benchmark():
    """Get the most recent benchmark report."""
    from app.services.multilingual.benchmark import get_multilingual_benchmark
    benchmark = get_multilingual_benchmark()
    report = benchmark.last_report
    if not report:
        raise HTTPException(status_code=404, detail="No benchmark has been run yet")
    return report.to_dict()


# --- EU AI Act Article 14 — Human Oversight ---


@router.post("/eu-ai-act/overseers")
async def designate_overseer(body: dict):
    """Designate a human overseer per EU AI Act Article 14."""
    from app.services.multilingual.eu_ai_act_docs import get_human_oversight_service

    name = body.get("name", "")
    if not name:
        raise HTTPException(status_code=400, detail="name field required")

    svc = get_human_oversight_service()
    overseer = svc.designate_overseer(
        name=name,
        role=body.get("role", ""),
        email=body.get("email", ""),
        department=body.get("department", ""),
        authority_level=body.get("authority_level", "standard"),
    )
    return overseer.to_dict()


@router.get("/eu-ai-act/overseers")
async def list_overseers():
    """List all designated human overseers."""
    from app.services.multilingual.eu_ai_act_docs import get_human_oversight_service
    svc = get_human_oversight_service()
    return [o.to_dict() for o in svc.list_overseers()]


@router.delete("/eu-ai-act/overseers/{overseer_id}")
async def remove_overseer(overseer_id: str):
    """Remove a designated human overseer."""
    from app.services.multilingual.eu_ai_act_docs import get_human_oversight_service
    svc = get_human_oversight_service()
    if not svc.remove_overseer(overseer_id):
        raise HTTPException(status_code=404, detail="Overseer not found")
    return {"status": "removed", "overseer_id": overseer_id}


@router.post("/eu-ai-act/checkpoints")
async def add_hitl_checkpoint(body: dict):
    """Add a HITL checkpoint for an AI application."""
    from app.services.multilingual.eu_ai_act_docs import get_human_oversight_service

    app_id = body.get("app_id", "")
    if not app_id:
        raise HTTPException(status_code=400, detail="app_id field required")

    checkpoint_type = body.get("checkpoint_type", "runtime_approval")
    svc = get_human_oversight_service()
    try:
        checkpoint = svc.add_checkpoint(
            app_id=app_id,
            checkpoint_type=checkpoint_type,
            description=body.get("description", ""),
            is_mandatory=body.get("is_mandatory", True),
            overseer_ids=body.get("overseer_ids", []),
            trigger_conditions=body.get("trigger_conditions", ""),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return checkpoint.to_dict()


@router.get("/eu-ai-act/checkpoints")
async def list_hitl_checkpoints(app_id: Optional[str] = None):
    """List HITL checkpoints, optionally filtered by app_id."""
    from app.services.multilingual.eu_ai_act_docs import get_human_oversight_service
    svc = get_human_oversight_service()
    return [cp.to_dict() for cp in svc.get_checkpoints(app_id)]


@router.delete("/eu-ai-act/checkpoints/{checkpoint_id}")
async def remove_hitl_checkpoint(checkpoint_id: str):
    """Remove a HITL checkpoint."""
    from app.services.multilingual.eu_ai_act_docs import get_human_oversight_service
    svc = get_human_oversight_service()
    if not svc.remove_checkpoint(checkpoint_id):
        raise HTTPException(status_code=404, detail="Checkpoint not found")
    return {"status": "removed", "checkpoint_id": checkpoint_id}


@router.post("/eu-ai-act/oversight-events")
async def log_oversight_event(body: dict):
    """Log a human oversight event."""
    from app.services.multilingual.eu_ai_act_docs import get_human_oversight_service

    app_id = body.get("app_id", "")
    if not app_id:
        raise HTTPException(status_code=400, detail="app_id field required")

    svc = get_human_oversight_service()
    try:
        event = svc.log_oversight_event(
            app_id=app_id,
            checkpoint_id=body.get("checkpoint_id", ""),
            overseer_id=body.get("overseer_id", ""),
            event_type=body.get("event_type", "review"),
            decision=body.get("decision", ""),
            reason=body.get("reason", ""),
            metadata=body.get("metadata"),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return event.to_dict()


@router.get("/eu-ai-act/oversight-events")
async def get_oversight_events(
    app_id: Optional[str] = None,
    overseer_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
):
    """Query human oversight events."""
    from app.services.multilingual.eu_ai_act_docs import get_human_oversight_service
    svc = get_human_oversight_service()
    events = svc.get_oversight_events(
        app_id=app_id, overseer_id=overseer_id, event_type=event_type, limit=limit,
    )
    return [e.to_dict() for e in events]


@router.get("/eu-ai-act/article14-documentation")
async def get_article14_documentation(app_id: Optional[str] = None):
    """Generate EU AI Act Article 14 human oversight documentation."""
    from app.services.multilingual.eu_ai_act_docs import get_human_oversight_service
    svc = get_human_oversight_service()
    return svc.generate_article14_documentation(app_id)


# --- EU AI Act Article 11 — Technical Documentation ---


@router.post("/eu-ai-act/technical-docs")
async def create_technical_doc(body: dict):
    """Create an Article 11 technical documentation entry for an AI application."""
    from app.services.multilingual.eu_ai_act_docs import get_technical_doc_service

    app_id = body.get("app_id", "")
    if not app_id:
        raise HTTPException(status_code=400, detail="app_id field required")

    svc = get_technical_doc_service()
    entry = svc.create_entry(
        app_id=app_id,
        system_description=body.get("system_description", ""),
        architecture_summary=body.get("architecture_summary", ""),
        intended_purpose=body.get("intended_purpose", ""),
        risk_management=body.get("risk_management", ""),
        monitoring_plan=body.get("monitoring_plan", ""),
    )
    return entry.to_dict()


@router.get("/eu-ai-act/technical-docs/{app_id}")
async def get_technical_doc(app_id: str):
    """Get the technical documentation entry for an AI application."""
    from app.services.multilingual.eu_ai_act_docs import get_technical_doc_service
    svc = get_technical_doc_service()
    entry = svc.get_entry(app_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Technical doc entry not found")
    return entry.to_dict()


@router.post("/eu-ai-act/technical-docs/{app_id}/training-data")
async def set_training_data(app_id: str, body: dict):
    """Set training data description for an application's technical doc."""
    from app.services.multilingual.eu_ai_act_docs import get_technical_doc_service
    svc = get_technical_doc_service()
    entry = svc.set_training_data(
        app_id=app_id,
        dataset_name=body.get("dataset_name", ""),
        dataset_size=body.get("dataset_size", ""),
        data_sources=body.get("data_sources", []),
        preprocessing_steps=body.get("preprocessing_steps", []),
        known_biases=body.get("known_biases", []),
        data_governance=body.get("data_governance", ""),
    )
    if not entry:
        raise HTTPException(status_code=404, detail="Technical doc entry not found")
    return entry.to_dict()


@router.post("/eu-ai-act/technical-docs/{app_id}/accuracy-measures")
async def add_accuracy_measure(app_id: str, body: dict):
    """Add an accuracy measure to an application's technical doc."""
    from app.services.multilingual.eu_ai_act_docs import get_technical_doc_service
    svc = get_technical_doc_service()
    entry = svc.add_accuracy_measure(
        app_id=app_id,
        metric_name=body.get("metric_name", ""),
        metric_value=body.get("metric_value", ""),
        evaluation_dataset=body.get("evaluation_dataset", ""),
        evaluation_date=body.get("evaluation_date", ""),
        notes=body.get("notes", ""),
    )
    if not entry:
        raise HTTPException(status_code=404, detail="Technical doc entry not found")
    return entry.to_dict()


@router.post("/eu-ai-act/technical-docs/{app_id}/robustness-measures")
async def add_robustness_measure(app_id: str, body: dict):
    """Add a robustness measure to an application's technical doc."""
    from app.services.multilingual.eu_ai_act_docs import get_technical_doc_service
    svc = get_technical_doc_service()
    entry = svc.add_robustness_measure(
        app_id=app_id,
        measure_name=body.get("measure_name", ""),
        description=body.get("description", ""),
        implementation_status=body.get("implementation_status", "implemented"),
    )
    if not entry:
        raise HTTPException(status_code=404, detail="Technical doc entry not found")
    return entry.to_dict()


@router.get("/eu-ai-act/technical-docs/{app_id}/export")
async def export_article11_package(app_id: str):
    """Generate and export the full Article 11 technical documentation package."""
    from app.services.multilingual.eu_ai_act_docs import get_technical_doc_service
    svc = get_technical_doc_service()
    package = svc.generate_article11_package(app_id)
    if not package:
        raise HTTPException(status_code=404, detail="Technical doc entry not found")
    return package


@router.delete("/eu-ai-act/technical-docs/{app_id}")
async def remove_technical_doc(app_id: str):
    """Remove technical documentation entry."""
    from app.services.multilingual.eu_ai_act_docs import get_technical_doc_service
    svc = get_technical_doc_service()
    if not svc.remove_entry(app_id):
        raise HTTPException(status_code=404, detail="Technical doc entry not found")
    return {"status": "removed", "app_id": app_id}


# ---------------------------------------------------------------------------
# Red Teaming Engine — Sprint 23
# ---------------------------------------------------------------------------


class CreateRedTeamCampaignRequest(BaseModel):
    name: str
    target_url: str
    description: str = ""
    probe_categories: list[str] = [
        "injection", "jailbreak", "pii_extraction",
        "tool_call_injection", "memory_poisoning",
        "privilege_escalation", "multi_step_attack",
    ]
    concurrency: int = 10
    timeout_seconds: int = 30
    created_by: str = "admin"


@router.post("/red-team/campaigns")
async def create_red_team_campaign(body: CreateRedTeamCampaignRequest):
    """Create a new red team campaign."""
    from app.services.red_team.runner import create_campaign
    campaign = create_campaign(
        name=body.name,
        target_url=body.target_url,
        description=body.description,
        probe_categories=body.probe_categories,
        concurrency=body.concurrency,
        timeout_seconds=body.timeout_seconds,
        created_by=body.created_by,
    )
    return campaign.to_dict()


@router.get("/red-team/campaigns")
async def list_red_team_campaigns():
    """List all red team campaigns."""
    from app.services.red_team.runner import list_campaigns
    return list_campaigns()


@router.get("/red-team/campaigns/{campaign_id}")
async def get_red_team_campaign(campaign_id: str):
    """Get a specific campaign with summary."""
    from app.services.red_team.runner import get_campaign
    campaign = get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign.to_dict()


@router.post("/red-team/campaigns/{campaign_id}/run")
async def run_red_team_campaign(campaign_id: str):
    """Execute a red team campaign (runs probes against target endpoint)."""
    import asyncio
    from app.services.red_team.runner import get_campaign, run_campaign, CampaignStatus
    campaign = get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.status == CampaignStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Campaign is already running")
    asyncio.ensure_future(run_campaign(campaign))
    return {"status": "started", "campaign_id": campaign_id}


@router.get("/red-team/campaigns/{campaign_id}/results")
async def get_red_team_results(
    campaign_id: str,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    detected_only: bool = False,
):
    """Get probe results for a campaign with optional filters."""
    from app.services.red_team.runner import get_campaign
    campaign = get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign.get_results_filtered(
        category=category,
        severity=severity,
        detected_only=detected_only,
    )


@router.get("/red-team/campaigns/{campaign_id}/report")
async def export_red_team_report(campaign_id: str):
    """Export findings report for a campaign (PDF-ready data)."""
    from app.services.red_team.runner import get_campaign, CampaignStatus
    campaign = get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.status != CampaignStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Campaign has not completed yet")
    return campaign.export_report()


@router.delete("/red-team/campaigns/{campaign_id}")
async def delete_red_team_campaign(campaign_id: str):
    """Delete a red team campaign."""
    from app.services.red_team.runner import delete_campaign
    if not delete_campaign(campaign_id):
        raise HTTPException(status_code=404, detail="Campaign not found")
    return {"status": "deleted", "campaign_id": campaign_id}


@router.get("/red-team/probes")
async def list_available_probes():
    """List all available probe suites and counts."""
    from app.services.red_team.probes.injection import INJECTION_PROBES
    from app.services.red_team.probes.jailbreak import JAILBREAK_PROBES
    from app.services.red_team.probes.pii_extraction import PII_EXTRACTION_PROBES
    from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
    from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
    from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
    from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
    all_suites = {
        "injection": INJECTION_PROBES,
        "jailbreak": JAILBREAK_PROBES,
        "pii_extraction": PII_EXTRACTION_PROBES,
        "tool_call_injection": TOOL_CALL_INJECTION_PROBES,
        "memory_poisoning": MEMORY_POISONING_PROBES,
        "privilege_escalation": PRIVILEGE_ESCALATION_PROBES,
        "multi_step_attack": MULTI_STEP_ATTACK_PROBES,
    }
    total = sum(len(probes) for probes in all_suites.values())
    suites_summary = {
        name: {
            "count": len(probes),
            "techniques": list(set(p["technique"] for p in probes)),
        }
        for name, probes in all_suites.items()
    }
    return {"total": total, "suites": suites_summary}


@router.get("/red-team/probes/{category}")
async def list_probes_by_category(category: str):
    """List probes in a specific category."""
    from app.services.red_team.probes.injection import INJECTION_PROBES
    from app.services.red_team.probes.jailbreak import JAILBREAK_PROBES
    from app.services.red_team.probes.pii_extraction import PII_EXTRACTION_PROBES
    from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
    from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
    from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
    from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
    suites = {
        "injection": INJECTION_PROBES,
        "jailbreak": JAILBREAK_PROBES,
        "pii_extraction": PII_EXTRACTION_PROBES,
        "tool_call_injection": TOOL_CALL_INJECTION_PROBES,
        "memory_poisoning": MEMORY_POISONING_PROBES,
        "privilege_escalation": PRIVILEGE_ESCALATION_PROBES,
        "multi_step_attack": MULTI_STEP_ATTACK_PROBES,
    }
    if category not in suites:
        raise HTTPException(status_code=404, detail=f"Unknown probe category: {category}")
    probes = suites[category]
    return {"category": category, "count": len(probes), "probes": probes}
