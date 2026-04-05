"""Control plane admin API for API key management, kill-switches, and policies."""

import json
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import APIKey, KillSwitch, PolicyRule, SecurityRule, RAGPolicyConfig, PolicyVersionSnapshot
from app.services.database import get_db
from app.services.key_service import create_api_key, revoke_api_key, hash_key
from app.services.kill_switch import (
    activate_kill_switch,
    deactivate_kill_switch,
    list_kill_switches,
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


class KillSwitchInfo(BaseModel):
    id: str
    model_name: str
    action: str
    fallback_model: Optional[str]
    activated_by: str
    reason: str
    is_active: bool
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
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return KillSwitchInfo(**data)


@router.get("/kill-switches", response_model=list[KillSwitchInfo])
async def list_kill_switches_endpoint(db: AsyncSession = Depends(get_db)):
    """List all kill-switches."""
    switches = await list_kill_switches(db)
    return [KillSwitchInfo(**s) for s in switches]


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
