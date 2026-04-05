"""Policy version management — versioned snapshots, diff, rollback, and simulation.

Every policy publish creates a versioned snapshot. Audit events record the
policy version at time of enforcement. Supports diff between versions,
one-click rollback, and dry-run simulation against recent request logs.
"""

import json
import logging
import time
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import PolicyRule, AuditLog

logger = logging.getLogger("sphinx.policy_versioning")


async def create_policy_snapshot(
    db: AsyncSession,
    policy_id: uuid.UUID,
    rules_json: str,
    description: str = "",
    created_by: str = "system",
) -> dict:
    """Create a versioned snapshot of a policy.

    Called automatically when a policy is published/updated.
    Returns the snapshot data dict.
    """
    from app.models.api_key import PolicyVersionSnapshot

    # Get the policy to determine next version number
    result = await db.execute(select(PolicyRule).where(PolicyRule.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise ValueError(f"Policy {policy_id} not found")

    # Find the highest existing version for this policy
    max_ver = await db.execute(
        select(func.max(PolicyVersionSnapshot.version)).where(
            PolicyVersionSnapshot.policy_id == policy_id
        )
    )
    current_max = max_ver.scalar() or 0
    new_version = current_max + 1

    snapshot = PolicyVersionSnapshot(
        id=uuid.uuid4(),
        policy_id=policy_id,
        version=new_version,
        name=policy.name,
        description=description or policy.description,
        policy_type=policy.policy_type,
        rules_json=rules_json,
        created_by=created_by,
    )
    db.add(snapshot)
    await db.commit()
    await db.refresh(snapshot)

    logger.info(
        "Created policy snapshot: policy=%s version=%d",
        policy.name, new_version,
    )

    return {
        "id": str(snapshot.id),
        "policy_id": str(snapshot.policy_id),
        "version": snapshot.version,
        "name": snapshot.name,
        "description": snapshot.description,
        "policy_type": snapshot.policy_type,
        "rules": json.loads(snapshot.rules_json) if snapshot.rules_json else {},
        "created_by": snapshot.created_by,
        "created_at": snapshot.created_at.isoformat() if snapshot.created_at else None,
    }


async def list_policy_versions(
    db: AsyncSession,
    policy_id: uuid.UUID,
) -> list[dict]:
    """List all version snapshots for a policy, ordered by version descending."""
    from app.models.api_key import PolicyVersionSnapshot

    result = await db.execute(
        select(PolicyVersionSnapshot)
        .where(PolicyVersionSnapshot.policy_id == policy_id)
        .order_by(PolicyVersionSnapshot.version.desc())
    )
    snapshots = result.scalars().all()

    return [
        {
            "id": str(s.id),
            "policy_id": str(s.policy_id),
            "version": s.version,
            "name": s.name,
            "description": s.description,
            "policy_type": s.policy_type,
            "rules": json.loads(s.rules_json) if s.rules_json else {},
            "created_by": s.created_by,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in snapshots
    ]


async def get_policy_version(
    db: AsyncSession,
    policy_id: uuid.UUID,
    version: int,
) -> Optional[dict]:
    """Get a specific version snapshot."""
    from app.models.api_key import PolicyVersionSnapshot

    result = await db.execute(
        select(PolicyVersionSnapshot).where(
            PolicyVersionSnapshot.policy_id == policy_id,
            PolicyVersionSnapshot.version == version,
        )
    )
    s = result.scalar_one_or_none()
    if not s:
        return None

    return {
        "id": str(s.id),
        "policy_id": str(s.policy_id),
        "version": s.version,
        "name": s.name,
        "description": s.description,
        "policy_type": s.policy_type,
        "rules": json.loads(s.rules_json) if s.rules_json else {},
        "created_by": s.created_by,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


async def diff_policy_versions(
    db: AsyncSession,
    policy_id: uuid.UUID,
    version_a: int,
    version_b: int,
) -> dict:
    """Compute diff between two policy versions.

    Returns a dict with added, removed, and changed fields.
    """
    ver_a = await get_policy_version(db, policy_id, version_a)
    ver_b = await get_policy_version(db, policy_id, version_b)

    if not ver_a:
        raise ValueError(f"Version {version_a} not found")
    if not ver_b:
        raise ValueError(f"Version {version_b} not found")

    rules_a = ver_a["rules"]
    rules_b = ver_b["rules"]

    added = {}
    removed = {}
    changed = {}

    all_keys = set(list(rules_a.keys()) + list(rules_b.keys()))
    for key in all_keys:
        if key not in rules_a:
            added[key] = rules_b[key]
        elif key not in rules_b:
            removed[key] = rules_a[key]
        elif rules_a[key] != rules_b[key]:
            changed[key] = {"old": rules_a[key], "new": rules_b[key]}

    return {
        "policy_id": str(policy_id),
        "version_a": version_a,
        "version_b": version_b,
        "added": added,
        "removed": removed,
        "changed": changed,
        "has_changes": bool(added or removed or changed),
    }


async def rollback_policy(
    db: AsyncSession,
    policy_id: uuid.UUID,
    target_version: int,
    rolled_back_by: str = "admin",
) -> dict:
    """Rollback a policy to a previous version.

    Creates a new version snapshot (so the rollback itself is versioned),
    updates the active policy, and refreshes the gateway cache.
    """
    from app.services.policy_cache import force_refresh

    # Get the target version snapshot
    target = await get_policy_version(db, policy_id, target_version)
    if not target:
        raise ValueError(f"Version {target_version} not found for policy {policy_id}")

    # Get the current policy
    result = await db.execute(select(PolicyRule).where(PolicyRule.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise ValueError(f"Policy {policy_id} not found")

    # Update the policy to the target version's rules
    old_rules = policy.rules_json
    policy.rules_json = json.dumps(target["rules"])
    policy.version += 1
    policy.description = f"Rolled back to version {target_version} by {rolled_back_by}"

    await db.commit()
    await db.refresh(policy)

    # Create a snapshot for the rollback
    snapshot = await create_policy_snapshot(
        db,
        policy_id,
        policy.rules_json,
        description=f"Rollback to version {target_version} by {rolled_back_by}",
        created_by=rolled_back_by,
    )

    # Propagate to gateway by refreshing the cache
    await force_refresh(db)

    logger.info(
        "Policy %s rolled back to version %d by %s (new version=%d)",
        policy.name, target_version, rolled_back_by, snapshot["version"],
    )

    return {
        "policy_id": str(policy_id),
        "rolled_back_to": target_version,
        "new_version": snapshot["version"],
        "rolled_back_by": rolled_back_by,
        "rules": target["rules"],
    }


async def simulate_policy(
    db: AsyncSession,
    policy_id: uuid.UUID,
    rules: dict,
    limit: int = 100,
) -> dict:
    """Simulate a policy against recent audit log entries.

    Dry-runs the provided rules against recent request history to preview
    which requests would be blocked/rewritten/allowed.

    Returns impact analysis: how many requests would change action.
    """
    from app.services.threat_detection.engine import ThreatDetectionEngine
    from app.services.threat_detection.action_engine import PolicyActionEngine

    # Get the policy to understand its type
    result = await db.execute(select(PolicyRule).where(PolicyRule.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise ValueError(f"Policy {policy_id} not found")

    # Load recent audit events
    audit_result = await db.execute(
        select(AuditLog)
        .order_by(AuditLog.event_timestamp.desc())
        .limit(limit)
    )
    recent_events = audit_result.scalars().all()

    if not recent_events:
        return {
            "policy_id": str(policy_id),
            "simulated_rules": rules,
            "total_requests": 0,
            "impact": [],
            "summary": {
                "would_block": 0,
                "would_allow": 0,
                "would_rewrite": 0,
                "would_change": 0,
                "no_change": 0,
            },
        }

    # Build a temporary action engine with the proposed rules
    action_overrides = rules.get("action_overrides", {})
    sim_action_engine = PolicyActionEngine(action_overrides=action_overrides)

    # Analyze each recent request
    impact = []
    summary = {
        "would_block": 0,
        "would_allow": 0,
        "would_rewrite": 0,
        "would_downgrade": 0,
        "would_change": 0,
        "no_change": 0,
    }

    for event in recent_events:
        metadata = json.loads(event.metadata_json) if event.metadata_json else {}
        original_action = event.action

        # Determine what the new policy would do
        risk_level = metadata.get("risk_level", "low")
        score = metadata.get("score", 0.0)

        new_action = sim_action_engine.get_actions().get(risk_level, "allow")

        # Normalize original action for comparison
        original_normalized = _normalize_action(original_action)

        changed = original_normalized != new_action

        entry = {
            "event_id": str(event.id),
            "timestamp": event.event_timestamp,
            "model": event.model,
            "tenant_id": event.tenant_id,
            "original_action": original_action,
            "simulated_action": new_action,
            "risk_level": risk_level,
            "score": score,
            "changed": changed,
        }
        impact.append(entry)

        summary[f"would_{new_action}"] = summary.get(f"would_{new_action}", 0) + 1
        if changed:
            summary["would_change"] += 1
        else:
            summary["no_change"] += 1

    return {
        "policy_id": str(policy_id),
        "simulated_rules": rules,
        "total_requests": len(recent_events),
        "impact": impact,
        "summary": summary,
    }


def _normalize_action(action: str) -> str:
    """Normalize audit action string to base action for comparison."""
    action_map = {
        "allowed": "allow",
        "blocked": "block",
        "blocked_threat": "block",
        "blocked_rag": "block",
        "rewritten_threat": "rewrite",
        "downgraded_threat": "downgrade",
        "rerouted": "allow",
        "rate_limited": "block",
    }
    return action_map.get(action, "allow")
