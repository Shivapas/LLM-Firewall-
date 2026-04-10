"""Sprint 19: Real-time Alert Engine.

Configurable alerts with email + webhook delivery.
Conditions: block_rate_spike, budget_exhaustion, new_critical_mcp_tool,
kill_switch_activation, anomaly_score_breach.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("sphinx.dashboard.alert_engine")


# ── Models ─────────────────────────────────────────────────────────────────


class AlertRuleConfig(BaseModel):
    name: str
    description: str = ""
    condition_type: str  # block_rate_spike, budget_exhaustion, new_critical_mcp_tool, kill_switch_activation, anomaly_score_breach
    condition_config: dict = Field(default_factory=dict)
    delivery_channel: str = "webhook"  # email, webhook
    delivery_target: str = ""
    cooldown_seconds: int = 300
    tenant_id: str = "*"


class AlertTriggerContext(BaseModel):
    """Context data passed when checking/firing an alert."""
    condition_type: str = ""
    tenant_id: str = ""
    metric_value: float = 0.0
    threshold: float = 0.0
    message: str = ""
    metadata: dict = Field(default_factory=dict)


class AlertEventRecord(BaseModel):
    id: str = ""
    alert_rule_id: str = ""
    alert_rule_name: str = ""
    condition_type: str = ""
    severity: str = "high"
    message: str = ""
    delivery_channel: str = ""
    delivery_target: str = ""
    delivery_status: str = "pending"
    tenant_id: str = ""
    metadata: dict = Field(default_factory=dict)
    created_at: str = ""


# ── Service ────────────────────────────────────────────────────────────────


class AlertEngineService:
    """Real-time alert engine that evaluates conditions and delivers alerts."""

    VALID_CONDITIONS = {
        "block_rate_spike",
        "budget_exhaustion",
        "new_critical_mcp_tool",
        "kill_switch_activation",
        "anomaly_score_breach",
        "post_inference_risk_alert",   # Sprint 4 — S4-T4 (FR-POST-04)
    }

    def __init__(self, session_factory=None):
        self._session_factory = session_factory
        self._evaluation_task: Optional[asyncio.Task] = None
        self._running = False

    # ── CRUD ───────────────────────────────────────────────────────────

    async def create_rule(self, config: AlertRuleConfig) -> dict:
        """Create a new alert rule."""
        from app.models.api_key import AlertRule

        rule = AlertRule(
            id=uuid.uuid4(),
            name=config.name,
            description=config.description,
            condition_type=config.condition_type,
            condition_config_json=json.dumps(config.condition_config),
            delivery_channel=config.delivery_channel,
            delivery_target=config.delivery_target,
            cooldown_seconds=config.cooldown_seconds,
            tenant_id=config.tenant_id,
        )

        if self._session_factory:
            async with self._session_factory() as db:
                db.add(rule)
                await db.commit()
                await db.refresh(rule)

        logger.info("Alert rule created: name=%s condition=%s", config.name, config.condition_type)
        return self._serialize_rule(rule)

    async def list_rules(self, tenant_id: Optional[str] = None) -> list[dict]:
        """List all alert rules."""
        if not self._session_factory:
            return []

        from sqlalchemy import select
        from app.models.api_key import AlertRule

        async with self._session_factory() as db:
            query = select(AlertRule).order_by(AlertRule.created_at.desc())
            if tenant_id:
                query = query.where(
                    (AlertRule.tenant_id == tenant_id) | (AlertRule.tenant_id == "*")
                )
            result = await db.execute(query)
            return [self._serialize_rule(r) for r in result.scalars().all()]

    async def delete_rule(self, rule_id: str) -> bool:
        """Delete an alert rule."""
        if not self._session_factory:
            return False

        from sqlalchemy import select, delete
        from app.models.api_key import AlertRule

        async with self._session_factory() as db:
            result = await db.execute(
                select(AlertRule).where(AlertRule.id == uuid.UUID(rule_id))
            )
            rule = result.scalar_one_or_none()
            if not rule:
                return False
            await db.delete(rule)
            await db.commit()
            return True

    async def update_rule(self, rule_id: str, updates: dict) -> Optional[dict]:
        """Update an alert rule."""
        if not self._session_factory:
            return None

        from sqlalchemy import select
        from app.models.api_key import AlertRule

        async with self._session_factory() as db:
            result = await db.execute(
                select(AlertRule).where(AlertRule.id == uuid.UUID(rule_id))
            )
            rule = result.scalar_one_or_none()
            if not rule:
                return None

            for key in ("name", "description", "condition_type", "delivery_channel",
                        "delivery_target", "cooldown_seconds", "is_active", "tenant_id"):
                if key in updates:
                    setattr(rule, key, updates[key])
            if "condition_config" in updates:
                rule.condition_config_json = json.dumps(updates["condition_config"])

            await db.commit()
            await db.refresh(rule)
            return self._serialize_rule(rule)

    # ── Alert firing ───────────────────────────────────────────────────

    async def fire_alert(self, rule_id: str, context: AlertTriggerContext) -> AlertEventRecord:
        """Fire an alert: create event record and attempt delivery."""
        from app.models.api_key import AlertRule, AlertEvent

        rule = None
        if self._session_factory:
            from sqlalchemy import select
            async with self._session_factory() as db:
                result = await db.execute(
                    select(AlertRule).where(AlertRule.id == uuid.UUID(rule_id))
                )
                rule = result.scalar_one_or_none()

        if not rule:
            raise ValueError(f"Alert rule {rule_id} not found")

        # Check cooldown
        now = datetime.now(timezone.utc)
        if rule.last_fired_at:
            cooldown_end = rule.last_fired_at + timedelta(seconds=rule.cooldown_seconds)
            if now < cooldown_end:
                logger.debug("Alert %s in cooldown, skipping", rule.name)
                return AlertEventRecord(
                    delivery_status="cooldown",
                    alert_rule_name=rule.name,
                    message="Alert in cooldown period",
                )

        # Create event
        event = AlertEvent(
            id=uuid.uuid4(),
            alert_rule_id=rule.id,
            alert_rule_name=rule.name,
            condition_type=context.condition_type,
            severity="high",
            message=context.message,
            delivery_channel=rule.delivery_channel,
            delivery_target=rule.delivery_target,
            delivery_status="pending",
            tenant_id=context.tenant_id,
            metadata_json=json.dumps(context.metadata),
        )

        # Attempt delivery
        delivery_status = await self._deliver_alert(
            channel=rule.delivery_channel,
            target=rule.delivery_target,
            message=context.message,
            metadata=context.metadata,
        )
        event.delivery_status = delivery_status

        # Persist
        if self._session_factory:
            async with self._session_factory() as db:
                db.add(event)
                # Update last_fired_at
                from sqlalchemy import select
                result = await db.execute(
                    select(AlertRule).where(AlertRule.id == rule.id)
                )
                db_rule = result.scalar_one_or_none()
                if db_rule:
                    db_rule.last_fired_at = now
                await db.commit()

        logger.warning(
            "Alert fired: rule=%s condition=%s delivery=%s",
            rule.name, context.condition_type, delivery_status,
        )

        return AlertEventRecord(
            id=str(event.id),
            alert_rule_id=str(rule.id),
            alert_rule_name=rule.name,
            condition_type=context.condition_type,
            severity="high",
            message=context.message,
            delivery_channel=rule.delivery_channel,
            delivery_target=rule.delivery_target,
            delivery_status=delivery_status,
            tenant_id=context.tenant_id,
            metadata=context.metadata,
            created_at=now.isoformat(),
        )

    async def evaluate_condition(self, condition_type: str, tenant_id: str = "*") -> Optional[AlertTriggerContext]:
        """Evaluate a condition type and return trigger context if condition is met."""
        if not self._session_factory:
            return None

        if condition_type == "block_rate_spike":
            return await self._check_block_rate_spike(tenant_id)
        elif condition_type == "budget_exhaustion":
            return await self._check_budget_exhaustion(tenant_id)
        elif condition_type == "kill_switch_activation":
            return await self._check_kill_switch_activation()
        elif condition_type == "anomaly_score_breach":
            return await self._check_anomaly_score_breach(tenant_id)
        elif condition_type == "new_critical_mcp_tool":
            return await self._check_new_critical_mcp_tool()

        return None

    # ── Sprint 4: Post-inference alert delivery (S4-T4) ────────────────

    async def notify_post_inference_alert(
        self, context: AlertTriggerContext
    ) -> list[AlertEventRecord]:
        """Fire all active ``post_inference_risk_alert`` rules matching the
        trigger context tenant (Sprint 4 / S4-T4 — FR-POST-04).

        Called from the post-inference worker after Thoth classifies a
        response as HIGH or CRITICAL risk.  Looks up all active rules with
        ``condition_type == "post_inference_risk_alert"`` and fires each one
        that matches the tenant scope and has not recently fired (cooldown).

        Args:
            context: AlertTriggerContext produced by the post-inference worker.

        Returns:
            List of fired AlertEventRecord instances (may be empty if no
            matching rules exist or all are in cooldown).
        """
        if not self._session_factory:
            return []

        from sqlalchemy import select
        from app.models.api_key import AlertRule

        try:
            async with self._session_factory() as db:
                result = await db.execute(
                    select(AlertRule).where(
                        AlertRule.condition_type == "post_inference_risk_alert",
                        AlertRule.is_active.is_(True),
                    )
                )
                rules = result.scalars().all()
        except Exception:
            logger.warning(
                "Failed to query post_inference_risk_alert rules", exc_info=True
            )
            return []

        fired: list[AlertEventRecord] = []
        for rule in rules:
            # Tenant scope — "*" matches any tenant
            if rule.tenant_id not in ("*", context.tenant_id):
                continue
            try:
                event = await self.fire_alert(str(rule.id), context)
                if event.delivery_status != "cooldown":
                    fired.append(event)
            except Exception:
                logger.warning(
                    "Error firing post_inference alert rule=%s", rule.name, exc_info=True
                )

        if fired:
            logger.info(
                "Post-inference alert rules fired: count=%d tenant=%s",
                len(fired),
                context.tenant_id,
            )
        return fired

    async def evaluate_all_rules(self) -> list[AlertEventRecord]:
        """Evaluate all active rules and fire alerts where conditions are met."""
        if not self._session_factory:
            return []

        from sqlalchemy import select
        from app.models.api_key import AlertRule

        fired = []
        async with self._session_factory() as db:
            result = await db.execute(
                select(AlertRule).where(AlertRule.is_active == True)
            )
            rules = result.scalars().all()

        for rule in rules:
            try:
                ctx = await self.evaluate_condition(rule.condition_type, rule.tenant_id)
                if ctx:
                    event = await self.fire_alert(str(rule.id), ctx)
                    if event.delivery_status != "cooldown":
                        fired.append(event)
            except Exception:
                logger.warning("Error evaluating rule %s", rule.name, exc_info=True)

        return fired

    async def list_events(self, limit: int = 50, tenant_id: Optional[str] = None) -> list[AlertEventRecord]:
        """List recent alert events."""
        if not self._session_factory:
            return []

        from sqlalchemy import select
        from app.models.api_key import AlertEvent

        async with self._session_factory() as db:
            query = select(AlertEvent).order_by(AlertEvent.created_at.desc()).limit(limit)
            if tenant_id:
                query = query.where(AlertEvent.tenant_id == tenant_id)
            result = await db.execute(query)
            events = []
            for e in result.scalars().all():
                meta = {}
                try:
                    meta = json.loads(e.metadata_json) if e.metadata_json else {}
                except Exception:
                    pass
                events.append(AlertEventRecord(
                    id=str(e.id),
                    alert_rule_id=str(e.alert_rule_id),
                    alert_rule_name=e.alert_rule_name,
                    condition_type=e.condition_type,
                    severity=e.severity,
                    message=e.message,
                    delivery_channel=e.delivery_channel,
                    delivery_target=e.delivery_target,
                    delivery_status=e.delivery_status,
                    tenant_id=e.tenant_id,
                    metadata=meta,
                    created_at=e.created_at.isoformat() if e.created_at else "",
                ))
            return events

    # ── Background evaluation loop ─────────────────────────────────────

    async def start(self, interval_seconds: int = 30):
        """Start the background alert evaluation loop."""
        if self._running:
            return
        self._running = True
        self._evaluation_task = asyncio.create_task(self._evaluation_loop(interval_seconds))
        logger.info("Alert engine started (interval=%ds)", interval_seconds)

    async def stop(self):
        """Stop the background evaluation loop."""
        self._running = False
        if self._evaluation_task:
            self._evaluation_task.cancel()
            try:
                await self._evaluation_task
            except asyncio.CancelledError:
                pass
            self._evaluation_task = None
        logger.info("Alert engine stopped")

    async def _evaluation_loop(self, interval: int):
        """Periodically evaluate all active rules."""
        while self._running:
            try:
                await self.evaluate_all_rules()
            except Exception:
                logger.warning("Alert evaluation cycle error", exc_info=True)
            await asyncio.sleep(interval)

    # ── Condition checks ───────────────────────────────────────────────

    async def _check_block_rate_spike(self, tenant_id: str) -> Optional[AlertTriggerContext]:
        """Check if block rate exceeds threshold in the last 5 minutes."""
        from sqlalchemy import select, func
        from app.models.api_key import AuditLog

        cutoff = time.time() - 300  # 5 minutes
        async with self._session_factory() as db:
            query = select(
                func.count(AuditLog.id),
                func.count(AuditLog.id).filter(AuditLog.action == "blocked"),
            ).where(AuditLog.event_timestamp >= cutoff)
            if tenant_id != "*":
                query = query.where(AuditLog.tenant_id == tenant_id)
            result = await db.execute(query)
            row = result.one()
            total = int(row[0])
            blocked = int(row[1])

        if total < 10:  # Minimum sample size
            return None

        block_rate = blocked / total
        threshold = 0.3  # 30% default
        if block_rate >= threshold:
            return AlertTriggerContext(
                condition_type="block_rate_spike",
                tenant_id=tenant_id,
                metric_value=round(block_rate * 100, 2),
                threshold=threshold * 100,
                message=f"Block rate spike: {block_rate*100:.1f}% (threshold: {threshold*100:.0f}%) in last 5 min",
                metadata={"total": total, "blocked": blocked},
            )
        return None

    async def _check_budget_exhaustion(self, tenant_id: str) -> Optional[AlertTriggerContext]:
        """Check if any API key is approaching budget exhaustion (>90%)."""
        from sqlalchemy import select
        from app.models.api_key import BudgetTier

        async with self._session_factory() as db:
            query = select(BudgetTier).where(BudgetTier.is_active == True)
            if tenant_id != "*":
                query = query.where(BudgetTier.tenant_id == tenant_id)
            result = await db.execute(query)
            tiers = result.scalars().all()

        # Check Redis for current usage
        from app.services.redis_client import get_redis
        r = await get_redis()
        for tier in tiers:
            budget_key = f"budget:{tier.tenant_id}"
            data = await r.hgetall(budget_key)
            if data:
                used = int(data.get("total_tokens", 0))
                if tier.token_budget > 0 and (used / tier.token_budget) >= 0.9:
                    return AlertTriggerContext(
                        condition_type="budget_exhaustion",
                        tenant_id=tier.tenant_id,
                        metric_value=round(used / tier.token_budget * 100, 1),
                        threshold=90.0,
                        message=f"Budget exhaustion: {used}/{tier.token_budget} tokens ({used/tier.token_budget*100:.0f}%) for model {tier.model_name}",
                        metadata={"model": tier.model_name, "used": used, "budget": tier.token_budget},
                    )
        return None

    async def _check_kill_switch_activation(self) -> Optional[AlertTriggerContext]:
        """Check for recently activated kill-switches."""
        from sqlalchemy import select
        from app.models.api_key import KillSwitchAuditLog

        cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
        async with self._session_factory() as db:
            result = await db.execute(
                select(KillSwitchAuditLog)
                .where(KillSwitchAuditLog.event_type == "activated")
                .where(KillSwitchAuditLog.created_at >= cutoff)
                .order_by(KillSwitchAuditLog.created_at.desc())
                .limit(1)
            )
            log = result.scalar_one_or_none()
            if log:
                return AlertTriggerContext(
                    condition_type="kill_switch_activation",
                    tenant_id="*",
                    message=f"Kill-switch activated: model={log.model_name} action={log.action} by={log.activated_by}",
                    metadata={"model": log.model_name, "action": log.action, "reason": log.reason},
                )
        return None

    async def _check_anomaly_score_breach(self, tenant_id: str) -> Optional[AlertTriggerContext]:
        """Check for high anomaly scores in recent audit logs."""
        from sqlalchemy import select, func
        from app.models.api_key import AuditLog

        cutoff = time.time() - 300
        async with self._session_factory() as db:
            query = select(func.max(AuditLog.risk_score)).where(
                AuditLog.event_timestamp >= cutoff
            )
            if tenant_id != "*":
                query = query.where(AuditLog.tenant_id == tenant_id)
            result = await db.execute(query)
            max_score = result.scalar() or 0.0

        threshold = 0.9
        if max_score >= threshold:
            return AlertTriggerContext(
                condition_type="anomaly_score_breach",
                tenant_id=tenant_id,
                metric_value=round(max_score, 3),
                threshold=threshold,
                message=f"Anomaly score breach: max risk_score={max_score:.3f} (threshold: {threshold})",
                metadata={"max_risk_score": max_score},
            )
        return None

    async def _check_new_critical_mcp_tool(self) -> Optional[AlertTriggerContext]:
        """Check for new Critical-risk MCP tools discovered recently."""
        from sqlalchemy import select
        from app.models.api_key import MCPCapability

        cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
        async with self._session_factory() as db:
            result = await db.execute(
                select(MCPCapability)
                .where(MCPCapability.risk_level == "critical")
                .where(MCPCapability.created_at >= cutoff)
                .limit(1)
            )
            cap = result.scalar_one_or_none()
            if cap:
                return AlertTriggerContext(
                    condition_type="new_critical_mcp_tool",
                    tenant_id="*",
                    message=f"New Critical-risk MCP tool discovered: {cap.tool_name}",
                    metadata={"tool_name": cap.tool_name, "risk_score": cap.risk_score},
                )
        return None

    # ── Delivery ───────────────────────────────────────────────────────

    async def _deliver_alert(self, channel: str, target: str, message: str, metadata: dict) -> str:
        """Deliver alert via email or webhook. Returns delivery status."""
        if channel == "webhook" and target:
            return await self._deliver_webhook(target, message, metadata)
        elif channel == "email" and target:
            return await self._deliver_email(target, message, metadata)
        return "no_target"

    async def _deliver_webhook(self, url: str, message: str, metadata: dict) -> str:
        """Send alert via webhook POST."""
        try:
            import httpx
            payload = {
                "text": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metadata": metadata,
            }
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code < 300:
                    return "sent"
                logger.warning("Webhook delivery failed: status=%d", resp.status_code)
                return "failed"
        except Exception:
            logger.warning("Webhook delivery error", exc_info=True)
            return "failed"

    async def _deliver_email(self, recipient: str, message: str, metadata: dict) -> str:
        """Send alert via email (placeholder — logs the email)."""
        logger.info("EMAIL ALERT to=%s message=%s", recipient, message)
        return "sent"

    # ── Helpers ─────────────────────────────────────────────────────────

    def _serialize_rule(self, rule) -> dict:
        config = {}
        try:
            config = json.loads(rule.condition_config_json) if rule.condition_config_json else {}
        except Exception:
            pass
        return {
            "id": str(rule.id),
            "name": rule.name,
            "description": rule.description,
            "condition_type": rule.condition_type,
            "condition_config": config,
            "delivery_channel": rule.delivery_channel,
            "delivery_target": rule.delivery_target,
            "cooldown_seconds": rule.cooldown_seconds,
            "last_fired_at": rule.last_fired_at.isoformat() if rule.last_fired_at else None,
            "tenant_id": rule.tenant_id,
            "is_active": rule.is_active,
            "created_at": rule.created_at.isoformat() if rule.created_at else None,
            "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
        }


# ── Singleton ──────────────────────────────────────────────────────────────

_service: Optional[AlertEngineService] = None


def get_alert_engine_service(session_factory=None) -> AlertEngineService:
    global _service
    if _service is None:
        _service = AlertEngineService(session_factory=session_factory)
    return _service
