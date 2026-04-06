"""Sprint 19: Onboarding Wizard.

Step-by-step onboarding:
1. Register first model
2. Issue first API key
3. Point test request at gateway
4. Verify first audit log entry
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("sphinx.dashboard.onboarding")


ONBOARDING_STEPS = [
    {
        "key": "step_register_model",
        "title": "Register your first model",
        "description": "Configure at least one LLM provider (OpenAI, Anthropic, etc.) via the Admin API.",
        "help_url": "/admin/providers",
    },
    {
        "key": "step_issue_api_key",
        "title": "Issue your first API key",
        "description": "Create an API key for your tenant via POST /admin/keys.",
        "help_url": "/admin/keys",
    },
    {
        "key": "step_send_test_request",
        "title": "Send a test request",
        "description": "Point a test request at the Sphinx gateway proxy endpoint.",
        "help_url": "/proxy/openai/v1/chat/completions",
    },
    {
        "key": "step_verify_audit_log",
        "title": "Verify audit log entry",
        "description": "Confirm your test request appears in the audit log via GET /admin/audit/logs.",
        "help_url": "/admin/audit/logs",
    },
]


class OnboardingStatus(BaseModel):
    tenant_id: str = ""
    steps: list[dict] = Field(default_factory=list)
    current_step: int = 0
    total_steps: int = 4
    completed: bool = False
    completed_at: Optional[str] = None
    progress_percentage: float = 0.0


class OnboardingWizardService:
    """Manages onboarding progress per tenant."""

    def __init__(self, session_factory=None):
        self._session_factory = session_factory

    async def get_status(self, tenant_id: str) -> OnboardingStatus:
        """Get current onboarding status for a tenant."""
        progress = await self._get_or_create_progress(tenant_id)
        return self._to_status(tenant_id, progress)

    async def complete_step(self, tenant_id: str, step_key: str) -> OnboardingStatus:
        """Mark an onboarding step as complete."""
        valid_keys = {s["key"] for s in ONBOARDING_STEPS}
        if step_key not in valid_keys:
            raise ValueError(f"Invalid step key: {step_key}")

        progress = await self._get_or_create_progress(tenant_id)

        if self._session_factory:
            from sqlalchemy import select
            from app.models.api_key import OnboardingProgress

            async with self._session_factory() as db:
                result = await db.execute(
                    select(OnboardingProgress).where(OnboardingProgress.tenant_id == tenant_id)
                )
                record = result.scalar_one_or_none()
                if record:
                    setattr(record, step_key, True)
                    # Check if all steps are done
                    all_done = all(
                        getattr(record, s["key"]) for s in ONBOARDING_STEPS
                    )
                    if all_done and not record.completed:
                        record.completed = True
                        record.completed_at = datetime.now(timezone.utc)
                    await db.commit()
                    await db.refresh(record)
                    progress = record

        logger.info("Onboarding step completed: tenant=%s step=%s", tenant_id, step_key)
        return self._to_status(tenant_id, progress)

    async def reset_progress(self, tenant_id: str) -> OnboardingStatus:
        """Reset onboarding progress for a tenant."""
        if self._session_factory:
            from sqlalchemy import select
            from app.models.api_key import OnboardingProgress

            async with self._session_factory() as db:
                result = await db.execute(
                    select(OnboardingProgress).where(OnboardingProgress.tenant_id == tenant_id)
                )
                record = result.scalar_one_or_none()
                if record:
                    for step in ONBOARDING_STEPS:
                        setattr(record, step["key"], False)
                    record.completed = False
                    record.completed_at = None
                    await db.commit()
                    await db.refresh(record)
                    return self._to_status(tenant_id, record)

        return OnboardingStatus(tenant_id=tenant_id, steps=self._build_steps(None))

    async def auto_detect_progress(self, tenant_id: str) -> OnboardingStatus:
        """Auto-detect onboarding progress by checking system state."""
        if not self._session_factory:
            return OnboardingStatus(tenant_id=tenant_id)

        from sqlalchemy import select, func
        from app.models.api_key import ProviderCredential, APIKey, AuditLog, OnboardingProgress

        async with self._session_factory() as db:
            # Check model registration
            providers = await db.execute(
                select(func.count(ProviderCredential.id)).where(ProviderCredential.is_enabled == True)
            )
            has_model = int(providers.scalar() or 0) > 0

            # Check API key
            keys = await db.execute(
                select(func.count(APIKey.id))
                .where(APIKey.tenant_id == tenant_id)
                .where(APIKey.is_active == True)
            )
            has_key = int(keys.scalar() or 0) > 0

            # Check test request (any audit log for this tenant)
            audits = await db.execute(
                select(func.count(AuditLog.id)).where(AuditLog.tenant_id == tenant_id)
            )
            has_request = int(audits.scalar() or 0) > 0

            # Verify audit log = has_request (same check)
            has_audit = has_request

            # Update progress record
            result = await db.execute(
                select(OnboardingProgress).where(OnboardingProgress.tenant_id == tenant_id)
            )
            record = result.scalar_one_or_none()
            if not record:
                record = OnboardingProgress(
                    id=uuid.uuid4(),
                    tenant_id=tenant_id,
                )
                db.add(record)

            record.step_register_model = has_model
            record.step_issue_api_key = has_key
            record.step_send_test_request = has_request
            record.step_verify_audit_log = has_audit

            all_done = has_model and has_key and has_request and has_audit
            if all_done and not record.completed:
                record.completed = True
                record.completed_at = datetime.now(timezone.utc)

            await db.commit()
            await db.refresh(record)

        return self._to_status(tenant_id, record)

    async def _get_or_create_progress(self, tenant_id: str):
        """Get or create onboarding progress record."""
        if not self._session_factory:
            return None

        from sqlalchemy import select
        from app.models.api_key import OnboardingProgress

        async with self._session_factory() as db:
            result = await db.execute(
                select(OnboardingProgress).where(OnboardingProgress.tenant_id == tenant_id)
            )
            record = result.scalar_one_or_none()
            if not record:
                record = OnboardingProgress(
                    id=uuid.uuid4(),
                    tenant_id=tenant_id,
                )
                db.add(record)
                await db.commit()
                await db.refresh(record)
            return record

    def _to_status(self, tenant_id: str, progress) -> OnboardingStatus:
        steps = self._build_steps(progress)
        completed_count = sum(1 for s in steps if s["completed"])

        current_step = 0
        for i, s in enumerate(steps):
            if not s["completed"]:
                current_step = i
                break
        else:
            current_step = len(steps)

        is_completed = progress.completed if progress and hasattr(progress, "completed") else False
        completed_at = None
        if progress and hasattr(progress, "completed_at") and progress.completed_at:
            completed_at = progress.completed_at.isoformat()

        return OnboardingStatus(
            tenant_id=tenant_id,
            steps=steps,
            current_step=current_step,
            total_steps=len(ONBOARDING_STEPS),
            completed=is_completed,
            completed_at=completed_at,
            progress_percentage=round((completed_count / len(ONBOARDING_STEPS)) * 100, 1),
        )

    def _build_steps(self, progress) -> list[dict]:
        steps = []
        for step_info in ONBOARDING_STEPS:
            completed = False
            if progress and hasattr(progress, step_info["key"]):
                completed = getattr(progress, step_info["key"])
            steps.append({
                "key": step_info["key"],
                "title": step_info["title"],
                "description": step_info["description"],
                "help_url": step_info["help_url"],
                "completed": completed,
            })
        return steps


# ── Singleton ──────────────────────────────────────────────────────────────

_service: Optional[OnboardingWizardService] = None


def get_onboarding_wizard_service(session_factory=None) -> OnboardingWizardService:
    global _service
    if _service is None:
        _service = OnboardingWizardService(session_factory=session_factory)
    return _service
