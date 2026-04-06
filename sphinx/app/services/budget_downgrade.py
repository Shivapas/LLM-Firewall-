"""Budget-Triggered Downgrade — when token budget for current tier is exceeded,
downgrade to a configured cheaper model tier and log the downgrade event.

Sprint 11: Sensitivity-Based Routing & Budget Downgrade.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from app.services.redis_client import get_redis
from app.services.token_budget import get_budget_state

logger = logging.getLogger("sphinx.budget_downgrade")

BUDGET_TIER_KEY_PREFIX = "budget_tier:"


@dataclass
class BudgetTierConfig:
    """Configuration for a single budget tier."""
    model_name: str = ""
    tier_name: str = "standard"
    token_budget: int = 1_000_000
    downgrade_model: str = ""
    budget_window_seconds: int = 3600
    tenant_id: str = "*"

    def to_dict(self) -> dict:
        return {
            "model_name": self.model_name,
            "tier_name": self.tier_name,
            "token_budget": self.token_budget,
            "downgrade_model": self.downgrade_model,
            "budget_window_seconds": self.budget_window_seconds,
            "tenant_id": self.tenant_id,
        }


@dataclass
class DowngradeDecision:
    """Result of budget downgrade evaluation."""
    should_downgrade: bool = False
    original_model: str = ""
    downgrade_model: str = ""
    tier_name: str = ""
    current_usage: int = 0
    budget_limit: int = 0
    usage_pct: float = 0.0
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "should_downgrade": self.should_downgrade,
            "original_model": self.original_model,
            "downgrade_model": self.downgrade_model,
            "tier_name": self.tier_name,
            "current_usage": self.current_usage,
            "budget_limit": self.budget_limit,
            "usage_pct": round(self.usage_pct, 2),
            "reason": self.reason,
        }


class BudgetDowngradeService:
    """Evaluates whether a request should be downgraded based on token budget tiers."""

    def __init__(self):
        self._tiers: dict[str, list[BudgetTierConfig]] = {}  # model_name -> tiers

    def load_tiers(self, tiers: list[dict]) -> None:
        """Load budget tier configurations from DB records."""
        self._tiers.clear()
        for t in tiers:
            model = t.get("model_name", "")
            config = BudgetTierConfig(
                model_name=model,
                tier_name=t.get("tier_name", "standard"),
                token_budget=t.get("token_budget", 1_000_000),
                downgrade_model=t.get("downgrade_model", ""),
                budget_window_seconds=t.get("budget_window_seconds", 3600),
                tenant_id=t.get("tenant_id", "*"),
            )
            if model not in self._tiers:
                self._tiers[model] = []
            self._tiers[model].append(config)
        logger.info("Loaded budget tiers for %d models", len(self._tiers))

    async def evaluate(
        self,
        model_name: str,
        api_key_id: str,
        tenant_id: str = "",
    ) -> DowngradeDecision:
        """Check if the current model's budget is exceeded and return downgrade decision."""
        decision = DowngradeDecision(original_model=model_name)

        tiers = self._get_tiers_for_model(model_name, tenant_id)
        if not tiers:
            decision.reason = "No budget tier configured for model"
            return decision

        # Get current budget state from Redis
        budget_state = await get_budget_state(api_key_id)
        current_usage = budget_state.get("total_tokens", 0)

        # Check the first matching tier (highest priority)
        tier = tiers[0]
        decision.current_usage = current_usage
        decision.budget_limit = tier.token_budget
        decision.tier_name = tier.tier_name
        decision.usage_pct = (current_usage / tier.token_budget * 100) if tier.token_budget > 0 else 0

        if current_usage >= tier.token_budget and tier.downgrade_model:
            decision.should_downgrade = True
            decision.downgrade_model = tier.downgrade_model
            decision.reason = (
                f"Budget exceeded for {model_name} tier={tier.tier_name}: "
                f"{current_usage}/{tier.token_budget} tokens "
                f"({decision.usage_pct:.1f}%). Downgrading to {tier.downgrade_model}"
            )
            logger.warning(
                "Budget downgrade triggered: model=%s -> %s usage=%d/%d tenant=%s",
                model_name, tier.downgrade_model, current_usage, tier.token_budget, tenant_id,
            )
        else:
            decision.reason = (
                f"Budget within limits: {current_usage}/{tier.token_budget} tokens "
                f"({decision.usage_pct:.1f}%)"
            )

        return decision

    def get_budget_usage_pct(self, model_name: str, current_usage: int, tenant_id: str = "") -> float:
        """Get budget usage percentage for a model (synchronous, for routing context)."""
        tiers = self._get_tiers_for_model(model_name, tenant_id)
        if not tiers:
            return 0.0
        tier = tiers[0]
        if tier.token_budget <= 0:
            return 0.0
        return (current_usage / tier.token_budget) * 100

    def is_budget_exceeded(self, model_name: str, current_usage: int, tenant_id: str = "") -> bool:
        """Check if budget is exceeded for a model (synchronous, for routing context)."""
        tiers = self._get_tiers_for_model(model_name, tenant_id)
        if not tiers:
            return False
        return current_usage >= tiers[0].token_budget

    def _get_tiers_for_model(self, model_name: str, tenant_id: str = "") -> list[BudgetTierConfig]:
        """Get applicable tiers for a model, preferring tenant-specific over global."""
        tiers = self._tiers.get(model_name, [])
        if not tiers:
            return []

        # Prefer tenant-specific tiers, fallback to global
        tenant_tiers = [t for t in tiers if t.tenant_id == tenant_id]
        if tenant_tiers:
            return tenant_tiers
        return [t for t in tiers if t.tenant_id == "*"]


# Module-level singleton
_service: Optional[BudgetDowngradeService] = None


def get_budget_downgrade_service() -> BudgetDowngradeService:
    global _service
    if _service is None:
        _service = BudgetDowngradeService()
    return _service
