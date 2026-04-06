"""Routing Decision Audit Log — records detailed routing decisions in the audit trail.

Sprint 11: Sensitivity-Based Routing & Budget Downgrade.

Records which rules were evaluated, which model was selected, and the reason
for selection in the audit event metadata.
"""

from __future__ import annotations

import logging
from typing import Optional

from app.services.audit import emit_audit_event
from app.services.routing_policy import RoutingDecision, RoutingAction

logger = logging.getLogger("sphinx.routing_audit")


async def emit_routing_audit_event(
    request_body: bytes,
    decision: RoutingDecision,
    tenant_id: str = "",
    project_id: str = "",
    api_key_id: str = "",
    downgrade_info: Optional[dict] = None,
    extra_metadata: Optional[dict] = None,
) -> None:
    """Emit an audit event recording the routing decision.

    This creates a dedicated audit record that captures:
    - Which routing rules were evaluated
    - Which model was selected and why
    - Whether a sensitivity-based reroute or budget downgrade occurred
    """
    # Determine the audit action based on routing decision
    if decision.action == RoutingAction.ROUTE and decision.target_model != decision.original_model:
        action = "routed_sensitivity"
    elif decision.action == RoutingAction.DOWNGRADE:
        action = "downgraded_budget"
    elif decision.action == RoutingAction.BLOCK:
        action = "blocked_routing"
    elif decision.action == RoutingAction.DEFAULT:
        action = "routed_default"
    else:
        action = "routed"

    metadata = {
        "routing_decision": decision.to_dict(),
    }
    if downgrade_info:
        metadata["budget_downgrade"] = downgrade_info
    if extra_metadata:
        metadata.update(extra_metadata)

    try:
        await emit_audit_event(
            request_body=request_body,
            tenant_id=tenant_id,
            project_id=project_id,
            api_key_id=api_key_id,
            model=decision.target_model or decision.original_model,
            provider=decision.target_provider,
            action=action,
            status_code=200 if decision.action != RoutingAction.BLOCK else 403,
            metadata=metadata,
        )
        logger.debug(
            "Routing audit event emitted: action=%s model=%s->%s rule=%s",
            action,
            decision.original_model,
            decision.target_model,
            decision.matched_rule_name,
        )
    except Exception:
        logger.warning("Failed to emit routing audit event", exc_info=True)
