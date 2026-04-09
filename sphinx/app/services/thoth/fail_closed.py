"""FAIL_CLOSED enforcement logic for Thoth classification unavailability.

Sprint 2 / S2-T3: When Thoth is unavailable and fail_closed mode is enabled,
block requests whose structural risk level meets the configured threshold
(default: HIGH or CRITICAL), rather than falling back silently.

Requirement reference
---------------------
FR-PRE-07:
  If Thoth returns an error or is unavailable, Sphinx SHALL FAIL_CLOSED on
  high-sensitivity policy rules and log a classification unavailability event.

FR-POL-05:
  Policy rules referencing classification attributes SHALL degrade gracefully
  when classification is unavailable (configurable: skip rule, use fallback
  action, or FAIL_CLOSED).

Design
------
FAIL_CLOSED is deliberately a narrow gate:
  - It fires only when the Thoth call was attempted and failed (timeout,
    unavailable, or circuit-open).  It does NOT fire when Thoth is disabled.
  - It relies solely on Sphinx's own structural risk assessment (Tier 1+2
    threat detection output) — not on anything from Thoth — so the fallback
    decision is always well-defined.
  - ``fail_closed_enabled`` defaults to False to ensure backwards-compatible
    behaviour for existing deployments.

Usage (from proxy.py)
---------------------
    from app.services.thoth.fail_closed import should_fail_closed

    if should_fail_closed(
        classification_event=classification_event,
        structural_risk_level=threat_result.risk_level,
        fail_closed_enabled=settings.thoth_fail_closed_enabled,
        fail_closed_risk_levels=settings.thoth_fail_closed_risk_levels,
    ):
        return JSONResponse(status_code=403, content={...})
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("sphinx.thoth.fail_closed")

# Events that indicate Thoth was unavailable (not merely disabled)
_UNAVAILABILITY_EVENTS: frozenset[str] = frozenset(
    {"timeout", "unavailable", "circuit_open"}
)

# Default structural risk levels that trigger FAIL_CLOSED blocking
_DEFAULT_FAIL_CLOSED_LEVELS: frozenset[str] = frozenset({"HIGH", "CRITICAL"})


def should_fail_closed(
    *,
    classification_event: str,
    structural_risk_level: str,
    fail_closed_enabled: bool,
    fail_closed_risk_levels: Optional[str] = None,
) -> bool:
    """Return True if the request should be blocked due to FAIL_CLOSED policy.

    Args:
        classification_event:   Event type returned by ``classify_prompt()``.
                                One of: ``"classified"``, ``"timeout"``,
                                ``"unavailable"``, ``"circuit_open"``,
                                ``"disabled"``, ``"no_content"``.
        structural_risk_level:  Risk level string from Sphinx's own threat
                                detection (e.g. ``"low"``, ``"medium"``,
                                ``"high"``, ``"critical"``).  Case-insensitive.
        fail_closed_enabled:    Master switch from Settings. If False, this
                                function always returns False.
        fail_closed_risk_levels: Comma-separated string of risk levels that
                                trigger blocking (e.g. ``"HIGH,CRITICAL"``).
                                Defaults to ``"HIGH,CRITICAL"`` when None.

    Returns:
        True  → caller MUST block the request and emit a FAIL_CLOSED audit event.
        False → caller proceeds with structural-only enforcement.
    """
    if not fail_closed_enabled:
        return False

    if classification_event not in _UNAVAILABILITY_EVENTS:
        # Classification succeeded, was disabled, or had no content — no block
        return False

    # Parse configured risk levels (normalise to uppercase)
    if fail_closed_risk_levels:
        effective_levels: frozenset[str] = frozenset(
            lvl.strip().upper()
            for lvl in fail_closed_risk_levels.split(",")
            if lvl.strip()
        )
    else:
        effective_levels = _DEFAULT_FAIL_CLOSED_LEVELS

    if structural_risk_level.upper() in effective_levels:
        logger.warning(
            "FAIL_CLOSED: blocking request — "
            "classification_event=%s structural_risk=%s configured_levels=%s",
            classification_event,
            structural_risk_level,
            ",".join(sorted(effective_levels)),
        )
        return True

    return False
