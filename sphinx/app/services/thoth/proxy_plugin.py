"""Thoth proxy plugin — Sprint 6 / S6-T1.

Implements Thoth semantic classification as a pluggable component callable
from Sphinx's reverse proxy intercept layer.  This is the Gateway / Proxy
Integration Mode (PRD §4.2, Priority P1).

Architecture
------------
``ThothProxyPlugin`` is a thin, stateless facade over the existing
``classify_prompt()`` core and the new ``RouteConfigRegistry``.  It adds:

1. Route-level enablement gate (S6-T2): consults ``RouteConfigRegistry`` to
   determine whether classification is active for the current application.
2. Per-route setting overrides: applies route-specific timeout_ms and
   fail_closed values that supersede the global Sphinx settings.
3. Vendor tagging: attaches the resolved LLM vendor to the returned context
   metadata so that audit records carry vendor identity for parity tracking.
4. Unified entry point: ``classify_for_route()`` is the single call site used
   by the proxy router — it returns the same
   ``(ClassificationContext | None, event_type)`` tuple as ``classify_prompt()``,
   making it a drop-in replacement in proxy.py.

Data flow (S6-T1 extension to FR-PRE-01):
┌─────────────────────────────────────────────────────────┐
│                Sphinx Reverse Proxy Layer                │
│  ┌───────────────────────────────────────────────────┐  │
│  │                ThothProxyPlugin                    │  │
│  │  1. RouteConfigRegistry.get_config(app_id)        │  │
│  │  2. Check enabled flag (S6-T2)                    │  │
│  │  3. Resolve effective timeout / fail_closed       │  │
│  │  4. classify_prompt() with route context          │  │
│  │  5. Attach vendor tag to ClassificationContext    │  │
│  └──────────────────────┬────────────────────────────┘  │
│                          │ (ClassificationContext, event) │
│  ┌───────────────────────▼────────────────────────────┐  │
│  │            Sphinx Policy Engine                    │  │
│  └─────────────────────────────────────────────────── ┘  │
└─────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from app.services.thoth.classifier import classify_prompt, UNAVAILABILITY_EVENTS
from app.services.thoth.models import ClassificationContext
from app.services.thoth.route_config import (
    RouteClassificationConfig,
    get_route_config_registry,
)

logger = logging.getLogger("sphinx.thoth.proxy_plugin")

# Canonical vendor identifiers used in audit records
VENDOR_OPENAI = "openai"
VENDOR_ANTHROPIC = "anthropic"
VENDOR_AZURE_OPENAI = "azure_openai"
VENDOR_BEDROCK = "bedrock"
VENDOR_OSS = "oss"
VENDOR_UNKNOWN = "unknown"

_KNOWN_VENDORS = frozenset(
    {VENDOR_OPENAI, VENDOR_ANTHROPIC, VENDOR_AZURE_OPENAI, VENDOR_BEDROCK, VENDOR_OSS}
)


@dataclass
class ProxyClassificationResult:
    """Extended classification result carrying proxy-layer metadata.

    Wraps the standard ``(ClassificationContext, event_type)`` pair with
    route-level context needed for vendor-tagged audit records and per-route
    policy enforcement.
    """

    classification: Optional[ClassificationContext]
    event_type: str                       # classified | timeout | unavailable | …
    application_id: str
    vendor: str = VENDOR_UNKNOWN          # Resolved LLM vendor
    route_config: Optional[RouteClassificationConfig] = None

    @property
    def is_classified(self) -> bool:
        """True only when Thoth returned a live classification."""
        return self.event_type == "classified"

    @property
    def is_unavailable(self) -> bool:
        """True when Thoth was unreachable / timed out / circuit open."""
        return self.event_type in UNAVAILABILITY_EVENTS

    def to_audit_dict(self) -> dict:
        """Serialise for inclusion in Sphinx audit record metadata."""
        base: dict = {
            "proxy_plugin": True,
            "application_id": self.application_id,
            "vendor": self.vendor,
            "event_type": self.event_type,
        }
        if self.classification is not None:
            base["thoth_classification"] = self.classification.to_dict()
        if self.route_config is not None:
            base["route_config"] = self.route_config.to_dict()
        return base


# ---------------------------------------------------------------------------
# Vendor detection
# ---------------------------------------------------------------------------

def detect_vendor(
    model_name: Optional[str],
    *,
    vendor_hint: str = "auto",
    model_endpoint: str = "unknown",
) -> str:
    """Infer the LLM vendor from the model name or explicit hint.

    Priority:
    1. If ``vendor_hint`` is a known vendor string, use it directly.
    2. Infer from ``model_name`` patterns (e.g. "gpt-" → openai).
    3. Infer from ``model_endpoint`` URL patterns.
    4. Fall back to ``VENDOR_UNKNOWN``.

    This function is deterministic and has no I/O — safe to call on every
    request without performance concern.

    Args:
        model_name:     Model name from the request body (e.g. ``"gpt-4o"``).
        vendor_hint:    Explicit vendor from ``RouteClassificationConfig``.
                        ``"auto"`` triggers pattern-based detection.
        model_endpoint: Target LLM endpoint URL or name (secondary signal).

    Returns:
        Canonical vendor string from ``VENDOR_*`` constants, or
        ``VENDOR_UNKNOWN`` when detection fails.
    """
    # 1. Explicit hint overrides detection
    if vendor_hint and vendor_hint != "auto":
        normalised = vendor_hint.lower()
        if normalised in _KNOWN_VENDORS:
            return normalised
        logger.debug(
            "detect_vendor: unrecognised vendor_hint=%r, falling back to auto",
            vendor_hint,
        )

    model = (model_name or "").lower()
    endpoint = (model_endpoint or "").lower()

    # 2. Model name patterns
    if model.startswith("gpt-") or model.startswith("o1") or model.startswith("text-davinci"):
        return VENDOR_OPENAI
    if model.startswith("claude-"):
        return VENDOR_ANTHROPIC
    if model.startswith("amazon.") or model.startswith("anthropic.") and "bedrock" in endpoint:
        return VENDOR_BEDROCK
    if model.startswith("amazon."):
        return VENDOR_BEDROCK
    if model.startswith("llama") or model.startswith("mistral") or model.startswith("falcon"):
        return VENDOR_OSS
    if model.startswith("gemini"):
        # Gemini is not yet in _KNOWN_VENDORS but treat as OSS for parity
        return VENDOR_OSS

    # 3. Endpoint URL patterns
    if "openai.com" in endpoint or "azure.com" in endpoint:
        if "azure" in endpoint:
            return VENDOR_AZURE_OPENAI
        return VENDOR_OPENAI
    if "anthropic.com" in endpoint:
        return VENDOR_ANTHROPIC
    if "bedrock" in endpoint or "amazonaws.com" in endpoint:
        return VENDOR_BEDROCK

    return VENDOR_UNKNOWN


# ---------------------------------------------------------------------------
# ThothProxyPlugin
# ---------------------------------------------------------------------------

class ThothProxyPlugin:
    """Thoth classification plugin for the Sphinx reverse proxy intercept layer.

    This class is stateless — it holds no per-request state.  A single
    instance can be shared across all concurrent requests (singleton pattern).

    Usage in proxy.py:
    ------------------
        plugin = ThothProxyPlugin()
        result = await plugin.classify_for_route(
            body=body,
            application_id=project_id,
            model_name=model_name,
            tenant_id=tenant_id,
            global_thoth_enabled=settings.thoth_enabled,
            global_timeout_ms=settings.thoth_timeout_ms,
            global_fail_closed_enabled=settings.thoth_fail_closed_enabled,
            circuit_breaker_enabled=settings.thoth_circuit_breaker_enabled,
        )
    """

    async def classify_for_route(
        self,
        body: bytes,
        *,
        application_id: str,
        model_name: Optional[str] = None,
        model_endpoint: str = "unknown",
        tenant_id: str = "unknown",
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        # Global Settings values (overridable per-route)
        global_thoth_enabled: bool = False,
        global_timeout_ms: int = 150,
        global_fail_closed_enabled: bool = False,
        circuit_breaker_enabled: bool = True,
    ) -> ProxyClassificationResult:
        """Classify a prompt via Thoth with route-level policy resolution.

        This is the primary entry point for the proxy layer.  It:
        1. Resolves the ``RouteClassificationConfig`` for *application_id*.
        2. Applies the per-route ``enabled`` gate (S6-T2).
        3. Merges per-route overrides with global settings.
        4. Calls ``classify_prompt()`` with the effective configuration.
        5. Attaches vendor metadata to the result.

        Args:
            body:                    Raw HTTP request body bytes.
            application_id:          Application/project identifier.
            model_name:              Model name from the request body.
            model_endpoint:          Target LLM endpoint name.
            tenant_id:               Hashed tenant identifier.
            session_id:              Optional session correlation ID.
            request_id:              Optional Sphinx trace ID.
            global_thoth_enabled:    Global ``Settings.thoth_enabled`` flag.
            global_timeout_ms:       Global ``Settings.thoth_timeout_ms``.
            global_fail_closed_enabled: Global ``Settings.thoth_fail_closed_enabled``.
            circuit_breaker_enabled: Whether to consult the circuit breaker.

        Returns:
            ``ProxyClassificationResult`` with classification and metadata.
        """
        # 1. Resolve per-route config (S6-T2)
        registry = get_route_config_registry()
        route_cfg = registry.get_config(
            application_id,
            fallback_enabled=global_thoth_enabled,
        )

        # 2. Per-route enablement gate
        if not route_cfg.enabled:
            logger.debug(
                "ThothProxyPlugin: classification DISABLED for application_id=%s",
                application_id,
            )
            return ProxyClassificationResult(
                classification=None,
                event_type="disabled",
                application_id=application_id,
                vendor=detect_vendor(
                    model_name,
                    vendor_hint=route_cfg.vendor_hint,
                    model_endpoint=model_endpoint,
                ),
                route_config=route_cfg,
            )

        # 3. Resolve effective timeout and fail_closed (per-route overrides global)
        effective_timeout_ms = (
            route_cfg.timeout_ms
            if route_cfg.timeout_ms is not None
            else global_timeout_ms
        )
        # Note: effective_fail_closed is passed back to the caller via the result;
        # the proxy router enforces FAIL_CLOSED using should_fail_closed() as before.

        # 4. Detect vendor for audit tagging (S6-T3 parity tracking)
        vendor = detect_vendor(
            model_name,
            vendor_hint=route_cfg.vendor_hint,
            model_endpoint=model_endpoint,
        )

        logger.debug(
            "ThothProxyPlugin: classifying application_id=%s vendor=%s timeout_ms=%d",
            application_id,
            vendor,
            effective_timeout_ms,
        )

        # 5. Call core classify_prompt()
        ctx, event_type = await classify_prompt(
            body,
            tenant_id=tenant_id,
            application_id=application_id,
            model_endpoint=model_endpoint,
            session_id=session_id,
            request_id=request_id,
            timeout_ms=effective_timeout_ms,
            circuit_breaker_enabled=circuit_breaker_enabled,
        )

        # 6. Attach vendor tag to ClassificationContext (extending its metadata)
        if ctx is not None and hasattr(ctx, "__dict__"):
            # We annotate the context object with vendor info for the audit layer.
            # ClassificationContext is a dataclass so this is safe.
            ctx.__dict__.setdefault("_vendor", vendor)

        return ProxyClassificationResult(
            classification=ctx,
            event_type=event_type,
            application_id=application_id,
            vendor=vendor,
            route_config=route_cfg,
        )

    def get_effective_fail_closed(
        self,
        route_cfg: RouteClassificationConfig,
        global_fail_closed_enabled: bool,
    ) -> bool:
        """Resolve the effective fail_closed setting for a given route config.

        Per-route value takes precedence; falls back to global setting.
        """
        if route_cfg.fail_closed is not None:
            return route_cfg.fail_closed
        return global_fail_closed_enabled


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_plugin: Optional[ThothProxyPlugin] = None


def get_thoth_proxy_plugin() -> ThothProxyPlugin:
    """Return the singleton ThothProxyPlugin, creating it if needed."""
    global _plugin
    if _plugin is None:
        _plugin = ThothProxyPlugin()
    return _plugin
