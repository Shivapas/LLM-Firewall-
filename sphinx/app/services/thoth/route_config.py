"""Route-level Thoth classification configuration — Sprint 6 / S6-T2.

Provides per-application (route-level) classification enablement so that
Thoth can be selectively activated or deactivated for different application
traffic streams flowing through Sphinx's reverse proxy layer.

Design
------
Each application is identified by its ``application_id`` (project ID).
A ``RouteClassificationConfig`` holds the enablement flag plus any per-route
overrides for timeout, fail_closed, and policy group.  The singleton
``RouteConfigRegistry`` maps application IDs to their configurations, with the
global Sphinx ``Settings.thoth_enabled`` as the default when no per-route
config is found.

FR-CFG-02: Classification enablement SHALL be configurable per policy group,
           allowing selective activation (e.g., enable for finance application
           traffic only).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("sphinx.thoth.route_config")


@dataclass
class RouteClassificationConfig:
    """Per-route (per-application) Thoth classification enablement configuration.

    Attributes:
        application_id:   Application identifier used as the registry key.
        enabled:          Whether Thoth classification is active for this route.
                          ``True`` by default; set to ``False`` to disable
                          classification for specific application traffic.
        timeout_ms:       Per-route override for the Thoth API timeout.
                          ``None`` inherits the global ``Settings.thoth_timeout_ms``.
        fail_closed:      Per-route override for FAIL_CLOSED mode.
                          ``None`` inherits ``Settings.thoth_fail_closed_enabled``.
        policy_group_id:  Optional label used to scope classification-dependent
                          policy rules to a specific policy group.
        vendor_hint:      Expected LLM vendor for this route.  One of:
                          ``"openai"``, ``"anthropic"``, ``"azure_openai"``,
                          ``"bedrock"``, ``"oss"``, or ``"auto"`` (default).
                          Used by the proxy plugin for vendor-tagged audit records.
    """

    application_id: str
    enabled: bool = True
    timeout_ms: Optional[int] = None      # None → inherit global setting
    fail_closed: Optional[bool] = None    # None → inherit global setting
    policy_group_id: str = ""
    vendor_hint: str = "auto"

    def to_dict(self) -> dict:
        return {
            "application_id": self.application_id,
            "enabled": self.enabled,
            "timeout_ms": self.timeout_ms,
            "fail_closed": self.fail_closed,
            "policy_group_id": self.policy_group_id,
            "vendor_hint": self.vendor_hint,
        }


class RouteConfigRegistry:
    """Registry mapping application_id → RouteClassificationConfig.

    Thread-safe for concurrent reads after ``load_configs()`` completes.
    Hot-reload is supported via a second ``load_configs()`` call which
    atomically replaces the config dict.

    Lifecycle:
    ----------
    1. ``load_configs(list[dict])`` — called at startup from the admin API or
       an on-disk configuration file.
    2. ``get_config(application_id)`` — called per-request by the proxy plugin
       to resolve the effective config for an incoming application request.
    3. ``register_config()`` / ``remove_config()`` — used by the admin API for
       real-time config updates without a full reload.
    """

    def __init__(self) -> None:
        self._configs: dict[str, RouteClassificationConfig] = {}

    # ------------------------------------------------------------------
    # Configuration management
    # ------------------------------------------------------------------

    def load_configs(self, configs: list[dict]) -> None:
        """Load per-route configurations from a list of config dicts.

        Atomically replaces the current registry contents.  Any application ID
        not present in *configs* will fall back to the global default on the
        next ``get_config()`` call.

        Args:
            configs: List of dicts, each with at minimum ``application_id``.
                     All other keys are optional and map to
                     ``RouteClassificationConfig`` fields.
        """
        loaded: dict[str, RouteClassificationConfig] = {}
        for cfg in configs:
            app_id = cfg.get("application_id", "")
            if not app_id:
                logger.warning(
                    "RouteConfigRegistry: skipping entry with empty application_id"
                )
                continue
            loaded[app_id] = RouteClassificationConfig(
                application_id=app_id,
                enabled=cfg.get("enabled", True),
                timeout_ms=cfg.get("timeout_ms"),
                fail_closed=cfg.get("fail_closed"),
                policy_group_id=cfg.get("policy_group_id", ""),
                vendor_hint=cfg.get("vendor_hint", "auto"),
            )

        self._configs = loaded
        logger.info(
            "RouteConfigRegistry: loaded %d per-route config(s)",
            len(loaded),
        )

    def register_config(self, config: RouteClassificationConfig) -> None:
        """Register or replace a per-route configuration.

        Idempotent: calling with an existing application_id replaces the
        previous configuration.
        """
        self._configs[config.application_id] = config
        logger.info(
            "RouteConfigRegistry: registered application_id=%s enabled=%s "
            "policy_group=%s vendor_hint=%s",
            config.application_id,
            config.enabled,
            config.policy_group_id or "(none)",
            config.vendor_hint,
        )

    def remove_config(self, application_id: str) -> bool:
        """Remove a per-route configuration.

        Returns:
            ``True`` if the config existed and was removed; ``False`` otherwise.
        """
        removed = self._configs.pop(application_id, None)
        if removed:
            logger.info(
                "RouteConfigRegistry: removed config for application_id=%s",
                application_id,
            )
        return removed is not None

    # ------------------------------------------------------------------
    # Per-request lookup
    # ------------------------------------------------------------------

    def get_config(
        self,
        application_id: str,
        *,
        fallback_enabled: bool = True,
    ) -> RouteClassificationConfig:
        """Return the RouteClassificationConfig for *application_id*.

        If no per-route config is registered for the given application,
        returns a default config that inherits ``fallback_enabled`` from the
        global ``Settings.thoth_enabled``.  This ensures every application
        request has a valid config object without requiring explicit
        per-application registration.

        Args:
            application_id:  Application/project identifier from the request.
            fallback_enabled: Default enablement state (from
                              ``Settings.thoth_enabled``).

        Returns:
            ``RouteClassificationConfig`` — either the registered per-route
            config or a default synthesised from the global settings.
        """
        config = self._configs.get(application_id)
        if config is not None:
            return config

        # No explicit per-route config → synthesise a default
        return RouteClassificationConfig(
            application_id=application_id,
            enabled=fallback_enabled,
        )

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    def list_configs(self) -> list[RouteClassificationConfig]:
        """Return all registered per-route configurations (copy)."""
        return list(self._configs.values())

    def count(self) -> int:
        """Return the number of registered per-route configurations."""
        return len(self._configs)


# ---------------------------------------------------------------------------
# Singleton lifecycle
# ---------------------------------------------------------------------------

_registry: Optional[RouteConfigRegistry] = None


def get_route_config_registry() -> RouteConfigRegistry:
    """Return the singleton RouteConfigRegistry, creating it if needed."""
    global _registry
    if _registry is None:
        _registry = RouteConfigRegistry()
    return _registry


def reset_route_config_registry() -> None:
    """Reset the singleton (used in tests and startup re-initialisation)."""
    global _registry
    _registry = None
