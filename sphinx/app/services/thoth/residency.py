"""On-prem / VPC Thoth endpoint support with data residency tagging — Sprint 7 / S7-T1.

Implements endpoint URL override with residency tagging so that Sphinx can
route Thoth classification calls to region-specific (on-prem or VPC) Thoth
deployments, satisfying Indian data residency requirements (DPDPA, RBI, CERT-In).

Design
------
``ResidencyConfig`` captures the deployment topology for a given Thoth endpoint:
- ``region``: geographic region code (e.g. ``"in-mum-1"`` for Mumbai).
- ``deployment_mode``: ``"saas"`` | ``"vpc"`` | ``"on_prem"``.
- ``data_residency_zone``: regulatory zone label (e.g. ``"INDIA"``, ``"EU"``).
- ``endpoint_url_override``: if set, replaces the global ``thoth_api_url``
  for all classification calls routed through this residency config.

``ResidencyConfigRegistry`` maps application IDs (or wildcard ``"*"``) to
residency configurations.  The proxy plugin and classifier consult the
registry to resolve the effective Thoth endpoint for each request.

Requirement references
----------------------
FR-CFG-04:  Thoth on-prem / VPC deployment configurations SHALL be supported
            via endpoint URL override.
PRD §9:     Data residency non-compliance (DPDPA/RBI) mitigated by mandatory
            on-prem or VPC Thoth deployment for regulated workloads.
NFR:        Data Residency — Thoth deployment model (SaaS / VPC / on-prem)
            must be selectable to satisfy Indian data residency requirements.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("sphinx.thoth.residency")

# Supported deployment modes
DEPLOY_SAAS = "saas"
DEPLOY_VPC = "vpc"
DEPLOY_ON_PREM = "on_prem"

_VALID_DEPLOY_MODES = frozenset({DEPLOY_SAAS, DEPLOY_VPC, DEPLOY_ON_PREM})

# Predefined residency zones aligned with regulatory regimes
ZONE_INDIA = "INDIA"
ZONE_EU = "EU"
ZONE_US = "US"
ZONE_GLOBAL = "GLOBAL"

_VALID_ZONES = frozenset({ZONE_INDIA, ZONE_EU, ZONE_US, ZONE_GLOBAL})

# Indian regulatory tags applied to residency-tagged audit records
DPDPA_TAG = "DPDPA_COMPLIANT"
RBI_TAG = "RBI_DATA_LOCALISATION"
CERT_IN_TAG = "CERT_IN_REPORTABLE"


@dataclass
class ResidencyConfig:
    """Data residency configuration for a Thoth endpoint deployment.

    Attributes:
        config_id:              Unique identifier for this config entry.
        application_id:         Application scope — ``"*"`` for global default.
        region:                 Geographic region code (e.g. ``"in-mum-1"``).
        deployment_mode:        ``"saas"`` | ``"vpc"`` | ``"on_prem"``.
        data_residency_zone:    Regulatory zone label (``"INDIA"``, ``"EU"``, etc.).
        endpoint_url_override:  Thoth API URL override for this deployment.
                                ``None`` means use the global ``thoth_api_url``.
        regulatory_tags:        List of regulatory compliance tags applied to
                                audit records for requests routed through this
                                endpoint (e.g. ``["DPDPA_COMPLIANT"]``).
        require_on_prem:        If True, classification calls MUST use the
                                override endpoint; global SaaS fallback is
                                prohibited for this application scope.
    """

    config_id: str = ""
    application_id: str = "*"
    region: str = ""
    deployment_mode: str = DEPLOY_SAAS
    data_residency_zone: str = ZONE_GLOBAL
    endpoint_url_override: Optional[str] = None
    regulatory_tags: list[str] = field(default_factory=list)
    require_on_prem: bool = False

    def to_dict(self) -> dict:
        return {
            "config_id": self.config_id,
            "application_id": self.application_id,
            "region": self.region,
            "deployment_mode": self.deployment_mode,
            "data_residency_zone": self.data_residency_zone,
            "endpoint_url_override": self.endpoint_url_override,
            "regulatory_tags": self.regulatory_tags,
            "require_on_prem": self.require_on_prem,
        }

    @property
    def is_india_residency(self) -> bool:
        """True if this config targets Indian data residency."""
        return self.data_residency_zone == ZONE_INDIA

    @property
    def is_local_deployment(self) -> bool:
        """True if the Thoth deployment is on-prem or VPC (not SaaS)."""
        return self.deployment_mode in (DEPLOY_VPC, DEPLOY_ON_PREM)


@dataclass
class ResidencyResolution:
    """Result of resolving the effective Thoth endpoint for a request.

    Returned by ``ResidencyConfigRegistry.resolve()`` and consumed by the
    classifier/proxy plugin to determine which Thoth URL to call.
    """

    effective_url: Optional[str]      # None → use global thoth_api_url
    residency_config: Optional[ResidencyConfig]
    regulatory_tags: list[str] = field(default_factory=list)
    deployment_mode: str = DEPLOY_SAAS
    data_residency_zone: str = ZONE_GLOBAL
    blocked: bool = False             # True if require_on_prem and no override URL
    block_reason: str = ""

    def to_audit_dict(self) -> dict:
        """Serialise residency metadata for inclusion in audit records."""
        result: dict = {
            "data_residency_zone": self.data_residency_zone,
            "deployment_mode": self.deployment_mode,
            "regulatory_tags": self.regulatory_tags,
        }
        if self.residency_config:
            result["region"] = self.residency_config.region
            result["config_id"] = self.residency_config.config_id
        if self.blocked:
            result["blocked"] = True
            result["block_reason"] = self.block_reason
        return result


class ResidencyConfigRegistry:
    """Registry mapping application_id → ResidencyConfig for endpoint routing.

    Supports a global default (``application_id == "*"``) and per-application
    overrides.  The global default is used when no application-specific config
    is registered.

    Lifecycle:
    ----------
    1. ``load_configs(list[dict])`` — bulk load from config file or admin API.
    2. ``register_config()`` — add/replace a single config entry.
    3. ``resolve(application_id)`` — per-request resolution of effective endpoint.
    """

    def __init__(self) -> None:
        self._configs: dict[str, ResidencyConfig] = {}

    def load_configs(self, configs: list[dict]) -> None:
        """Bulk load residency configurations. Replaces all existing entries."""
        loaded: dict[str, ResidencyConfig] = {}
        for cfg in configs:
            app_id = cfg.get("application_id", "*")
            loaded[app_id] = ResidencyConfig(
                config_id=cfg.get("config_id", ""),
                application_id=app_id,
                region=cfg.get("region", ""),
                deployment_mode=cfg.get("deployment_mode", DEPLOY_SAAS),
                data_residency_zone=cfg.get("data_residency_zone", ZONE_GLOBAL),
                endpoint_url_override=cfg.get("endpoint_url_override"),
                regulatory_tags=cfg.get("regulatory_tags", []),
                require_on_prem=cfg.get("require_on_prem", False),
            )
        self._configs = loaded
        logger.info(
            "ResidencyConfigRegistry: loaded %d config(s)", len(loaded)
        )

    def register_config(self, config: ResidencyConfig) -> None:
        """Register or replace a residency configuration."""
        self._configs[config.application_id] = config
        logger.info(
            "ResidencyConfigRegistry: registered application_id=%s zone=%s "
            "mode=%s region=%s override_url=%s",
            config.application_id,
            config.data_residency_zone,
            config.deployment_mode,
            config.region,
            config.endpoint_url_override or "(global)",
        )

    def remove_config(self, application_id: str) -> bool:
        """Remove a residency configuration. Returns True if it existed."""
        removed = self._configs.pop(application_id, None)
        return removed is not None

    def resolve(
        self,
        application_id: str,
        *,
        global_thoth_url: str = "",
    ) -> ResidencyResolution:
        """Resolve the effective Thoth endpoint and residency metadata.

        Priority:
        1. Application-specific config (exact match on application_id).
        2. Global default config (application_id == "*").
        3. No residency config → use global thoth_api_url with GLOBAL zone.

        Args:
            application_id: Application/project identifier from the request.
            global_thoth_url: Global ``Settings.thoth_api_url`` fallback.

        Returns:
            ``ResidencyResolution`` with the effective URL and metadata.
        """
        # 1. Application-specific config
        config = self._configs.get(application_id)

        # 2. Global wildcard fallback
        if config is None:
            config = self._configs.get("*")

        # 3. No config at all
        if config is None:
            return ResidencyResolution(
                effective_url=None,
                residency_config=None,
                deployment_mode=DEPLOY_SAAS,
                data_residency_zone=ZONE_GLOBAL,
            )

        effective_url = config.endpoint_url_override

        # Check require_on_prem constraint
        if config.require_on_prem and not effective_url:
            logger.warning(
                "ResidencyConfigRegistry: require_on_prem is True but no "
                "endpoint_url_override for application_id=%s — blocking",
                application_id,
            )
            return ResidencyResolution(
                effective_url=None,
                residency_config=config,
                regulatory_tags=config.regulatory_tags,
                deployment_mode=config.deployment_mode,
                data_residency_zone=config.data_residency_zone,
                blocked=True,
                block_reason=(
                    "require_on_prem is True but no endpoint_url_override "
                    f"configured for application_id={application_id}"
                ),
            )

        return ResidencyResolution(
            effective_url=effective_url,
            residency_config=config,
            regulatory_tags=config.regulatory_tags,
            deployment_mode=config.deployment_mode,
            data_residency_zone=config.data_residency_zone,
        )

    def list_configs(self) -> list[ResidencyConfig]:
        """Return all registered residency configurations."""
        return list(self._configs.values())

    def get_india_configs(self) -> list[ResidencyConfig]:
        """Return all configs targeting Indian data residency."""
        return [c for c in self._configs.values() if c.is_india_residency]

    def count(self) -> int:
        return len(self._configs)


# ---------------------------------------------------------------------------
# Singleton lifecycle
# ---------------------------------------------------------------------------

_registry: Optional[ResidencyConfigRegistry] = None


def get_residency_config_registry() -> ResidencyConfigRegistry:
    """Return the singleton ResidencyConfigRegistry, creating it if needed."""
    global _registry
    if _registry is None:
        _registry = ResidencyConfigRegistry()
    return _registry


def reset_residency_config_registry() -> None:
    """Reset the singleton (used in tests and startup re-initialisation)."""
    global _registry
    _registry = None
