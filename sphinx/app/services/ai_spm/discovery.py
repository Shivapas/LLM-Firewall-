"""AI-SPM Integration (Shadow AI Discovery) — Sprint 29.

Connect Sphinx gateway to AI Security Posture Management (AISPM) asset
inventory.  Discovered AI assets not routing through the gateway are flagged
as ungoverned in the dashboard.  Enrollment flow to onboard them.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger("sphinx.ai_spm.discovery")


class AssetStatus(str, Enum):
    GOVERNED = "governed"           # Routed through Sphinx gateway
    UNGOVERNED = "ungoverned"       # Discovered but not routed
    PENDING_ENROLLMENT = "pending_enrollment"
    ENROLLED = "enrolled"           # Enrollment complete
    IGNORED = "ignored"             # Admin chose to ignore


class AssetType(str, Enum):
    LLM_API = "llm_api"
    EMBEDDING_API = "embedding_api"
    AGENT = "agent"
    FINE_TUNED_MODEL = "fine_tuned_model"
    RAG_PIPELINE = "rag_pipeline"
    CHATBOT = "chatbot"
    OTHER = "other"


@dataclass
class AIAsset:
    """A discovered AI asset in the organization."""
    asset_id: str = ""
    name: str = ""
    asset_type: str = "llm_api"
    provider: str = ""              # e.g. "openai", "anthropic", "internal"
    endpoint: str = ""              # API endpoint or service URL
    tenant_id: str = ""
    team: str = ""                  # team/department that owns the asset
    status: str = "ungoverned"
    risk_level: str = "medium"      # low, medium, high, critical
    discovered_at: str = ""
    enrolled_at: str = ""
    last_seen_at: str = ""
    discovery_source: str = ""      # network_scan, api_log, manual, cloud_audit
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "asset_type": self.asset_type,
            "provider": self.provider,
            "endpoint": self.endpoint,
            "tenant_id": self.tenant_id,
            "team": self.team,
            "status": self.status,
            "risk_level": self.risk_level,
            "discovered_at": self.discovered_at,
            "enrolled_at": self.enrolled_at,
            "last_seen_at": self.last_seen_at,
            "discovery_source": self.discovery_source,
            "metadata": self.metadata,
        }


@dataclass
class EnrollmentRequest:
    """Request to enroll an ungoverned AI asset into the Sphinx gateway."""
    request_id: str = ""
    asset_id: str = ""
    requested_by: str = ""
    routing_policy: str = ""       # policy to apply after enrollment
    status: str = "pending"        # pending, approved, rejected
    created_at: str = ""
    resolved_at: str = ""
    resolution_note: str = ""

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "asset_id": self.asset_id,
            "requested_by": self.requested_by,
            "routing_policy": self.routing_policy,
            "status": self.status,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
            "resolution_note": self.resolution_note,
        }


class AISPMDiscoveryService:
    """Manages the AI asset inventory and shadow AI discovery workflow.

    Responsibilities:
    - Maintain inventory of all known AI assets
    - Flag assets not routing through Sphinx as ungoverned
    - Provide enrollment flow to bring shadow AI under governance
    - Dashboard integration for visibility
    """

    def __init__(self) -> None:
        self._assets: dict[str, AIAsset] = {}
        self._enrollment_requests: dict[str, EnrollmentRequest] = {}
        # Set of endpoint hashes that are routed through the gateway
        self._governed_endpoints: set[str] = set()
        self._stats: dict[str, int] = {
            "total_assets": 0,
            "governed_assets": 0,
            "ungoverned_assets": 0,
            "pending_enrollments": 0,
            "completed_enrollments": 0,
        }

    def register_governed_endpoint(self, endpoint: str) -> None:
        """Register an endpoint as routed through the Sphinx gateway."""
        self._governed_endpoints.add(endpoint)

    def discover_asset(
        self,
        name: str,
        asset_type: str = "llm_api",
        provider: str = "",
        endpoint: str = "",
        tenant_id: str = "",
        team: str = "",
        discovery_source: str = "network_scan",
        risk_level: str = "medium",
        metadata: dict[str, Any] | None = None,
    ) -> AIAsset:
        """Register a newly discovered AI asset.

        Automatically determines governed/ungoverned status based on
        whether the endpoint is registered with the gateway.
        """
        now = datetime.now(timezone.utc).isoformat()
        is_governed = endpoint in self._governed_endpoints

        asset = AIAsset(
            asset_id=str(uuid.uuid4()),
            name=name,
            asset_type=asset_type,
            provider=provider,
            endpoint=endpoint,
            tenant_id=tenant_id,
            team=team,
            status=AssetStatus.GOVERNED.value if is_governed else AssetStatus.UNGOVERNED.value,
            risk_level=risk_level,
            discovered_at=now,
            last_seen_at=now,
            discovery_source=discovery_source,
            metadata=metadata or {},
        )

        self._assets[asset.asset_id] = asset
        self._stats["total_assets"] += 1

        if is_governed:
            self._stats["governed_assets"] += 1
        else:
            self._stats["ungoverned_assets"] += 1
            logger.warning(
                "Ungoverned AI asset discovered: name=%s provider=%s endpoint=%s team=%s",
                name, provider, endpoint, team,
            )

        return asset

    def update_asset_activity(self, asset_id: str) -> bool:
        """Update last_seen timestamp for an asset."""
        asset = self._assets.get(asset_id)
        if asset is None:
            return False
        asset.last_seen_at = datetime.now(timezone.utc).isoformat()
        return True

    def request_enrollment(
        self,
        asset_id: str,
        requested_by: str = "system",
        routing_policy: str = "default",
    ) -> EnrollmentRequest | None:
        """Create an enrollment request for an ungoverned asset."""
        asset = self._assets.get(asset_id)
        if asset is None:
            return None
        if asset.status not in (AssetStatus.UNGOVERNED.value, AssetStatus.IGNORED.value):
            return None

        now = datetime.now(timezone.utc).isoformat()
        req = EnrollmentRequest(
            request_id=str(uuid.uuid4()),
            asset_id=asset_id,
            requested_by=requested_by,
            routing_policy=routing_policy,
            status="pending",
            created_at=now,
        )

        self._enrollment_requests[req.request_id] = req
        asset.status = AssetStatus.PENDING_ENROLLMENT.value
        self._stats["pending_enrollments"] += 1

        logger.info(
            "Enrollment requested: asset=%s name=%s requested_by=%s",
            asset_id, asset.name, requested_by,
        )
        return req

    def approve_enrollment(
        self,
        request_id: str,
        resolution_note: str = "",
    ) -> bool:
        """Approve an enrollment request and mark the asset as enrolled."""
        req = self._enrollment_requests.get(request_id)
        if req is None or req.status != "pending":
            return False

        asset = self._assets.get(req.asset_id)
        if asset is None:
            return False

        now = datetime.now(timezone.utc).isoformat()
        req.status = "approved"
        req.resolved_at = now
        req.resolution_note = resolution_note

        asset.status = AssetStatus.ENROLLED.value
        asset.enrolled_at = now
        self._governed_endpoints.add(asset.endpoint)

        self._stats["pending_enrollments"] = max(0, self._stats["pending_enrollments"] - 1)
        self._stats["completed_enrollments"] += 1
        self._stats["ungoverned_assets"] = max(0, self._stats["ungoverned_assets"] - 1)
        self._stats["governed_assets"] += 1

        logger.info("Enrollment approved: asset=%s name=%s", req.asset_id, asset.name)
        return True

    def reject_enrollment(self, request_id: str, resolution_note: str = "") -> bool:
        """Reject an enrollment request."""
        req = self._enrollment_requests.get(request_id)
        if req is None or req.status != "pending":
            return False

        asset = self._assets.get(req.asset_id)
        now = datetime.now(timezone.utc).isoformat()
        req.status = "rejected"
        req.resolved_at = now
        req.resolution_note = resolution_note

        if asset:
            asset.status = AssetStatus.UNGOVERNED.value

        self._stats["pending_enrollments"] = max(0, self._stats["pending_enrollments"] - 1)
        return True

    def ignore_asset(self, asset_id: str) -> bool:
        """Mark an asset as intentionally ignored."""
        asset = self._assets.get(asset_id)
        if asset is None:
            return False
        asset.status = AssetStatus.IGNORED.value
        return True

    # ── Queries ──────────────────────────────────────────────────────────

    def get_asset(self, asset_id: str) -> AIAsset | None:
        return self._assets.get(asset_id)

    def list_assets(
        self,
        status: str = "",
        tenant_id: str = "",
        asset_type: str = "",
    ) -> list[AIAsset]:
        assets = list(self._assets.values())
        if status:
            assets = [a for a in assets if a.status == status]
        if tenant_id:
            assets = [a for a in assets if a.tenant_id == tenant_id]
        if asset_type:
            assets = [a for a in assets if a.asset_type == asset_type]
        return assets

    def list_ungoverned(self, tenant_id: str = "") -> list[AIAsset]:
        return self.list_assets(status=AssetStatus.UNGOVERNED.value, tenant_id=tenant_id)

    def list_enrollment_requests(self, status: str = "") -> list[EnrollmentRequest]:
        reqs = list(self._enrollment_requests.values())
        if status:
            reqs = [r for r in reqs if r.status == status]
        return reqs

    def get_stats(self) -> dict[str, int]:
        return dict(self._stats)

    def asset_count(self) -> int:
        return len(self._assets)

    def get_dashboard_summary(self) -> dict[str, Any]:
        """Summary for the Sphinx dashboard."""
        return {
            "total_assets": len(self._assets),
            "governed": self._stats["governed_assets"],
            "ungoverned": self._stats["ungoverned_assets"],
            "pending_enrollments": self._stats["pending_enrollments"],
            "completed_enrollments": self._stats["completed_enrollments"],
            "ungoverned_assets": [a.to_dict() for a in self.list_ungoverned()],
        }


# ── Singleton ────────────────────────────────────────────────────────────

_service: AISPMDiscoveryService | None = None


def get_ai_spm_service() -> AISPMDiscoveryService:
    global _service
    if _service is None:
        _service = AISPMDiscoveryService()
    return _service


def reset_ai_spm_service() -> None:
    global _service
    _service = None
