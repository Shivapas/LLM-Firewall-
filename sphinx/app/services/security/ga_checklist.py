"""Sprint 20 — GA Release Checklist Service.

Tracks the General Availability release readiness across four sign-off
domains: Security, Performance, Compliance, and Operations.

Each checklist item can be signed off individually.  The GA is considered
ready when all required items are signed off.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("sphinx.ga_checklist")


# ── Checklist Definitions ────────────────────────────────────────────────────

GA_CHECKLIST_ITEMS: list[dict] = [
    # Security Review
    {
        "id": "SEC-01",
        "category": "security",
        "title": "Penetration test completed",
        "description": "External pentest engagement completed for gateway API, admin UI, audit log API, and vector DB firewall",
        "required": True,
        "signoff_role": "Security Lead",
    },
    {
        "id": "SEC-02",
        "category": "security",
        "title": "Zero Critical/High findings unresolved",
        "description": "All Critical and High severity findings from pentest have been remediated and verified",
        "required": True,
        "signoff_role": "Security Lead",
    },
    {
        "id": "SEC-03",
        "category": "security",
        "title": "Dependency vulnerability scan clean",
        "description": "No known Critical/High CVEs in production dependencies",
        "required": True,
        "signoff_role": "Security Lead",
    },
    {
        "id": "SEC-04",
        "category": "security",
        "title": "Secrets management verified",
        "description": "No hardcoded secrets; Vault/sealed-secrets integration confirmed",
        "required": True,
        "signoff_role": "Security Lead",
    },
    # Performance
    {
        "id": "PERF-01",
        "category": "performance",
        "title": "Load test passed at 1000 RPS",
        "description": "Gateway sustains 1000 RPS with p99 latency < 80 ms on keyword + PII path",
        "required": True,
        "signoff_role": "Engineering Lead",
    },
    {
        "id": "PERF-02",
        "category": "performance",
        "title": "Memory profiling — no leaks",
        "description": "No memory leaks detected under sustained 1-hour load test",
        "required": True,
        "signoff_role": "Engineering Lead",
    },
    {
        "id": "PERF-03",
        "category": "performance",
        "title": "CPU hotspot optimization complete",
        "description": "Regex compilation, cache eviction, and detection pipeline optimized",
        "required": True,
        "signoff_role": "Engineering Lead",
    },
    # Compliance
    {
        "id": "COMP-01",
        "category": "compliance",
        "title": "GDPR compliance report generation verified",
        "description": "GDPR compliance report generates correctly with all required sections",
        "required": True,
        "signoff_role": "Product Owner",
    },
    {
        "id": "COMP-02",
        "category": "compliance",
        "title": "HIPAA compliance report generation verified",
        "description": "HIPAA compliance report generates correctly with all required sections",
        "required": True,
        "signoff_role": "Product Owner",
    },
    {
        "id": "COMP-03",
        "category": "compliance",
        "title": "SOC 2 compliance report generation verified",
        "description": "SOC 2 compliance report generates correctly with all required sections",
        "required": True,
        "signoff_role": "Product Owner",
    },
    {
        "id": "COMP-04",
        "category": "compliance",
        "title": "Audit trail tamper-evidence verified",
        "description": "Hash-chain audit log integrity verification passes end-to-end",
        "required": True,
        "signoff_role": "Product Owner",
    },
    # Operations
    {
        "id": "OPS-01",
        "category": "operations",
        "title": "Production K8s manifests validated",
        "description": "K8s manifests deploy cleanly to staging; HPA scales pods under load",
        "required": True,
        "signoff_role": "Engineering Lead",
    },
    {
        "id": "OPS-02",
        "category": "operations",
        "title": "Runbook complete",
        "description": "Operations runbook covers: deployment, rollback, incident response, scaling, backup/restore",
        "required": True,
        "signoff_role": "Engineering Lead",
    },
    {
        "id": "OPS-03",
        "category": "operations",
        "title": "Monitoring and alerting configured",
        "description": "Health probes, metrics, dashboards, and alert rules configured for production",
        "required": True,
        "signoff_role": "Engineering Lead",
    },
    {
        "id": "OPS-04",
        "category": "operations",
        "title": "On-premise deployment guide published",
        "description": "Self-hosted deployment documentation covers Docker Compose and K8s variants",
        "required": True,
        "signoff_role": "Product Owner",
    },
]


# ── Data Models ──────────────────────────────────────────────────────────────


@dataclass
class ChecklistItemStatus:
    """Status of a single checklist item."""

    id: str = ""
    category: str = ""
    title: str = ""
    description: str = ""
    required: bool = True
    signoff_role: str = ""
    signed_off: bool = False
    signed_off_by: str = ""
    signed_off_at: Optional[float] = None
    notes: str = ""


@dataclass
class GAChecklistStatus:
    """Overall GA checklist status."""

    checklist_id: str = ""
    version: str = "1.0.0"
    items: list[ChecklistItemStatus] = field(default_factory=list)
    total_items: int = 0
    signed_off_items: int = 0
    required_items: int = 0
    required_signed_off: int = 0
    progress_percentage: float = 0.0
    ga_ready: bool = False
    created_at: float = 0.0
    updated_at: float = 0.0

    def summary(self) -> str:
        return (
            f"GA Release Checklist v{self.version}\n"
            f"  Progress: {self.signed_off_items}/{self.total_items} items signed off "
            f"({self.progress_percentage:.0f}%)\n"
            f"  Required: {self.required_signed_off}/{self.required_items} complete\n"
            f"  GA Ready: {'YES' if self.ga_ready else 'NO'}"
        )


# ── Service ──────────────────────────────────────────────────────────────────


class GAChecklistService:
    """Manages the GA release checklist state."""

    def __init__(self, session_factory=None):
        self._session_factory = session_factory
        self._items: dict[str, ChecklistItemStatus] = {}
        self._checklist_id = f"GA-{uuid.uuid4().hex[:8].upper()}"
        self._created_at = time.time()
        self._initialize_items()

    def _initialize_items(self) -> None:
        """Populate checklist from definitions."""
        for item_def in GA_CHECKLIST_ITEMS:
            self._items[item_def["id"]] = ChecklistItemStatus(
                id=item_def["id"],
                category=item_def["category"],
                title=item_def["title"],
                description=item_def["description"],
                required=item_def["required"],
                signoff_role=item_def["signoff_role"],
            )

    def get_status(self) -> GAChecklistStatus:
        """Get full checklist status."""
        items = list(self._items.values())
        total = len(items)
        signed_off = sum(1 for i in items if i.signed_off)
        required = sum(1 for i in items if i.required)
        required_signed = sum(1 for i in items if i.required and i.signed_off)

        return GAChecklistStatus(
            checklist_id=self._checklist_id,
            items=items,
            total_items=total,
            signed_off_items=signed_off,
            required_items=required,
            required_signed_off=required_signed,
            progress_percentage=round(signed_off / total * 100, 1) if total > 0 else 0,
            ga_ready=required_signed == required,
            created_at=self._created_at,
            updated_at=time.time(),
        )

    def sign_off_item(self, item_id: str, signed_by: str, notes: str = "") -> ChecklistItemStatus:
        """Sign off a checklist item."""
        if item_id not in self._items:
            raise ValueError(f"Unknown checklist item: {item_id}")

        item = self._items[item_id]
        item.signed_off = True
        item.signed_off_by = signed_by
        item.signed_off_at = time.time()
        item.notes = notes

        logger.info("GA checklist item %s signed off by %s", item_id, signed_by)
        return item

    def revoke_signoff(self, item_id: str) -> ChecklistItemStatus:
        """Revoke a sign-off (e.g., if regression found)."""
        if item_id not in self._items:
            raise ValueError(f"Unknown checklist item: {item_id}")

        item = self._items[item_id]
        item.signed_off = False
        item.signed_off_by = ""
        item.signed_off_at = None
        item.notes = ""

        logger.info("GA checklist item %s sign-off revoked", item_id)
        return item

    def get_items_by_category(self, category: str) -> list[ChecklistItemStatus]:
        """Get all items for a category."""
        return [i for i in self._items.values() if i.category == category]

    def get_unsigned_items(self) -> list[ChecklistItemStatus]:
        """Get all items that have not been signed off."""
        return [i for i in self._items.values() if not i.signed_off]

    def get_item(self, item_id: str) -> Optional[ChecklistItemStatus]:
        """Get a single item by ID."""
        return self._items.get(item_id)

    def reset(self) -> GAChecklistStatus:
        """Reset all sign-offs."""
        self._initialize_items()
        self._checklist_id = f"GA-{uuid.uuid4().hex[:8].upper()}"
        self._created_at = time.time()
        logger.info("GA checklist reset")
        return self.get_status()


# ── Singleton ────────────────────────────────────────────────────────────────

_service: Optional[GAChecklistService] = None


def get_ga_checklist_service(session_factory=None) -> GAChecklistService:
    global _service
    if _service is None:
        _service = GAChecklistService(session_factory=session_factory)
    return _service
