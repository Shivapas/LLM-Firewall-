"""v2.0 Release Checklist — Sprint 30.

Security review of all Phase 7-8 features, performance regression test
(all new checks < 50ms p99 overhead), documentation update, v2.0 release notes.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("sphinx.release.v2_checklist")


@dataclass
class ChecklistItem:
    """A single item on the v2.0 release checklist."""
    item_id: str = ""
    category: str = ""          # security_review, performance, documentation, testing
    title: str = ""
    description: str = ""
    status: str = "pending"     # pending, in_progress, passed, failed, waived
    assigned_to: str = ""       # engineering_lead, security_lead, product_owner
    evidence: str = ""          # proof/link/note for completion
    checked_at: str = ""
    checked_by: str = ""

    def to_dict(self) -> dict:
        return {
            "item_id": self.item_id,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "assigned_to": self.assigned_to,
            "evidence": self.evidence,
            "checked_at": self.checked_at,
            "checked_by": self.checked_by,
        }


@dataclass
class PerformanceBenchmark:
    """Performance benchmark result for a specific check."""
    benchmark_id: str = ""
    check_name: str = ""
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    max_ms: float = 0.0
    sample_count: int = 0
    passes_threshold: bool = True   # p99 < 50ms
    threshold_ms: float = 50.0
    measured_at: str = ""

    def to_dict(self) -> dict:
        return {
            "benchmark_id": self.benchmark_id,
            "check_name": self.check_name,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
            "max_ms": self.max_ms,
            "sample_count": self.sample_count,
            "passes_threshold": self.passes_threshold,
            "threshold_ms": self.threshold_ms,
            "measured_at": self.measured_at,
        }


# Default checklist items covering Phase 7-8 features
DEFAULT_CHECKLIST: list[dict[str, str]] = [
    # Security Reviews
    {"category": "security_review", "title": "HITL enforcement checkpoint review",
     "description": "Review approval workflow for bypass vulnerabilities", "assigned_to": "security_lead"},
    {"category": "security_review", "title": "A2A firewall policy review",
     "description": "Verify agent-to-agent communication controls", "assigned_to": "security_lead"},
    {"category": "security_review", "title": "Memory poisoning block review",
     "description": "Verify memory store firewall blocks injection attacks", "assigned_to": "security_lead"},
    {"category": "security_review", "title": "Model scan gate review",
     "description": "Verify model artifact scanner detects known exploits", "assigned_to": "security_lead"},
    {"category": "security_review", "title": "Multi-turn escalation review",
     "description": "Verify cross-turn risk accumulation triggers correctly", "assigned_to": "security_lead"},
    {"category": "security_review", "title": "Semantic cache security review",
     "description": "Verify namespace isolation and poisoning detection", "assigned_to": "security_lead"},
    # Performance
    {"category": "performance", "title": "HITL check overhead < 50ms p99",
     "description": "Measure HITL approval check latency in isolation", "assigned_to": "engineering_lead"},
    {"category": "performance", "title": "Model scan overhead < 50ms p99",
     "description": "Measure model artifact scanning latency", "assigned_to": "engineering_lead"},
    {"category": "performance", "title": "Multi-turn risk check overhead < 50ms p99",
     "description": "Measure cross-turn risk accumulation latency", "assigned_to": "engineering_lead"},
    {"category": "performance", "title": "Semantic cache lookup overhead < 50ms p99",
     "description": "Measure cache similarity search latency", "assigned_to": "engineering_lead"},
    {"category": "performance", "title": "A2A firewall overhead < 50ms p99",
     "description": "Measure agent communication policy check latency", "assigned_to": "engineering_lead"},
    {"category": "performance", "title": "Memory firewall overhead < 50ms p99",
     "description": "Measure memory store interception latency", "assigned_to": "engineering_lead"},
    # Testing
    {"category": "testing", "title": "Phase 8 integration test suite passes",
     "description": "All end-to-end tests for Phase 7-8 features pass in staging", "assigned_to": "engineering_lead"},
    {"category": "testing", "title": "Load test at 1000 RPS",
     "description": "Verify system handles 1000 RPS with Phase 7-8 checks enabled", "assigned_to": "engineering_lead"},
    # Documentation
    {"category": "documentation", "title": "Phase 7-8 feature documentation",
     "description": "All new features documented in user guide", "assigned_to": "product_owner"},
    {"category": "documentation", "title": "v2.0 release notes",
     "description": "Comprehensive release notes covering all Phase 7-8 features", "assigned_to": "product_owner"},
    {"category": "documentation", "title": "API reference update",
     "description": "All new API endpoints documented in API reference", "assigned_to": "engineering_lead"},
    # Sign-offs
    {"category": "sign_off", "title": "Engineering Lead sign-off",
     "description": "Engineering Lead approves v2.0 release", "assigned_to": "engineering_lead"},
    {"category": "sign_off", "title": "Security Lead sign-off",
     "description": "Security Lead approves v2.0 release", "assigned_to": "security_lead"},
    {"category": "sign_off", "title": "Product Owner sign-off",
     "description": "Product Owner approves v2.0 release", "assigned_to": "product_owner"},
]


class V2ReleaseChecklist:
    """Manages the v2.0 release checklist and sign-off process."""

    def __init__(self) -> None:
        self._items: list[ChecklistItem] = []
        self._benchmarks: list[PerformanceBenchmark] = []
        self._initialized = False

    def initialize(self) -> None:
        """Initialize checklist with default items."""
        if self._initialized:
            return
        for item_def in DEFAULT_CHECKLIST:
            self._items.append(ChecklistItem(
                item_id=str(uuid.uuid4()),
                category=item_def["category"],
                title=item_def["title"],
                description=item_def["description"],
                assigned_to=item_def["assigned_to"],
            ))
        self._initialized = True
        logger.info("v2.0 release checklist initialized: %d items", len(self._items))

    def update_item_status(
        self,
        item_id: str,
        status: str,
        checked_by: str = "",
        evidence: str = "",
    ) -> ChecklistItem | None:
        """Update the status of a checklist item."""
        for item in self._items:
            if item.item_id == item_id:
                item.status = status
                item.checked_by = checked_by
                item.evidence = evidence
                item.checked_at = datetime.now(timezone.utc).isoformat()
                logger.info(
                    "Checklist item updated: %s -> %s by %s",
                    item.title, status, checked_by,
                )
                return item
        return None

    def record_benchmark(
        self,
        check_name: str,
        p50_ms: float,
        p95_ms: float,
        p99_ms: float,
        max_ms: float = 0.0,
        sample_count: int = 0,
        threshold_ms: float = 50.0,
    ) -> PerformanceBenchmark:
        """Record a performance benchmark measurement."""
        benchmark = PerformanceBenchmark(
            benchmark_id=str(uuid.uuid4()),
            check_name=check_name,
            p50_ms=p50_ms,
            p95_ms=p95_ms,
            p99_ms=p99_ms,
            max_ms=max_ms,
            sample_count=sample_count,
            passes_threshold=p99_ms < threshold_ms,
            threshold_ms=threshold_ms,
            measured_at=datetime.now(timezone.utc).isoformat(),
        )
        self._benchmarks.append(benchmark)
        logger.info(
            "Benchmark recorded: %s p99=%.1fms pass=%s",
            check_name, p99_ms, benchmark.passes_threshold,
        )
        return benchmark

    def get_items(self, category: str = "", status: str = "") -> list[ChecklistItem]:
        items = self._items
        if category:
            items = [i for i in items if i.category == category]
        if status:
            items = [i for i in items if i.status == status]
        return items

    def get_benchmarks(self) -> list[PerformanceBenchmark]:
        return list(self._benchmarks)

    def is_release_ready(self) -> dict[str, Any]:
        """Check if all checklist items are completed and all benchmarks pass."""
        total = len(self._items)
        passed = sum(1 for i in self._items if i.status in ("passed", "waived"))
        failed = sum(1 for i in self._items if i.status == "failed")
        pending = total - passed - failed

        benchmarks_pass = all(b.passes_threshold for b in self._benchmarks)
        all_signed = all(
            i.status in ("passed", "waived")
            for i in self._items
            if i.category == "sign_off"
        )

        return {
            "is_ready": passed == total and benchmarks_pass,
            "total_items": total,
            "passed": passed,
            "failed": failed,
            "pending": pending,
            "benchmarks_pass": benchmarks_pass,
            "benchmarks_count": len(self._benchmarks),
            "all_signed_off": all_signed,
        }

    def item_count(self) -> int:
        return len(self._items)


# ── Singleton ────────────────────────────────────────────────────────────

_checklist: V2ReleaseChecklist | None = None


def get_v2_release_checklist() -> V2ReleaseChecklist:
    global _checklist
    if _checklist is None:
        _checklist = V2ReleaseChecklist()
    return _checklist


def reset_v2_release_checklist() -> None:
    global _checklist
    _checklist = None
