"""Cache Security Controls — Sprint 30.

Per-tenant cache namespace isolation, cache poisoning detection
(flag cached responses containing injection patterns), automatic
full-cache invalidation on policy change.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.services.semantic_cache.cache_layer import CacheEntry, SemanticCacheLayer

logger = logging.getLogger("sphinx.semantic_cache.security")


# ── Injection patterns to detect in cached responses ─────────────────────

CACHE_POISON_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(all\s+)?previous\s+instructions", "prompt_injection"),
    (r"system:\s*you\s+are", "role_hijack"),
    (r"<\|im_start\|>system", "delimiter_injection"),
    (r"\[INST\].*\[/INST\]", "template_injection"),
    (r"\\n\\nHuman:", "conversation_injection"),
    (r"eval\s*\(", "code_injection"),
    (r"exec\s*\(", "code_injection"),
    (r"__import__\s*\(", "code_injection"),
    (r"<script[^>]*>", "xss_injection"),
    (r"javascript:", "xss_injection"),
]


@dataclass
class PoisonDetectionResult:
    """Result of scanning a cache entry for poisoning."""
    is_poisoned: bool = False
    entry_id: str = ""
    patterns_matched: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    severity: str = "none"   # none, low, medium, high, critical
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "is_poisoned": self.is_poisoned,
            "entry_id": self.entry_id,
            "patterns_matched": self.patterns_matched,
            "categories": self.categories,
            "severity": self.severity,
            "details": self.details,
        }


@dataclass
class NamespaceIsolationCheck:
    """Result of a namespace isolation verification."""
    check_id: str = ""
    requesting_tenant: str = ""
    target_tenant: str = ""
    is_isolated: bool = True
    violation: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "requesting_tenant": self.requesting_tenant,
            "target_tenant": self.target_tenant,
            "is_isolated": self.is_isolated,
            "violation": self.violation,
            "timestamp": self.timestamp,
        }


class CacheSecurityController:
    """Security controls for the semantic cache.

    Responsibilities:
    - Verify tenant namespace isolation (tenant A cannot access B's cache)
    - Scan cached responses for injection/poisoning patterns
    - Trigger full-cache invalidation on policy changes
    - Track security events
    """

    def __init__(self, cache: SemanticCacheLayer | None = None) -> None:
        self._cache = cache
        self._compiled_patterns: list[tuple[re.Pattern, str]] = [
            (re.compile(p, re.IGNORECASE), cat)
            for p, cat in CACHE_POISON_PATTERNS
        ]
        self._poison_events: list[PoisonDetectionResult] = []
        self._isolation_checks: list[NamespaceIsolationCheck] = []
        self._stats: dict[str, int] = {
            "total_poison_scans": 0,
            "poisoned_entries_found": 0,
            "isolation_checks": 0,
            "isolation_violations": 0,
            "policy_invalidations": 0,
        }

    def set_cache(self, cache: SemanticCacheLayer) -> None:
        self._cache = cache

    def scan_for_poisoning(self, entry: CacheEntry) -> PoisonDetectionResult:
        """Scan a cache entry's response for injection patterns."""
        self._stats["total_poison_scans"] += 1

        matched_patterns: list[str] = []
        categories: set[str] = set()

        response = entry.response_text
        for pattern, category in self._compiled_patterns:
            if pattern.search(response):
                matched_patterns.append(pattern.pattern)
                categories.add(category)

        if matched_patterns:
            self._stats["poisoned_entries_found"] += 1
            severity = "critical" if len(matched_patterns) >= 3 else "high" if len(matched_patterns) >= 2 else "medium"
            result = PoisonDetectionResult(
                is_poisoned=True,
                entry_id=entry.entry_id,
                patterns_matched=matched_patterns,
                categories=list(categories),
                severity=severity,
                details={"response_length": len(response)},
            )
            self._poison_events.append(result)
            logger.warning(
                "Cache poisoning detected: entry=%s patterns=%d categories=%s",
                entry.entry_id, len(matched_patterns), categories,
            )
            return result

        return PoisonDetectionResult(
            is_poisoned=False,
            entry_id=entry.entry_id,
        )

    def verify_namespace_isolation(
        self,
        requesting_tenant: str,
        target_tenant: str,
    ) -> NamespaceIsolationCheck:
        """Verify that one tenant cannot access another's cache namespace."""
        self._stats["isolation_checks"] += 1

        is_isolated = requesting_tenant == target_tenant
        check = NamespaceIsolationCheck(
            check_id=str(uuid.uuid4()),
            requesting_tenant=requesting_tenant,
            target_tenant=target_tenant,
            is_isolated=is_isolated,
            violation="" if is_isolated else f"Tenant {requesting_tenant} attempted to access cache of tenant {target_tenant}",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        if not is_isolated:
            self._stats["isolation_violations"] += 1
            logger.warning(
                "Cache namespace isolation violation: %s tried to access %s",
                requesting_tenant, target_tenant,
            )

        self._isolation_checks.append(check)
        return check

    def on_policy_change(self, tenant_id: str, policy_version: str) -> int:
        """Handle a policy change by invalidating affected cache entries.

        Full-cache invalidation for the tenant when policy changes.
        """
        if self._cache is None:
            return 0

        self._stats["policy_invalidations"] += 1
        count = self._cache.invalidate_tenant(tenant_id)
        logger.info(
            "Policy change invalidation: tenant=%s policy=%s entries_removed=%d",
            tenant_id, policy_version, count,
        )
        return count

    def scan_tenant_cache(self, tenant_id: str) -> list[PoisonDetectionResult]:
        """Scan all cache entries for a tenant for poisoning."""
        if self._cache is None:
            return []

        results: list[PoisonDetectionResult] = []
        entries = self._cache.get_tenant_entries(tenant_id)
        for entry in entries:
            result = self.scan_for_poisoning(entry)
            if result.is_poisoned:
                results.append(result)
        return results

    def get_poison_events(self, limit: int = 50) -> list[PoisonDetectionResult]:
        return self._poison_events[-limit:]

    def get_isolation_checks(self, limit: int = 50) -> list[NamespaceIsolationCheck]:
        return self._isolation_checks[-limit:]

    def get_stats(self) -> dict[str, int]:
        return dict(self._stats)


# ── Singleton ────────────────────────────────────────────────────────────

_controller: CacheSecurityController | None = None


def get_cache_security_controller(
    cache: SemanticCacheLayer | None = None,
) -> CacheSecurityController:
    global _controller
    if _controller is None:
        _controller = CacheSecurityController(cache=cache)
    elif cache is not None:
        _controller.set_cache(cache)
    return _controller


def reset_cache_security_controller() -> None:
    global _controller
    _controller = None
