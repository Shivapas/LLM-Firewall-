"""Model Provenance Registry — Sprint 29.

Hash-based model integrity registry: store SHA-256 of approved model
artifacts.  Block deployment of unregistered or hash-mismatch models.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("sphinx.model_scanner.provenance")


@dataclass
class ModelRegistration:
    """An approved model artifact in the registry."""
    registration_id: str = ""
    model_name: str = ""
    model_version: str = ""
    file_hash: str = ""          # SHA-256 of the approved artifact
    file_size: int = 0
    model_format: str = ""
    source: str = ""             # e.g. "huggingface", "internal", "vendor"
    registered_by: str = ""
    scan_id: str = ""            # reference to the scan that approved it
    is_active: bool = True
    registered_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "registration_id": self.registration_id,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "model_format": self.model_format,
            "source": self.source,
            "registered_by": self.registered_by,
            "scan_id": self.scan_id,
            "is_active": self.is_active,
            "registered_at": self.registered_at,
            "metadata": self.metadata,
        }


@dataclass
class ProvenanceCheck:
    """Result of a provenance verification check."""
    check_id: str = ""
    model_name: str = ""
    file_hash: str = ""
    is_registered: bool = False
    hash_matches: bool = False
    registration: ModelRegistration | None = None
    checked_at: str = ""
    action: str = "block"       # allow, block

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "model_name": self.model_name,
            "file_hash": self.file_hash,
            "is_registered": self.is_registered,
            "hash_matches": self.hash_matches,
            "registration": self.registration.to_dict() if self.registration else None,
            "checked_at": self.checked_at,
            "action": self.action,
        }


class ModelProvenanceRegistry:
    """Registry of approved model artifacts with hash-based integrity checks.

    Workflow:
    1. Scan model with ModelArtifactScanner.
    2. If scan passes, register model hash in this registry.
    3. At deployment time, verify model hash against registry.
    4. Block deployment if hash is unregistered or mismatched.
    """

    def __init__(self) -> None:
        # model_name -> {version -> ModelRegistration}
        self._registry: dict[str, dict[str, ModelRegistration]] = {}
        # file_hash -> ModelRegistration (for fast hash lookup)
        self._hash_index: dict[str, ModelRegistration] = {}
        self._check_history: list[ProvenanceCheck] = []
        self._stats: dict[str, int] = {
            "total_registrations": 0,
            "total_checks": 0,
            "checks_passed": 0,
            "checks_blocked": 0,
        }

    def register(
        self,
        model_name: str,
        model_version: str,
        file_hash: str,
        file_size: int = 0,
        model_format: str = "",
        source: str = "",
        registered_by: str = "system",
        scan_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> ModelRegistration:
        """Register an approved model artifact."""
        reg = ModelRegistration(
            registration_id=str(uuid.uuid4()),
            model_name=model_name,
            model_version=model_version,
            file_hash=file_hash,
            file_size=file_size,
            model_format=model_format,
            source=source,
            registered_by=registered_by,
            scan_id=scan_id,
            is_active=True,
            registered_at=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {},
        )

        if model_name not in self._registry:
            self._registry[model_name] = {}
        self._registry[model_name][model_version] = reg
        self._hash_index[file_hash] = reg
        self._stats["total_registrations"] += 1

        logger.info(
            "Model registered: name=%s version=%s hash=%s source=%s",
            model_name, model_version, file_hash[:16], source,
        )
        return reg

    def revoke(self, model_name: str, model_version: str) -> bool:
        """Revoke a model registration (mark inactive)."""
        versions = self._registry.get(model_name, {})
        reg = versions.get(model_version)
        if reg is None:
            return False
        reg.is_active = False
        logger.info("Model revoked: name=%s version=%s", model_name, model_version)
        return True

    def verify(self, model_name: str, file_hash: str) -> ProvenanceCheck:
        """Verify a model artifact against the registry.

        Returns:
            ProvenanceCheck with is_registered, hash_matches, and action.
        """
        self._stats["total_checks"] += 1
        now = datetime.now(timezone.utc).isoformat()
        check_id = str(uuid.uuid4())

        # Check by hash first (fastest path)
        reg = self._hash_index.get(file_hash)
        if reg and reg.is_active and reg.model_name == model_name:
            self._stats["checks_passed"] += 1
            check = ProvenanceCheck(
                check_id=check_id,
                model_name=model_name,
                file_hash=file_hash,
                is_registered=True,
                hash_matches=True,
                registration=reg,
                checked_at=now,
                action="allow",
            )
            self._check_history.append(check)
            return check

        # Check by name — model exists but hash doesn't match
        versions = self._registry.get(model_name, {})
        if versions:
            # Model is registered but hash doesn't match any version
            self._stats["checks_blocked"] += 1
            check = ProvenanceCheck(
                check_id=check_id,
                model_name=model_name,
                file_hash=file_hash,
                is_registered=True,
                hash_matches=False,
                checked_at=now,
                action="block",
            )
            self._check_history.append(check)
            logger.warning(
                "Model provenance MISMATCH: name=%s provided_hash=%s (no matching version)",
                model_name, file_hash[:16],
            )
            return check

        # Model not registered at all
        self._stats["checks_blocked"] += 1
        check = ProvenanceCheck(
            check_id=check_id,
            model_name=model_name,
            file_hash=file_hash,
            is_registered=False,
            hash_matches=False,
            checked_at=now,
            action="block",
        )
        self._check_history.append(check)
        logger.warning("Model UNREGISTERED: name=%s hash=%s", model_name, file_hash[:16])
        return check

    def get_registration(self, model_name: str, model_version: str = "") -> ModelRegistration | None:
        """Get a specific registration."""
        versions = self._registry.get(model_name, {})
        if model_version:
            return versions.get(model_version)
        # Return latest active version
        active = [v for v in versions.values() if v.is_active]
        return active[-1] if active else None

    def list_registrations(self, model_name: str = "") -> list[ModelRegistration]:
        """List all registrations, optionally filtered by model name."""
        if model_name:
            return list(self._registry.get(model_name, {}).values())
        return [
            reg
            for versions in self._registry.values()
            for reg in versions.values()
        ]

    def get_check_history(self, limit: int = 50) -> list[ProvenanceCheck]:
        return self._check_history[-limit:]

    def get_stats(self) -> dict[str, int]:
        return dict(self._stats)

    def registration_count(self) -> int:
        return sum(len(v) for v in self._registry.values())


# ── Singleton ────────────────────────────────────────────────────────────

_registry: ModelProvenanceRegistry | None = None


def get_model_provenance_registry() -> ModelProvenanceRegistry:
    global _registry
    if _registry is None:
        _registry = ModelProvenanceRegistry()
    return _registry


def reset_model_provenance_registry() -> None:
    global _registry
    _registry = None
