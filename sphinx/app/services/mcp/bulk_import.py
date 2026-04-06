"""Bulk Scope Policy Import — Sprint 17.

Import agent scope policies via JSON/YAML for bulk onboarding of large
agent fleets. Supports validation, dry-run mode, and error reporting.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("sphinx.mcp.bulk_import")


# ── Data structures ──────────────────────────────────────────────────────


@dataclass
class ImportResult:
    """Result of a bulk import operation."""
    total: int = 0
    created: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list[dict] = field(default_factory=list)
    dry_run: bool = False

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "created": self.created,
            "updated": self.updated,
            "skipped": self.skipped,
            "errors": self.errors,
            "dry_run": self.dry_run,
        }


REQUIRED_FIELDS = {"agent_id"}
OPTIONAL_FIELDS = {
    "display_name", "description", "allowed_mcp_servers",
    "allowed_tools", "context_scope", "redact_fields", "is_active",
}
ALL_FIELDS = REQUIRED_FIELDS | OPTIONAL_FIELDS


# ── Bulk Import Service ──────────────────────────────────────────────────


class BulkImportService:
    """Handles bulk import of agent scope policies from JSON/YAML.

    Validates input, creates or updates agent accounts in the scope
    service, and returns detailed results with error reporting.
    """

    def __init__(self, scope_service=None):
        self._scope_service = scope_service

    def set_scope_service(self, scope_service):
        """Set the scope service dependency."""
        self._scope_service = scope_service

    def validate_policy(self, policy: dict) -> list[str]:
        """Validate a single agent policy dict. Returns list of errors."""
        errors: list[str] = []

        if not isinstance(policy, dict):
            return ["Policy must be a dict/object"]

        # Required fields
        if "agent_id" not in policy:
            errors.append("Missing required field: agent_id")
        elif not isinstance(policy["agent_id"], str) or not policy["agent_id"].strip():
            errors.append("agent_id must be a non-empty string")

        # Type checks for list fields
        for field_name in ("allowed_mcp_servers", "allowed_tools", "context_scope", "redact_fields"):
            if field_name in policy:
                value = policy[field_name]
                if not isinstance(value, list):
                    errors.append(f"{field_name} must be a list")
                elif not all(isinstance(item, str) for item in value):
                    errors.append(f"All items in {field_name} must be strings")

        # Type checks for string fields
        for field_name in ("display_name", "description"):
            if field_name in policy and not isinstance(policy[field_name], str):
                errors.append(f"{field_name} must be a string")

        # Type check for boolean
        if "is_active" in policy and not isinstance(policy["is_active"], bool):
            errors.append("is_active must be a boolean")

        # Warn on unknown fields
        unknown = set(policy.keys()) - ALL_FIELDS
        if unknown:
            errors.append(f"Unknown fields: {sorted(unknown)}")

        return errors

    def import_policies(
        self,
        policies: list[dict],
        dry_run: bool = False,
        update_existing: bool = True,
    ) -> ImportResult:
        """Import a list of agent scope policies.

        Args:
            policies: List of policy dicts with agent_id and scope config
            dry_run: If True, validate only without creating/updating accounts
            update_existing: If True, update existing accounts; if False, skip them

        Returns:
            ImportResult with counts and any errors
        """
        if not self._scope_service:
            raise RuntimeError("Scope service not configured")

        result = ImportResult(total=len(policies), dry_run=dry_run)

        for idx, policy in enumerate(policies):
            # Validate
            errors = self.validate_policy(policy)
            if errors:
                result.errors.append({
                    "index": idx,
                    "agent_id": policy.get("agent_id", "<missing>"),
                    "errors": errors,
                })
                result.skipped += 1
                continue

            agent_id = policy["agent_id"].strip()

            if dry_run:
                # Just validate, don't create/update
                existing = self._scope_service.get_account(agent_id)
                if existing:
                    result.updated += 1
                else:
                    result.created += 1
                continue

            # Check if account exists
            existing = self._scope_service.get_account(agent_id)

            if existing and not update_existing:
                result.skipped += 1
                continue

            try:
                if existing:
                    # Update existing account
                    self._scope_service.update_account(
                        agent_id=agent_id,
                        display_name=policy.get("display_name"),
                        description=policy.get("description"),
                        allowed_mcp_servers=policy.get("allowed_mcp_servers"),
                        allowed_tools=policy.get("allowed_tools"),
                        context_scope=policy.get("context_scope"),
                        redact_fields=policy.get("redact_fields"),
                        is_active=policy.get("is_active"),
                    )
                    result.updated += 1
                else:
                    # Create new account
                    self._scope_service.create_account(
                        agent_id=agent_id,
                        display_name=policy.get("display_name", ""),
                        description=policy.get("description", ""),
                        allowed_mcp_servers=policy.get("allowed_mcp_servers"),
                        allowed_tools=policy.get("allowed_tools"),
                        context_scope=policy.get("context_scope"),
                        redact_fields=policy.get("redact_fields"),
                    )
                    result.created += 1
            except Exception as e:
                result.errors.append({
                    "index": idx,
                    "agent_id": agent_id,
                    "errors": [str(e)],
                })
                result.skipped += 1

        logger.info(
            "Bulk import: total=%d created=%d updated=%d skipped=%d errors=%d dry_run=%s",
            result.total, result.created, result.updated, result.skipped,
            len(result.errors), dry_run,
        )
        return result

    def parse_json(self, raw: str) -> list[dict]:
        """Parse JSON input. Accepts array or single object."""
        data = json.loads(raw)
        if isinstance(data, dict):
            # Single policy wrapped in {"policies": [...]} or bare dict
            if "policies" in data and isinstance(data["policies"], list):
                return data["policies"]
            return [data]
        if isinstance(data, list):
            return data
        raise ValueError("Input must be a JSON array or object")

    def parse_yaml(self, raw: str) -> list[dict]:
        """Parse YAML input. Requires PyYAML."""
        try:
            import yaml
        except ImportError:
            raise ImportError("PyYAML is required for YAML import: pip install pyyaml")

        data = yaml.safe_load(raw)
        if isinstance(data, dict):
            if "policies" in data and isinstance(data["policies"], list):
                return data["policies"]
            return [data]
        if isinstance(data, list):
            return data
        raise ValueError("Input must be a YAML array or object")


# ── Singleton ────────────────────────────────────────────────────────────

_bulk_import_service: BulkImportService | None = None


def get_bulk_import_service(scope_service=None) -> BulkImportService:
    """Get or create the singleton bulk import service."""
    global _bulk_import_service
    if _bulk_import_service is None:
        _bulk_import_service = BulkImportService(scope_service=scope_service)
    return _bulk_import_service


def reset_bulk_import_service() -> None:
    """Reset for testing."""
    global _bulk_import_service
    _bulk_import_service = None
