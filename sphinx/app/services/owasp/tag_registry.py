"""SP-360: OWASP LLM Top 10 v2025 tag registry.

Loads the tag registry YAML that maps every Sphinx module to the OWASP LLM
Top 10 v2025 categories it addresses.

SP-360 acceptance criteria:
  - Tag registry covers all 30 v2.0 modules + 3 new modules
  - Each module tagged with 1-N OWASP categories
  - Reviewed by product
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

import yaml

logger = logging.getLogger("sphinx.owasp.tag_registry")

_REGISTRY_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "config", "owasp_tag_registry.yaml"
)

# OWASP LLM Top 10 v2025 category IDs
OWASP_CATEGORIES = [
    "LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
    "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
]


@dataclass
class OWASPCategory:
    """An OWASP LLM Top 10 v2025 category."""

    category_id: str
    name: str
    description: str


@dataclass
class ModuleTag:
    """A Sphinx module's OWASP tag mapping."""

    module_key: str
    name: str
    version: str
    description: str
    owasp_tags: list[str]
    config_key: str
    default_enabled: bool
    module_id: str = ""


@dataclass
class TagRegistry:
    """The full OWASP tag registry."""

    owasp_version: str
    registry_version: str
    last_updated: str
    categories: dict[str, OWASPCategory] = field(default_factory=dict)
    modules: dict[str, ModuleTag] = field(default_factory=dict)

    @property
    def module_count(self) -> int:
        return len(self.modules)

    @property
    def category_count(self) -> int:
        return len(self.categories)

    def get_modules_for_category(self, category_id: str) -> list[ModuleTag]:
        """Return all modules tagged with the given OWASP category."""
        return [
            m for m in self.modules.values()
            if category_id in m.owasp_tags
        ]

    def get_categories_for_module(self, module_key: str) -> list[str]:
        """Return the OWASP categories tagged on the given module."""
        module = self.modules.get(module_key)
        if module is None:
            return []
        return list(module.owasp_tags)

    def to_dict(self) -> dict:
        """Serialize the registry to a dict."""
        return {
            "owasp_version": self.owasp_version,
            "registry_version": self.registry_version,
            "last_updated": self.last_updated,
            "category_count": self.category_count,
            "module_count": self.module_count,
            "categories": {
                k: {"name": v.name, "description": v.description}
                for k, v in self.categories.items()
            },
            "modules": {
                k: {
                    "name": v.name,
                    "version": v.version,
                    "description": v.description,
                    "owasp_tags": v.owasp_tags,
                    "config_key": v.config_key,
                    "default_enabled": v.default_enabled,
                    "module_id": v.module_id,
                }
                for k, v in self.modules.items()
            },
        }


def load_tag_registry(path: str | None = None) -> TagRegistry:
    """Load the OWASP tag registry from YAML.

    Args:
        path: Optional override path to the YAML file.
              Defaults to config/owasp_tag_registry.yaml.
    """
    registry_path = path or _REGISTRY_PATH
    registry_path = os.path.normpath(registry_path)

    with open(registry_path, "r") as f:
        data = yaml.safe_load(f)

    categories = {}
    for cat_id, cat_data in data.get("categories", {}).items():
        categories[cat_id] = OWASPCategory(
            category_id=cat_id,
            name=cat_data["name"],
            description=cat_data["description"],
        )

    modules = {}
    for mod_key, mod_data in data.get("modules", {}).items():
        modules[mod_key] = ModuleTag(
            module_key=mod_key,
            name=mod_data["name"],
            version=mod_data.get("version", ""),
            description=mod_data.get("description", ""),
            owasp_tags=mod_data.get("owasp_tags", []),
            config_key=mod_data.get("config_key", ""),
            default_enabled=mod_data.get("default_enabled", False),
            module_id=mod_data.get("module_id", ""),
        )

    registry = TagRegistry(
        owasp_version=data.get("owasp_version", "2025"),
        registry_version=data.get("registry_version", "1.0.0"),
        last_updated=data.get("last_updated", ""),
        categories=categories,
        modules=modules,
    )

    logger.info(
        "OWASP tag registry loaded: %d categories, %d modules",
        registry.category_count,
        registry.module_count,
    )
    return registry


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_registry: Optional[TagRegistry] = None


def get_tag_registry() -> TagRegistry:
    """Get or create the singleton tag registry."""
    global _registry
    if _registry is None:
        _registry = load_tag_registry()
    return _registry


def reset_tag_registry() -> None:
    """Reset the singleton (for testing)."""
    global _registry
    _registry = None
