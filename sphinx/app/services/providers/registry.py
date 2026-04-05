"""Provider registry for model-to-provider mapping and weighted selection."""

from __future__ import annotations

import logging
import random
from typing import Optional

from app.services.providers.base import BaseProvider
from app.services.providers.openai import OpenAIProvider
from app.services.providers.anthropic import AnthropicProvider
from app.services.providers.gemini import GeminiProvider

logger = logging.getLogger("sphinx.providers.registry")


# Default model-to-provider mapping
MODEL_PROVIDER_MAP: dict[str, str] = {}

# Build from provider classes
for _provider_cls in [OpenAIProvider, AnthropicProvider, GeminiProvider]:
    for _model in _provider_cls.supported_models:
        MODEL_PROVIDER_MAP[_model] = _provider_cls.provider_name


class ProviderRegistry:
    """Registry of provider adapters with model routing and weighted selection."""

    def __init__(self):
        self._providers: dict[str, list[tuple[BaseProvider, float]]] = {}
        # provider_name -> [(provider_instance, weight), ...]

    def register(self, provider: BaseProvider, weight: float = 1.0) -> None:
        """Register a provider instance with an optional weight for load balancing."""
        name = provider.provider_name
        if name not in self._providers:
            self._providers[name] = []
        self._providers[name].append((provider, weight))
        logger.info("Registered provider %s (weight=%.2f)", name, weight)

    def get_provider_for_model(self, model_name: str) -> Optional[BaseProvider]:
        """Resolve a model name to a provider instance using weighted selection.

        Lookup order:
        1. Exact match in MODEL_PROVIDER_MAP
        2. Prefix match (e.g. "gpt-" -> openai, "claude-" -> anthropic, "gemini-" -> gemini)
        3. None if no match
        """
        provider_name = MODEL_PROVIDER_MAP.get(model_name)

        if not provider_name:
            provider_name = self._resolve_by_prefix(model_name)

        if not provider_name:
            logger.warning("No provider found for model=%s", model_name)
            return None

        return self._select_weighted(provider_name)

    def get_provider_by_name(self, provider_name: str) -> Optional[BaseProvider]:
        """Get a provider by its name, using weighted selection if multiple registered."""
        return self._select_weighted(provider_name)

    def list_providers(self) -> dict[str, int]:
        """Return registered providers and their instance counts."""
        return {name: len(instances) for name, instances in self._providers.items()}

    def _resolve_by_prefix(self, model_name: str) -> Optional[str]:
        """Resolve provider by model name prefix."""
        prefix_map = {
            "gpt-": "openai",
            "o1": "openai",
            "o3": "openai",
            "claude-": "anthropic",
            "gemini-": "gemini",
        }
        for prefix, provider in prefix_map.items():
            if model_name.startswith(prefix):
                return provider
        return None

    def _select_weighted(self, provider_name: str) -> Optional[BaseProvider]:
        """Select a provider instance using weighted random selection."""
        instances = self._providers.get(provider_name, [])
        if not instances:
            return None
        if len(instances) == 1:
            return instances[0][0]

        # Weighted random selection
        providers, weights = zip(*instances)
        return random.choices(providers, weights=weights, k=1)[0]
