"""Tests for the routing engine."""

import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.services.routing import resolve_provider, get_registry, initialize_registry
from app.services.providers.openai import OpenAIProvider
from app.services.providers.anthropic import AnthropicProvider
from app.services.providers.gemini import GeminiProvider


class TestResolveProvider:
    def setup_method(self):
        # Reset the global registry for each test
        import app.services.routing as routing_mod
        routing_mod._registry = None

    def test_resolve_openai_model(self):
        reg = get_registry()
        reg.register(OpenAIProvider(base_url="https://api.openai.com", api_key="test"))
        provider = resolve_provider("gpt-4")
        assert provider is not None
        assert provider.provider_name == "openai"

    def test_resolve_anthropic_model(self):
        reg = get_registry()
        reg.register(AnthropicProvider(base_url="https://api.anthropic.com", api_key="test"))
        provider = resolve_provider("claude-3-sonnet-20240229")
        assert provider is not None
        assert provider.provider_name == "anthropic"

    def test_resolve_gemini_model(self):
        reg = get_registry()
        reg.register(GeminiProvider(base_url="https://gem.api", api_key="test"))
        provider = resolve_provider("gemini-1.5-pro")
        assert provider is not None
        assert provider.provider_name == "gemini"

    def test_resolve_unknown_returns_none(self):
        assert resolve_provider("unknown-model-xyz") is None


@pytest.mark.asyncio
async def test_initialize_registry():
    import app.services.routing as routing_mod
    routing_mod._registry = None

    providers = [
        {"provider_name": "openai", "api_key": "sk-test", "base_url": "https://api.openai.com"},
        {"provider_name": "anthropic", "api_key": "sk-ant", "base_url": "https://api.anthropic.com"},
        {"provider_name": "gemini", "api_key": "gem-key", "base_url": "https://gem.api"},
    ]
    registry = await initialize_registry(providers)
    info = registry.list_providers()
    assert info["openai"] == 1
    assert info["anthropic"] == 1
    assert info["gemini"] == 1


@pytest.mark.asyncio
async def test_initialize_registry_unknown_provider():
    import app.services.routing as routing_mod
    routing_mod._registry = None

    providers = [
        {"provider_name": "unknown_provider", "api_key": "key", "base_url": "https://example.com"},
    ]
    registry = await initialize_registry(providers)
    assert "unknown_provider" not in registry.list_providers()
