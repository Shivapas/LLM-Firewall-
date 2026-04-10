"""Sprint 6 — Gateway / Proxy Integration Mode Tests.

Exit criteria (PRD §10 Sprint 6):
  - Thoth classification operates identically across all LLM vendor endpoints
    routed through Sphinx.
  - Per-application classification policy is configurable at the route level.

Test coverage
-------------
S6-T1  ThothProxyPlugin — Thoth callable from Sphinx reverse proxy intercept.
         - plugin.classify_for_route() returns ProxyClassificationResult
         - vendor tag is correctly attached to the result
         - route config is resolved and applied
         - disabled route returns event_type="disabled"

S6-T2  RouteConfigRegistry — per-application classification on/off.
         - load_configs() / register_config() / remove_config()
         - get_config() returns per-route config when registered
         - get_config() synthesises default when not registered
         - fallback_enabled flag propagates correctly
         - per-route timeout_ms overrides global setting
         - per-route fail_closed overrides global setting

S6-T3  VendorParityValidator — cross-vendor semantic parity.
         - OpenAI, Anthropic, Azure OAI, Bedrock, OSS body formats all extract
           non-empty prompt text
         - validate_cross_vendor_parity() reports parity_ok=True
         - Empty body gives extraction_ok=False
         - detect_vendor() correctly identifies vendors from model names

S6-T4  Integration — multi-application traffic with mixed classification policies.
         - Two applications: one enabled, one disabled → correct routing
         - Per-route timeout override is respected
         - Per-route fail_closed override is respected
         - Vendor metadata appears in ProxyClassificationResult.to_audit_dict()
         - Cross-vendor: same content classified identically for OpenAI and Anthropic
         - Circuit breaker open → event_type="circuit_open" propagated through plugin
         - Alembic migration 025 has correct revision chain

FR-CFG-02  Selective classification activation per policy group.
FR-PRE-01  All prompts classified before LLM forwarding (via plugin).
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ===========================================================================
# S6-T2: RouteConfigRegistry
# ===========================================================================


class TestRouteClassificationConfig:
    """RouteClassificationConfig dataclass contract."""

    def test_defaults(self):
        from app.services.thoth.route_config import RouteClassificationConfig

        cfg = RouteClassificationConfig(application_id="app-001")
        assert cfg.enabled is True
        assert cfg.timeout_ms is None
        assert cfg.fail_closed is None
        assert cfg.policy_group_id == ""
        assert cfg.vendor_hint == "auto"

    def test_to_dict_contains_all_fields(self):
        from app.services.thoth.route_config import RouteClassificationConfig

        cfg = RouteClassificationConfig(
            application_id="finance-app",
            enabled=True,
            timeout_ms=200,
            fail_closed=True,
            policy_group_id="finance_group",
            vendor_hint="anthropic",
        )
        d = cfg.to_dict()
        assert d["application_id"] == "finance-app"
        assert d["enabled"] is True
        assert d["timeout_ms"] == 200
        assert d["fail_closed"] is True
        assert d["policy_group_id"] == "finance_group"
        assert d["vendor_hint"] == "anthropic"


class TestRouteConfigRegistry:
    """RouteConfigRegistry — per-application CRUD and resolution."""

    def _fresh_registry(self):
        from app.services.thoth.route_config import RouteConfigRegistry

        return RouteConfigRegistry()

    def test_empty_registry_returns_default(self):
        reg = self._fresh_registry()
        cfg = reg.get_config("unknown-app", fallback_enabled=True)
        assert cfg.application_id == "unknown-app"
        assert cfg.enabled is True

    def test_empty_registry_respects_fallback_disabled(self):
        reg = self._fresh_registry()
        cfg = reg.get_config("unknown-app", fallback_enabled=False)
        assert cfg.enabled is False

    def test_load_configs_populates_registry(self):
        reg = self._fresh_registry()
        reg.load_configs([
            {"application_id": "app-a", "enabled": True, "timeout_ms": 100},
            {"application_id": "app-b", "enabled": False},
        ])
        assert reg.count() == 2

    def test_load_configs_skips_missing_application_id(self):
        reg = self._fresh_registry()
        reg.load_configs([{"enabled": True}])  # no application_id
        assert reg.count() == 0

    def test_get_config_returns_registered_config(self):
        from app.services.thoth.route_config import RouteClassificationConfig

        reg = self._fresh_registry()
        reg.register_config(
            RouteClassificationConfig(
                application_id="finance-app",
                enabled=False,
                timeout_ms=300,
                policy_group_id="finops",
                vendor_hint="openai",
            )
        )
        cfg = reg.get_config("finance-app")
        assert cfg.enabled is False
        assert cfg.timeout_ms == 300
        assert cfg.policy_group_id == "finops"
        assert cfg.vendor_hint == "openai"

    def test_get_config_unregistered_app_uses_fallback(self):
        from app.services.thoth.route_config import RouteClassificationConfig

        reg = self._fresh_registry()
        reg.register_config(RouteClassificationConfig("other-app", enabled=False))
        # A different app should still get the default
        cfg = reg.get_config("unknown-app", fallback_enabled=True)
        assert cfg.enabled is True

    def test_register_config_overwrites_previous(self):
        from app.services.thoth.route_config import RouteClassificationConfig

        reg = self._fresh_registry()
        reg.register_config(RouteClassificationConfig("app-x", enabled=True))
        reg.register_config(RouteClassificationConfig("app-x", enabled=False))
        assert reg.get_config("app-x").enabled is False

    def test_remove_config_returns_true_when_existed(self):
        from app.services.thoth.route_config import RouteClassificationConfig

        reg = self._fresh_registry()
        reg.register_config(RouteClassificationConfig("remove-me"))
        assert reg.remove_config("remove-me") is True
        assert reg.count() == 0

    def test_remove_config_returns_false_when_not_found(self):
        reg = self._fresh_registry()
        assert reg.remove_config("ghost-app") is False

    def test_list_configs_returns_all(self):
        from app.services.thoth.route_config import RouteClassificationConfig

        reg = self._fresh_registry()
        reg.load_configs([
            {"application_id": "a1"},
            {"application_id": "a2"},
            {"application_id": "a3"},
        ])
        assert len(reg.list_configs()) == 3

    def test_load_configs_replaces_existing(self):
        from app.services.thoth.route_config import RouteClassificationConfig

        reg = self._fresh_registry()
        reg.register_config(RouteClassificationConfig("old-app"))
        reg.load_configs([{"application_id": "new-app"}])
        assert reg.count() == 1
        assert reg.get_config("old-app").enabled is True  # synthesised default
        assert reg.get_config("new-app").enabled is True  # from loaded config

    def test_fail_closed_per_route_override_none_propagates(self):
        from app.services.thoth.route_config import RouteClassificationConfig

        reg = self._fresh_registry()
        reg.register_config(
            RouteClassificationConfig("app-no-fc", fail_closed=None)
        )
        cfg = reg.get_config("app-no-fc")
        assert cfg.fail_closed is None  # should inherit global

    def test_fail_closed_per_route_override_true(self):
        from app.services.thoth.route_config import RouteClassificationConfig

        reg = self._fresh_registry()
        reg.register_config(
            RouteClassificationConfig("strict-app", fail_closed=True)
        )
        cfg = reg.get_config("strict-app")
        assert cfg.fail_closed is True


# ===========================================================================
# S6-T3: VendorParityValidator + detect_vendor
# ===========================================================================


class TestDetectVendor:
    """detect_vendor() from proxy_plugin resolves vendor correctly."""

    def _dv(self, model_name, vendor_hint="auto", model_endpoint=""):
        from app.services.thoth.proxy_plugin import detect_vendor

        return detect_vendor(model_name, vendor_hint=vendor_hint, model_endpoint=model_endpoint)

    def test_openai_model_prefix(self):
        assert self._dv("gpt-4o") == "openai"

    def test_openai_o1_prefix(self):
        assert self._dv("o1-preview") == "openai"

    def test_anthropic_model_prefix(self):
        assert self._dv("claude-3-5-sonnet-20241022") == "anthropic"

    def test_llama_is_oss(self):
        assert self._dv("llama-3.1-8b-instruct") == "oss"

    def test_mistral_is_oss(self):
        assert self._dv("mistral-7b-instruct") == "oss"

    def test_amazon_titan_is_bedrock(self):
        assert self._dv("amazon.titan-text-express-v1") == "bedrock"

    def test_explicit_vendor_hint_overrides_detection(self):
        assert self._dv("gpt-4", vendor_hint="anthropic") == "anthropic"

    def test_unrecognised_vendor_hint_falls_back_to_auto(self):
        # "foobar" is not a known vendor — should fall back to model-based detection
        assert self._dv("gpt-4o", vendor_hint="foobar") == "openai"

    def test_endpoint_url_openai(self):
        assert self._dv(None, model_endpoint="https://api.openai.com/v1") == "openai"

    def test_endpoint_url_azure(self):
        assert self._dv(None, model_endpoint="https://myinstance.openai.azure.com") == "azure_openai"

    def test_endpoint_url_anthropic(self):
        assert self._dv(None, model_endpoint="https://api.anthropic.com/v1") == "anthropic"

    def test_unknown_model_and_endpoint(self):
        from app.services.thoth.proxy_plugin import VENDOR_UNKNOWN

        assert self._dv("mystery-model-v1") == VENDOR_UNKNOWN


class TestVendorParityValidator:
    """S6-T3: VendorParityValidator confirms identical classification inputs."""

    @pytest.fixture
    def validator(self):
        from app.services.thoth.vendor_parity import VendorParityValidator

        return VendorParityValidator()

    def test_openai_body_extracts_prompt(self, validator):
        from app.services.thoth.vendor_parity import build_openai_body, VENDOR_OPENAI

        body = build_openai_body("What is the capital of France?")
        result = validator.validate_extraction(body, VENDOR_OPENAI)
        assert result.extraction_ok is True
        assert "France" in result.prompt_text

    def test_anthropic_body_extracts_prompt(self, validator):
        from app.services.thoth.vendor_parity import build_anthropic_body, VENDOR_ANTHROPIC

        body = build_anthropic_body("Tell me about Aadhaar card security.")
        result = validator.validate_extraction(body, VENDOR_ANTHROPIC)
        assert result.extraction_ok is True
        assert "Aadhaar" in result.prompt_text

    def test_azure_openai_body_extracts_prompt(self, validator):
        from app.services.thoth.vendor_parity import build_azure_openai_body, VENDOR_AZURE_OPENAI

        body = build_azure_openai_body("Explain DPDPA compliance requirements.")
        result = validator.validate_extraction(body, VENDOR_AZURE_OPENAI)
        assert result.extraction_ok is True
        assert "DPDPA" in result.prompt_text

    def test_bedrock_body_extracts_prompt(self, validator):
        from app.services.thoth.vendor_parity import build_bedrock_body, VENDOR_BEDROCK

        body = build_bedrock_body("What are the key provisions of RBI guidelines?")
        result = validator.validate_extraction(body, VENDOR_BEDROCK)
        assert result.extraction_ok is True
        assert "RBI" in result.prompt_text

    def test_oss_body_extracts_prompt(self, validator):
        from app.services.thoth.vendor_parity import build_oss_body, VENDOR_OSS

        body = build_oss_body("Summarise the recent security incident.")
        result = validator.validate_extraction(body, VENDOR_OSS)
        assert result.extraction_ok is True
        assert "security" in result.prompt_text

    def test_system_prompt_extracted_from_openai_body(self, validator):
        """OpenAI messages-array format: system role content is in prompt_text.

        The core classifier treats role=system messages in the messages array
        as part of prompt_text (not the separate system_prompt field, which is
        for top-level 'system' keys as used by the Anthropic API).
        Both formats produce non-empty extraction_ok=True results.
        """
        from app.services.thoth.vendor_parity import build_openai_body, VENDOR_OPENAI

        body = build_openai_body(
            "Help me with my query.",
            system_prompt="You are a helpful assistant.",
        )
        result = validator.validate_extraction(body, VENDOR_OPENAI)
        assert result.extraction_ok is True
        # For OpenAI messages-array format, the system message content is
        # concatenated into prompt_text (classifier treats role=system as a
        # promptable turn). The semantic content is preserved either way.
        assert "helpful assistant" in result.prompt_text

    def test_system_prompt_extracted_from_anthropic_body(self, validator):
        from app.services.thoth.vendor_parity import build_anthropic_body, VENDOR_ANTHROPIC

        body = build_anthropic_body(
            "How do I secure my application?",
            system_prompt="You are a security expert.",
        )
        result = validator.validate_extraction(body, VENDOR_ANTHROPIC)
        assert result.system_prompt is not None
        assert "security expert" in result.system_prompt

    def test_empty_body_gives_extraction_failed(self, validator):
        result = validator.validate_extraction(b"", "openai")
        assert result.extraction_ok is False
        assert result.char_count == 0

    def test_invalid_json_body_gives_extraction_failed(self, validator):
        result = validator.validate_extraction(b"not json at all", "openai")
        assert result.extraction_ok is False

    def test_validate_cross_vendor_parity_all_pass(self, validator):
        """Core S6-T3 assertion: same content → parity_ok across all 5 vendors."""
        report = validator.validate_cross_vendor_parity(
            user_message="Please provide my account balance details.",
            system_prompt="You are a banking assistant.",
        )
        assert report.parity_ok is True
        assert report.total_samples == 5
        assert len(report.failing) == 0
        assert len(report.passing) == 5

    def test_parity_report_contains_all_vendors(self, validator):
        from app.services.thoth.vendor_parity import (
            VENDOR_OPENAI,
            VENDOR_ANTHROPIC,
            VENDOR_AZURE_OPENAI,
            VENDOR_BEDROCK,
            VENDOR_OSS,
        )

        report = validator.validate_cross_vendor_parity("Tell me about India's data privacy laws.")
        vendor_names = {d.vendor for d in report.details}
        assert VENDOR_OPENAI in vendor_names
        assert VENDOR_ANTHROPIC in vendor_names
        assert VENDOR_AZURE_OPENAI in vendor_names
        assert VENDOR_BEDROCK in vendor_names
        assert VENDOR_OSS in vendor_names

    def test_build_parity_report_with_failing_vendor(self, validator):
        """Parity report correctly identifies a vendor with empty extraction."""
        samples = [
            (b"", "broken_vendor"),
        ]
        report = validator.build_parity_report(samples)
        assert report.parity_ok is False
        assert "broken_vendor" in report.failing

    def test_to_dict_is_serialisable(self, validator):
        report = validator.validate_cross_vendor_parity("Test message")
        d = report.to_dict()
        assert isinstance(d["total_samples"], int)
        assert isinstance(d["passing"], list)
        assert isinstance(d["failing"], list)
        assert isinstance(d["parity_ok"], bool)
        assert isinstance(d["details"], list)
        # Verify JSON-serialisable
        json.dumps(d)

    def test_extraction_result_to_dict(self, validator):
        from app.services.thoth.vendor_parity import build_openai_body, VENDOR_OPENAI

        body = build_openai_body("Sample query")
        result = validator.validate_extraction(body, VENDOR_OPENAI)
        d = result.to_dict()
        assert "vendor" in d
        assert "extraction_ok" in d
        assert "char_count" in d
        json.dumps(d)


# ===========================================================================
# S6-T1: ThothProxyPlugin
# ===========================================================================

def _make_classification_ctx(
    intent="general_query",
    risk_level="LOW",
    confidence=0.90,
    pii_detected=False,
) -> object:
    from app.services.thoth.models import ClassificationContext

    return ClassificationContext(
        request_id=str(uuid.uuid4()),
        intent=intent,
        risk_level=risk_level,
        confidence=confidence,
        pii_detected=pii_detected,
        pii_types=[],
        source="thoth",
    )


class TestThothProxyPlugin:
    """S6-T1: ThothProxyPlugin callable from proxy intercept layer."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        """Ensure each test starts with a clean RouteConfigRegistry."""
        from app.services.thoth.route_config import reset_route_config_registry

        reset_route_config_registry()
        yield
        reset_route_config_registry()

    @pytest.mark.asyncio
    async def test_returns_disabled_when_route_not_enabled(self):
        from app.services.thoth.route_config import (
            RouteClassificationConfig,
            get_route_config_registry,
        )
        from app.services.thoth.proxy_plugin import ThothProxyPlugin

        get_route_config_registry().register_config(
            RouteClassificationConfig("disabled-app", enabled=False)
        )

        plugin = ThothProxyPlugin()
        result = await plugin.classify_for_route(
            b'{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}',
            application_id="disabled-app",
            model_name="gpt-4",
            global_thoth_enabled=True,
        )

        assert result.event_type == "disabled"
        assert result.classification is None
        assert result.application_id == "disabled-app"

    @pytest.mark.asyncio
    async def test_returns_disabled_when_global_disabled_and_no_route_config(self):
        from app.services.thoth.proxy_plugin import ThothProxyPlugin

        plugin = ThothProxyPlugin()
        result = await plugin.classify_for_route(
            b'{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}',
            application_id="any-app",
            global_thoth_enabled=False,
        )
        assert result.event_type == "disabled"

    @pytest.mark.asyncio
    async def test_classify_for_route_calls_classify_prompt(self):
        """classify_for_route delegates to classify_prompt with correct args."""
        from app.services.thoth.proxy_plugin import ThothProxyPlugin

        ctx = _make_classification_ctx()

        with patch(
            "app.services.thoth.proxy_plugin.classify_prompt",
            new=AsyncMock(return_value=(ctx, "classified")),
        ) as mock_classify:
            plugin = ThothProxyPlugin()
            result = await plugin.classify_for_route(
                b'{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hello"}]}',
                application_id="finance-app",
                model_name="claude-3-5-sonnet-20241022",
                tenant_id="tenant-1",
                global_thoth_enabled=True,
                global_timeout_ms=150,
            )

        assert result.event_type == "classified"
        assert result.classification is ctx
        assert result.application_id == "finance-app"
        mock_classify.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_vendor_tag_attached_for_openai(self):
        from app.services.thoth.proxy_plugin import ThothProxyPlugin, VENDOR_OPENAI

        ctx = _make_classification_ctx()
        with patch(
            "app.services.thoth.proxy_plugin.classify_prompt",
            new=AsyncMock(return_value=(ctx, "classified")),
        ):
            plugin = ThothProxyPlugin()
            result = await plugin.classify_for_route(
                b'{"model":"gpt-4o","messages":[{"role":"user","content":"test"}]}',
                application_id="openai-app",
                model_name="gpt-4o",
                global_thoth_enabled=True,
            )
        assert result.vendor == VENDOR_OPENAI

    @pytest.mark.asyncio
    async def test_vendor_tag_attached_for_anthropic(self):
        from app.services.thoth.proxy_plugin import ThothProxyPlugin, VENDOR_ANTHROPIC

        ctx = _make_classification_ctx()
        with patch(
            "app.services.thoth.proxy_plugin.classify_prompt",
            new=AsyncMock(return_value=(ctx, "classified")),
        ):
            plugin = ThothProxyPlugin()
            result = await plugin.classify_for_route(
                b'{"model":"claude-3-opus","messages":[{"role":"user","content":"test"}]}',
                application_id="anthropic-app",
                model_name="claude-3-opus-20240229",
                global_thoth_enabled=True,
            )
        assert result.vendor == VENDOR_ANTHROPIC

    @pytest.mark.asyncio
    async def test_per_route_timeout_overrides_global(self):
        """Route-level timeout_ms is passed to classify_prompt, not global."""
        from app.services.thoth.route_config import (
            RouteClassificationConfig,
            get_route_config_registry,
        )
        from app.services.thoth.proxy_plugin import ThothProxyPlugin

        get_route_config_registry().register_config(
            RouteClassificationConfig("slow-app", enabled=True, timeout_ms=400)
        )

        ctx = _make_classification_ctx()
        captured_timeout: list[int] = []

        async def _mock_classify(body, *, timeout_ms, **kwargs):
            captured_timeout.append(timeout_ms)
            return (ctx, "classified")

        with patch("app.services.thoth.proxy_plugin.classify_prompt", new=_mock_classify):
            plugin = ThothProxyPlugin()
            await plugin.classify_for_route(
                b'{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}',
                application_id="slow-app",
                model_name="gpt-4",
                global_thoth_enabled=True,
                global_timeout_ms=150,
            )

        assert captured_timeout == [400], (
            f"Expected route timeout 400ms, got {captured_timeout}"
        )

    @pytest.mark.asyncio
    async def test_global_timeout_used_when_no_route_override(self):
        from app.services.thoth.proxy_plugin import ThothProxyPlugin

        ctx = _make_classification_ctx()
        captured_timeout: list[int] = []

        async def _mock_classify(body, *, timeout_ms, **kwargs):
            captured_timeout.append(timeout_ms)
            return (ctx, "classified")

        with patch("app.services.thoth.proxy_plugin.classify_prompt", new=_mock_classify):
            plugin = ThothProxyPlugin()
            await plugin.classify_for_route(
                b'{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}',
                application_id="default-app",
                global_thoth_enabled=True,
                global_timeout_ms=200,
            )

        assert captured_timeout == [200]

    @pytest.mark.asyncio
    async def test_timeout_event_propagated_through_plugin(self):
        from app.services.thoth.proxy_plugin import ThothProxyPlugin
        from app.services.thoth.models import make_timeout_context

        timeout_ctx = make_timeout_context("trace-123")

        with patch(
            "app.services.thoth.proxy_plugin.classify_prompt",
            new=AsyncMock(return_value=(timeout_ctx, "timeout")),
        ):
            plugin = ThothProxyPlugin()
            result = await plugin.classify_for_route(
                b'{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}',
                application_id="app-x",
                global_thoth_enabled=True,
            )

        assert result.event_type == "timeout"
        assert result.is_unavailable is True
        assert result.is_classified is False

    @pytest.mark.asyncio
    async def test_circuit_open_event_propagated(self):
        from app.services.thoth.proxy_plugin import ThothProxyPlugin
        from app.services.thoth.models import make_unavailable_context

        unavail_ctx = make_unavailable_context("trace-456", reason="circuit_open")

        with patch(
            "app.services.thoth.proxy_plugin.classify_prompt",
            new=AsyncMock(return_value=(unavail_ctx, "circuit_open")),
        ):
            plugin = ThothProxyPlugin()
            result = await plugin.classify_for_route(
                b'{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}',
                application_id="app-y",
                global_thoth_enabled=True,
            )

        assert result.event_type == "circuit_open"
        assert result.is_unavailable is True

    def test_get_effective_fail_closed_uses_route_override_true(self):
        from app.services.thoth.proxy_plugin import ThothProxyPlugin
        from app.services.thoth.route_config import RouteClassificationConfig

        plugin = ThothProxyPlugin()
        cfg = RouteClassificationConfig("app", fail_closed=True)
        assert plugin.get_effective_fail_closed(cfg, global_fail_closed_enabled=False) is True

    def test_get_effective_fail_closed_uses_route_override_false(self):
        from app.services.thoth.proxy_plugin import ThothProxyPlugin
        from app.services.thoth.route_config import RouteClassificationConfig

        plugin = ThothProxyPlugin()
        cfg = RouteClassificationConfig("app", fail_closed=False)
        assert plugin.get_effective_fail_closed(cfg, global_fail_closed_enabled=True) is False

    def test_get_effective_fail_closed_falls_back_to_global(self):
        from app.services.thoth.proxy_plugin import ThothProxyPlugin
        from app.services.thoth.route_config import RouteClassificationConfig

        plugin = ThothProxyPlugin()
        cfg = RouteClassificationConfig("app", fail_closed=None)
        assert plugin.get_effective_fail_closed(cfg, global_fail_closed_enabled=True) is True
        assert plugin.get_effective_fail_closed(cfg, global_fail_closed_enabled=False) is False

    def test_proxy_classification_result_to_audit_dict(self):
        from app.services.thoth.proxy_plugin import ProxyClassificationResult
        from app.services.thoth.route_config import RouteClassificationConfig

        ctx = _make_classification_ctx()
        result = ProxyClassificationResult(
            classification=ctx,
            event_type="classified",
            application_id="finance-app",
            vendor="openai",
            route_config=RouteClassificationConfig(
                "finance-app",
                enabled=True,
                policy_group_id="finops",
            ),
        )
        d = result.to_audit_dict()
        assert d["proxy_plugin"] is True
        assert d["vendor"] == "openai"
        assert d["application_id"] == "finance-app"
        assert "thoth_classification" in d
        assert "route_config" in d
        # Verify JSON-serialisable
        json.dumps(d)

    def test_proxy_result_is_classified_true(self):
        from app.services.thoth.proxy_plugin import ProxyClassificationResult

        result = ProxyClassificationResult(
            classification=_make_classification_ctx(),
            event_type="classified",
            application_id="app",
        )
        assert result.is_classified is True
        assert result.is_unavailable is False

    def test_proxy_result_is_unavailable_true_for_timeout(self):
        from app.services.thoth.proxy_plugin import ProxyClassificationResult

        result = ProxyClassificationResult(
            classification=None,
            event_type="timeout",
            application_id="app",
        )
        assert result.is_unavailable is True
        assert result.is_classified is False

    def test_singleton_returns_same_instance(self):
        from app.services.thoth.proxy_plugin import get_thoth_proxy_plugin, ThothProxyPlugin

        a = get_thoth_proxy_plugin()
        b = get_thoth_proxy_plugin()
        assert a is b
        assert isinstance(a, ThothProxyPlugin)


# ===========================================================================
# S6-T4: Integration tests — multi-application mixed classification policies
# ===========================================================================


class TestMultiApplicationIntegration:
    """S6-T4: Multi-application traffic with mixed classification policies."""

    @pytest.fixture(autouse=True)
    def reset_registry(self):
        from app.services.thoth.route_config import reset_route_config_registry

        reset_route_config_registry()
        yield
        reset_route_config_registry()

    @pytest.mark.asyncio
    async def test_two_apps_one_enabled_one_disabled(self):
        """Finance app enabled, general app disabled → correct per-app routing."""
        from app.services.thoth.route_config import (
            RouteClassificationConfig,
            get_route_config_registry,
        )
        from app.services.thoth.proxy_plugin import ThothProxyPlugin

        registry = get_route_config_registry()
        registry.register_config(RouteClassificationConfig("finance-app", enabled=True))
        registry.register_config(RouteClassificationConfig("general-app", enabled=False))

        ctx = _make_classification_ctx()

        with patch(
            "app.services.thoth.proxy_plugin.classify_prompt",
            new=AsyncMock(return_value=(ctx, "classified")),
        ) as mock_classify:
            plugin = ThothProxyPlugin()
            body = b'{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}'

            # Finance app → classification called
            finance_result = await plugin.classify_for_route(
                body,
                application_id="finance-app",
                global_thoth_enabled=True,
            )
            assert finance_result.event_type == "classified"

            # General app → classification NOT called
            general_result = await plugin.classify_for_route(
                body,
                application_id="general-app",
                global_thoth_enabled=True,
            )
            assert general_result.event_type == "disabled"

        # classify_prompt should only have been called for finance-app
        assert mock_classify.await_count == 1

    @pytest.mark.asyncio
    async def test_policy_group_id_in_route_config(self):
        """Policy group ID is preserved in ProxyClassificationResult.route_config."""
        from app.services.thoth.route_config import (
            RouteClassificationConfig,
            get_route_config_registry,
        )
        from app.services.thoth.proxy_plugin import ThothProxyPlugin

        get_route_config_registry().register_config(
            RouteClassificationConfig(
                "regulated-app",
                enabled=True,
                policy_group_id="financial_services",
            )
        )

        ctx = _make_classification_ctx()
        with patch(
            "app.services.thoth.proxy_plugin.classify_prompt",
            new=AsyncMock(return_value=(ctx, "classified")),
        ):
            plugin = ThothProxyPlugin()
            result = await plugin.classify_for_route(
                b'{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}',
                application_id="regulated-app",
                global_thoth_enabled=True,
            )

        assert result.route_config is not None
        assert result.route_config.policy_group_id == "financial_services"

    @pytest.mark.asyncio
    async def test_cross_vendor_same_content_same_event_type(self):
        """Same prompt via OpenAI and Anthropic formats → same classification event."""
        from app.services.thoth.proxy_plugin import ThothProxyPlugin
        from app.services.thoth.vendor_parity import build_openai_body, build_anthropic_body

        user_msg = "What is the procedure to export customer PAN card numbers?"
        openai_body = build_openai_body(user_msg)
        anthropic_body = build_anthropic_body(user_msg)

        ctx = _make_classification_ctx(intent="data_exfiltration", risk_level="HIGH", confidence=0.91)

        with patch(
            "app.services.thoth.proxy_plugin.classify_prompt",
            new=AsyncMock(return_value=(ctx, "classified")),
        ):
            plugin = ThothProxyPlugin()

            openai_result = await plugin.classify_for_route(
                openai_body,
                application_id="test-app",
                model_name="gpt-4o",
                global_thoth_enabled=True,
            )
            anthropic_result = await plugin.classify_for_route(
                anthropic_body,
                application_id="test-app",
                model_name="claude-3-5-sonnet-20241022",
                global_thoth_enabled=True,
            )

        # Both should produce the same event_type and classification
        assert openai_result.event_type == anthropic_result.event_type == "classified"
        assert openai_result.classification.intent == anthropic_result.classification.intent

    @pytest.mark.asyncio
    async def test_per_route_fail_closed_override_respected(self):
        """Per-route fail_closed=True overrides global fail_closed=False."""
        from app.services.thoth.route_config import (
            RouteClassificationConfig,
            get_route_config_registry,
        )
        from app.services.thoth.proxy_plugin import ThothProxyPlugin
        from app.services.thoth.models import make_timeout_context

        get_route_config_registry().register_config(
            RouteClassificationConfig("strict-app", enabled=True, fail_closed=True)
        )

        timeout_ctx = make_timeout_context("t-001")
        with patch(
            "app.services.thoth.proxy_plugin.classify_prompt",
            new=AsyncMock(return_value=(timeout_ctx, "timeout")),
        ):
            plugin = ThothProxyPlugin()
            result = await plugin.classify_for_route(
                b'{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}',
                application_id="strict-app",
                global_thoth_enabled=True,
                global_fail_closed_enabled=False,  # Global says don't fail closed
            )

        # The route says fail_closed=True — plugin.get_effective_fail_closed
        # should resolve to True (per-route wins)
        assert result.route_config.fail_closed is True
        effective = plugin.get_effective_fail_closed(
            result.route_config,
            global_fail_closed_enabled=False,
        )
        assert effective is True

    @pytest.mark.asyncio
    async def test_audit_dict_vendor_tagged_for_bedrock(self):
        from app.services.thoth.proxy_plugin import ThothProxyPlugin, VENDOR_BEDROCK
        from app.services.thoth.vendor_parity import build_bedrock_body

        body = build_bedrock_body("Summarise the latest security report.")

        ctx = _make_classification_ctx()
        with patch(
            "app.services.thoth.proxy_plugin.classify_prompt",
            new=AsyncMock(return_value=(ctx, "classified")),
        ):
            plugin = ThothProxyPlugin()
            result = await plugin.classify_for_route(
                body,
                application_id="bedrock-app",
                model_name="amazon.titan-text-express-v1",
                global_thoth_enabled=True,
            )

        assert result.vendor == VENDOR_BEDROCK
        audit_dict = result.to_audit_dict()
        assert audit_dict["vendor"] == VENDOR_BEDROCK

    @pytest.mark.asyncio
    async def test_multiple_apps_each_with_own_timeout(self):
        """Three apps with different timeout overrides all use their own."""
        from app.services.thoth.route_config import (
            RouteClassificationConfig,
            get_route_config_registry,
        )
        from app.services.thoth.proxy_plugin import ThothProxyPlugin

        registry = get_route_config_registry()
        registry.register_config(RouteClassificationConfig("app-fast", timeout_ms=50))
        registry.register_config(RouteClassificationConfig("app-mid", timeout_ms=200))
        registry.register_config(RouteClassificationConfig("app-slow", timeout_ms=500))

        timeouts: list[int] = []
        ctx = _make_classification_ctx()

        async def _mock_classify(body, *, timeout_ms, **kwargs):
            timeouts.append(timeout_ms)
            return (ctx, "classified")

        body = b'{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}'
        with patch("app.services.thoth.proxy_plugin.classify_prompt", new=_mock_classify):
            plugin = ThothProxyPlugin()
            for app_id in ("app-fast", "app-mid", "app-slow"):
                await plugin.classify_for_route(
                    body,
                    application_id=app_id,
                    global_thoth_enabled=True,
                    global_timeout_ms=150,
                )

        assert timeouts == [50, 200, 500]

    def test_vendor_hint_in_route_config_used_for_detection(self):
        """vendor_hint in RouteClassificationConfig is used by detect_vendor."""
        from app.services.thoth.proxy_plugin import detect_vendor

        # Model is OSS llama but vendor_hint says anthropic
        vendor = detect_vendor("llama-3.1-8b", vendor_hint="anthropic")
        assert vendor == "anthropic"


# ===========================================================================
# Migration 025 structural validation
# ===========================================================================


class TestMigration025:
    """Alembic migration 025 adds route_classification_configs table."""

    def _load_migration(self):
        mig_path = (
            pathlib.Path(__file__).parent.parent
            / "alembic/versions/025_sprint6_proxy_plugin_route_config.py"
        )
        spec = importlib.util.spec_from_file_location("migration_025", mig_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_revision_chain(self):
        mod = self._load_migration()
        assert mod.revision == "025"
        assert mod.down_revision == "024"

    def test_upgrade_creates_table(self):
        mod = self._load_migration()
        tables_created: list[str] = []

        def _mock_create_table(table_name, *cols, **kw):
            tables_created.append(table_name)

        from alembic import op as _op
        from unittest.mock import patch as _patch

        with (
            _patch.object(_op, "create_table", side_effect=_mock_create_table),
            _patch.object(_op, "create_index"),
        ):
            mod.upgrade()

        assert "route_classification_configs" in tables_created

    def test_upgrade_creates_expected_indexes(self):
        mod = self._load_migration()
        indexes_created: list[str] = []

        def _mock_create_index(idx_name, *args, **kwargs):
            indexes_created.append(idx_name)

        from alembic import op as _op
        from unittest.mock import patch as _patch

        with (
            _patch.object(_op, "create_table"),
            _patch.object(_op, "create_index", side_effect=_mock_create_index),
        ):
            mod.upgrade()

        assert "ix_route_cfg_application_id" in indexes_created
        assert "ix_route_cfg_policy_group_id" in indexes_created

    def test_downgrade_drops_table_and_indexes(self):
        mod = self._load_migration()
        dropped_tables: list[str] = []
        dropped_indexes: list[str] = []

        def _mock_drop_table(name):
            dropped_tables.append(name)

        def _mock_drop_index(name, **kw):
            dropped_indexes.append(name)

        from alembic import op as _op
        from unittest.mock import patch as _patch

        with (
            _patch.object(_op, "drop_table", side_effect=_mock_drop_table),
            _patch.object(_op, "drop_index", side_effect=_mock_drop_index),
        ):
            mod.downgrade()

        assert "route_classification_configs" in dropped_tables
        assert "ix_route_cfg_application_id" in dropped_indexes
        assert "ix_route_cfg_policy_group_id" in dropped_indexes


# ===========================================================================
# Singleton accessor tests
# ===========================================================================


class TestSingletonAccessors:
    """Singleton get_* functions return correct types."""

    def test_get_route_config_registry_creates_instance(self):
        from app.services.thoth.route_config import (
            reset_route_config_registry,
            get_route_config_registry,
            RouteConfigRegistry,
        )

        reset_route_config_registry()
        registry = get_route_config_registry()
        assert isinstance(registry, RouteConfigRegistry)

    def test_get_route_config_registry_returns_same_instance(self):
        from app.services.thoth.route_config import (
            reset_route_config_registry,
            get_route_config_registry,
        )

        reset_route_config_registry()
        r1 = get_route_config_registry()
        r2 = get_route_config_registry()
        assert r1 is r2

    def test_get_vendor_parity_validator_creates_instance(self):
        from app.services.thoth.vendor_parity import (
            get_vendor_parity_validator,
            VendorParityValidator,
        )

        v = get_vendor_parity_validator()
        assert isinstance(v, VendorParityValidator)

    def test_get_vendor_parity_validator_same_instance(self):
        from app.services.thoth.vendor_parity import get_vendor_parity_validator

        a = get_vendor_parity_validator()
        b = get_vendor_parity_validator()
        assert a is b
