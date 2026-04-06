"""Sprint 11 Tests — Sensitivity-Based Routing & Budget Downgrade.

Covers:
- Routing policy evaluator (sensitivity, budget, compliance tag, composite rules)
- Sensitivity-to-model mapping (PII/PHI → on-premise, clean → public)
- Budget-triggered downgrade (exceeded → cheaper model)
- Llama self-hosted adapter (OpenAI-compatible + Ollama native)
- Routing decision audit log
- Admin API endpoints for routing rules and budget tiers
- Integration test: proxy pipeline with routing policy
"""

import asyncio
import json
import time
import uuid
from unittest.mock import AsyncMock, patch, MagicMock

import pytest


# ── Routing Policy Evaluator Tests ──────────────────────────────────────


class TestRoutingPolicyEvaluator:
    """Tests for the routing policy evaluator."""

    def _make_evaluator(self):
        from app.services.routing_policy import RoutingPolicyEvaluator
        return RoutingPolicyEvaluator(
            private_model="llama-3.1-70b",
            private_provider="llama",
            public_model="gpt-4o",
            public_provider="openai",
        )

    def _make_context(self, **kwargs):
        from app.services.routing_policy import RoutingContext
        defaults = {
            "model_name": "gpt-4o",
            "tenant_id": "tenant-1",
            "api_key_id": "key-1",
            "compliance_tags": [],
            "sensitivity_score": 0.0,
            "requires_private_model": False,
            "kill_switch_active": False,
            "budget_exceeded": False,
            "budget_usage_pct": 0.0,
        }
        defaults.update(kwargs)
        return RoutingContext(**defaults)

    def test_pii_routes_to_private_model(self):
        """Requests tagged with PII route to on-premise model."""
        from app.services.routing_policy import RoutingAction

        evaluator = self._make_evaluator()
        ctx = self._make_context(compliance_tags=["PII"])
        decision = evaluator.evaluate(ctx)

        assert decision.action == RoutingAction.ROUTE
        assert decision.target_model == "llama-3.1-70b"
        assert decision.target_provider == "llama"
        assert "PII" in decision.reason
        assert decision.matched_rule_name == "builtin:sensitivity_routing"

    def test_phi_routes_to_private_model(self):
        """Requests tagged with PHI route to on-premise model."""
        from app.services.routing_policy import RoutingAction

        evaluator = self._make_evaluator()
        ctx = self._make_context(compliance_tags=["PHI"])
        decision = evaluator.evaluate(ctx)

        assert decision.action == RoutingAction.ROUTE
        assert decision.target_model == "llama-3.1-70b"
        assert "PHI" in decision.reason

    def test_ip_routes_to_private_model(self):
        """Requests tagged with IP route to on-premise model."""
        from app.services.routing_policy import RoutingAction

        evaluator = self._make_evaluator()
        ctx = self._make_context(compliance_tags=["IP"])
        decision = evaluator.evaluate(ctx)

        assert decision.action == RoutingAction.ROUTE
        assert decision.target_model == "llama-3.1-70b"

    def test_multiple_sensitive_tags_route_to_private(self):
        """Requests with multiple sensitive tags (PII + PHI) route to on-premise."""
        from app.services.routing_policy import RoutingAction

        evaluator = self._make_evaluator()
        ctx = self._make_context(compliance_tags=["PII", "PHI", "REGULATED"])
        decision = evaluator.evaluate(ctx)

        assert decision.action == RoutingAction.ROUTE
        assert decision.target_model == "llama-3.1-70b"

    def test_clean_request_uses_default_routing(self):
        """Clean requests (no PII/PHI/IP) use default routing."""
        from app.services.routing_policy import RoutingAction

        evaluator = self._make_evaluator()
        ctx = self._make_context(compliance_tags=["PUBLIC"])
        decision = evaluator.evaluate(ctx)

        assert decision.action == RoutingAction.DEFAULT
        assert decision.target_model == "gpt-4o"  # original model preserved

    def test_requires_private_model_flag(self):
        """requires_private_model flag triggers private routing even without tags."""
        from app.services.routing_policy import RoutingAction

        evaluator = self._make_evaluator()
        ctx = self._make_context(requires_private_model=True)
        decision = evaluator.evaluate(ctx)

        assert decision.action == RoutingAction.ROUTE
        assert decision.target_model == "llama-3.1-70b"

    def test_custom_rule_sensitivity_match(self):
        """Custom routing rule with sensitivity condition matches."""
        from app.services.routing_policy import RoutingAction

        evaluator = self._make_evaluator()
        evaluator.load_rules([
            {
                "id": "rule-1",
                "name": "route-regulated-to-llama",
                "priority": 10,
                "condition_type": "sensitivity",
                "condition_json": '{"tags": ["REGULATED"], "operator": "any"}',
                "target_model": "llama-3.1-405b",
                "target_provider": "llama",
                "action": "route",
                "tenant_id": "*",
                "is_active": True,
            }
        ])
        ctx = self._make_context(compliance_tags=["REGULATED"])
        decision = evaluator.evaluate(ctx)

        assert decision.action == RoutingAction.ROUTE
        assert decision.target_model == "llama-3.1-405b"
        assert decision.matched_rule_name == "route-regulated-to-llama"

    def test_custom_rule_budget_exceeded(self):
        """Custom routing rule with budget condition triggers on budget exceeded."""
        from app.services.routing_policy import RoutingAction

        evaluator = self._make_evaluator()
        evaluator.load_rules([
            {
                "id": "rule-2",
                "name": "budget-downgrade",
                "priority": 50,
                "condition_type": "budget",
                "condition_json": '{"budget_exceeded": true}',
                "target_model": "gpt-3.5-turbo",
                "action": "downgrade",
                "tenant_id": "*",
                "is_active": True,
            }
        ])
        ctx = self._make_context(budget_exceeded=True)
        decision = evaluator.evaluate(ctx)

        assert decision.action == RoutingAction.DOWNGRADE
        assert decision.target_model == "gpt-3.5-turbo"

    def test_rule_priority_ordering(self):
        """Higher priority (lower number) rules are evaluated first."""
        from app.services.routing_policy import RoutingAction

        evaluator = self._make_evaluator()
        evaluator.load_rules([
            {
                "id": "rule-low",
                "name": "low-priority",
                "priority": 100,
                "condition_type": "budget",
                "condition_json": '{"budget_exceeded": true}',
                "target_model": "gpt-3.5-turbo",
                "action": "downgrade",
                "tenant_id": "*",
                "is_active": True,
            },
            {
                "id": "rule-high",
                "name": "high-priority",
                "priority": 1,
                "condition_type": "budget",
                "condition_json": '{"budget_exceeded": true}',
                "target_model": "llama-3.2-1b",
                "action": "route",
                "tenant_id": "*",
                "is_active": True,
            },
        ])
        ctx = self._make_context(budget_exceeded=True)
        decision = evaluator.evaluate(ctx)

        assert decision.matched_rule_name == "high-priority"
        assert decision.target_model == "llama-3.2-1b"

    def test_inactive_rule_skipped(self):
        """Inactive rules are skipped during evaluation."""
        from app.services.routing_policy import RoutingAction

        evaluator = self._make_evaluator()
        evaluator.load_rules([
            {
                "id": "rule-inactive",
                "name": "inactive-rule",
                "priority": 1,
                "condition_type": "budget",
                "condition_json": '{"budget_exceeded": true}',
                "target_model": "gpt-3.5-turbo",
                "action": "downgrade",
                "tenant_id": "*",
                "is_active": False,
            }
        ])
        ctx = self._make_context(budget_exceeded=True)
        decision = evaluator.evaluate(ctx)

        assert decision.action == RoutingAction.DEFAULT

    def test_tenant_scoped_rule(self):
        """Rules scoped to a specific tenant only apply to that tenant."""
        from app.services.routing_policy import RoutingAction

        evaluator = self._make_evaluator()
        evaluator.load_rules([
            {
                "id": "rule-scoped",
                "name": "tenant-specific",
                "priority": 10,
                "condition_type": "budget",
                "condition_json": '{"budget_exceeded": true}',
                "target_model": "gpt-3.5-turbo",
                "action": "downgrade",
                "tenant_id": "tenant-2",
                "is_active": True,
            }
        ])
        # Different tenant
        ctx = self._make_context(budget_exceeded=True, tenant_id="tenant-1")
        decision = evaluator.evaluate(ctx)
        assert decision.action == RoutingAction.DEFAULT

        # Matching tenant
        ctx2 = self._make_context(budget_exceeded=True, tenant_id="tenant-2")
        decision2 = evaluator.evaluate(ctx2)
        assert decision2.action == RoutingAction.DOWNGRADE

    def test_composite_rule_and_operator(self):
        """Composite rule with AND operator requires all sub-conditions."""
        from app.services.routing_policy import RoutingAction

        evaluator = self._make_evaluator()
        evaluator.load_rules([
            {
                "id": "rule-composite",
                "name": "sensitive-and-over-budget",
                "priority": 5,
                "condition_type": "composite",
                "condition_json": json.dumps({
                    "operator": "and",
                    "conditions": [
                        {"type": "compliance_tag", "condition": {"tags": ["REGULATED"], "operator": "any"}},
                        {"type": "budget", "condition": {"budget_exceeded": True}},
                    ]
                }),
                "target_model": "llama-3.2-3b",
                "action": "route",
                "tenant_id": "*",
                "is_active": True,
            }
        ])

        # Only one condition met → no match
        ctx1 = self._make_context(compliance_tags=["REGULATED"], budget_exceeded=False)
        assert evaluator.evaluate(ctx1).action == RoutingAction.DEFAULT

        # Both conditions met → match
        ctx2 = self._make_context(compliance_tags=["REGULATED"], budget_exceeded=True)
        decision = evaluator.evaluate(ctx2)
        assert decision.action == RoutingAction.ROUTE
        assert decision.target_model == "llama-3.2-3b"

    def test_compliance_tag_none_operator(self):
        """Compliance tag rule with 'none' operator matches when no tags present."""
        from app.services.routing_policy import RoutingAction

        evaluator = self._make_evaluator()
        evaluator.load_rules([
            {
                "id": "rule-none",
                "name": "no-pii-public",
                "priority": 10,
                "condition_type": "compliance_tag",
                "condition_json": '{"tags": ["PII", "PHI"], "operator": "none"}',
                "target_model": "gpt-4o",
                "target_provider": "openai",
                "action": "route",
                "tenant_id": "*",
                "is_active": True,
            }
        ])

        ctx_clean = self._make_context(compliance_tags=["PUBLIC"])
        assert evaluator.evaluate(ctx_clean).action == RoutingAction.ROUTE

        ctx_pii = self._make_context(compliance_tags=["PII"])
        # PII triggers builtin sensitivity routing first
        decision = evaluator.evaluate(ctx_pii)
        assert decision.target_model == "llama-3.1-70b"

    def test_decision_to_dict(self):
        """RoutingDecision serializes to dict correctly."""
        evaluator = self._make_evaluator()
        ctx = self._make_context(compliance_tags=["PII"])
        decision = evaluator.evaluate(ctx)
        d = decision.to_dict()

        assert "action" in d
        assert "target_model" in d
        assert "original_model" in d
        assert "reason" in d
        assert "evaluation_time_ms" in d
        assert isinstance(d["evaluation_time_ms"], float)

    def test_sensitivity_score_above_threshold(self):
        """Sensitivity condition with score_above threshold."""
        from app.services.routing_policy import RoutingAction

        evaluator = self._make_evaluator()
        evaluator.load_rules([
            {
                "id": "rule-score",
                "name": "high-sensitivity-score",
                "priority": 10,
                "condition_type": "sensitivity",
                "condition_json": '{"operator": "score_above", "threshold": 0.8}',
                "target_model": "llama-3.1-70b",
                "action": "route",
                "tenant_id": "*",
                "is_active": True,
            }
        ])

        ctx_low = self._make_context(sensitivity_score=0.3)
        assert evaluator.evaluate(ctx_low).action == RoutingAction.DEFAULT

        ctx_high = self._make_context(sensitivity_score=0.9)
        decision = evaluator.evaluate(ctx_high)
        assert decision.action == RoutingAction.ROUTE


# ── Budget Downgrade Service Tests ──────────────────────────────────────


class TestBudgetDowngradeService:
    """Tests for the budget-triggered downgrade service."""

    def _make_service(self):
        from app.services.budget_downgrade import BudgetDowngradeService
        svc = BudgetDowngradeService()
        svc.load_tiers([
            {
                "model_name": "gpt-4o",
                "tier_name": "premium",
                "token_budget": 100000,
                "downgrade_model": "gpt-3.5-turbo",
                "budget_window_seconds": 3600,
                "tenant_id": "*",
            },
            {
                "model_name": "gpt-3.5-turbo",
                "tier_name": "standard",
                "token_budget": 500000,
                "downgrade_model": "llama-3.2-3b",
                "budget_window_seconds": 3600,
                "tenant_id": "*",
            },
        ])
        return svc

    @pytest.mark.asyncio
    async def test_budget_exceeded_triggers_downgrade(self):
        """When token budget exceeded, downgrade to cheaper model."""
        svc = self._make_service()

        with patch("app.services.budget_downgrade.get_budget_state", new_callable=AsyncMock) as mock_state:
            mock_state.return_value = {"total_tokens": 150000}
            decision = await svc.evaluate("gpt-4o", "key-1", "tenant-1")

        assert decision.should_downgrade is True
        assert decision.original_model == "gpt-4o"
        assert decision.downgrade_model == "gpt-3.5-turbo"
        assert decision.current_usage == 150000
        assert decision.budget_limit == 100000
        assert decision.usage_pct > 100

    @pytest.mark.asyncio
    async def test_budget_within_limits_no_downgrade(self):
        """When token budget within limits, no downgrade."""
        svc = self._make_service()

        with patch("app.services.budget_downgrade.get_budget_state", new_callable=AsyncMock) as mock_state:
            mock_state.return_value = {"total_tokens": 50000}
            decision = await svc.evaluate("gpt-4o", "key-1", "tenant-1")

        assert decision.should_downgrade is False
        assert decision.downgrade_model == ""

    @pytest.mark.asyncio
    async def test_no_tier_configured_no_downgrade(self):
        """Models without budget tier configured are not downgraded."""
        svc = self._make_service()

        with patch("app.services.budget_downgrade.get_budget_state", new_callable=AsyncMock) as mock_state:
            mock_state.return_value = {"total_tokens": 999999}
            decision = await svc.evaluate("claude-3-opus", "key-1", "tenant-1")

        assert decision.should_downgrade is False

    def test_is_budget_exceeded_sync(self):
        """Synchronous budget check for routing context."""
        svc = self._make_service()

        assert svc.is_budget_exceeded("gpt-4o", 150000) is True
        assert svc.is_budget_exceeded("gpt-4o", 50000) is False
        assert svc.is_budget_exceeded("unknown-model", 999999) is False

    def test_budget_usage_pct(self):
        """Budget usage percentage calculation."""
        svc = self._make_service()

        assert svc.get_budget_usage_pct("gpt-4o", 50000) == 50.0
        assert svc.get_budget_usage_pct("gpt-4o", 100000) == 100.0
        assert svc.get_budget_usage_pct("unknown-model", 100000) == 0.0

    def test_downgrade_decision_to_dict(self):
        """DowngradeDecision serializes correctly."""
        from app.services.budget_downgrade import DowngradeDecision
        d = DowngradeDecision(
            should_downgrade=True,
            original_model="gpt-4o",
            downgrade_model="gpt-3.5-turbo",
            current_usage=150000,
            budget_limit=100000,
            usage_pct=150.0,
        )
        result = d.to_dict()
        assert result["should_downgrade"] is True
        assert result["downgrade_model"] == "gpt-3.5-turbo"

    @pytest.mark.asyncio
    async def test_tenant_specific_tier_preferred(self):
        """Tenant-specific tiers take priority over global."""
        from app.services.budget_downgrade import BudgetDowngradeService

        svc = BudgetDowngradeService()
        svc.load_tiers([
            {
                "model_name": "gpt-4o",
                "tier_name": "global",
                "token_budget": 100000,
                "downgrade_model": "gpt-3.5-turbo",
                "tenant_id": "*",
            },
            {
                "model_name": "gpt-4o",
                "tier_name": "enterprise",
                "token_budget": 500000,
                "downgrade_model": "gpt-4o-mini",
                "tenant_id": "enterprise-tenant",
            },
        ])

        with patch("app.services.budget_downgrade.get_budget_state", new_callable=AsyncMock) as mock_state:
            mock_state.return_value = {"total_tokens": 200000}

            # Enterprise tenant → higher budget, not exceeded
            decision = await svc.evaluate("gpt-4o", "key-1", "enterprise-tenant")
            assert decision.should_downgrade is False

            # Regular tenant → lower budget, exceeded
            decision2 = await svc.evaluate("gpt-4o", "key-1", "regular-tenant")
            assert decision2.should_downgrade is True
            assert decision2.downgrade_model == "gpt-3.5-turbo"


# ── Llama Provider Adapter Tests ────────────────────────────────────────


class TestLlamaProvider:
    """Tests for the self-hosted Llama provider adapter."""

    def _make_provider(self, api_mode="openai_compat"):
        from app.services.providers.llama import LlamaProvider
        return LlamaProvider(
            base_url="http://localhost:11434",
            api_key="test-key",
            api_mode=api_mode,
        )

    def test_openai_compat_normalize_request(self):
        """OpenAI-compatible mode produces /v1/chat/completions request."""
        from app.services.providers.base import UnifiedRequest, UnifiedMessage

        provider = self._make_provider(api_mode="openai_compat")
        req = UnifiedRequest(
            model="llama-3.1-70b",
            messages=[UnifiedMessage(role="user", content="Hello")],
            temperature=0.7,
            max_tokens=100,
            stream=False,
        )
        url, headers, body = provider.normalize_request(req)

        assert url == "http://localhost:11434/v1/chat/completions"
        assert headers["Authorization"] == "Bearer test-key"

        body_json = json.loads(body)
        assert body_json["model"] == "llama-3.1-70b"
        assert body_json["messages"][0]["content"] == "Hello"
        assert body_json["temperature"] == 0.7
        assert body_json["max_tokens"] == 100

    def test_ollama_native_normalize_request(self):
        """Ollama native mode produces /api/chat request with options."""
        from app.services.providers.base import UnifiedRequest, UnifiedMessage

        provider = self._make_provider(api_mode="ollama_native")
        req = UnifiedRequest(
            model="llama-3.1-70b",
            messages=[UnifiedMessage(role="user", content="Hello")],
            temperature=0.5,
            max_tokens=200,
        )
        url, headers, body = provider.normalize_request(req)

        assert url == "http://localhost:11434/api/chat"
        assert "Authorization" not in headers  # Ollama doesn't use auth typically

        body_json = json.loads(body)
        assert body_json["model"] == "llama-3.1-70b"
        assert body_json["options"]["temperature"] == 0.5
        assert body_json["options"]["num_predict"] == 200

    def test_openai_compat_normalize_response(self):
        """OpenAI-compatible response is normalized correctly."""
        provider = self._make_provider(api_mode="openai_compat")
        response_data = {
            "id": "cmpl-123",
            "model": "llama-3.1-70b",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hello!"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
            },
        }
        result = provider.normalize_response(200, response_data)

        assert result.provider == "llama"
        assert result.choices[0].message.content == "Hello!"
        assert result.usage.total_tokens == 15

    def test_ollama_native_normalize_response(self):
        """Ollama native response is normalized correctly."""
        provider = self._make_provider(api_mode="ollama_native")
        response_data = {
            "model": "llama-3.1-70b",
            "message": {"role": "assistant", "content": "Hello!"},
            "done": True,
            "prompt_eval_count": 10,
            "eval_count": 5,
        }
        result = provider.normalize_response(200, response_data)

        assert result.provider == "llama"
        assert result.choices[0].message.content == "Hello!"
        assert result.choices[0].finish_reason == "stop"
        assert result.usage.prompt_tokens == 10
        assert result.usage.completion_tokens == 5

    def test_openai_compat_stream_chunk(self):
        """OpenAI-compatible streaming chunk parsed correctly."""
        provider = self._make_provider(api_mode="openai_compat")
        chunk_line = 'data: {"id":"cmpl-1","choices":[{"delta":{"content":"Hi"},"finish_reason":null}],"model":"llama-3.1-70b"}'

        chunk = provider.normalize_stream_chunk(chunk_line)
        assert chunk is not None
        assert chunk.delta_content == "Hi"
        assert chunk.provider == "llama"

    def test_openai_compat_stream_done(self):
        """[DONE] marker returns None."""
        provider = self._make_provider(api_mode="openai_compat")
        assert provider.normalize_stream_chunk("data: [DONE]") is None

    def test_ollama_native_stream_chunk(self):
        """Ollama native streaming chunk parsed correctly."""
        provider = self._make_provider(api_mode="ollama_native")
        chunk_line = '{"model":"llama-3.1-70b","message":{"role":"assistant","content":"world"},"done":false}'

        chunk = provider.normalize_stream_chunk(chunk_line)
        assert chunk is not None
        assert chunk.delta_content == "world"
        assert chunk.finish_reason is None

    def test_ollama_native_stream_done(self):
        """Ollama native done=true chunk has stop finish reason."""
        provider = self._make_provider(api_mode="ollama_native")
        chunk_line = '{"model":"llama-3.1-70b","message":{"role":"assistant","content":""},"done":true}'

        chunk = provider.normalize_stream_chunk(chunk_line)
        assert chunk is not None
        assert chunk.finish_reason == "stop"

    def test_supported_models(self):
        """Llama provider declares correct supported models."""
        from app.services.providers.llama import LlamaProvider
        assert "llama-3.1-70b" in LlamaProvider.supported_models
        assert "llama-3.1-8b" in LlamaProvider.supported_models
        assert "codellama-70b" in LlamaProvider.supported_models

    def test_provider_name(self):
        provider = self._make_provider()
        assert provider.provider_name == "llama"


# ── Provider Registry Tests ─────────────────────────────────────────────


class TestProviderRegistryLlama:
    """Test that Llama is registered in the provider registry."""

    def test_llama_in_model_map(self):
        from app.services.providers.registry import MODEL_PROVIDER_MAP
        assert MODEL_PROVIDER_MAP.get("llama-3.1-70b") == "llama"
        assert MODEL_PROVIDER_MAP.get("codellama-70b") == "llama"

    def test_llama_prefix_resolution(self):
        from app.services.providers.registry import ProviderRegistry
        from app.services.providers.llama import LlamaProvider

        registry = ProviderRegistry()
        provider = LlamaProvider(base_url="http://localhost:11434")
        registry.register(provider)

        resolved = registry.get_provider_for_model("llama-3.3-70b")
        assert resolved is not None
        assert resolved.provider_name == "llama"


# ── Routing Decision Audit Log Tests ────────────────────────────────────


class TestRoutingAudit:
    """Tests for routing decision audit logging."""

    @pytest.mark.asyncio
    async def test_emit_sensitivity_routing_audit(self):
        """Sensitivity-based routing emits audit event with correct action."""
        from app.services.routing_audit import emit_routing_audit_event
        from app.services.routing_policy import RoutingDecision, RoutingAction

        decision = RoutingDecision(
            action=RoutingAction.ROUTE,
            target_model="llama-3.1-70b",
            target_provider="llama",
            original_model="gpt-4o",
            reason="PII detected",
            matched_rule_name="builtin:sensitivity_routing",
        )

        with patch("app.services.routing_audit.emit_audit_event", new_callable=AsyncMock) as mock_emit:
            await emit_routing_audit_event(
                request_body=b'{}',
                decision=decision,
                tenant_id="tenant-1",
                api_key_id="key-1",
            )

            mock_emit.assert_called_once()
            call_kwargs = mock_emit.call_args[1]
            assert call_kwargs["action"] == "routed_sensitivity"
            assert call_kwargs["model"] == "llama-3.1-70b"
            assert "routing_decision" in call_kwargs["metadata"]

    @pytest.mark.asyncio
    async def test_emit_budget_downgrade_audit(self):
        """Budget downgrade emits audit event with downgrade info."""
        from app.services.routing_audit import emit_routing_audit_event
        from app.services.routing_policy import RoutingDecision, RoutingAction

        decision = RoutingDecision(
            action=RoutingAction.DOWNGRADE,
            target_model="gpt-3.5-turbo",
            original_model="gpt-4o",
            reason="Budget exceeded",
        )

        downgrade_info = {
            "should_downgrade": True,
            "original_model": "gpt-4o",
            "downgrade_model": "gpt-3.5-turbo",
            "current_usage": 150000,
            "budget_limit": 100000,
        }

        with patch("app.services.routing_audit.emit_audit_event", new_callable=AsyncMock) as mock_emit:
            await emit_routing_audit_event(
                request_body=b'{}',
                decision=decision,
                tenant_id="tenant-1",
                api_key_id="key-1",
                downgrade_info=downgrade_info,
            )

            call_kwargs = mock_emit.call_args[1]
            assert call_kwargs["action"] == "downgraded_budget"
            assert "budget_downgrade" in call_kwargs["metadata"]

    @pytest.mark.asyncio
    async def test_emit_default_routing_audit(self):
        """Default routing emits audit event with routed_default action."""
        from app.services.routing_audit import emit_routing_audit_event
        from app.services.routing_policy import RoutingDecision, RoutingAction

        decision = RoutingDecision(
            action=RoutingAction.DEFAULT,
            target_model="gpt-4o",
            original_model="gpt-4o",
        )

        with patch("app.services.routing_audit.emit_audit_event", new_callable=AsyncMock) as mock_emit:
            await emit_routing_audit_event(
                request_body=b'{}',
                decision=decision,
                tenant_id="tenant-1",
            )

            call_kwargs = mock_emit.call_args[1]
            assert call_kwargs["action"] == "routed_default"

    @pytest.mark.asyncio
    async def test_audit_emit_failure_handled_gracefully(self):
        """Audit emit failures are handled without propagating exceptions."""
        from app.services.routing_audit import emit_routing_audit_event
        from app.services.routing_policy import RoutingDecision, RoutingAction

        decision = RoutingDecision(action=RoutingAction.ROUTE, target_model="llama-3.1-70b")

        with patch("app.services.routing_audit.emit_audit_event", new_callable=AsyncMock) as mock_emit:
            mock_emit.side_effect = Exception("Kafka down")
            # Should not raise
            await emit_routing_audit_event(request_body=b'{}', decision=decision)


# ── Integration Tests: Routing Policy with Pipeline Context ─────────────


class TestProxyRoutingIntegration:
    """Integration tests for routing policy evaluation in pipeline context."""

    def test_pii_detected_routes_to_private_in_pipeline(self):
        """PII-tagged request routes to on-premise model (end-to-end logic)."""
        from app.services.routing_policy import get_routing_policy_evaluator, RoutingContext, RoutingAction

        evaluator = get_routing_policy_evaluator()
        ctx = RoutingContext(
            model_name="gpt-4o",
            tenant_id="tenant-1",
            compliance_tags=["PII"],
        )
        decision = evaluator.evaluate(ctx)
        assert decision.action == RoutingAction.ROUTE
        assert decision.target_model == "llama-3.1-70b"

    def test_phi_detected_routes_to_private_in_pipeline(self):
        """PHI-tagged request routes to on-premise model."""
        from app.services.routing_policy import get_routing_policy_evaluator, RoutingContext, RoutingAction

        evaluator = get_routing_policy_evaluator()
        ctx = RoutingContext(
            model_name="gpt-4o",
            tenant_id="tenant-1",
            compliance_tags=["PHI"],
        )
        decision = evaluator.evaluate(ctx)
        assert decision.action == RoutingAction.ROUTE
        assert decision.target_model == "llama-3.1-70b"

    def test_clean_request_routes_to_public_in_pipeline(self):
        """Clean request (no PII/PHI) keeps original model."""
        from app.services.routing_policy import get_routing_policy_evaluator, RoutingContext, RoutingAction

        evaluator = get_routing_policy_evaluator()
        ctx = RoutingContext(
            model_name="gpt-4o",
            tenant_id="tenant-1",
            compliance_tags=["PUBLIC"],
        )
        decision = evaluator.evaluate(ctx)
        assert decision.action == RoutingAction.DEFAULT
        assert decision.target_model == "gpt-4o"

    @pytest.mark.asyncio
    async def test_budget_exceeded_triggers_downgrade_in_pipeline(self):
        """Budget exceeded triggers model downgrade in pipeline context."""
        from app.services.budget_downgrade import BudgetDowngradeService

        svc = BudgetDowngradeService()
        svc.load_tiers([{
            "model_name": "gpt-4o",
            "tier_name": "standard",
            "token_budget": 100000,
            "downgrade_model": "gpt-3.5-turbo",
            "tenant_id": "*",
        }])

        with patch("app.services.budget_downgrade.get_budget_state", new_callable=AsyncMock) as mock_state:
            mock_state.return_value = {"total_tokens": 200000}
            decision = await svc.evaluate("gpt-4o", "key-1", "tenant-1")

        assert decision.should_downgrade is True
        assert decision.downgrade_model == "gpt-3.5-turbo"
        assert decision.current_usage == 200000

    @pytest.mark.asyncio
    async def test_downgrade_event_logged_in_audit(self):
        """Budget downgrade event is logged in audit trail."""
        from app.services.routing_audit import emit_routing_audit_event
        from app.services.routing_policy import RoutingDecision, RoutingAction

        decision = RoutingDecision(
            action=RoutingAction.DOWNGRADE,
            target_model="gpt-3.5-turbo",
            original_model="gpt-4o",
            reason="Budget exceeded",
        )

        with patch("app.services.routing_audit.emit_audit_event", new_callable=AsyncMock) as mock_emit:
            await emit_routing_audit_event(
                request_body=b'{"model": "gpt-4o"}',
                decision=decision,
                tenant_id="tenant-1",
                api_key_id="key-1",
                downgrade_info={"current_usage": 150000, "budget_limit": 100000},
            )

            mock_emit.assert_called_once()
            call_kwargs = mock_emit.call_args[1]
            assert call_kwargs["action"] == "downgraded_budget"
            assert call_kwargs["model"] == "gpt-3.5-turbo"


# ── Admin API Endpoint Registration Tests ───────────────────────────────


class TestAdminRoutingEndpoints:
    """Tests that verify admin API endpoints are properly registered."""

    def test_routing_rules_endpoints_registered(self):
        """Verify routing rules CRUD endpoints exist in admin router."""
        from app.routers.admin import router
        route_paths = [getattr(r, 'path', '') for r in router.routes]
        assert any("routing-rules" in p for p in route_paths)

    def test_budget_tiers_endpoints_registered(self):
        """Verify budget tier endpoints exist in admin router."""
        from app.routers.admin import router
        route_paths = [getattr(r, 'path', '') for r in router.routes]
        assert any("budget-tiers" in p for p in route_paths)

    def test_routing_policy_status_endpoint_registered(self):
        """Verify routing policy status endpoint exists."""
        from app.routers.admin import router
        route_paths = [getattr(r, 'path', '') for r in router.routes]
        assert any("routing-policy/status" in p for p in route_paths)

    def test_create_routing_rule_request_model(self):
        """CreateRoutingRuleRequest model validates correctly."""
        from app.routers.admin import CreateRoutingRuleRequest
        req = CreateRoutingRuleRequest(
            name="test-rule",
            condition_type="sensitivity",
            condition_json='{"tags": ["PII"], "operator": "any"}',
            target_model="llama-3.1-70b",
            action="route",
        )
        assert req.name == "test-rule"
        assert req.priority == 100  # default

    def test_create_budget_tier_request_model(self):
        """CreateBudgetTierRequest model validates correctly."""
        from app.routers.admin import CreateBudgetTierRequest
        req = CreateBudgetTierRequest(
            model_name="gpt-4o",
            token_budget=500000,
            downgrade_model="gpt-3.5-turbo",
        )
        assert req.model_name == "gpt-4o"
        assert req.tier_name == "standard"  # default
        assert req.budget_window_seconds == 3600  # default
