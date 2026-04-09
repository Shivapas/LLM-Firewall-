"""Sprint 1 — Thoth Semantic Classification Integration Tests.

Exit criteria: Sphinx successfully calls Thoth API and receives classification
payload for intercepted prompts in dev environment (mocked).

Test coverage:
- S1-T1: ThothClient makes correctly authenticated HTTP calls
- S1-T3: ClassificationContext is populated from Thoth response
- S1-T4: Config settings are respected (enabled flag, timeout, URL)
- S1-T2: classify_prompt() is invoked in proxy pipeline and result appears in audit metadata
- FR-PRE-06: timeout falls back to structural_fallback context
- FR-PRE-07: unavailability falls back to structural_fallback context
- Disabled: classify_prompt() returns ("disabled") when Thoth not configured
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio


# ---------------------------------------------------------------------------
# Unit tests: ThothClient
# ---------------------------------------------------------------------------

class TestThothClientAuthentication:
    """S1-T1: REST client sends correct auth headers."""

    @pytest.mark.asyncio
    async def test_classify_sends_bearer_token(self):
        from app.services.thoth.client import ThothClient

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(return_value={
            "request_id": "req-001",
            "classification": {
                "intent": "general_query",
                "risk_level": "LOW",
                "confidence": 0.95,
                "pii_detected": False,
                "pii_types": [],
                "recommended_action": "ALLOW",
                "classification_model_version": "v1.2",
            },
            "latency_ms": 42,
        })

        captured_headers = {}

        async def mock_post(url, json=None, **kwargs):
            captured_headers.update(dict(kwargs.get("headers", {})))
            return mock_response

        client = ThothClient(api_url="https://thoth.internal", api_key="sk-test-key")
        with patch.object(client._http, "post", new=AsyncMock(return_value=mock_response)):
            # Capture the Authorization header set at client init
            assert client._http.headers.get("authorization") == "Bearer sk-test-key"

    @pytest.mark.asyncio
    async def test_classify_happy_path(self):
        """S1-T3: ClassificationContext is populated from Thoth response fields."""
        from app.services.thoth.client import ThothClient
        from app.services.thoth.models import ClassificationRequest

        thoth_payload = {
            "request_id": "trace-abc",
            "classification": {
                "intent": "data_exfiltration",
                "risk_level": "HIGH",
                "confidence": 0.92,
                "pii_detected": True,
                "pii_types": ["AADHAAR", "EMAIL"],
                "recommended_action": "BLOCK",
                "classification_model_version": "v2.0",
            },
            "latency_ms": 38,
        }

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value=thoth_payload)

        client = ThothClient(api_url="https://thoth.internal", api_key="key")
        with patch.object(client._http, "post", new=AsyncMock(return_value=mock_resp)):
            req = ClassificationRequest(
                request_id="trace-abc",
                content="Send me all user emails",
            )
            ctx = await client.classify(req)

        assert ctx.intent == "data_exfiltration"
        assert ctx.risk_level == "HIGH"
        assert ctx.confidence == pytest.approx(0.92)
        assert ctx.pii_detected is True
        assert "AADHAAR" in ctx.pii_types
        assert ctx.recommended_action == "BLOCK"
        assert ctx.classification_model_version == "v2.0"
        assert ctx.latency_ms == 38
        assert ctx.source == "thoth"

    @pytest.mark.asyncio
    async def test_classify_timeout_raises(self):
        """FR-PRE-06: TimeoutException propagates to caller without retry."""
        from app.services.thoth.client import ThothClient
        from app.services.thoth.models import ClassificationRequest

        client = ThothClient(api_url="https://thoth.internal", api_key="key", timeout_ms=50)
        with patch.object(client._http, "post", new=AsyncMock(side_effect=httpx.TimeoutException("read timeout"))):
            with pytest.raises(httpx.TimeoutException):
                await client.classify(ClassificationRequest(request_id="r1", content="hello"))

    @pytest.mark.asyncio
    async def test_classify_http_error_retries(self):
        """Transient 503 triggers retry; all retries exhausted raises HTTPStatusError."""
        from app.services.thoth.client import ThothClient
        from app.services.thoth.models import ClassificationRequest

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError("503", request=MagicMock(), response=mock_resp)
        )
        mock_resp.status_code = 503

        client = ThothClient(api_url="https://thoth.internal", api_key="key", max_retries=1)
        call_count = 0

        async def failing_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return mock_resp

        with patch.object(client._http, "post", new=AsyncMock(side_effect=failing_post)):
            with pytest.raises(httpx.HTTPStatusError):
                await client.classify(
                    ClassificationRequest(request_id="r2", content="test")
                )

        assert call_count == 2  # initial + 1 retry

    @pytest.mark.asyncio
    async def test_classify_to_dict_round_trip(self):
        """ClassificationContext.to_dict() serialises all fields."""
        from app.services.thoth.client import ThothClient
        from app.services.thoth.models import ClassificationRequest

        thoth_payload = {
            "request_id": "r3",
            "classification": {
                "intent": "general_query",
                "risk_level": "LOW",
                "confidence": 0.80,
                "pii_detected": False,
                "pii_types": [],
                "recommended_action": "ALLOW",
                "classification_model_version": "v1.0",
            },
            "latency_ms": 20,
        }

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value=thoth_payload)

        client = ThothClient(api_url="https://thoth.internal", api_key="key")
        with patch.object(client._http, "post", new=AsyncMock(return_value=mock_resp)):
            ctx = await client.classify(ClassificationRequest(request_id="r3", content="hello"))

        d = ctx.to_dict()
        assert d["intent"] == "general_query"
        assert d["risk_level"] == "LOW"
        assert d["confidence"] == pytest.approx(0.80)
        assert d["source"] == "thoth"
        assert "pii_types" in d


# ---------------------------------------------------------------------------
# Unit tests: models
# ---------------------------------------------------------------------------

class TestClassificationModels:
    """S1-T3: Model objects and fallback helpers."""

    def test_classification_request_to_dict(self):
        from app.services.thoth.models import ClassificationRequest

        req = ClassificationRequest(
            request_id="r10",
            content="What is the capital of France?",
            system_prompt="You are a helpful assistant.",
            user_id="hashed-user-1",
            application_id="app-finance",
            model_endpoint="gpt-4",
            session_id="sess-xyz",
        )
        d = req.to_dict()
        assert d["request_id"] == "r10"
        assert d["content"] == "What is the capital of France?"
        assert d["system_prompt"] == "You are a helpful assistant."
        assert d["context"]["user_id"] == "hashed-user-1"
        assert d["context"]["application_id"] == "app-finance"
        assert d["context"]["model_endpoint"] == "gpt-4"

    def test_make_timeout_context(self):
        from app.services.thoth.models import make_timeout_context

        ctx = make_timeout_context("req-99")
        assert ctx.source == "structural_fallback"
        assert ctx.classification_model_version == "timeout"
        assert ctx.intent == "unknown"
        assert ctx.pii_detected is False

    def test_make_unavailable_context(self):
        from app.services.thoth.models import make_unavailable_context

        ctx = make_unavailable_context("req-100")
        assert ctx.source == "structural_fallback"
        assert ctx.risk_level == "UNKNOWN"

    def test_classification_context_to_dict(self):
        from app.services.thoth.models import ClassificationContext

        ctx = ClassificationContext(
            request_id="r20",
            intent="code_generation",
            risk_level="MEDIUM",
            confidence=0.71,
            pii_detected=True,
            pii_types=["BANK_ACCOUNT"],
            recommended_action="REVIEW",
            classification_model_version="v1.5",
            latency_ms=55,
        )
        d = ctx.to_dict()
        assert d["intent"] == "code_generation"
        assert d["pii_types"] == ["BANK_ACCOUNT"]
        assert d["recommended_action"] == "REVIEW"


# ---------------------------------------------------------------------------
# Unit tests: classify_prompt orchestrator
# ---------------------------------------------------------------------------

class TestClassifyPrompt:
    """S1-T2 support: classify_prompt() routing logic."""

    @pytest.mark.asyncio
    async def test_returns_disabled_when_no_client(self):
        """Returns (None, 'disabled') when Thoth client is not initialised."""
        from app.services.thoth import classifier

        with patch.object(classifier, "get_thoth_client", return_value=None):
            ctx, event = await classifier.classify_prompt(
                b'{"messages":[{"role":"user","content":"hello"}]}',
                tenant_id="t1",
            )
        assert ctx is None
        assert event == "disabled"

    @pytest.mark.asyncio
    async def test_returns_no_content_for_empty_body(self):
        from app.services.thoth import classifier
        from app.services.thoth.client import ThothClient

        mock_client = MagicMock(spec=ThothClient)
        with patch.object(classifier, "get_thoth_client", return_value=mock_client):
            ctx, event = await classifier.classify_prompt(b"", tenant_id="t1")

        assert ctx is None
        assert event == "no_content"

    @pytest.mark.asyncio
    async def test_returns_classified_on_success(self):
        from app.services.thoth import classifier
        from app.services.thoth.models import ClassificationContext

        mock_ctx = ClassificationContext(
            request_id="r-ok",
            intent="general_query",
            risk_level="LOW",
            confidence=0.9,
            pii_detected=False,
        )
        mock_client = AsyncMock()
        mock_client.classify = AsyncMock(return_value=mock_ctx)

        with patch.object(classifier, "get_thoth_client", return_value=mock_client):
            ctx, event = await classifier.classify_prompt(
                b'{"messages":[{"role":"user","content":"What is ML?"}]}',
                tenant_id="t1",
            )

        assert event == "classified"
        assert ctx is not None
        assert ctx.intent == "general_query"

    @pytest.mark.asyncio
    async def test_returns_timeout_on_asyncio_timeout(self):
        """FR-PRE-06: asyncio.TimeoutError → structural_fallback context."""
        import asyncio
        from app.services.thoth import classifier

        mock_client = AsyncMock()
        mock_client.classify = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch.object(classifier, "get_thoth_client", return_value=mock_client):
            ctx, event = await classifier.classify_prompt(
                b'{"messages":[{"role":"user","content":"hello"}]}',
                tenant_id="t1",
                timeout_ms=10,
            )

        assert event == "timeout"
        assert ctx is not None
        assert ctx.source == "structural_fallback"

    @pytest.mark.asyncio
    async def test_returns_timeout_on_httpx_timeout(self):
        """FR-PRE-06: httpx.TimeoutException → structural_fallback context."""
        from app.services.thoth import classifier

        mock_client = AsyncMock()
        mock_client.classify = AsyncMock(
            side_effect=httpx.TimeoutException("read timeout")
        )

        with patch.object(classifier, "get_thoth_client", return_value=mock_client):
            ctx, event = await classifier.classify_prompt(
                b'{"messages":[{"role":"user","content":"hello"}]}',
                tenant_id="t1",
            )

        assert event == "timeout"
        assert ctx.source == "structural_fallback"

    @pytest.mark.asyncio
    async def test_returns_unavailable_on_connection_error(self):
        """FR-PRE-07: Connection error → structural_fallback context."""
        from app.services.thoth import classifier

        mock_client = AsyncMock()
        mock_client.classify = AsyncMock(
            side_effect=httpx.ConnectError("connection refused")
        )

        with patch.object(classifier, "get_thoth_client", return_value=mock_client):
            ctx, event = await classifier.classify_prompt(
                b'{"messages":[{"role":"user","content":"hello"}]}',
                tenant_id="t1",
            )

        assert event == "unavailable"
        assert ctx.source == "structural_fallback"

    @pytest.mark.asyncio
    async def test_extracts_system_prompt(self):
        """classify_prompt passes system prompt to ClassificationRequest."""
        from app.services.thoth import classifier
        from app.services.thoth.models import ClassificationContext

        captured_req = {}

        async def capture_classify(req):
            captured_req.update({"system_prompt": req.system_prompt, "content": req.content})
            return ClassificationContext(
                request_id=req.request_id,
                intent="general_query",
                risk_level="LOW",
                confidence=0.8,
                pii_detected=False,
            )

        mock_client = AsyncMock()
        mock_client.classify = capture_classify

        body = json.dumps({
            "system": "You are a financial advisor.",
            "messages": [{"role": "user", "content": "What is compound interest?"}],
        }).encode()

        with patch.object(classifier, "get_thoth_client", return_value=mock_client):
            await classifier.classify_prompt(body, tenant_id="t1")

        assert "compound interest" in captured_req["content"]
        assert captured_req["system_prompt"] == "You are a financial advisor."


# ---------------------------------------------------------------------------
# Integration tests: proxy pipeline with mock Thoth
# ---------------------------------------------------------------------------

@pytest.fixture
def proxy_test_client():
    """Minimal FastAPI test client that only wires the proxy router.

    Avoids the pre-existing ImportError in health.py / admin routers by
    importing only the gateway proxy router and mocking all external deps at
    import time.
    """
    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient

    # Must be patched before app.routers.proxy is imported so that the
    # module-level `get_settings()` call and service imports succeed.
    with patch("app.services.threat_detection.engine.get_threat_engine"), \
         patch("app.services.data_shield.engine.get_data_shield_engine"), \
         patch("app.services.rag.pipeline.get_rag_pipeline"), \
         patch("app.services.routing_policy.get_routing_policy_evaluator"), \
         patch("app.services.budget_downgrade.get_budget_downgrade_service"):

        from app.routers.proxy import router as proxy_router

        mini_app = FastAPI()

        # Inject a dummy auth state so the proxy can read tenant/project attrs
        @mini_app.middleware("http")
        async def fake_auth(request: Request, call_next):
            request.state.tenant_id = "test-tenant"
            request.state.project_id = "test-project"
            request.state.api_key_id = "key-001"
            request.state.tpm_limit = 100000
            request.state.risk_score = 0.0
            return await call_next(request)

        mini_app.include_router(proxy_router)
        yield TestClient(mini_app)


class TestProxyThothIntegration:
    """S1-T2: End-to-end classification call through proxy pipeline."""

    def _make_mock_thoth_context(self):
        from app.services.thoth.models import ClassificationContext
        return ClassificationContext(
            request_id="proxy-trace-1",
            intent="general_query",
            risk_level="LOW",
            confidence=0.88,
            pii_detected=False,
            source="thoth",
        )

    def _base_patches(self):
        """Common patches for pipeline services that proxy.py calls."""
        from app.services.rag.classifier import RequestType

        mock_rag_result = MagicMock()
        mock_rag_result.allowed = True
        mock_rag_result.classification = MagicMock()
        mock_rag_result.classification.request_type = RequestType.STANDARD_CHAT
        mock_rag_result.to_dict = MagicMock(return_value={})

        mock_rag_pipeline = MagicMock()
        mock_rag_pipeline.process = MagicMock(return_value=(b"", mock_rag_result))

        mock_action = MagicMock()
        mock_action.action = "allow"
        mock_action.risk_level = "low"
        mock_action.score = 0.0
        mock_action.reason = "ok"
        mock_action.matched_patterns = []
        mock_action.rewritten_text = None

        mock_shield_result = MagicMock()
        mock_shield_result.redaction = MagicMock()
        mock_shield_result.redaction.redaction_count = 0
        mock_shield_result.pii_count = 0
        mock_shield_result.phi_count = 0
        mock_shield_result.credential_count = 0
        mock_shield_result.to_dict = MagicMock(return_value={})

        mock_threat_engine = MagicMock()
        mock_threat_engine.scan_request_body_with_escalation = MagicMock(
            return_value=(mock_action, None)
        )

        mock_data_shield = MagicMock()
        mock_data_shield.scan_request_body = MagicMock(
            return_value=(b"", mock_shield_result)
        )

        mock_routing_decision = MagicMock()
        mock_routing_decision.action.name = "DEFAULT"

        from app.services.routing_policy import RoutingAction
        mock_routing_decision.action = RoutingAction.DEFAULT
        mock_routing_decision.to_dict = MagicMock(return_value={})

        mock_evaluator = MagicMock()
        mock_evaluator.evaluate = MagicMock(return_value=mock_routing_decision)

        mock_budget_svc = MagicMock()
        mock_budget_svc.is_budget_exceeded = MagicMock(return_value=False)
        mock_budget_svc.get_budget_usage_pct = MagicMock(return_value=0.0)

        return {
            "rag_pipeline": mock_rag_pipeline,
            "threat_engine": mock_threat_engine,
            "data_shield": mock_data_shield,
            "evaluator": mock_evaluator,
            "budget_svc": mock_budget_svc,
        }

    def test_classification_metadata_appears_in_audit_when_enabled(self, proxy_test_client):
        """When Thoth is enabled, audit metadata contains thoth_classification."""
        mock_ctx = self._make_mock_thoth_context()
        emitted_audit = {}
        patches = self._base_patches()

        async def capture_audit(**kwargs):
            emitted_audit.update(kwargs.get("metadata") or {})

        mock_upstream = httpx.Response(
            200,
            json={
                "id": "chatcmpl-test",
                "choices": [{"message": {"role": "assistant", "content": "Hi!"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
            },
        )

        mock_settings = MagicMock()
        mock_settings.thoth_enabled = True
        mock_settings.thoth_timeout_ms = 150
        mock_settings.default_provider_url = "http://mock-llm:9000"
        mock_settings.allowed_provider_hosts = ""

        with patch("app.routers.proxy.get_settings", return_value=mock_settings), \
             patch("app.routers.proxy.classify_prompt", new=AsyncMock(return_value=(mock_ctx, "classified"))), \
             patch("app.routers.proxy.check_kill_switch", new=AsyncMock(return_value=None)), \
             patch("app.routers.proxy.check_rate_limit", new=AsyncMock(return_value={"allowed": True})), \
             patch("app.routers.proxy.emit_audit_event", new=AsyncMock(side_effect=capture_audit)), \
             patch("app.routers.proxy.get_threat_engine", return_value=patches["threat_engine"]), \
             patch("app.routers.proxy.get_data_shield_engine", return_value=patches["data_shield"]), \
             patch("app.routers.proxy.get_rag_pipeline", return_value=patches["rag_pipeline"]), \
             patch("app.routers.proxy.get_routing_policy_evaluator", return_value=patches["evaluator"]), \
             patch("app.routers.proxy.get_budget_downgrade_service", return_value=patches["budget_svc"]), \
             patch("app.routers.proxy.get_budget_state", new=AsyncMock(return_value={"total_tokens": 0})), \
             patch("app.routers.proxy.record_token_usage", new=AsyncMock()), \
             patch("app.routers.proxy.persist_usage_to_db", new=AsyncMock()), \
             patch("app.routers.proxy.proxy_request", new=AsyncMock(return_value=mock_upstream)):

            resp = proxy_test_client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "What is ML?"}]},
                headers={"Authorization": "Bearer spx-test"},
            )

        assert resp.status_code == 200
        assert "thoth_classification" in emitted_audit
        assert emitted_audit["thoth_classification"]["intent"] == "general_query"
        assert emitted_audit["thoth_event"] == "classified"

    def test_classification_timeout_logs_event_in_audit(self, proxy_test_client):
        """FR-PRE-06: timeout context is written to audit metadata."""
        from app.services.thoth.models import make_timeout_context

        timeout_ctx = make_timeout_context("proxy-trace-2")
        emitted_audit = {}
        patches = self._base_patches()

        async def capture_audit(**kwargs):
            emitted_audit.update(kwargs.get("metadata") or {})

        mock_upstream = httpx.Response(
            200,
            json={
                "id": "cmpl-t",
                "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            },
        )

        mock_settings = MagicMock()
        mock_settings.thoth_enabled = True
        mock_settings.thoth_timeout_ms = 150
        mock_settings.default_provider_url = "http://mock-llm:9000"
        mock_settings.allowed_provider_hosts = ""

        with patch("app.routers.proxy.get_settings", return_value=mock_settings), \
             patch("app.routers.proxy.classify_prompt", new=AsyncMock(return_value=(timeout_ctx, "timeout"))), \
             patch("app.routers.proxy.check_kill_switch", new=AsyncMock(return_value=None)), \
             patch("app.routers.proxy.check_rate_limit", new=AsyncMock(return_value={"allowed": True})), \
             patch("app.routers.proxy.emit_audit_event", new=AsyncMock(side_effect=capture_audit)), \
             patch("app.routers.proxy.get_threat_engine", return_value=patches["threat_engine"]), \
             patch("app.routers.proxy.get_data_shield_engine", return_value=patches["data_shield"]), \
             patch("app.routers.proxy.get_rag_pipeline", return_value=patches["rag_pipeline"]), \
             patch("app.routers.proxy.get_routing_policy_evaluator", return_value=patches["evaluator"]), \
             patch("app.routers.proxy.get_budget_downgrade_service", return_value=patches["budget_svc"]), \
             patch("app.routers.proxy.get_budget_state", new=AsyncMock(return_value={"total_tokens": 0})), \
             patch("app.routers.proxy.record_token_usage", new=AsyncMock()), \
             patch("app.routers.proxy.persist_usage_to_db", new=AsyncMock()), \
             patch("app.routers.proxy.proxy_request", new=AsyncMock(return_value=mock_upstream)):

            resp = proxy_test_client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]},
                headers={"Authorization": "Bearer spx-test"},
            )

        assert resp.status_code == 200
        assert emitted_audit.get("thoth_event") == "timeout"
        assert emitted_audit["thoth_classification"]["source"] == "structural_fallback"

    def test_thoth_disabled_no_classification_metadata(self, proxy_test_client):
        """When Thoth is disabled, no classification metadata in audit."""
        emitted_audit = {}
        patches = self._base_patches()

        async def capture_audit(**kwargs):
            emitted_audit.update(kwargs.get("metadata") or {})

        mock_upstream = httpx.Response(
            200,
            json={
                "id": "cmpl-off",
                "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            },
        )

        mock_settings = MagicMock()
        mock_settings.thoth_enabled = False
        mock_settings.thoth_timeout_ms = 150
        mock_settings.default_provider_url = "http://mock-llm:9000"
        mock_settings.allowed_provider_hosts = ""

        with patch("app.routers.proxy.get_settings", return_value=mock_settings), \
             patch("app.routers.proxy.classify_prompt", new=AsyncMock(return_value=(None, "disabled"))), \
             patch("app.routers.proxy.check_kill_switch", new=AsyncMock(return_value=None)), \
             patch("app.routers.proxy.check_rate_limit", new=AsyncMock(return_value={"allowed": True})), \
             patch("app.routers.proxy.emit_audit_event", new=AsyncMock(side_effect=capture_audit)), \
             patch("app.routers.proxy.get_threat_engine", return_value=patches["threat_engine"]), \
             patch("app.routers.proxy.get_data_shield_engine", return_value=patches["data_shield"]), \
             patch("app.routers.proxy.get_rag_pipeline", return_value=patches["rag_pipeline"]), \
             patch("app.routers.proxy.get_routing_policy_evaluator", return_value=patches["evaluator"]), \
             patch("app.routers.proxy.get_budget_downgrade_service", return_value=patches["budget_svc"]), \
             patch("app.routers.proxy.get_budget_state", new=AsyncMock(return_value={"total_tokens": 0})), \
             patch("app.routers.proxy.record_token_usage", new=AsyncMock()), \
             patch("app.routers.proxy.persist_usage_to_db", new=AsyncMock()), \
             patch("app.routers.proxy.proxy_request", new=AsyncMock(return_value=mock_upstream)):

            resp = proxy_test_client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]},
                headers={"Authorization": "Bearer spx-test"},
            )

        assert resp.status_code == 200
        assert "thoth_classification" not in emitted_audit
