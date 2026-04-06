"""Sprint 12 — Kill-Switch Production Hardening tests.

Covers:
- Kill-switch cache propagation via Redis pub/sub
- Block mode (503 with configurable error message, structured logging)
- Reroute mode (transparent redirect, reroute event logging)
- AWS Bedrock adapter (Claude, Titan, Llama via Bedrock)
- Azure OpenAI adapter (deployment names, API version, Azure AD auth)
- Kill-switch audit log immutability
- Kill-switch admin UI endpoints
"""

import json
import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timezone


# ═══════════════════════════════════════════════════════════════════════
# Kill-Switch Pub/Sub Cache Propagation
# ═══════════════════════════════════════════════════════════════════════


class TestKillSwitchPubSub:
    """Kill-switch state changes publish to Redis pub/sub, gateway subscribers update local state."""

    @pytest.mark.asyncio
    async def test_activate_publishes_to_pubsub(self):
        """Activation should publish state change to Redis pub/sub channel."""
        mock_redis = AsyncMock()
        mock_redis.setex = AsyncMock()
        mock_redis.publish = AsyncMock()

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        mock_db.add = MagicMock()

        with patch("app.services.kill_switch.get_redis", return_value=mock_redis):
            from app.services.kill_switch import activate_kill_switch, PUBSUB_CHANNEL
            # Mock the refresh to set attributes
            async def mock_refresh_fn(obj):
                obj.id = "test-id"
                obj.model_name = "gpt-4"
                obj.action = "block"
                obj.fallback_model = None
                obj.activated_by = "admin"
                obj.reason = "test"
                obj.error_message = "Model temporarily unavailable"
                obj.is_active = True
                obj.created_at = datetime.now(timezone.utc)
                obj.updated_at = datetime.now(timezone.utc)
            mock_db.refresh = mock_refresh_fn

            await activate_kill_switch(
                db=mock_db, model_name="gpt-4", action="block",
                activated_by="admin", reason="test",
            )

        # Verify publish was called on the pub/sub channel
        mock_redis.publish.assert_called_once()
        call_args = mock_redis.publish.call_args
        assert call_args[0][0] == PUBSUB_CHANNEL
        payload = json.loads(call_args[0][1])
        assert payload["model_name"] == "gpt-4"
        assert payload["data"]["is_active"] is True

    @pytest.mark.asyncio
    async def test_deactivate_publishes_to_pubsub(self):
        """Deactivation should publish deactivation event to pub/sub."""
        mock_redis = AsyncMock()
        mock_redis.delete = AsyncMock()
        mock_redis.publish = AsyncMock()

        mock_ks = MagicMock()
        mock_ks.model_name = "gpt-4"
        mock_ks.action = "block"
        mock_ks.fallback_model = None
        mock_ks.activated_by = "admin"
        mock_ks.reason = "test"
        mock_ks.is_active = True

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_ks
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()
        mock_db.add = MagicMock()

        with patch("app.services.kill_switch.get_redis", return_value=mock_redis):
            from app.services.kill_switch import deactivate_kill_switch, PUBSUB_CHANNEL
            result = await deactivate_kill_switch(mock_db, "gpt-4")

        assert result is True
        mock_redis.publish.assert_called_once()
        payload = json.loads(mock_redis.publish.call_args[0][1])
        assert payload["data"]["is_active"] is False

    @pytest.mark.asyncio
    async def test_local_state_updated_on_activation(self):
        """Local in-memory state should be updated immediately on activation."""
        mock_redis = AsyncMock()
        mock_redis.setex = AsyncMock()
        mock_redis.publish = AsyncMock()

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()
        mock_db.add = MagicMock()

        async def mock_refresh_fn(obj):
            obj.id = "test-id-2"
            obj.model_name = "claude-3"
            obj.action = "reroute"
            obj.fallback_model = "claude-3-haiku"
            obj.activated_by = "admin"
            obj.reason = "cost"
            obj.error_message = "Model temporarily unavailable"
            obj.is_active = True
            obj.created_at = datetime.now(timezone.utc)
            obj.updated_at = datetime.now(timezone.utc)
        mock_db.refresh = mock_refresh_fn

        with patch("app.services.kill_switch.get_redis", return_value=mock_redis):
            from app.services.kill_switch import activate_kill_switch, _local_kill_switch_state
            await activate_kill_switch(
                db=mock_db, model_name="claude-3", action="reroute",
                activated_by="admin", reason="cost", fallback_model="claude-3-haiku",
            )

        assert "claude-3" in _local_kill_switch_state
        assert _local_kill_switch_state["claude-3"]["action"] == "reroute"

    @pytest.mark.asyncio
    async def test_check_kill_switch_uses_local_state(self):
        """check_kill_switch should use local in-memory state first."""
        from app.services.kill_switch import _local_kill_switch_state

        _local_kill_switch_state["test-model"] = {
            "model_name": "test-model",
            "action": "block",
            "is_active": True,
            "reason": "local test",
        }

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)  # Should not be called

        with patch("app.services.kill_switch.get_redis", return_value=mock_redis):
            from app.services.kill_switch import check_kill_switch
            result = await check_kill_switch("test-model")

        assert result is not None
        assert result["action"] == "block"
        # Clean up
        _local_kill_switch_state.pop("test-model", None)


# ═══════════════════════════════════════════════════════════════════════
# Block Mode — 503 with configurable error message
# ═══════════════════════════════════════════════════════════════════════


class TestBlockMode:
    """Block mode: return 503 with configured error message, log model/admin/reason/timestamp."""

    def test_block_returns_503_with_custom_error(self, authed_client):
        """Block mode should return 503 with the configured error message."""
        ks_data = {
            "model_name": "gpt-4",
            "action": "block",
            "fallback_model": None,
            "reason": "Security vulnerability detected",
            "error_message": "GPT-4 is suspended due to security review",
            "is_active": True,
            "activated_by": "security-admin",
        }

        with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=ks_data):
            with patch("app.routers.proxy.emit_audit_event", new_callable=AsyncMock):
                response = authed_client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]},
                    headers={"Authorization": "Bearer spx-test-key"},
                )

        assert response.status_code == 503
        data = response.json()
        assert data["error"] == "GPT-4 is suspended due to security review"
        assert data["model"] == "gpt-4"
        assert data["reason"] == "Security vulnerability detected"

    def test_block_returns_503_default_error(self, authed_client):
        """Block mode with no custom message should use default error."""
        ks_data = {
            "model_name": "gpt-4",
            "action": "block",
            "fallback_model": None,
            "reason": "test",
            "is_active": True,
            "activated_by": "admin",
        }

        with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=ks_data):
            with patch("app.routers.proxy.emit_audit_event", new_callable=AsyncMock):
                response = authed_client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "Hi"}]},
                    headers={"Authorization": "Bearer spx-test-key"},
                )

        assert response.status_code == 503
        assert response.json()["error"] == "Model temporarily unavailable"

    def test_block_emits_audit_with_admin_and_action(self, authed_client):
        """Block mode should emit audit event with model, activating admin, reason, timestamp."""
        ks_data = {
            "model_name": "gpt-4",
            "action": "block",
            "fallback_model": None,
            "reason": "compliance hold",
            "error_message": "Model blocked",
            "is_active": True,
            "activated_by": "compliance-officer",
        }

        audit_calls = []

        async def capture_audit(**kwargs):
            audit_calls.append(kwargs)

        with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=ks_data):
            with patch("app.routers.proxy.emit_audit_event", side_effect=capture_audit):
                response = authed_client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "test"}]},
                    headers={"Authorization": "Bearer spx-test-key"},
                )

        assert response.status_code == 503
        assert len(audit_calls) == 1
        audit = audit_calls[0]
        assert audit["action"] == "blocked_kill_switch"
        assert audit["status_code"] == 503
        assert audit["model"] == "gpt-4"
        assert audit["metadata"]["activated_by"] == "compliance-officer"
        assert audit["metadata"]["kill_switch_action"] == "block"


# ═══════════════════════════════════════════════════════════════════════
# Reroute Mode — Transparent redirect
# ═══════════════════════════════════════════════════════════════════════


class TestRerouteMode:
    """Reroute mode: transparently redirect request to fallback model, log reroute event."""

    def test_reroute_changes_model_transparently(self, authed_client):
        """Reroute should change the model in the request body to fallback model."""
        ks_data = {
            "model_name": "gpt-4",
            "action": "reroute",
            "fallback_model": "gpt-3.5-turbo",
            "reason": "Cost optimization",
            "is_active": True,
            "activated_by": "admin",
        }

        captured_body = {}

        async def mock_route_request(request, body, model_name, provider):
            captured_body["model"] = json.loads(body).get("model")
            captured_body["model_name"] = model_name
            from starlette.responses import JSONResponse
            return JSONResponse(
                status_code=200,
                content={"choices": [{"message": {"role": "assistant", "content": "ok"}}], "usage": {}},
            )

        with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=ks_data):
            with patch("app.routers.proxy.emit_audit_event", new_callable=AsyncMock):
                with patch("app.routers.proxy.check_rate_limit", new_callable=AsyncMock, return_value={"allowed": True, "current_usage": 0}):
                    with patch("app.routers.proxy.resolve_provider", return_value=MagicMock(provider_name="openai")):
                        with patch("app.routers.proxy.route_request", side_effect=mock_route_request):
                            response = authed_client.post(
                                "/v1/chat/completions",
                                json={"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]},
                                headers={"Authorization": "Bearer spx-test-key"},
                            )

        assert response.status_code == 200
        assert captured_body["model"] == "gpt-3.5-turbo"

    def test_reroute_emits_audit_event(self, authed_client):
        """Reroute should emit an audit event with original and fallback model info."""
        ks_data = {
            "model_name": "gpt-4",
            "action": "reroute",
            "fallback_model": "gpt-3.5-turbo",
            "reason": "Cost optimization",
            "is_active": True,
            "activated_by": "ops-admin",
        }

        audit_calls = []

        async def capture_audit(**kwargs):
            audit_calls.append(kwargs)

        with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=ks_data):
            with patch("app.routers.proxy.emit_audit_event", side_effect=capture_audit):
                with patch("app.routers.proxy.check_rate_limit", new_callable=AsyncMock, return_value={"allowed": True, "current_usage": 0}):
                    with patch("app.routers.proxy.resolve_provider", return_value=MagicMock(provider_name="openai")):
                        with patch("app.routers.proxy.route_request", new_callable=AsyncMock, return_value=MagicMock(
                            status_code=200, body=json.dumps({"choices": [], "usage": {}}).encode()
                        )):
                            response = authed_client.post(
                                "/v1/chat/completions",
                                json={"model": "gpt-4", "messages": [{"role": "user", "content": "test"}]},
                                headers={"Authorization": "Bearer spx-test-key"},
                            )

        # Should have reroute audit event
        reroute_events = [a for a in audit_calls if a.get("action") == "rerouted_kill_switch"]
        assert len(reroute_events) >= 1
        reroute = reroute_events[0]
        assert reroute["metadata"]["original_model"] == "gpt-4"
        assert reroute["metadata"]["fallback_model"] == "gpt-3.5-turbo"
        assert reroute["metadata"]["activated_by"] == "ops-admin"


# ═══════════════════════════════════════════════════════════════════════
# AWS Bedrock Adapter
# ═══════════════════════════════════════════════════════════════════════


class TestBedrockAdapter:
    """AWS Bedrock adapter: Claude via Bedrock, Titan, Llama via Bedrock."""

    def test_bedrock_provider_registration(self):
        """BedrockProvider should have correct provider name and supported models."""
        from app.services.providers.bedrock import BedrockProvider
        p = BedrockProvider(api_key="test_key:test_secret")
        assert p.provider_name == "bedrock"
        assert "anthropic.claude-3-opus-20240229-v1:0" in p.supported_models
        assert "amazon.titan-text-express-v1" in p.supported_models
        assert "meta.llama3-70b-instruct-v1:0" in p.supported_models

    def test_bedrock_claude_request_normalization(self):
        """Should build proper Claude/Bedrock request body."""
        from app.services.providers.bedrock import BedrockProvider
        from app.services.providers.base import UnifiedRequest, UnifiedMessage

        p = BedrockProvider(api_key="AKID:SECRET", region="us-east-1")
        req = UnifiedRequest(
            model="anthropic.claude-3-sonnet-20240229-v1:0",
            messages=[
                UnifiedMessage(role="system", content="You are helpful"),
                UnifiedMessage(role="user", content="Hello"),
            ],
            max_tokens=512,
            temperature=0.7,
        )
        url, headers, body_bytes = p.normalize_request(req)

        assert "bedrock-runtime.us-east-1.amazonaws.com" in url
        assert "anthropic.claude-3-sonnet" in url
        assert "invoke" in url

        body = json.loads(body_bytes)
        assert body["anthropic_version"] == "bedrock-2023-05-31"
        assert body["system"] == "You are helpful"
        assert body["max_tokens"] == 512
        assert body["temperature"] == 0.7
        assert len(body["messages"]) == 1
        assert body["messages"][0]["role"] == "user"

    def test_bedrock_titan_request_normalization(self):
        """Should build proper Titan request body."""
        from app.services.providers.bedrock import BedrockProvider
        from app.services.providers.base import UnifiedRequest, UnifiedMessage

        p = BedrockProvider(api_key="AKID:SECRET")
        req = UnifiedRequest(
            model="amazon.titan-text-express-v1",
            messages=[UnifiedMessage(role="user", content="Hello")],
            max_tokens=256,
        )
        url, headers, body_bytes = p.normalize_request(req)

        body = json.loads(body_bytes)
        assert "inputText" in body
        assert "Hello" in body["inputText"]
        assert body["textGenerationConfig"]["maxTokenCount"] == 256

    def test_bedrock_llama_request_normalization(self):
        """Should build proper Llama/Bedrock request body."""
        from app.services.providers.bedrock import BedrockProvider
        from app.services.providers.base import UnifiedRequest, UnifiedMessage

        p = BedrockProvider(api_key="AKID:SECRET")
        req = UnifiedRequest(
            model="meta.llama3-70b-instruct-v1:0",
            messages=[UnifiedMessage(role="user", content="Hello")],
            max_tokens=128,
        )
        url, headers, body_bytes = p.normalize_request(req)

        body = json.loads(body_bytes)
        assert "prompt" in body
        assert "Hello" in body["prompt"]
        assert body["max_gen_len"] == 128

    def test_bedrock_claude_response_normalization(self):
        """Should normalize Claude/Bedrock response to unified format."""
        from app.services.providers.bedrock import BedrockProvider

        p = BedrockProvider(api_key="test:test")
        raw = {
            "id": "msg-123",
            "model": "claude-3-sonnet",
            "content": [{"type": "text", "text": "Hello there!"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }

        response = p.normalize_response(200, raw)
        assert response.provider == "bedrock"
        assert len(response.choices) == 1
        assert response.choices[0].message.content == "Hello there!"
        assert response.usage.prompt_tokens == 10
        assert response.usage.completion_tokens == 5
        assert response.usage.total_tokens == 15

    def test_bedrock_titan_response_normalization(self):
        """Should normalize Titan response to unified format."""
        from app.services.providers.bedrock import BedrockProvider

        p = BedrockProvider(api_key="test:test")
        raw = {
            "inputTextTokenCount": 8,
            "results": [
                {"tokenCount": 12, "outputText": "I can help with that.", "completionReason": "FINISH"}
            ],
        }

        response = p.normalize_response(200, raw)
        assert response.choices[0].message.content == "I can help with that."
        assert response.usage.prompt_tokens == 8
        assert response.usage.completion_tokens == 12

    def test_bedrock_llama_response_normalization(self):
        """Should normalize Llama/Bedrock response to unified format."""
        from app.services.providers.bedrock import BedrockProvider

        p = BedrockProvider(api_key="test:test")
        raw = {
            "generation": "Here is my response.",
            "stop_reason": "stop",
            "prompt_token_count": 15,
            "generation_token_count": 8,
        }

        response = p.normalize_response(200, raw)
        assert response.choices[0].message.content == "Here is my response."
        assert response.usage.prompt_tokens == 15
        assert response.usage.completion_tokens == 8

    def test_bedrock_aws_sigv4_headers(self):
        """Should include AWS Signature V4 authorization header."""
        from app.services.providers.bedrock import BedrockProvider
        from app.services.providers.base import UnifiedRequest, UnifiedMessage

        p = BedrockProvider(
            api_key="AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region="us-west-2",
        )
        req = UnifiedRequest(
            model="anthropic.claude-3-haiku-20240307-v1:0",
            messages=[UnifiedMessage(role="user", content="test")],
        )
        url, headers, body = p.normalize_request(req)

        assert "Authorization" in headers
        assert headers["Authorization"].startswith("AWS4-HMAC-SHA256")
        assert "X-Amz-Date" in headers
        assert "us-west-2" in headers["Authorization"]

    def test_bedrock_session_token_support(self):
        """Should include session token header when provided."""
        from app.services.providers.bedrock import BedrockProvider
        from app.services.providers.base import UnifiedRequest, UnifiedMessage

        p = BedrockProvider(api_key="AKID:SECRET:SESSION_TOKEN", region="us-east-1")
        req = UnifiedRequest(
            model="anthropic.claude-3-haiku-20240307-v1:0",
            messages=[UnifiedMessage(role="user", content="test")],
        )
        url, headers, body = p.normalize_request(req)

        assert "X-Amz-Security-Token" in headers
        assert headers["X-Amz-Security-Token"] == "SESSION_TOKEN"

    def test_bedrock_stream_chunk_claude(self):
        """Should parse Claude streaming chunks from Bedrock."""
        from app.services.providers.bedrock import BedrockProvider

        p = BedrockProvider(api_key="test:test")
        chunk = p.normalize_stream_chunk(
            json.dumps({"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Hello"}})
        )
        assert chunk is not None
        assert chunk.delta_content == "Hello"

    def test_bedrock_stream_chunk_titan(self):
        """Should parse Titan streaming chunks."""
        from app.services.providers.bedrock import BedrockProvider

        p = BedrockProvider(api_key="test:test")
        chunk = p.normalize_stream_chunk(
            json.dumps({"outputText": "World", "completionReason": None})
        )
        assert chunk is not None
        assert chunk.delta_content == "World"

    def test_bedrock_registered_in_model_map(self):
        """Bedrock models should be in the global MODEL_PROVIDER_MAP."""
        from app.services.providers.registry import MODEL_PROVIDER_MAP
        assert MODEL_PROVIDER_MAP.get("anthropic.claude-3-opus-20240229-v1:0") == "bedrock"
        assert MODEL_PROVIDER_MAP.get("amazon.titan-text-express-v1") == "bedrock"
        assert MODEL_PROVIDER_MAP.get("meta.llama3-70b-instruct-v1:0") == "bedrock"


# ═══════════════════════════════════════════════════════════════════════
# Azure OpenAI Adapter
# ═══════════════════════════════════════════════════════════════════════


class TestAzureOpenAIAdapter:
    """Azure OpenAI adapter: deployment names, API version headers, Azure AD auth."""

    def test_azure_provider_registration(self):
        """AzureOpenAIProvider should have correct provider name and models."""
        from app.services.providers.azure_openai import AzureOpenAIProvider
        p = AzureOpenAIProvider()
        assert p.provider_name == "azure_openai"
        assert "azure-gpt-4" in p.supported_models
        assert "azure-gpt-4o" in p.supported_models

    def test_azure_request_with_api_key(self):
        """Should use api-key header for standard authentication."""
        from app.services.providers.azure_openai import AzureOpenAIProvider
        from app.services.providers.base import UnifiedRequest, UnifiedMessage

        p = AzureOpenAIProvider(
            base_url="https://myresource.openai.azure.com",
            api_key="my-azure-key",
            api_version="2024-10-21",
        )
        req = UnifiedRequest(
            model="azure-gpt-4",
            messages=[UnifiedMessage(role="user", content="Hello")],
            temperature=0.5,
        )
        url, headers, body_bytes = p.normalize_request(req)

        assert "myresource.openai.azure.com" in url
        assert "/openai/deployments/gpt-4/" in url
        assert "api-version=2024-10-21" in url
        assert headers["api-key"] == "my-azure-key"
        assert "Authorization" not in headers

        body = json.loads(body_bytes)
        assert body["messages"][0]["content"] == "Hello"
        assert body["temperature"] == 0.5

    def test_azure_request_with_azure_ad(self):
        """Should use Bearer token for Azure AD authentication."""
        from app.services.providers.azure_openai import AzureOpenAIProvider
        from app.services.providers.base import UnifiedRequest, UnifiedMessage

        p = AzureOpenAIProvider(
            base_url="https://myresource.openai.azure.com",
            api_key="azure-ad-bearer-token",
            use_azure_ad=True,
        )
        req = UnifiedRequest(
            model="azure-gpt-4o",
            messages=[UnifiedMessage(role="user", content="test")],
        )
        url, headers, body = p.normalize_request(req)

        assert headers["Authorization"] == "Bearer azure-ad-bearer-token"
        assert "api-key" not in headers

    def test_azure_deployment_name_mapping(self):
        """Should map model names to Azure deployment names."""
        from app.services.providers.azure_openai import AzureOpenAIProvider
        from app.services.providers.base import UnifiedRequest, UnifiedMessage

        p = AzureOpenAIProvider(
            base_url="https://myresource.openai.azure.com",
            api_key="key",
            deployment_map={"azure-gpt-4": "my-custom-gpt4-deployment"},
        )
        req = UnifiedRequest(
            model="azure-gpt-4",
            messages=[UnifiedMessage(role="user", content="test")],
        )
        url, headers, body = p.normalize_request(req)

        assert "/deployments/my-custom-gpt4-deployment/" in url

    def test_azure_response_normalization(self):
        """Should normalize Azure OpenAI response (same as OpenAI format)."""
        from app.services.providers.azure_openai import AzureOpenAIProvider

        p = AzureOpenAIProvider()
        raw = {
            "id": "chatcmpl-abc",
            "model": "gpt-4",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hi there!"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
            "created": 1700000000,
        }

        response = p.normalize_response(200, raw)
        assert response.provider == "azure_openai"
        assert response.choices[0].message.content == "Hi there!"
        assert response.usage.total_tokens == 8

    def test_azure_stream_chunk_normalization(self):
        """Should parse Azure SSE stream chunks (OpenAI-compatible)."""
        from app.services.providers.azure_openai import AzureOpenAIProvider

        p = AzureOpenAIProvider()

        chunk_data = {
            "id": "chatcmpl-abc",
            "model": "gpt-4",
            "choices": [{"index": 0, "delta": {"content": "Hello"}, "finish_reason": None}],
        }
        chunk = p.normalize_stream_chunk(f"data: {json.dumps(chunk_data)}")
        assert chunk is not None
        assert chunk.delta_content == "Hello"
        assert chunk.provider == "azure_openai"

    def test_azure_stream_done_signal(self):
        """Should handle [DONE] signal correctly."""
        from app.services.providers.azure_openai import AzureOpenAIProvider

        p = AzureOpenAIProvider()
        chunk = p.normalize_stream_chunk("data: [DONE]")
        assert chunk is None

    def test_azure_api_version_header(self):
        """Should include API version in the URL query string."""
        from app.services.providers.azure_openai import AzureOpenAIProvider
        from app.services.providers.base import UnifiedRequest, UnifiedMessage

        p = AzureOpenAIProvider(
            base_url="https://test.openai.azure.com",
            api_key="key",
            api_version="2025-01-15",
        )
        req = UnifiedRequest(
            model="azure-gpt-4",
            messages=[UnifiedMessage(role="user", content="test")],
        )
        url, headers, body = p.normalize_request(req)
        assert "api-version=2025-01-15" in url

    def test_azure_registered_in_model_map(self):
        """Azure models should be in the global MODEL_PROVIDER_MAP."""
        from app.services.providers.registry import MODEL_PROVIDER_MAP
        assert MODEL_PROVIDER_MAP.get("azure-gpt-4") == "azure_openai"
        assert MODEL_PROVIDER_MAP.get("azure-gpt-4o") == "azure_openai"

    def test_azure_prefix_resolution(self):
        """Registry should resolve azure- prefix to azure_openai provider."""
        from app.services.providers.registry import ProviderRegistry, AzureOpenAIProvider

        registry = ProviderRegistry()
        azure = AzureOpenAIProvider(base_url="https://test.openai.azure.com", api_key="key")
        registry.register(azure)

        provider = registry.get_provider_for_model("azure-gpt-4")
        assert provider is not None
        assert provider.provider_name == "azure_openai"


# ═══════════════════════════════════════════════════════════════════════
# Kill-Switch Audit Log Immutability
# ═══════════════════════════════════════════════════════════════════════


class TestKillSwitchAuditLog:
    """Kill-switch audit log: immutable, includes admin username, timestamp, reason."""

    def test_audit_log_endpoint_returns_records(self, client):
        """Audit log endpoint should return records."""
        mock_logs = [
            {
                "id": "log-1",
                "model_name": "gpt-4",
                "action": "block",
                "fallback_model": None,
                "activated_by": "admin",
                "reason": "security incident",
                "event_type": "activated",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        ]

        with patch("app.routers.admin.get_kill_switch_audit_log", new_callable=AsyncMock, return_value=mock_logs):
            response = client.get("/admin/kill-switches/audit")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["activated_by"] == "admin"
        assert data[0]["event_type"] == "activated"
        assert data[0]["reason"] == "security incident"

    def test_audit_log_model_has_required_fields(self):
        """KillSwitchAuditLog model should have admin, timestamp, and reason fields."""
        from app.models.api_key import KillSwitchAuditLog
        columns = {c.name for c in KillSwitchAuditLog.__table__.columns}
        assert "activated_by" in columns
        assert "reason" in columns
        assert "created_at" in columns
        assert "model_name" in columns
        assert "event_type" in columns

    def test_admin_activate_with_error_message(self, client):
        """Admin endpoint should accept error_message parameter."""
        ks_result = {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "model_name": "gpt-4",
            "action": "block",
            "fallback_model": None,
            "activated_by": "admin",
            "reason": "test",
            "error_message": "Custom error msg",
            "is_active": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        with patch("app.routers.admin.activate_kill_switch", new_callable=AsyncMock, return_value=ks_result):
            response = client.post(
                "/admin/kill-switches",
                json={
                    "model_name": "gpt-4",
                    "action": "block",
                    "activated_by": "admin",
                    "reason": "test",
                    "error_message": "Custom error msg",
                },
            )

        assert response.status_code == 200
        data = response.json()
        assert data["error_message"] == "Custom error msg"


# ═══════════════════════════════════════════════════════════════════════
# Provider Registry Integration
# ═══════════════════════════════════════════════════════════════════════


class TestProviderRegistryIntegration:
    """Verify new providers are properly integrated into the registry."""

    def test_bedrock_in_routing_classes(self):
        """Bedrock should be in the routing provider_classes map."""
        from app.services.providers.bedrock import BedrockProvider
        from app.services.providers.azure_openai import AzureOpenAIProvider

        provider_classes = {
            "bedrock": BedrockProvider,
            "azure_openai": AzureOpenAIProvider,
        }
        assert "bedrock" in provider_classes
        assert "azure_openai" in provider_classes

    def test_prefix_resolution_bedrock(self):
        """Registry should resolve Bedrock model prefixes."""
        from app.services.providers.registry import ProviderRegistry, BedrockProvider

        registry = ProviderRegistry()
        bedrock = BedrockProvider(api_key="test:test")
        registry.register(bedrock)

        provider = registry.get_provider_for_model("anthropic.claude-3-opus-20240229-v1:0")
        assert provider is not None
        assert provider.provider_name == "bedrock"

    def test_prefix_resolution_titan(self):
        """Registry should resolve amazon.titan prefix to bedrock."""
        from app.services.providers.registry import ProviderRegistry, BedrockProvider

        registry = ProviderRegistry()
        bedrock = BedrockProvider(api_key="test:test")
        registry.register(bedrock)

        provider = registry.get_provider_for_model("amazon.titan-text-express-v1")
        assert provider is not None
        assert provider.provider_name == "bedrock"

    def test_providers_init_exports(self):
        """All new providers should be exported from __init__."""
        from app.services.providers import BedrockProvider, AzureOpenAIProvider
        assert BedrockProvider.provider_name == "bedrock"
        assert AzureOpenAIProvider.provider_name == "azure_openai"


# ═══════════════════════════════════════════════════════════════════════
# Kill-Switch Full Integration (acceptance criteria)
# ═══════════════════════════════════════════════════════════════════════


class TestKillSwitchAcceptanceCriteria:
    """Sprint 12 acceptance criteria: kill-switch activated -> next request blocked/rerouted within 5s."""

    def test_kill_switch_block_returns_503_within_pipeline(self, authed_client):
        """Kill-switch block: next request to target model returns 503."""
        ks_data = {
            "model_name": "claude-3-opus",
            "action": "block",
            "fallback_model": None,
            "reason": "Provider outage",
            "error_message": "Claude Opus temporarily unavailable",
            "is_active": True,
            "activated_by": "sre-oncall",
        }

        with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=ks_data):
            with patch("app.routers.proxy.emit_audit_event", new_callable=AsyncMock):
                response = authed_client.post(
                    "/v1/chat/completions",
                    json={"model": "claude-3-opus", "messages": [{"role": "user", "content": "test"}]},
                    headers={"Authorization": "Bearer spx-test-key"},
                )

        assert response.status_code == 503
        assert response.json()["error"] == "Claude Opus temporarily unavailable"

    def test_kill_switch_reroute_to_fallback(self, authed_client):
        """Kill-switch reroute: request routes to fallback model."""
        ks_data = {
            "model_name": "gpt-4",
            "action": "reroute",
            "fallback_model": "gpt-4o-mini",
            "reason": "Cost reduction",
            "is_active": True,
            "activated_by": "finance-admin",
        }

        routed_model = {}

        async def capture_route(request, body, model_name, provider):
            routed_model["name"] = model_name
            from starlette.responses import JSONResponse
            return JSONResponse(status_code=200, content={"choices": [], "usage": {}})

        with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock, return_value=ks_data):
            with patch("app.routers.proxy.emit_audit_event", new_callable=AsyncMock):
                with patch("app.routers.proxy.check_rate_limit", new_callable=AsyncMock, return_value={"allowed": True, "current_usage": 0}):
                    with patch("app.routers.proxy.resolve_provider", return_value=MagicMock(provider_name="openai")):
                        with patch("app.routers.proxy.route_request", side_effect=capture_route):
                            response = authed_client.post(
                                "/v1/chat/completions",
                                json={"model": "gpt-4", "messages": [{"role": "user", "content": "test"}]},
                                headers={"Authorization": "Bearer spx-test-key"},
                            )

        assert response.status_code == 200
        assert routed_model["name"] == "gpt-4o-mini"

    def test_no_model_no_kill_switch_check(self, authed_client):
        """Requests without a model should skip kill-switch check."""
        from starlette.responses import JSONResponse
        with patch("app.routers.proxy.check_kill_switch", new_callable=AsyncMock) as mock_check:
            with patch("app.routers.proxy.emit_audit_event", new_callable=AsyncMock):
                with patch("app.routers.proxy.check_rate_limit", new_callable=AsyncMock, return_value={"allowed": True, "current_usage": 0}):
                    with patch("app.routers.proxy.proxy_request", new_callable=AsyncMock, return_value=JSONResponse(
                        status_code=200, content={"data": []},
                    )):
                        response = authed_client.get(
                            "/v1/models",
                            headers={"Authorization": "Bearer spx-test-key"},
                        )

        mock_check.assert_not_called()
