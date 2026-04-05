"""Tests for LLM provider adapters and unified schema normalization."""

import json
import pytest

from app.services.providers.base import UnifiedRequest, UnifiedMessage, UnifiedResponse
from app.services.providers.openai import OpenAIProvider
from app.services.providers.anthropic import AnthropicProvider
from app.services.providers.gemini import GeminiProvider
from app.services.providers.registry import ProviderRegistry


# ── OpenAI Provider ─────────────────────────────────────────────────


class TestOpenAIProvider:
    def setup_method(self):
        self.provider = OpenAIProvider(base_url="https://api.openai.com", api_key="sk-test")

    def test_normalize_request_basic(self):
        req = UnifiedRequest(
            model="gpt-4",
            messages=[UnifiedMessage(role="user", content="Hello")],
            temperature=0.7,
            max_tokens=100,
        )
        url, headers, body_bytes = self.provider.normalize_request(req)

        assert url == "https://api.openai.com/v1/chat/completions"
        assert headers["Authorization"] == "Bearer sk-test"
        body = json.loads(body_bytes)
        assert body["model"] == "gpt-4"
        assert body["messages"][0]["role"] == "user"
        assert body["temperature"] == 0.7
        assert body["max_tokens"] == 100
        assert body["stream"] is False

    def test_normalize_request_streaming(self):
        req = UnifiedRequest(
            model="gpt-4", messages=[UnifiedMessage(role="user", content="Hi")], stream=True,
        )
        _, _, body_bytes = self.provider.normalize_request(req)
        body = json.loads(body_bytes)
        assert body["stream"] is True

    def test_normalize_response(self):
        raw = {
            "id": "chatcmpl-123",
            "model": "gpt-4",
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": "Hello!"}, "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
            "created": 1234567890,
        }
        resp = self.provider.normalize_response(200, raw)

        assert resp.id == "chatcmpl-123"
        assert resp.provider == "openai"
        assert len(resp.choices) == 1
        assert resp.choices[0].message.content == "Hello!"
        assert resp.usage.total_tokens == 8

    def test_normalize_stream_chunk(self):
        line = 'data: {"id":"c1","model":"gpt-4","choices":[{"delta":{"content":"Hi"},"finish_reason":null}]}'
        chunk = self.provider.normalize_stream_chunk(line)
        assert chunk is not None
        assert chunk.delta_content == "Hi"
        assert chunk.provider == "openai"

    def test_normalize_stream_chunk_done(self):
        assert self.provider.normalize_stream_chunk("data: [DONE]") is None

    def test_normalize_stream_chunk_empty(self):
        assert self.provider.normalize_stream_chunk("") is None


# ── Anthropic Provider ──────────────────────────────────────────────


class TestAnthropicProvider:
    def setup_method(self):
        self.provider = AnthropicProvider(base_url="https://api.anthropic.com", api_key="sk-ant-test")

    def test_normalize_request_with_system(self):
        req = UnifiedRequest(
            model="claude-3-sonnet-20240229",
            messages=[
                UnifiedMessage(role="system", content="You are helpful."),
                UnifiedMessage(role="user", content="Hello"),
            ],
            max_tokens=200,
        )
        url, headers, body_bytes = self.provider.normalize_request(req)

        assert url == "https://api.anthropic.com/v1/messages"
        assert headers["x-api-key"] == "sk-ant-test"
        assert headers["anthropic-version"] == "2023-06-01"

        body = json.loads(body_bytes)
        assert body["model"] == "claude-3-sonnet-20240229"
        assert body["system"] == "You are helpful."
        # System message should not be in messages array
        assert all(m["role"] != "system" for m in body["messages"])
        assert body["max_tokens"] == 200

    def test_normalize_response(self):
        raw = {
            "id": "msg-123",
            "model": "claude-3-sonnet-20240229",
            "content": [{"type": "text", "text": "I'm Claude!"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
        resp = self.provider.normalize_response(200, raw)

        assert resp.provider == "anthropic"
        assert resp.choices[0].message.content == "I'm Claude!"
        assert resp.usage.prompt_tokens == 10
        assert resp.usage.completion_tokens == 5
        assert resp.usage.total_tokens == 15

    def test_normalize_stream_chunk_text_delta(self):
        line = 'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}'
        chunk = self.provider.normalize_stream_chunk(line)
        assert chunk is not None
        assert chunk.delta_content == "Hello"

    def test_normalize_stream_chunk_stop(self):
        line = 'data: {"type":"message_stop"}'
        chunk = self.provider.normalize_stream_chunk(line)
        assert chunk is not None
        assert chunk.finish_reason == "stop"


# ── Gemini Provider ─────────────────────────────────────────────────


class TestGeminiProvider:
    def setup_method(self):
        self.provider = GeminiProvider(
            base_url="https://generativelanguage.googleapis.com", api_key="gem-test"
        )

    def test_normalize_request(self):
        req = UnifiedRequest(
            model="gemini-1.5-pro",
            messages=[
                UnifiedMessage(role="system", content="Be helpful."),
                UnifiedMessage(role="user", content="Hi"),
            ],
            temperature=0.5,
            max_tokens=256,
        )
        url, headers, body_bytes = self.provider.normalize_request(req)

        assert "gemini-1.5-pro:generateContent" in url
        assert "key=gem-test" in url
        body = json.loads(body_bytes)
        assert "systemInstruction" in body
        assert body["contents"][0]["role"] == "user"
        assert body["generationConfig"]["temperature"] == 0.5
        assert body["generationConfig"]["maxOutputTokens"] == 256

    def test_normalize_request_streaming(self):
        req = UnifiedRequest(
            model="gemini-1.5-flash",
            messages=[UnifiedMessage(role="user", content="Hi")],
            stream=True,
        )
        url, _, _ = self.provider.normalize_request(req)
        assert "streamGenerateContent" in url

    def test_normalize_response(self):
        raw = {
            "candidates": [
                {
                    "content": {"role": "model", "parts": [{"text": "Hello from Gemini!"}]},
                    "finishReason": "STOP",
                }
            ],
            "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 5, "totalTokenCount": 8},
        }
        resp = self.provider.normalize_response(200, raw)

        assert resp.provider == "gemini"
        assert resp.choices[0].message.content == "Hello from Gemini!"
        assert resp.choices[0].message.role == "assistant"
        assert resp.choices[0].finish_reason == "stop"
        assert resp.usage.total_tokens == 8

    def test_normalize_stream_chunk(self):
        line = '{"candidates":[{"content":{"parts":[{"text":"Hi"}]}}]}'
        chunk = self.provider.normalize_stream_chunk(line)
        assert chunk is not None
        assert chunk.delta_content == "Hi"


# ── Provider Registry ───────────────────────────────────────────────


class TestProviderRegistry:
    def test_register_and_resolve(self):
        reg = ProviderRegistry()
        provider = OpenAIProvider(base_url="https://api.openai.com", api_key="test")
        reg.register(provider)

        resolved = reg.get_provider_for_model("gpt-4")
        assert resolved is not None
        assert resolved.provider_name == "openai"

    def test_resolve_anthropic(self):
        reg = ProviderRegistry()
        provider = AnthropicProvider(base_url="https://api.anthropic.com", api_key="test")
        reg.register(provider)

        resolved = reg.get_provider_for_model("claude-3-sonnet-20240229")
        assert resolved is not None
        assert resolved.provider_name == "anthropic"

    def test_resolve_gemini(self):
        reg = ProviderRegistry()
        provider = GeminiProvider(base_url="https://gem.api", api_key="test")
        reg.register(provider)

        resolved = reg.get_provider_for_model("gemini-1.5-pro")
        assert resolved is not None
        assert resolved.provider_name == "gemini"

    def test_resolve_by_prefix(self):
        reg = ProviderRegistry()
        reg.register(OpenAIProvider(base_url="", api_key=""))
        # Should resolve unknown gpt model by prefix
        resolved = reg.get_provider_for_model("gpt-5-turbo")
        assert resolved is not None
        assert resolved.provider_name == "openai"

    def test_unknown_model_returns_none(self):
        reg = ProviderRegistry()
        assert reg.get_provider_for_model("unknown-model") is None

    def test_weighted_selection(self):
        reg = ProviderRegistry()
        p1 = OpenAIProvider(base_url="https://api1", api_key="k1")
        p2 = OpenAIProvider(base_url="https://api2", api_key="k2")
        reg.register(p1, weight=1.0)
        reg.register(p2, weight=1.0)

        # Both should be possible over many selections
        results = set()
        for _ in range(100):
            p = reg.get_provider_for_model("gpt-4")
            results.add(p.base_url)
        assert len(results) == 2

    def test_list_providers(self):
        reg = ProviderRegistry()
        reg.register(OpenAIProvider(base_url="", api_key=""))
        reg.register(AnthropicProvider(base_url="", api_key=""))
        info = reg.list_providers()
        assert info["openai"] == 1
        assert info["anthropic"] == 1
