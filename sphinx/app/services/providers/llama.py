"""Self-hosted Llama provider adapter — supports Ollama, vLLM, and OpenAI-compatible
local deployments.

Sprint 11: Sensitivity-Based Routing & Budget Downgrade.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from app.services.providers.base import (
    BaseProvider,
    UnifiedRequest,
    UnifiedResponse,
    UnifiedChoice,
    UnifiedMessage,
    UnifiedUsage,
    UnifiedStreamChunk,
)

logger = logging.getLogger("sphinx.providers.llama")


class LlamaProvider(BaseProvider):
    """Adapter for self-hosted Llama models via Ollama, vLLM, or any OpenAI-compatible API.

    Supports two API modes:
    - OpenAI-compatible (default): /v1/chat/completions (works with vLLM, Ollama with OpenAI compat)
    - Native Ollama: /api/chat (Ollama's native REST API)
    """

    provider_name = "llama"
    supported_models = [
        "llama-3.1-8b", "llama-3.1-70b", "llama-3.1-405b",
        "llama-3.2-1b", "llama-3.2-3b", "llama-3.2-11b", "llama-3.2-90b",
        "llama-3.3-70b",
        "codellama-34b", "codellama-70b",
    ]

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        api_key: str = "",
        api_mode: str = "openai_compat",
    ):
        """Initialize Llama provider.

        Args:
            base_url: Base URL of the Llama-compatible server.
            api_key: API key (optional for local deployments).
            api_mode: "openai_compat" for /v1/chat/completions or "ollama_native" for /api/chat.
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.api_mode = api_mode

    def normalize_request(self, unified: UnifiedRequest) -> tuple[str, dict, bytes]:
        """Convert unified request to Llama-compatible format."""
        if self.api_mode == "ollama_native":
            return self._normalize_ollama_native(unified)
        return self._normalize_openai_compat(unified)

    def _normalize_openai_compat(self, unified: UnifiedRequest) -> tuple[str, dict, bytes]:
        """OpenAI-compatible format (vLLM, Ollama OpenAI compat mode)."""
        url = f"{self.base_url}/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        body = {
            "model": unified.model,
            "messages": [{"role": m.role, "content": m.content} for m in unified.messages],
            "stream": unified.stream,
        }
        if unified.temperature is not None:
            body["temperature"] = unified.temperature
        if unified.max_tokens is not None:
            body["max_tokens"] = unified.max_tokens
        if unified.top_p is not None:
            body["top_p"] = unified.top_p

        return url, headers, json.dumps(body).encode()

    def _normalize_ollama_native(self, unified: UnifiedRequest) -> tuple[str, dict, bytes]:
        """Ollama native /api/chat format."""
        url = f"{self.base_url}/api/chat"
        headers = {"Content-Type": "application/json"}

        body = {
            "model": unified.model,
            "messages": [{"role": m.role, "content": m.content} for m in unified.messages],
            "stream": unified.stream,
        }
        # Ollama uses 'options' for generation parameters
        options = {}
        if unified.temperature is not None:
            options["temperature"] = unified.temperature
        if unified.max_tokens is not None:
            options["num_predict"] = unified.max_tokens
        if unified.top_p is not None:
            options["top_p"] = unified.top_p
        if options:
            body["options"] = options

        return url, headers, json.dumps(body).encode()

    def normalize_response(self, status_code: int, response_data: dict) -> UnifiedResponse:
        """Convert Llama response to unified format."""
        if self.api_mode == "ollama_native":
            return self._normalize_ollama_response(status_code, response_data)
        return self._normalize_openai_response(status_code, response_data)

    def _normalize_openai_response(self, status_code: int, response_data: dict) -> UnifiedResponse:
        """Parse OpenAI-compatible response (vLLM, Ollama compat)."""
        choices = []
        for c in response_data.get("choices", []):
            msg = c.get("message", {})
            choices.append(UnifiedChoice(
                index=c.get("index", 0),
                message=UnifiedMessage(
                    role=msg.get("role", "assistant"),
                    content=msg.get("content", ""),
                ),
                finish_reason=c.get("finish_reason"),
            ))

        usage_data = response_data.get("usage", {})
        return UnifiedResponse(
            id=response_data.get("id", ""),
            provider=self.provider_name,
            model=response_data.get("model", ""),
            choices=choices,
            usage=UnifiedUsage(
                prompt_tokens=usage_data.get("prompt_tokens", 0),
                completion_tokens=usage_data.get("completion_tokens", 0),
                total_tokens=usage_data.get("total_tokens", 0),
            ),
            created=response_data.get("created", 0),
            raw_response=response_data,
        )

    def _normalize_ollama_response(self, status_code: int, response_data: dict) -> UnifiedResponse:
        """Parse Ollama native response format.

        Ollama returns: {"model": "...", "message": {"role": "...", "content": "..."}, ...}
        """
        msg = response_data.get("message", {})
        choices = [
            UnifiedChoice(
                index=0,
                message=UnifiedMessage(
                    role=msg.get("role", "assistant"),
                    content=msg.get("content", ""),
                ),
                finish_reason="stop" if response_data.get("done") else None,
            )
        ]

        # Ollama provides eval_count, prompt_eval_count
        prompt_tokens = response_data.get("prompt_eval_count", 0)
        completion_tokens = response_data.get("eval_count", 0)

        return UnifiedResponse(
            provider=self.provider_name,
            model=response_data.get("model", ""),
            choices=choices,
            usage=UnifiedUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
            ),
            raw_response=response_data,
        )

    def normalize_stream_chunk(self, raw_line: str) -> Optional[UnifiedStreamChunk]:
        """Parse streaming chunk from Llama-compatible server."""
        if self.api_mode == "ollama_native":
            return self._normalize_ollama_stream_chunk(raw_line)
        return self._normalize_openai_stream_chunk(raw_line)

    def _normalize_openai_stream_chunk(self, raw_line: str) -> Optional[UnifiedStreamChunk]:
        """Parse OpenAI-compatible SSE stream chunk."""
        line = raw_line.strip()
        if not line.startswith("data: "):
            return None
        data_str = line[6:]
        if data_str == "[DONE]":
            return None

        try:
            data = json.loads(data_str)
        except json.JSONDecodeError:
            return None

        choices = data.get("choices", [])
        if not choices:
            return None

        delta = choices[0].get("delta", {})
        return UnifiedStreamChunk(
            id=data.get("id", ""),
            provider=self.provider_name,
            model=data.get("model", ""),
            delta_content=delta.get("content", ""),
            finish_reason=choices[0].get("finish_reason"),
            raw_chunk=data,
        )

    def _normalize_ollama_stream_chunk(self, raw_line: str) -> Optional[UnifiedStreamChunk]:
        """Parse Ollama native streaming chunk.

        Ollama streams JSON objects, one per line:
        {"model": "...", "message": {"role": "...", "content": "..."}, "done": false}
        """
        line = raw_line.strip()
        if not line:
            return None

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        msg = data.get("message", {})
        return UnifiedStreamChunk(
            provider=self.provider_name,
            model=data.get("model", ""),
            delta_content=msg.get("content", ""),
            finish_reason="stop" if data.get("done") else None,
            raw_chunk=data,
        )
