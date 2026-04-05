"""OpenAI provider adapter."""

from __future__ import annotations

import json
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


class OpenAIProvider(BaseProvider):
    """Adapter for OpenAI API (gpt-4, gpt-4o, gpt-3.5-turbo, etc.)."""

    provider_name = "openai"
    supported_models = [
        "gpt-4", "gpt-4o", "gpt-4o-mini", "gpt-4-turbo",
        "gpt-3.5-turbo", "o1", "o1-mini", "o1-pro", "o3-mini",
    ]

    def __init__(self, base_url: str = "https://api.openai.com", api_key: str = ""):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def normalize_request(self, unified: UnifiedRequest) -> tuple[str, dict, bytes]:
        """OpenAI uses the same format as our unified schema (it's the reference)."""
        url = f"{self.base_url}/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

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

    def normalize_response(self, status_code: int, response_data: dict) -> UnifiedResponse:
        """OpenAI response is already in our reference format."""
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

    def normalize_stream_chunk(self, raw_line: str) -> Optional[UnifiedStreamChunk]:
        """Parse OpenAI SSE stream chunk."""
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
