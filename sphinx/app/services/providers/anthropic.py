"""Anthropic Claude provider adapter."""

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


class AnthropicProvider(BaseProvider):
    """Adapter for Anthropic Claude API."""

    provider_name = "anthropic"
    supported_models = [
        "claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307",
        "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022",
        "claude-sonnet-4-20250514", "claude-opus-4-20250514",
    ]

    def __init__(self, base_url: str = "https://api.anthropic.com", api_key: str = ""):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def normalize_request(self, unified: UnifiedRequest) -> tuple[str, dict, bytes]:
        """Convert unified request to Anthropic Messages API format."""
        url = f"{self.base_url}/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }

        # Extract system message if present
        system_text = ""
        messages = []
        for m in unified.messages:
            if m.role == "system":
                system_text = m.content
            else:
                messages.append({"role": m.role, "content": m.content})

        body: dict = {
            "model": unified.model,
            "messages": messages,
            "max_tokens": unified.max_tokens or 1024,
        }
        if system_text:
            body["system"] = system_text
        if unified.temperature is not None:
            body["temperature"] = unified.temperature
        if unified.top_p is not None:
            body["top_p"] = unified.top_p
        if unified.stream:
            body["stream"] = True

        return url, headers, json.dumps(body).encode()

    def normalize_response(self, status_code: int, response_data: dict) -> UnifiedResponse:
        """Convert Anthropic response to unified format."""
        content_blocks = response_data.get("content", [])
        text = ""
        for block in content_blocks:
            if block.get("type") == "text":
                text += block.get("text", "")

        usage_data = response_data.get("usage", {})
        return UnifiedResponse(
            id=response_data.get("id", ""),
            provider=self.provider_name,
            model=response_data.get("model", ""),
            choices=[
                UnifiedChoice(
                    index=0,
                    message=UnifiedMessage(role="assistant", content=text),
                    finish_reason=response_data.get("stop_reason", "end_turn"),
                )
            ],
            usage=UnifiedUsage(
                prompt_tokens=usage_data.get("input_tokens", 0),
                completion_tokens=usage_data.get("output_tokens", 0),
                total_tokens=usage_data.get("input_tokens", 0) + usage_data.get("output_tokens", 0),
            ),
            raw_response=response_data,
        )

    def normalize_stream_chunk(self, raw_line: str) -> Optional[UnifiedStreamChunk]:
        """Parse Anthropic SSE stream events."""
        line = raw_line.strip()
        if not line.startswith("data: "):
            return None
        data_str = line[6:]

        try:
            data = json.loads(data_str)
        except json.JSONDecodeError:
            return None

        event_type = data.get("type", "")

        if event_type == "content_block_delta":
            delta = data.get("delta", {})
            if delta.get("type") == "text_delta":
                return UnifiedStreamChunk(
                    provider=self.provider_name,
                    delta_content=delta.get("text", ""),
                    raw_chunk=data,
                )

        if event_type == "message_stop":
            return UnifiedStreamChunk(
                provider=self.provider_name,
                finish_reason="stop",
                raw_chunk=data,
            )

        return None
