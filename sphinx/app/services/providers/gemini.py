"""Google Gemini provider adapter."""

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


ROLE_MAP = {"user": "user", "assistant": "model", "system": "user"}
ROLE_MAP_REVERSE = {"model": "assistant", "user": "user"}


class GeminiProvider(BaseProvider):
    """Adapter for Google Gemini API."""

    provider_name = "gemini"
    supported_models = [
        "gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash",
        "gemini-2.5-pro", "gemini-2.5-flash",
    ]

    def __init__(self, base_url: str = "https://generativelanguage.googleapis.com", api_key: str = ""):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def normalize_request(self, unified: UnifiedRequest) -> tuple[str, dict, bytes]:
        """Convert unified request to Gemini generateContent format."""
        model = unified.model
        action = "streamGenerateContent" if unified.stream else "generateContent"
        url = f"{self.base_url}/v1beta/models/{model}:{action}?key={self.api_key}"

        headers = {"Content-Type": "application/json"}

        # Convert messages to Gemini contents format
        contents = []
        system_instruction = None
        for m in unified.messages:
            if m.role == "system":
                system_instruction = {"parts": [{"text": m.content}]}
            else:
                contents.append({
                    "role": ROLE_MAP.get(m.role, "user"),
                    "parts": [{"text": m.content}],
                })

        body: dict = {"contents": contents}
        if system_instruction:
            body["systemInstruction"] = system_instruction

        generation_config: dict = {}
        if unified.temperature is not None:
            generation_config["temperature"] = unified.temperature
        if unified.max_tokens is not None:
            generation_config["maxOutputTokens"] = unified.max_tokens
        if unified.top_p is not None:
            generation_config["topP"] = unified.top_p
        if generation_config:
            body["generationConfig"] = generation_config

        return url, headers, json.dumps(body).encode()

    def normalize_response(self, status_code: int, response_data: dict) -> UnifiedResponse:
        """Convert Gemini response to unified format."""
        candidates = response_data.get("candidates", [])
        choices = []
        for i, candidate in enumerate(candidates):
            content = candidate.get("content", {})
            parts = content.get("parts", [])
            text = "".join(p.get("text", "") for p in parts)
            role = ROLE_MAP_REVERSE.get(content.get("role", "model"), "assistant")

            finish_reason_map = {
                "STOP": "stop",
                "MAX_TOKENS": "length",
                "SAFETY": "content_filter",
            }
            raw_finish = candidate.get("finishReason", "STOP")
            finish_reason = finish_reason_map.get(raw_finish, raw_finish.lower())

            choices.append(UnifiedChoice(
                index=i,
                message=UnifiedMessage(role=role, content=text),
                finish_reason=finish_reason,
            ))

        usage_meta = response_data.get("usageMetadata", {})
        return UnifiedResponse(
            provider=self.provider_name,
            model=unified.model if hasattr(self, '_last_model') else "",
            choices=choices,
            usage=UnifiedUsage(
                prompt_tokens=usage_meta.get("promptTokenCount", 0),
                completion_tokens=usage_meta.get("candidatesTokenCount", 0),
                total_tokens=usage_meta.get("totalTokenCount", 0),
            ),
            raw_response=response_data,
        )

    def normalize_stream_chunk(self, raw_line: str) -> Optional[UnifiedStreamChunk]:
        """Parse Gemini streaming response (JSON array chunks)."""
        line = raw_line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            return None

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        candidates = data.get("candidates", [])
        if not candidates:
            return None

        candidate = candidates[0]
        content = candidate.get("content", {})
        parts = content.get("parts", [])
        text = "".join(p.get("text", "") for p in parts)

        finish_reason = None
        if candidate.get("finishReason"):
            finish_reason = "stop" if candidate["finishReason"] == "STOP" else candidate["finishReason"].lower()

        return UnifiedStreamChunk(
            provider=self.provider_name,
            delta_content=text,
            finish_reason=finish_reason,
            raw_chunk=data,
        )
