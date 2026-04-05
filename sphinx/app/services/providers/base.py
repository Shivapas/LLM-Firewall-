"""Base provider adapter and unified request/response schema."""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Optional

from pydantic import BaseModel, Field


class UnifiedMessage(BaseModel):
    role: str
    content: str


class UnifiedRequest(BaseModel):
    """Normalized request format used internally by the gateway."""
    model: str
    messages: list[UnifiedMessage] = []
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    top_p: Optional[float] = None
    stream: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)


class UnifiedUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class UnifiedChoice(BaseModel):
    index: int = 0
    message: UnifiedMessage
    finish_reason: Optional[str] = None


class UnifiedResponse(BaseModel):
    """Normalized response format returned by provider adapters."""
    id: str = Field(default_factory=lambda: f"sphinx-{uuid.uuid4().hex[:12]}")
    provider: str = ""
    model: str = ""
    choices: list[UnifiedChoice] = []
    usage: UnifiedUsage = Field(default_factory=UnifiedUsage)
    created: int = Field(default_factory=lambda: int(time.time()))
    raw_response: Optional[dict[str, Any]] = None


class UnifiedStreamChunk(BaseModel):
    """A single chunk from a streaming response."""
    id: str = ""
    provider: str = ""
    model: str = ""
    delta_content: str = ""
    finish_reason: Optional[str] = None
    raw_chunk: Optional[dict[str, Any]] = None


class BaseProvider(ABC):
    """Abstract base class for LLM provider adapters."""

    provider_name: str = ""

    # Models this provider handles
    supported_models: list[str] = []

    @abstractmethod
    def normalize_request(self, unified: UnifiedRequest) -> tuple[str, dict, bytes]:
        """Convert unified request to provider-specific format.

        Returns:
            (url_path, headers, body_bytes)
        """

    @abstractmethod
    def normalize_response(self, status_code: int, response_data: dict) -> UnifiedResponse:
        """Convert provider-specific response to unified format."""

    @abstractmethod
    def normalize_stream_chunk(self, raw_line: str) -> Optional[UnifiedStreamChunk]:
        """Convert a single SSE line from the provider into a unified stream chunk."""

    def build_sse_line(self, chunk: UnifiedStreamChunk) -> str:
        """Convert a unified stream chunk to an OpenAI-compatible SSE line."""
        import json
        data = {
            "id": chunk.id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": chunk.model,
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": chunk.delta_content} if chunk.delta_content else {},
                    "finish_reason": chunk.finish_reason,
                }
            ],
        }
        return f"data: {json.dumps(data)}\n\n"
