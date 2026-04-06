"""Azure OpenAI provider adapter.

Handles Azure deployment names, API version headers, and Azure AD authentication.
"""

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


class AzureOpenAIProvider(BaseProvider):
    """Adapter for Azure OpenAI Service.

    Azure OpenAI uses deployment-based routing with API version headers.
    Supports both API key and Azure AD (bearer token) authentication.
    """

    provider_name = "azure_openai"
    supported_models = [
        # Azure deployments typically use custom names, but we list common ones
        "azure-gpt-4",
        "azure-gpt-4o",
        "azure-gpt-4o-mini",
        "azure-gpt-4-turbo",
        "azure-gpt-35-turbo",
        "azure-o1",
        "azure-o1-mini",
        "azure-o3-mini",
    ]

    def __init__(
        self,
        base_url: str = "",
        api_key: str = "",
        api_version: str = "2024-10-21",
        deployment_map: Optional[dict[str, str]] = None,
        use_azure_ad: bool = False,
    ):
        """Initialize Azure OpenAI adapter.

        Args:
            base_url: Azure resource endpoint (e.g., https://myresource.openai.azure.com)
            api_key: Azure OpenAI API key or Azure AD bearer token
            api_version: Azure OpenAI API version
            deployment_map: Mapping of model names to Azure deployment names
            use_azure_ad: If True, use Azure AD authentication (bearer token)
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.api_version = api_version
        self.use_azure_ad = use_azure_ad
        self.deployment_map = deployment_map or {
            "azure-gpt-4": "gpt-4",
            "azure-gpt-4o": "gpt-4o",
            "azure-gpt-4o-mini": "gpt-4o-mini",
            "azure-gpt-4-turbo": "gpt-4-turbo",
            "azure-gpt-35-turbo": "gpt-35-turbo",
            "azure-o1": "o1",
            "azure-o1-mini": "o1-mini",
            "azure-o3-mini": "o3-mini",
        }

    def _resolve_deployment(self, model_name: str) -> str:
        """Map model name to Azure deployment name."""
        return self.deployment_map.get(model_name, model_name)

    def normalize_request(self, unified: UnifiedRequest) -> tuple[str, dict, bytes]:
        """Convert unified request to Azure OpenAI format."""
        deployment = self._resolve_deployment(unified.model)
        url = (
            f"{self.base_url}/openai/deployments/{deployment}"
            f"/chat/completions?api-version={self.api_version}"
        )

        headers: dict[str, str] = {
            "Content-Type": "application/json",
        }

        if self.use_azure_ad:
            headers["Authorization"] = f"Bearer {self.api_key}"
        else:
            headers["api-key"] = self.api_key

        body: dict = {
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
        """Convert Azure OpenAI response to unified format.

        Azure OpenAI response format is identical to OpenAI's.
        """
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
        """Parse Azure OpenAI SSE stream chunk (same format as OpenAI)."""
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
