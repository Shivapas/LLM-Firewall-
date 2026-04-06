"""AWS Bedrock provider adapter.

Supports Claude via Bedrock, Amazon Titan, and Llama via Bedrock.
Handles Bedrock's InvokeModel and InvokeModelWithResponseStream APIs.
"""

from __future__ import annotations

import json
import hashlib
import hmac
import datetime
from typing import Optional
from urllib.parse import urlparse, quote

from app.services.providers.base import (
    BaseProvider,
    UnifiedRequest,
    UnifiedResponse,
    UnifiedChoice,
    UnifiedMessage,
    UnifiedUsage,
    UnifiedStreamChunk,
)


class BedrockProvider(BaseProvider):
    """Adapter for AWS Bedrock: Claude, Titan, and Llama models."""

    provider_name = "bedrock"
    supported_models = [
        # Claude via Bedrock
        "anthropic.claude-3-opus-20240229-v1:0",
        "anthropic.claude-3-sonnet-20240229-v1:0",
        "anthropic.claude-3-haiku-20240307-v1:0",
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "anthropic.claude-3-5-haiku-20241022-v1:0",
        # Amazon Titan
        "amazon.titan-text-express-v1",
        "amazon.titan-text-lite-v1",
        "amazon.titan-text-premier-v1:0",
        # Llama via Bedrock
        "meta.llama3-8b-instruct-v1:0",
        "meta.llama3-70b-instruct-v1:0",
        "meta.llama3-1-405b-instruct-v1:0",
        "meta.llama3-2-90b-instruct-v1:0",
    ]

    def __init__(
        self,
        base_url: str = "",
        api_key: str = "",
        region: str = "us-east-1",
        aws_access_key_id: str = "",
        aws_secret_access_key: str = "",
        aws_session_token: str = "",
    ):
        self.region = region
        self.aws_access_key_id = aws_access_key_id or api_key.split(":")[0] if ":" in api_key else api_key
        self.aws_secret_access_key = aws_secret_access_key or (api_key.split(":")[1] if ":" in api_key else "")
        self.aws_session_token = aws_session_token or (api_key.split(":")[2] if api_key.count(":") >= 2 else "")
        self.base_url = base_url or f"https://bedrock-runtime.{region}.amazonaws.com"

    def normalize_request(self, unified: UnifiedRequest) -> tuple[str, dict, bytes]:
        """Convert unified request to Bedrock InvokeModel format."""
        model_id = unified.model
        action = "invoke-with-response-stream" if unified.stream else "invoke"
        url = f"{self.base_url}/model/{model_id}/{action}"

        # Build provider-specific body based on model family
        if model_id.startswith("anthropic."):
            body = self._build_claude_body(unified)
        elif model_id.startswith("amazon.titan"):
            body = self._build_titan_body(unified)
        elif model_id.startswith("meta.llama"):
            body = self._build_llama_body(unified)
        else:
            body = self._build_claude_body(unified)

        body_bytes = json.dumps(body).encode()

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Sign request with AWS Signature V4
        headers = self._sign_request(url, headers, body_bytes)

        return url, headers, body_bytes

    def normalize_response(self, status_code: int, response_data: dict) -> UnifiedResponse:
        """Convert Bedrock response to unified format."""
        # Detect model family from response structure
        if "content" in response_data:
            return self._normalize_claude_response(response_data)
        elif "results" in response_data:
            return self._normalize_titan_response(response_data)
        elif "generation" in response_data:
            return self._normalize_llama_response(response_data)

        # Fallback: try to extract text from common patterns
        return UnifiedResponse(
            provider=self.provider_name,
            choices=[
                UnifiedChoice(
                    index=0,
                    message=UnifiedMessage(
                        role="assistant",
                        content=str(response_data),
                    ),
                    finish_reason="stop",
                )
            ],
            raw_response=response_data,
        )

    def normalize_stream_chunk(self, raw_line: str) -> Optional[UnifiedStreamChunk]:
        """Parse Bedrock streaming response chunks."""
        line = raw_line.strip()
        if not line:
            return None

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            # Bedrock streams event-based; try extracting from event wrapper
            if "bytes" in line:
                try:
                    import base64
                    event_data = json.loads(line)
                    payload = base64.b64decode(event_data["bytes"])
                    data = json.loads(payload)
                except Exception:
                    return None
            else:
                return None

        # Claude via Bedrock streaming
        if data.get("type") == "content_block_delta":
            delta = data.get("delta", {})
            if delta.get("type") == "text_delta":
                return UnifiedStreamChunk(
                    provider=self.provider_name,
                    delta_content=delta.get("text", ""),
                    raw_chunk=data,
                )
        elif data.get("type") == "message_stop":
            return UnifiedStreamChunk(
                provider=self.provider_name,
                finish_reason="stop",
                raw_chunk=data,
            )

        # Titan streaming
        if "outputText" in data:
            return UnifiedStreamChunk(
                provider=self.provider_name,
                delta_content=data.get("outputText", ""),
                finish_reason="stop" if data.get("completionReason") == "FINISH" else None,
                raw_chunk=data,
            )

        # Llama via Bedrock streaming
        if "generation" in data:
            return UnifiedStreamChunk(
                provider=self.provider_name,
                delta_content=data.get("generation", ""),
                finish_reason="stop" if data.get("stop_reason") else None,
                raw_chunk=data,
            )

        return None

    # ── Model-specific body builders ─────────────────────────────────

    def _build_claude_body(self, unified: UnifiedRequest) -> dict:
        """Build Anthropic Claude request body for Bedrock."""
        system_text = ""
        messages = []
        for m in unified.messages:
            if m.role == "system":
                system_text = m.content
            else:
                messages.append({"role": m.role, "content": m.content})

        body: dict = {
            "anthropic_version": "bedrock-2023-05-31",
            "messages": messages,
            "max_tokens": unified.max_tokens or 1024,
        }
        if system_text:
            body["system"] = system_text
        if unified.temperature is not None:
            body["temperature"] = unified.temperature
        if unified.top_p is not None:
            body["top_p"] = unified.top_p

        return body

    def _build_titan_body(self, unified: UnifiedRequest) -> dict:
        """Build Amazon Titan request body."""
        prompt = "\n".join(
            f"{m.role}: {m.content}" for m in unified.messages
        )

        config: dict = {}
        if unified.max_tokens is not None:
            config["maxTokenCount"] = unified.max_tokens
        if unified.temperature is not None:
            config["temperature"] = unified.temperature
        if unified.top_p is not None:
            config["topP"] = unified.top_p

        body: dict = {"inputText": prompt}
        if config:
            body["textGenerationConfig"] = config
        return body

    def _build_llama_body(self, unified: UnifiedRequest) -> dict:
        """Build Llama request body for Bedrock."""
        prompt = "\n".join(
            f"{'<|start_header_id|>' + m.role + '<|end_header_id|>'}\n{m.content}<|eot_id|>"
            for m in unified.messages
        )
        prompt = f"<|begin_of_text|>{prompt}<|start_header_id|>assistant<|end_header_id|>\n"

        body: dict = {"prompt": prompt}
        if unified.max_tokens is not None:
            body["max_gen_len"] = unified.max_tokens
        if unified.temperature is not None:
            body["temperature"] = unified.temperature
        if unified.top_p is not None:
            body["top_p"] = unified.top_p

        return body

    # ── Model-specific response normalizers ──────────────────────────

    def _normalize_claude_response(self, data: dict) -> UnifiedResponse:
        """Normalize Claude via Bedrock response."""
        content_blocks = data.get("content", [])
        text = "".join(
            block.get("text", "") for block in content_blocks
            if block.get("type") == "text"
        )
        usage = data.get("usage", {})

        return UnifiedResponse(
            id=data.get("id", ""),
            provider=self.provider_name,
            model=data.get("model", ""),
            choices=[
                UnifiedChoice(
                    index=0,
                    message=UnifiedMessage(role="assistant", content=text),
                    finish_reason=data.get("stop_reason", "end_turn"),
                )
            ],
            usage=UnifiedUsage(
                prompt_tokens=usage.get("input_tokens", 0),
                completion_tokens=usage.get("output_tokens", 0),
                total_tokens=usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
            ),
            raw_response=data,
        )

    def _normalize_titan_response(self, data: dict) -> UnifiedResponse:
        """Normalize Amazon Titan response."""
        results = data.get("results", [{}])
        text = results[0].get("outputText", "") if results else ""
        token_count = results[0].get("tokenCount", 0) if results else 0

        return UnifiedResponse(
            provider=self.provider_name,
            choices=[
                UnifiedChoice(
                    index=0,
                    message=UnifiedMessage(role="assistant", content=text),
                    finish_reason=results[0].get("completionReason", "FINISH").lower() if results else "stop",
                )
            ],
            usage=UnifiedUsage(
                prompt_tokens=data.get("inputTextTokenCount", 0),
                completion_tokens=token_count,
                total_tokens=data.get("inputTextTokenCount", 0) + token_count,
            ),
            raw_response=data,
        )

    def _normalize_llama_response(self, data: dict) -> UnifiedResponse:
        """Normalize Llama via Bedrock response."""
        text = data.get("generation", "")

        return UnifiedResponse(
            provider=self.provider_name,
            choices=[
                UnifiedChoice(
                    index=0,
                    message=UnifiedMessage(role="assistant", content=text),
                    finish_reason="stop" if data.get("stop_reason") else "stop",
                )
            ],
            usage=UnifiedUsage(
                prompt_tokens=data.get("prompt_token_count", 0),
                completion_tokens=data.get("generation_token_count", 0),
                total_tokens=data.get("prompt_token_count", 0) + data.get("generation_token_count", 0),
            ),
            raw_response=data,
        )

    # ── AWS Signature V4 ─────────────────────────────────────────────

    def _sign_request(self, url: str, headers: dict, body: bytes) -> dict:
        """Sign request with AWS Signature Version 4."""
        now = datetime.datetime.now(datetime.timezone.utc)
        datestamp = now.strftime("%Y%m%d")
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")

        parsed = urlparse(url)
        host = parsed.hostname
        canonical_uri = quote(parsed.path, safe="/-_.~")
        canonical_querystring = parsed.query or ""

        headers["Host"] = host
        headers["X-Amz-Date"] = amz_date

        if self.aws_session_token:
            headers["X-Amz-Security-Token"] = self.aws_session_token

        signed_headers = sorted(k.lower() for k in headers.keys())
        signed_headers_str = ";".join(signed_headers)
        canonical_headers = "".join(
            f"{k}:{headers[k]}\n"
            for k in sorted(headers.keys(), key=str.lower)
        )

        payload_hash = hashlib.sha256(body).hexdigest()
        headers["X-Amz-Content-Sha256"] = payload_hash

        # Rebuild canonical headers with the new header
        signed_headers = sorted(k.lower() for k in headers.keys())
        signed_headers_str = ";".join(signed_headers)
        canonical_headers = "".join(
            f"{k.lower()}:{headers[k].strip()}\n"
            for k in sorted(headers.keys(), key=str.lower)
        )

        canonical_request = (
            f"POST\n{canonical_uri}\n{canonical_querystring}\n"
            f"{canonical_headers}\n{signed_headers_str}\n{payload_hash}"
        )

        service = "bedrock"
        credential_scope = f"{datestamp}/{self.region}/{service}/aws4_request"
        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        )

        # Derive signing key
        k_date = self._hmac_sha256(f"AWS4{self.aws_secret_access_key}".encode(), datestamp)
        k_region = self._hmac_sha256(k_date, self.region)
        k_service = self._hmac_sha256(k_region, service)
        k_signing = self._hmac_sha256(k_service, "aws4_request")

        signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

        headers["Authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self.aws_access_key_id}/{credential_scope}, "
            f"SignedHeaders={signed_headers_str}, Signature={signature}"
        )

        return headers

    @staticmethod
    def _hmac_sha256(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()
