"""Sprint 14 — Output Guardrail Test Suite.

Tests:
- Streaming chunk interceptor: SSE parsing, sliding window buffering
- Output PII redaction: SSN, email, phone, name in streamed output
- Output credential detection: API keys, connection strings, private keys
- Output policy evaluation: Stream/Redact/Block actions
- Regulated data leakage detection: compliance tag matching
- End-to-end: model response containing SSN, API key, PII → correctly redacted
"""

import asyncio
import json
import pytest

from app.services.output_scanner.chunk_interceptor import (
    ParsedSSEChunk,
    SlidingWindowBuffer,
    parse_sse_chunk,
    rebuild_sse_chunk,
)
from app.services.output_scanner.output_policy import (
    OutputAction,
    OutputPolicyEvaluator,
    OutputPolicyResult,
    OutputPolicyRule,
)
from app.services.output_scanner.leakage_detector import (
    LeakageDetector,
    LeakageDetectionResult,
)
from app.services.output_scanner.engine import (
    OutputScannerEngine,
    OutputScanContext,
    OutputScanResult,
)
from app.services.data_shield.pii_recognizer import PIIEntity, PIIType


# ────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────

def _make_sse_chunk(content: str, chunk_id: str = "chatcmpl-1", model: str = "gpt-4", finish_reason=None) -> bytes:
    """Build a realistic OpenAI-compatible SSE chunk."""
    data = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": 1700000000,
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {"content": content} if content else {},
                "finish_reason": finish_reason,
            }
        ],
    }
    return f"data: {json.dumps(data)}\n\n".encode("utf-8")


def _make_done_chunk() -> bytes:
    return b"data: [DONE]\n\n"


async def _collect_stream(engine, chunks, context=None):
    """Helper to collect all chunks from the scanner stream."""
    async def chunk_iter():
        for c in chunks:
            yield c

    result_chunks = []
    async for chunk in engine.scan_stream(chunk_iter(), context=context):
        result_chunks.append(chunk)
    return result_chunks


# ────────────────────────────────────────────────────────────────────────
# 1. Streaming Chunk Interceptor Tests
# ────────────────────────────────────────────────────────────────────────

class TestChunkInterceptor:
    """Test SSE chunk parsing and sliding window buffering."""

    def test_parse_normal_chunk(self):
        raw = _make_sse_chunk("Hello world")
        parsed = parse_sse_chunk(raw)
        assert parsed.delta_content == "Hello world"
        assert not parsed.is_done
        assert not parsed.parse_error
        assert parsed.chunk_id == "chatcmpl-1"
        assert parsed.model == "gpt-4"

    def test_parse_done_chunk(self):
        raw = _make_done_chunk()
        parsed = parse_sse_chunk(raw)
        assert parsed.is_done
        assert parsed.delta_content == ""

    def test_parse_finish_reason_stop(self):
        raw = _make_sse_chunk("", finish_reason="stop")
        parsed = parse_sse_chunk(raw)
        assert parsed.is_done
        assert parsed.finish_reason == "stop"

    def test_parse_invalid_json(self):
        raw = b"data: {invalid json}\n\n"
        parsed = parse_sse_chunk(raw)
        assert parsed.parse_error

    def test_parse_empty_bytes(self):
        parsed = parse_sse_chunk(b"")
        # No data lines, no content
        assert parsed.delta_content == ""
        assert not parsed.is_done

    def test_sliding_window_buffer(self):
        buf = SlidingWindowBuffer(window_size=3)
        for i in range(5):
            chunk = ParsedSSEChunk(raw_bytes=b"", delta_content=f"chunk{i}")
            buf.push(chunk)

        # Window should only hold last 3 chunks
        assert buf.chunk_count == 3
        assert buf.buffered_text == "chunk2chunk3chunk4"

    def test_sliding_window_clear(self):
        buf = SlidingWindowBuffer(window_size=3)
        buf.push(ParsedSSEChunk(raw_bytes=b"", delta_content="hello"))
        buf.clear()
        assert buf.chunk_count == 0
        assert buf.buffered_text == ""

    def test_rebuild_sse_chunk(self):
        raw = _make_sse_chunk("original content")
        parsed = parse_sse_chunk(raw)
        rebuilt = rebuild_sse_chunk(parsed, "redacted content")
        reparsed = parse_sse_chunk(rebuilt)
        assert reparsed.delta_content == "redacted content"

    def test_rebuild_done_chunk_unchanged(self):
        raw = _make_done_chunk()
        parsed = parse_sse_chunk(raw)
        rebuilt = rebuild_sse_chunk(parsed, "anything")
        assert rebuilt == raw


# ────────────────────────────────────────────────────────────────────────
# 2. Output PII Redaction Tests
# ────────────────────────────────────────────────────────────────────────

class TestOutputPIIRedaction:
    """Test PII/PHI detection and redaction in output stream."""

    def setup_method(self):
        self.engine = OutputScannerEngine()

    def test_ssn_redacted(self):
        text = "Your SSN is 123-45-6789."
        redacted, entities = self.engine.scan_text(text)
        assert "[REDACTED" in redacted
        assert "123-45-6789" not in redacted
        assert any(e.entity_type == PIIType.SSN for e in entities)

    def test_email_redacted(self):
        text = "Contact us at john.doe@example.com for support."
        redacted, entities = self.engine.scan_text(text)
        assert "john.doe@example.com" not in redacted
        assert "[REDACTED" in redacted
        assert any(e.entity_type == PIIType.EMAIL for e in entities)

    def test_phone_redacted(self):
        text = "Call me at (555) 123-4567 please."
        redacted, entities = self.engine.scan_text(text)
        assert "(555) 123-4567" not in redacted
        assert any(e.entity_type == PIIType.PHONE for e in entities)

    def test_no_pii_passthrough(self):
        text = "The weather is nice today."
        redacted, entities = self.engine.scan_text(text)
        assert redacted == text
        assert entities == []

    def test_multiple_pii_redacted(self):
        text = "Name: John Smith, SSN: 123-45-6789, Email: john@test.com"
        redacted, entities = self.engine.scan_text(text)
        assert "123-45-6789" not in redacted
        assert "john@test.com" not in redacted
        assert len(entities) >= 2


# ────────────────────────────────────────────────────────────────────────
# 3. Output Credential Detection Tests
# ────────────────────────────────────────────────────────────────────────

class TestOutputCredentialDetection:
    """Test credential detection in model output."""

    def setup_method(self):
        self.engine = OutputScannerEngine()

    def test_openai_api_key_detected(self):
        text = "Use this key: sk-abc123def456ghi789jkl012mno345pqr678stu901vwx"
        redacted, entities = self.engine.scan_text(text)
        assert "sk-abc123" not in redacted
        assert "[REDACTED" in redacted
        entity_types = {e.entity_type.value for e in entities}
        assert "OPENAI_API_KEY" in entity_types

    def test_github_token_detected(self):
        text = "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        redacted, entities = self.engine.scan_text(text)
        assert "ghp_ABCDEFGHIJ" not in redacted
        entity_types = {e.entity_type.value for e in entities}
        assert "GITHUB_TOKEN" in entity_types

    def test_connection_string_detected(self):
        text = "Connect to: postgresql://user:pass@host:5432/dbname"
        redacted, entities = self.engine.scan_text(text)
        assert "postgresql://user:pass" not in redacted
        entity_types = {e.entity_type.value for e in entities}
        assert "CONNECTION_STRING" in entity_types

    def test_private_key_detected(self):
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIBogIBAAJBALRiMLAH...(truncated for test)...key data here\n"
            "-----END RSA PRIVATE KEY-----"
        )
        redacted, entities = self.engine.scan_text(text)
        assert "BEGIN RSA PRIVATE KEY" not in redacted
        entity_types = {e.entity_type.value for e in entities}
        assert "PRIVATE_KEY" in entity_types

    def test_aws_access_key_detected(self):
        text = "AWS key: AKIAIOSFODNN7EXAMPLE"
        redacted, entities = self.engine.scan_text(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted

    def test_stripe_key_detected(self):
        text = "Stripe: sk_live_4eC39HqLyjWDarjtT1zdp7dc"
        redacted, entities = self.engine.scan_text(text)
        assert "sk_live_" not in redacted

    def test_clean_output_passthrough(self):
        text = "Here is how to set up authentication in your app."
        redacted, entities = self.engine.scan_text(text)
        assert redacted == text
        assert entities == []


# ────────────────────────────────────────────────────────────────────────
# 4. Output Policy Evaluation Tests
# ────────────────────────────────────────────────────────────────────────

class TestOutputPolicyEvaluation:
    """Test policy rule evaluation against output content."""

    def setup_method(self):
        self.evaluator = OutputPolicyEvaluator()

    def test_no_entities_stream_action(self):
        result = self.evaluator.evaluate([], 0)
        assert result.action == OutputAction.STREAM
        assert result.matched_rules == []

    def test_ssn_triggers_redact(self):
        result = self.evaluator.evaluate(["SSN"], 1)
        assert result.action == OutputAction.REDACT
        assert len(result.matched_rules) > 0

    def test_api_key_triggers_redact(self):
        result = self.evaluator.evaluate(["OPENAI_API_KEY"], 1)
        assert result.action == OutputAction.REDACT

    def test_private_key_triggers_block(self):
        result = self.evaluator.evaluate(["PRIVATE_KEY"], 1)
        assert result.action == OutputAction.BLOCK

    def test_email_triggers_redact(self):
        result = self.evaluator.evaluate(["EMAIL"], 1)
        assert result.action == OutputAction.REDACT

    def test_phi_triggers_redact(self):
        result = self.evaluator.evaluate(["PATIENT_ID", "MEDICATION"], 2)
        assert result.action == OutputAction.REDACT
        assert result.entity_count == 2

    def test_multiple_entity_types_highest_action(self):
        # PRIVATE_KEY (block) + EMAIL (redact) → block wins
        result = self.evaluator.evaluate(["PRIVATE_KEY", "EMAIL"], 2)
        assert result.action == OutputAction.BLOCK

    def test_compliance_tags_trigger_incident_log(self):
        result = self.evaluator.evaluate(["SSN"], 1, compliance_tags=["PII"])
        assert result.incident_logged
        assert result.action == OutputAction.REDACT

    def test_custom_rules(self):
        custom_rules = [
            OutputPolicyRule(
                rule_id="CUSTOM-001",
                name="Block all emails",
                entity_types=["EMAIL"],
                action=OutputAction.BLOCK,
                priority=1,
            ),
        ]
        evaluator = OutputPolicyEvaluator(rules=custom_rules)
        result = evaluator.evaluate(["EMAIL"], 1)
        assert result.action == OutputAction.BLOCK
        assert result.matched_rules[0].rule_id == "CUSTOM-001"


# ────────────────────────────────────────────────────────────────────────
# 5. Regulated Data Leakage Detection Tests
# ────────────────────────────────────────────────────────────────────────

class TestLeakageDetection:
    """Test regulated data leakage detection."""

    def setup_method(self):
        self.detector = LeakageDetector()

    def test_no_leakage_without_entities(self):
        result = self.detector.detect([], ["PII"])
        assert not result.leakage_detected

    def test_no_leakage_without_tags(self):
        entities = [PIIEntity(PIIType.SSN, "123-45-6789", 0, 11)]
        result = self.detector.detect(entities, [])
        assert not result.leakage_detected

    def test_pii_leakage_detected(self):
        entities = [PIIEntity(PIIType.SSN, "123-45-6789", 0, 11)]
        result = self.detector.detect(entities, ["PII"])
        assert result.leakage_detected
        assert "PII" in result.compliance_tags_violated
        assert len(result.incidents) == 1
        assert result.incidents[0].severity == "high"

    def test_phi_leakage_critical_severity(self):
        entities = [PIIEntity(PIIType.PATIENT_ID, "PAT-12345", 0, 9)]
        result = self.detector.detect(entities, ["PHI"])
        assert result.leakage_detected
        assert "PHI" in result.compliance_tags_violated
        assert result.incidents[0].severity == "critical"

    def test_credential_leakage_detected(self):
        entities = [PIIEntity(PIIType.OPENAI_API_KEY, "sk-abc123", 0, 8)]
        result = self.detector.detect(entities, ["IP"])
        assert result.leakage_detected
        assert "IP" in result.compliance_tags_violated
        assert result.incidents[0].severity == "critical"

    def test_no_cross_tag_leakage(self):
        """PII entity should not trigger on PHI tag."""
        entities = [PIIEntity(PIIType.EMAIL, "test@test.com", 0, 13)]
        result = self.detector.detect(entities, ["PHI"])
        assert not result.leakage_detected

    def test_multiple_tag_violations(self):
        entities = [
            PIIEntity(PIIType.SSN, "123-45-6789", 0, 11),
            PIIEntity(PIIType.PATIENT_ID, "PAT-12345", 20, 29),
        ]
        result = self.detector.detect(entities, ["PII", "PHI"])
        assert result.leakage_detected
        assert set(result.compliance_tags_violated) == {"PII", "PHI"}
        assert len(result.incidents) == 2

    def test_leakage_result_dict(self):
        entities = [PIIEntity(PIIType.SSN, "123-45-6789", 0, 11)]
        result = self.detector.detect(entities, ["PII"])
        d = result.to_dict()
        assert d["leakage_detected"] is True
        assert d["incident_count"] == 1


# ────────────────────────────────────────────────────────────────────────
# 6. End-to-End Streaming Output Scanner Tests
# ────────────────────────────────────────────────────────────────────────

class TestEndToEndStreamScanner:
    """End-to-end tests: model response containing SSN, API key, PII → correctly redacted."""

    def setup_method(self):
        self.engine = OutputScannerEngine(window_size=5)

    @pytest.mark.asyncio
    async def test_ssn_in_stream_redacted(self):
        """SSN in model output is redacted before reaching the client."""
        chunks = [
            _make_sse_chunk("Your social security number is "),
            _make_sse_chunk("123-45-6789"),
            _make_sse_chunk(". Please keep it safe."),
            _make_done_chunk(),
        ]
        result_chunks = await _collect_stream(self.engine, chunks)

        # Reconstruct output text from result chunks
        output_text = ""
        for c in result_chunks:
            parsed = parse_sse_chunk(c)
            output_text += parsed.delta_content

        assert "123-45-6789" not in output_text

    @pytest.mark.asyncio
    async def test_api_key_in_stream_redacted(self):
        """API key in model output is replaced with [REDACTED] marker."""
        api_key = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx"
        chunks = [
            _make_sse_chunk("Here is your API key: "),
            _make_sse_chunk(api_key),
            _make_sse_chunk(" — use it wisely."),
            _make_done_chunk(),
        ]
        result_chunks = await _collect_stream(self.engine, chunks)

        output_text = ""
        for c in result_chunks:
            parsed = parse_sse_chunk(c)
            output_text += parsed.delta_content

        assert api_key not in output_text
        assert "[REDACTED" in output_text

    @pytest.mark.asyncio
    async def test_email_in_stream_redacted(self):
        chunks = [
            _make_sse_chunk("Contact john.doe@example.com for help."),
            _make_done_chunk(),
        ]
        result_chunks = await _collect_stream(self.engine, chunks)

        output_text = ""
        for c in result_chunks:
            parsed = parse_sse_chunk(c)
            output_text += parsed.delta_content

        assert "john.doe@example.com" not in output_text

    @pytest.mark.asyncio
    async def test_clean_stream_passthrough(self):
        """Clean output with no sensitive data passes through unchanged."""
        chunks = [
            _make_sse_chunk("Hello, "),
            _make_sse_chunk("how can I "),
            _make_sse_chunk("help you today?"),
            _make_done_chunk(),
        ]
        result_chunks = await _collect_stream(self.engine, chunks)

        output_text = ""
        for c in result_chunks:
            parsed = parse_sse_chunk(c)
            output_text += parsed.delta_content

        assert output_text == "Hello, how can I help you today?"

    @pytest.mark.asyncio
    async def test_done_chunk_preserved(self):
        """[DONE] marker is always forwarded to client."""
        chunks = [
            _make_sse_chunk("Hello"),
            _make_done_chunk(),
        ]
        result_chunks = await _collect_stream(self.engine, chunks)

        last_chunk = result_chunks[-1]
        parsed = parse_sse_chunk(last_chunk)
        assert parsed.is_done

    @pytest.mark.asyncio
    async def test_private_key_in_stream_blocked(self):
        """Private key triggers BLOCK policy — client receives [REDACTED]."""
        pk = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIBogIBAAJBALRiMLAHtest1234567890testdatahere\n"
            "-----END RSA PRIVATE KEY-----"
        )
        chunks = [
            _make_sse_chunk(pk),
            _make_done_chunk(),
        ]
        result_chunks = await _collect_stream(self.engine, chunks)

        output_text = ""
        for c in result_chunks:
            parsed = parse_sse_chunk(c)
            output_text += parsed.delta_content

        assert "BEGIN RSA PRIVATE KEY" not in output_text

    @pytest.mark.asyncio
    async def test_leakage_detection_with_compliance_tags(self):
        """Regulated data leakage is detected when compliance tags are set."""
        ctx = OutputScanContext(
            tenant_id="tenant-1",
            request_id="req-1",
            input_compliance_tags=["PII"],
            model="gpt-4",
        )
        chunks = [
            _make_sse_chunk("Your SSN is 123-45-6789."),
            _make_done_chunk(),
        ]
        # We just verify the stream completes without error and SSN is redacted
        result_chunks = await _collect_stream(self.engine, chunks, context=ctx)

        output_text = ""
        for c in result_chunks:
            parsed = parse_sse_chunk(c)
            output_text += parsed.delta_content

        assert "123-45-6789" not in output_text

    @pytest.mark.asyncio
    async def test_connection_string_in_stream_redacted(self):
        chunks = [
            _make_sse_chunk("Database URL: postgresql://admin:secret@db.host.com:5432/production"),
            _make_done_chunk(),
        ]
        result_chunks = await _collect_stream(self.engine, chunks)

        output_text = ""
        for c in result_chunks:
            parsed = parse_sse_chunk(c)
            output_text += parsed.delta_content

        assert "postgresql://admin:secret" not in output_text
        assert "[REDACTED" in output_text


# ────────────────────────────────────────────────────────────────────────
# 7. Non-Streaming Response Scanner Tests
# ────────────────────────────────────────────────────────────────────────

class TestNonStreamingResponseScanner:
    """Test scanning of non-streaming (complete) responses."""

    def setup_method(self):
        self.engine = OutputScannerEngine()

    def test_ssn_in_response_redacted(self):
        response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Your SSN is 123-45-6789."
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
        }
        body = json.dumps(response).encode()
        redacted_body, result = self.engine.scan_non_streaming_response(body)

        data = json.loads(redacted_body)
        content = data["choices"][0]["message"]["content"]
        assert "123-45-6789" not in content
        assert result.entities_found > 0

    def test_api_key_in_response_redacted(self):
        response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Your key: sk-abc123def456ghi789jkl012mno345pqr678stu901vwx"
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        body = json.dumps(response).encode()
        redacted_body, result = self.engine.scan_non_streaming_response(body)

        data = json.loads(redacted_body)
        content = data["choices"][0]["message"]["content"]
        assert "sk-abc123" not in content
        assert "[REDACTED" in content

    def test_clean_response_unchanged(self):
        response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "The capital of France is Paris."
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        body = json.dumps(response).encode()
        redacted_body, result = self.engine.scan_non_streaming_response(body)

        data = json.loads(redacted_body)
        assert data["choices"][0]["message"]["content"] == "The capital of France is Paris."
        assert result.entities_found == 0

    def test_invalid_json_passthrough(self):
        body = b"not json"
        result_body, result = self.engine.scan_non_streaming_response(body)
        assert result_body == body
        assert result.entities_found == 0

    def test_leakage_detection_in_non_streaming(self):
        ctx = OutputScanContext(
            tenant_id="tenant-1",
            input_compliance_tags=["PII"],
        )
        response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "User SSN: 123-45-6789"
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        body = json.dumps(response).encode()
        redacted_body, result = self.engine.scan_non_streaming_response(body, context=ctx)
        assert result.leakage_result is not None
        assert result.leakage_result.leakage_detected
