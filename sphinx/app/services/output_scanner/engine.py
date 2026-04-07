"""Output Scanner Engine — orchestrates streaming output scanning.

Intercepts SSE stream chunks, applies sliding window buffering, runs PII/PHI
redaction, credential detection, policy evaluation, and leakage detection on
model output before forwarding to the client.
"""

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional

from app.services.data_shield.engine import DataShieldEngine, get_data_shield_engine
from app.services.data_shield.pii_recognizer import PIIEntity, PIIType
from app.services.data_shield.redaction_engine import RedactionEngine
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
    get_output_policy_evaluator,
)
from app.services.output_scanner.leakage_detector import (
    LeakageDetector,
    LeakageDetectionResult,
)

logger = logging.getLogger("sphinx.output_scanner.engine")

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="output-scan")


@dataclass
class OutputScanResult:
    """Aggregated result from scanning a complete stream."""
    total_chunks: int = 0
    scanned_chunks: int = 0
    entities_found: int = 0
    entities_redacted: int = 0
    chunks_blocked: int = 0
    policy_result: OutputPolicyResult | None = None
    leakage_result: LeakageDetectionResult | None = None
    scan_time_ms: float = 0.0
    entity_types: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        result = {
            "total_chunks": self.total_chunks,
            "scanned_chunks": self.scanned_chunks,
            "entities_found": self.entities_found,
            "entities_redacted": self.entities_redacted,
            "chunks_blocked": self.chunks_blocked,
            "scan_time_ms": round(self.scan_time_ms, 2),
            "entity_types": sorted(self.entity_types),
        }
        if self.policy_result:
            result["policy"] = self.policy_result.to_dict()
        if self.leakage_result:
            result["leakage"] = self.leakage_result.to_dict()
        return result


@dataclass
class OutputScanContext:
    """Context for an output scanning session, carrying input-phase metadata."""
    tenant_id: str = ""
    request_id: str = ""
    input_compliance_tags: list[str] = field(default_factory=list)
    model: str = ""


class OutputScannerEngine:
    """Main output scanner engine — scans streaming LLM output for sensitive data."""

    def __init__(
        self,
        window_size: int = 5,
        data_shield: DataShieldEngine | None = None,
        policy_evaluator: OutputPolicyEvaluator | None = None,
    ):
        self._window_size = window_size
        self._data_shield = data_shield or get_data_shield_engine()
        self._policy = policy_evaluator or get_output_policy_evaluator()
        self._redactor = RedactionEngine()
        self._leakage_detector = LeakageDetector()

    def scan_text(self, text: str) -> tuple[str, list[PIIEntity]]:
        """Scan a text string for PII/PHI/credentials and return (redacted_text, entities).

        This is the core scanning function used on buffered text.
        """
        if not text:
            return text, []

        entities = self._data_shield.scan(text)
        if not entities:
            return text, []

        result = self._redactor.redact(text, entities)
        return result.redacted_text, entities

    def scan_chunk_content(self, content: str) -> tuple[str, list[PIIEntity]]:
        """Scan a single chunk's content. For chunks that don't need windowing."""
        return self.scan_text(content)

    def evaluate_policy(
        self,
        entities: list[PIIEntity],
        compliance_tags: list[str] | None = None,
    ) -> OutputPolicyResult:
        """Evaluate output policy against detected entities."""
        entity_types = [
            e.entity_type.value if isinstance(e.entity_type, PIIType) else str(e.entity_type)
            for e in entities
        ]
        return self._policy.evaluate(
            detected_entity_types=entity_types,
            entity_count=len(entities),
            compliance_tags=compliance_tags,
        )

    def detect_leakage(
        self,
        entities: list[PIIEntity],
        input_compliance_tags: list[str],
    ) -> LeakageDetectionResult:
        """Detect regulated data leakage in output."""
        return self._leakage_detector.detect(entities, input_compliance_tags)

    async def scan_stream(
        self,
        upstream_chunks: AsyncIterator[bytes],
        context: OutputScanContext | None = None,
    ) -> AsyncIterator[bytes]:
        """Scan a streaming SSE response, yielding redacted/filtered chunks.

        This is the main entry point for stream scanning. It:
        1. Parses each SSE chunk
        2. Buffers content in a sliding window
        3. Scans buffered text for PII/credentials
        4. Applies policy rules
        5. Detects regulated data leakage
        6. Yields redacted chunks to the client

        Args:
            upstream_chunks: Async iterator of raw SSE bytes from the LLM provider.
            context: Scanning context with input-phase metadata.

        Yields:
            Possibly-redacted SSE byte chunks.
        """
        ctx = context or OutputScanContext()
        buffer = SlidingWindowBuffer(window_size=self._window_size)
        scan_result = OutputScanResult()
        start_time = time.perf_counter()
        all_entities: list[PIIEntity] = []
        loop = asyncio.get_running_loop()

        # Accumulate full output text for final leakage check
        full_output_text = ""

        async for raw_chunk in upstream_chunks:
            scan_result.total_chunks += 1
            parsed = parse_sse_chunk(raw_chunk)

            # Pass through non-content chunks (errors, done markers, etc.)
            if parsed.is_done or parsed.parse_error or not parsed.delta_content:
                yield raw_chunk
                continue

            scan_result.scanned_chunks += 1
            full_output_text += parsed.delta_content

            # Push into sliding window
            buffer.push(parsed)

            # Scan the buffered window text
            buffered_text = buffer.buffered_text
            redacted_text, entities = await loop.run_in_executor(
                _executor, self.scan_text, buffered_text,
            )

            if entities:
                all_entities.extend(entities)
                scan_result.entities_found += len(entities)
                for e in entities:
                    etype = e.entity_type.value if isinstance(e.entity_type, PIIType) else str(e.entity_type)
                    scan_result.entity_types.add(etype)

                # Evaluate policy for this set of entities
                policy_result = self.evaluate_policy(entities, ctx.input_compliance_tags)

                if policy_result.action == OutputAction.BLOCK:
                    # Block: yield a redacted placeholder chunk instead
                    scan_result.chunks_blocked += 1
                    blocked_content = "[REDACTED]"
                    yield rebuild_sse_chunk(parsed, blocked_content)
                    logger.warning(
                        "Output chunk BLOCKED: entities=%d rules=%s tenant=%s",
                        len(entities),
                        [r.rule_id for r in policy_result.matched_rules],
                        ctx.tenant_id,
                    )
                    continue

                if policy_result.action == OutputAction.REDACT:
                    # Redact: extract the portion of redacted text corresponding to this chunk
                    # Since we scanned the full buffer, we need the redacted content for the
                    # current chunk only. Calculate offset into the redacted text.
                    chunk_content = parsed.delta_content
                    redacted_chunk_content, chunk_entities = await loop.run_in_executor(
                        _executor, self.scan_chunk_content, chunk_content,
                    )
                    if chunk_entities:
                        scan_result.entities_redacted += len(chunk_entities)
                        yield rebuild_sse_chunk(parsed, redacted_chunk_content)
                        logger.info(
                            "Output chunk REDACTED: %d entities in chunk tenant=%s",
                            len(chunk_entities), ctx.tenant_id,
                        )
                        continue

            # No entities or policy says stream — pass through
            yield raw_chunk

        # Final leakage detection on full output
        if full_output_text and ctx.input_compliance_tags:
            _, final_entities = await loop.run_in_executor(
                _executor, self.scan_text, full_output_text,
            )
            if final_entities:
                leakage_result = self.detect_leakage(final_entities, ctx.input_compliance_tags)
                scan_result.leakage_result = leakage_result
                if leakage_result.leakage_detected:
                    logger.warning(
                        "Regulated data leakage detected in output: incidents=%d tags=%s tenant=%s request=%s",
                        len(leakage_result.incidents),
                        leakage_result.compliance_tags_violated,
                        ctx.tenant_id,
                        ctx.request_id,
                    )

        scan_result.scan_time_ms = (time.perf_counter() - start_time) * 1000
        logger.info(
            "Output scan complete: chunks=%d scanned=%d entities=%d redacted=%d blocked=%d time=%.1fms tenant=%s",
            scan_result.total_chunks,
            scan_result.scanned_chunks,
            scan_result.entities_found,
            scan_result.entities_redacted,
            scan_result.chunks_blocked,
            scan_result.scan_time_ms,
            ctx.tenant_id,
        )

    def scan_non_streaming_response(
        self,
        response_body: bytes,
        context: OutputScanContext | None = None,
    ) -> tuple[bytes, OutputScanResult]:
        """Scan a non-streaming response body for sensitive data.

        Returns (possibly_redacted_body, scan_result).
        """
        ctx = context or OutputScanContext()
        scan_result = OutputScanResult()
        start_time = time.perf_counter()

        try:
            data = json.loads(response_body)
        except (json.JSONDecodeError, TypeError):
            return response_body, scan_result

        # Extract text from response choices
        text_parts: list[str] = []
        choices = data.get("choices", [])
        for choice in choices:
            msg = choice.get("message", {})
            content = msg.get("content", "")
            if content:
                text_parts.append(content)

        if not text_parts:
            return response_body, scan_result

        full_text = "\n".join(text_parts)
        redacted_text, entities = self.scan_text(full_text)

        if entities:
            scan_result.entities_found = len(entities)
            for e in entities:
                etype = e.entity_type.value if isinstance(e.entity_type, PIIType) else str(e.entity_type)
                scan_result.entity_types.add(etype)

            # Evaluate policy
            policy_result = self.evaluate_policy(entities, ctx.input_compliance_tags)
            scan_result.policy_result = policy_result

            if policy_result.action in (OutputAction.BLOCK, OutputAction.REDACT):
                scan_result.entities_redacted = len(entities)
                # Apply redaction to response body
                for choice in data.get("choices", []):
                    msg = choice.get("message", {})
                    content = msg.get("content", "")
                    if content:
                        redacted_content, _ = self.scan_text(content)
                        msg["content"] = redacted_content

                response_body = json.dumps(data).encode()

            # Leakage detection
            if ctx.input_compliance_tags:
                leakage_result = self.detect_leakage(entities, ctx.input_compliance_tags)
                scan_result.leakage_result = leakage_result

        scan_result.scan_time_ms = (time.perf_counter() - start_time) * 1000
        return response_body, scan_result


# Singleton
_engine: Optional[OutputScannerEngine] = None


def get_output_scanner_engine() -> OutputScannerEngine:
    global _engine
    if _engine is None:
        _engine = OutputScannerEngine()
    return _engine


def reset_output_scanner_engine() -> None:
    global _engine
    _engine = None
