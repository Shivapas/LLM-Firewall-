"""Streaming Chunk Interceptor — intercepts SSE stream chunks from LLM providers.

Buffers a minimal context window (sliding window) to detect multi-chunk patterns
such as API keys or PII that may be split across SSE chunks.
"""

import json
import logging
import time
from collections import deque
from dataclasses import dataclass, field

logger = logging.getLogger("sphinx.output_scanner.chunk_interceptor")


@dataclass
class ParsedSSEChunk:
    """Parsed content from a single SSE data line."""
    raw_bytes: bytes
    delta_content: str = ""
    finish_reason: str | None = None
    chunk_id: str = ""
    model: str = ""
    is_done: bool = False
    parse_error: bool = False


@dataclass
class SlidingWindowBuffer:
    """Sliding window buffer that accumulates text across chunks for multi-chunk pattern detection."""
    window_size: int = 5
    _chunks: deque[ParsedSSEChunk] = field(default_factory=deque)
    _text_buffer: str = ""

    def push(self, chunk: ParsedSSEChunk) -> None:
        """Add a chunk to the buffer."""
        self._chunks.append(chunk)
        self._text_buffer += chunk.delta_content
        while len(self._chunks) > self.window_size:
            evicted = self._chunks.popleft()
            self._text_buffer = self._text_buffer[len(evicted.delta_content):]

    @property
    def buffered_text(self) -> str:
        """Return the combined text of all buffered chunks."""
        return self._text_buffer

    @property
    def chunk_count(self) -> int:
        return len(self._chunks)

    def get_chunks(self) -> list[ParsedSSEChunk]:
        return list(self._chunks)

    def clear(self) -> None:
        self._chunks.clear()
        self._text_buffer = ""


def parse_sse_chunk(raw_bytes: bytes) -> ParsedSSEChunk:
    """Parse a raw SSE byte chunk into structured form.

    Handles OpenAI-compatible SSE format: `data: {...}` lines.
    """
    chunk = ParsedSSEChunk(raw_bytes=raw_bytes)

    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        chunk.parse_error = True
        return chunk

    # Handle [DONE] marker
    stripped = text.strip()
    if stripped == "data: [DONE]" or stripped == "[DONE]":
        chunk.is_done = True
        return chunk

    # Extract data lines
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("data: "):
            json_str = line[6:]
            if json_str == "[DONE]":
                chunk.is_done = True
                return chunk
            try:
                data = json.loads(json_str)
                chunk.chunk_id = data.get("id", "")
                chunk.model = data.get("model", "")
                choices = data.get("choices", [])
                if choices:
                    choice = choices[0]
                    delta = choice.get("delta", {})
                    chunk.delta_content = delta.get("content", "")
                    chunk.finish_reason = choice.get("finish_reason")
                    if chunk.finish_reason == "stop":
                        chunk.is_done = True
            except (json.JSONDecodeError, TypeError, KeyError):
                chunk.parse_error = True

    return chunk


def rebuild_sse_chunk(original_chunk: ParsedSSEChunk, new_content: str) -> bytes:
    """Rebuild an SSE chunk with modified content, preserving the original structure."""
    if original_chunk.is_done or original_chunk.parse_error:
        return original_chunk.raw_bytes

    try:
        text = original_chunk.raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        return original_chunk.raw_bytes

    # Find and replace the data JSON line
    lines = text.split("\n")
    rebuilt_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("data: ") and stripped != "data: [DONE]":
            json_str = stripped[6:]
            try:
                data = json.loads(json_str)
                choices = data.get("choices", [])
                if choices:
                    delta = choices[0].get("delta", {})
                    if "content" in delta:
                        delta["content"] = new_content
                rebuilt_lines.append(f"data: {json.dumps(data)}")
            except (json.JSONDecodeError, TypeError):
                rebuilt_lines.append(line)
        else:
            rebuilt_lines.append(line)

    return "\n".join(rebuilt_lines).encode("utf-8")
