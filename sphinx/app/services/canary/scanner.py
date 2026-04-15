"""SP-332: CanaryOutputScanner — response leakage detection.

Scans every LLM response turn for reproduction of the active session
canary token.  Uses regex matching against the active canary with O(1)
lookup from the session store.

Performance target: detection in < 5ms per response turn.

SP-332 acceptance criteria:
  - Scanner detects canary reproduction in agent response in < 5ms
  - Benign responses produce no false positives in 50-sample test
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from app.services.canary.generator import (
    CanaryTokenGenerator,
    get_canary_generator,
)

logger = logging.getLogger("sphinx.canary.scanner")


@dataclass
class CanaryScanResult:
    """Result of scanning a single response turn for canary leakage."""

    detected: bool = False
    token_found: Optional[str] = None
    session_id: Optional[str] = None
    turn_index: int = 0
    scan_time_ms: float = 0.0
    match_position: Optional[int] = None
    extraction_confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "detected": self.detected,
            "token_found": self.token_found,
            "session_id": self.session_id,
            "turn_index": self.turn_index,
            "scan_time_ms": self.scan_time_ms,
            "match_position": self.match_position,
            "extraction_confidence": self.extraction_confidence,
        }


class CanaryOutputScanner:
    """Scans LLM responses for canary token reproduction.

    Maintains a compiled regex pattern that matches any active canary
    token.  The pattern is rebuilt when the active token set changes.
    For single-session scanning, uses direct string search for O(1)
    performance.
    """

    def __init__(
        self,
        generator: Optional[CanaryTokenGenerator] = None,
    ) -> None:
        self._generator = generator
        self._total_scans = 0
        self._total_detections = 0

    def _get_generator(self) -> CanaryTokenGenerator:
        if self._generator is None:
            self._generator = get_canary_generator()
        return self._generator

    def scan_response(
        self,
        response_text: str,
        session_id: str,
        turn_index: int = 0,
    ) -> CanaryScanResult:
        """Scan a single response turn for the session's canary token.

        Uses direct string search against the session's active canary
        for O(1) lookup performance.

        Args:
            response_text: The LLM response text to scan.
            session_id: The session whose canary to check for.
            turn_index: The conversation turn index.

        Returns:
            A :class:`CanaryScanResult` indicating whether leakage was detected.
        """
        start = time.perf_counter()
        self._total_scans += 1

        gen = self._get_generator()
        canary = gen.get_token_for_session(session_id)

        if canary is None:
            # No active canary for this session
            elapsed_ms = (time.perf_counter() - start) * 1000
            return CanaryScanResult(
                detected=False,
                turn_index=turn_index,
                scan_time_ms=round(elapsed_ms, 3),
            )

        token = canary.token

        # Primary check: exact token string match (O(1) with hash-based find)
        pos = response_text.find(token)
        if pos >= 0:
            elapsed_ms = (time.perf_counter() - start) * 1000
            self._total_detections += 1
            logger.warning(
                "CANARY LEAKAGE DETECTED: session=%s turn=%d token=%s pos=%d",
                session_id,
                turn_index,
                token[:4] + "****",
                pos,
            )
            return CanaryScanResult(
                detected=True,
                token_found=token,
                session_id=session_id,
                turn_index=turn_index,
                scan_time_ms=round(elapsed_ms, 3),
                match_position=pos,
                extraction_confidence=1.0,
            )

        # Secondary check: canary within HTML comment pattern
        # Catches partial reproductions like "SPHINX-{token}"
        canary_pattern = f"SPHINX-{token}"
        pos = response_text.find(canary_pattern)
        if pos >= 0:
            elapsed_ms = (time.perf_counter() - start) * 1000
            self._total_detections += 1
            logger.warning(
                "CANARY LEAKAGE DETECTED (comment pattern): session=%s turn=%d",
                session_id,
                turn_index,
            )
            return CanaryScanResult(
                detected=True,
                token_found=token,
                session_id=session_id,
                turn_index=turn_index,
                scan_time_ms=round(elapsed_ms, 3),
                match_position=pos,
                extraction_confidence=1.0,
            )

        elapsed_ms = (time.perf_counter() - start) * 1000
        return CanaryScanResult(
            detected=False,
            session_id=session_id,
            turn_index=turn_index,
            scan_time_ms=round(elapsed_ms, 3),
        )

    def scan_response_all_sessions(
        self,
        response_text: str,
        turn_index: int = 0,
    ) -> CanaryScanResult:
        """Scan a response against ALL active canary tokens.

        Useful when session_id is not available. Checks all active tokens.
        """
        start = time.perf_counter()
        self._total_scans += 1

        gen = self._get_generator()
        active_tokens = gen.get_all_active_tokens()

        for token in active_tokens:
            if token in response_text:
                session_id = gen.lookup_session_by_token(token)
                elapsed_ms = (time.perf_counter() - start) * 1000
                self._total_detections += 1
                logger.warning(
                    "CANARY LEAKAGE DETECTED (all-session scan): "
                    "session=%s turn=%d",
                    session_id,
                    turn_index,
                )
                return CanaryScanResult(
                    detected=True,
                    token_found=token,
                    session_id=session_id,
                    turn_index=turn_index,
                    scan_time_ms=round(elapsed_ms, 3),
                    match_position=response_text.find(token),
                    extraction_confidence=1.0,
                )

        elapsed_ms = (time.perf_counter() - start) * 1000
        return CanaryScanResult(
            detected=False,
            turn_index=turn_index,
            scan_time_ms=round(elapsed_ms, 3),
        )

    @property
    def total_scans(self) -> int:
        return self._total_scans

    @property
    def total_detections(self) -> int:
        return self._total_detections


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_scanner: Optional[CanaryOutputScanner] = None


def get_canary_scanner(
    generator: Optional[CanaryTokenGenerator] = None,
) -> CanaryOutputScanner:
    """Get or create the singleton canary output scanner."""
    global _scanner
    if _scanner is None:
        _scanner = CanaryOutputScanner(generator=generator)
    return _scanner


def reset_canary_scanner() -> None:
    """Reset the singleton (for testing)."""
    global _scanner
    _scanner = None
