"""Instruction-Pattern Scanner for Memory Writes — Sprint 25.

Scans content being written to agent memory for instruction-like patterns:
- Imperative commands ("execute", "run", "ignore previous", "override")
- Policy override language ("disregard", "forget all", "new instructions")
- Future-tense directives ("you will", "you must", "when asked, always")
- Hidden instructions (Base64-encoded commands, Unicode tricks)
- Role-play / persona injection ("you are now", "act as", "pretend to be")

Suspicious writes are flagged for blocking or quarantine depending on the
agent's write policy.
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("sphinx.memory_firewall.instruction_scanner")


# ── Scan Verdict ─────────────────────────────────────────────────────────


@dataclass
class ScanVerdict:
    """Result of scanning content for instruction patterns."""
    is_suspicious: bool = False
    risk_score: float = 0.0
    matched_patterns: list[dict] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "is_suspicious": self.is_suspicious,
            "risk_score": self.risk_score,
            "matched_patterns": self.matched_patterns,
            "summary": self.summary,
        }


# ── Pattern Definitions ─────────────────────────────────────────────────

# Each pattern: (id, description, regex, weight)
INSTRUCTION_PATTERNS: list[tuple[str, str, str, float]] = [
    # ── Imperative commands ──
    (
        "imp_execute",
        "Direct execution command",
        r"\b(execute|run|perform|invoke|call)\s+(this|the|following|these)\b",
        0.7,
    ),
    (
        "imp_ignore_previous",
        "Instruction to ignore prior context",
        r"\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|context|rules?|guidelines?)\b",
        0.9,
    ),
    (
        "imp_override",
        "Policy override language",
        r"\b(override|bypass|skip|disable)\s+(the\s+)?(policy|policies|security|filter|restriction|rule|guard)\b",
        0.9,
    ),
    (
        "imp_do_not_mention",
        "Instruction to suppress information",
        r"\b(do\s+not|don'?t|never)\s+(mention|reveal|disclose|share|tell|show)\b",
        0.6,
    ),
    (
        "imp_always_respond",
        "Unconditional response directive",
        r"\b(always|must)\s+(respond|reply|answer|say|output)\b",
        0.5,
    ),
    # ── Future-tense directives ──
    (
        "fut_you_will",
        "Future-tense directive",
        r"\byou\s+(will|shall|must|should)\s+(always|never|only|from\s+now)\b",
        0.7,
    ),
    (
        "fut_when_asked",
        "Conditional future directive",
        r"\b(when|if|whenever)\s+(asked|prompted|queried|requested)\s*,?\s*(always|you\s+must|you\s+should|you\s+will)\b",
        0.8,
    ),
    (
        "fut_from_now_on",
        "Persistent behavior change",
        r"\b(from\s+now\s+on|henceforth|going\s+forward|from\s+this\s+point)\b",
        0.7,
    ),
    # ── Role-play / persona injection ──
    (
        "role_you_are_now",
        "Persona override",
        r"\byou\s+are\s+(now|no\s+longer|henceforth)\b",
        0.8,
    ),
    (
        "role_act_as",
        "Role-play injection",
        r"\b(act\s+as|pretend\s+to\s+be|behave\s+as|assume\s+the\s+role)\b",
        0.7,
    ),
    (
        "role_new_instructions",
        "New instructions block",
        r"\b(new\s+instructions?|updated?\s+instructions?|revised?\s+instructions?)\s*[:]\b",
        0.9,
    ),
    # ── System prompt leakage / injection ──
    (
        "sys_system_prompt",
        "System prompt reference",
        r"\b(system\s+prompt|system\s+message|hidden\s+instructions?)\b",
        0.6,
    ),
    (
        "sys_jailbreak",
        "Jailbreak attempt language",
        r"\b(jailbreak|DAN|do\s+anything\s+now|developer\s+mode|god\s+mode)\b",
        0.9,
    ),
    # ── Encoded / obfuscated payloads ──
    (
        "enc_base64_block",
        "Base64-encoded block in content",
        r"[A-Za-z0-9+/]{40,}={0,2}",
        0.4,
    ),
    (
        "enc_unicode_escape",
        "Unicode escape sequences",
        r"(\\u[0-9a-fA-F]{4}){3,}",
        0.5,
    ),
    # ── Prompt injection markers ──
    (
        "inj_instruction_delimiter",
        "Instruction delimiter characters",
        r"(---+\s*(BEGIN|START|NEW)\s*(INSTRUCTION|SYSTEM|PROMPT))",
        0.9,
    ),
    (
        "inj_xml_tag_injection",
        "XML-style tag injection",
        r"<\s*(system|instruction|prompt|command|execute)[^>]*>",
        0.8,
    ),
    (
        "inj_markdown_injection",
        "Markdown instruction block",
        r"```\s*(system|instruction|prompt)\b",
        0.7,
    ),
]


# ── Instruction Pattern Scanner ──────────────────────────────────────────


class InstructionPatternScanner:
    """Scans memory write content for instruction-like patterns.

    Uses a weighted pattern matching approach: each matched pattern contributes
    its weight to a cumulative risk score.  Content is flagged as suspicious
    when the score exceeds the configured threshold.
    """

    DEFAULT_THRESHOLD = 0.6

    def __init__(
        self,
        threshold: float = DEFAULT_THRESHOLD,
        extra_patterns: list[tuple[str, str, str, float]] | None = None,
    ):
        self._threshold = threshold
        self._patterns = list(INSTRUCTION_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)
        # Pre-compile regexes
        self._compiled: list[tuple[str, str, re.Pattern, float]] = [
            (pid, desc, re.compile(regex, re.IGNORECASE | re.MULTILINE), weight)
            for pid, desc, regex, weight in self._patterns
        ]

    @property
    def threshold(self) -> float:
        return self._threshold

    @threshold.setter
    def threshold(self, value: float) -> None:
        self._threshold = max(0.0, min(1.0, value))

    @property
    def pattern_count(self) -> int:
        return len(self._compiled)

    def scan(self, content: str) -> ScanVerdict:
        """Scan content for instruction-like patterns.

        Returns a ScanVerdict with risk_score and matched patterns.
        """
        if not content or not content.strip():
            return ScanVerdict(
                is_suspicious=False,
                risk_score=0.0,
                summary="Empty content",
            )

        matched: list[dict] = []
        total_weight = 0.0

        for pattern_id, description, compiled, weight in self._compiled:
            matches = compiled.findall(content)
            if matches:
                matched.append({
                    "pattern_id": pattern_id,
                    "description": description,
                    "weight": weight,
                    "match_count": len(matches),
                })
                total_weight += weight

        # Normalize to 0–1 range (cap at 1.0)
        risk_score = min(1.0, total_weight)

        is_suspicious = risk_score >= self._threshold

        summary_parts = []
        if matched:
            summary_parts.append(
                f"Matched {len(matched)} pattern(s): "
                + ", ".join(m["pattern_id"] for m in matched)
            )
        else:
            summary_parts.append("No instruction patterns detected")

        return ScanVerdict(
            is_suspicious=is_suspicious,
            risk_score=round(risk_score, 4),
            matched_patterns=matched,
            summary="; ".join(summary_parts),
        )

    def scan_with_decoded_check(self, content: str) -> ScanVerdict:
        """Scan content and also check for Base64-encoded instructions.

        First scans the raw content, then attempts to decode any Base64
        blocks and scans the decoded text.
        """
        verdict = self.scan(content)

        # Try to find and decode base64 blocks
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
        b64_matches = b64_pattern.findall(content)

        for b64_str in b64_matches:
            try:
                decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
                if decoded and len(decoded) > 10:
                    decoded_verdict = self.scan(decoded)
                    if decoded_verdict.is_suspicious:
                        # Merge decoded findings
                        for mp in decoded_verdict.matched_patterns:
                            mp["pattern_id"] = f"decoded_{mp['pattern_id']}"
                            mp["description"] = f"[Base64-decoded] {mp['description']}"
                        verdict.matched_patterns.extend(decoded_verdict.matched_patterns)
                        verdict.risk_score = min(1.0, verdict.risk_score + decoded_verdict.risk_score)
                        verdict.is_suspicious = verdict.risk_score >= self._threshold
                        verdict.summary += f"; Base64-decoded content suspicious (score={decoded_verdict.risk_score:.2f})"
            except Exception:
                pass

        return verdict

    def get_patterns(self) -> list[dict]:
        """Return all registered patterns."""
        return [
            {
                "pattern_id": pid,
                "description": desc,
                "weight": weight,
            }
            for pid, desc, _, weight in self._compiled
        ]


# ── Singleton ────────────────────────────────────────────────────────────

_scanner: InstructionPatternScanner | None = None


def get_instruction_scanner() -> InstructionPatternScanner:
    global _scanner
    if _scanner is None:
        _scanner = InstructionPatternScanner()
    return _scanner


def reset_instruction_scanner() -> None:
    global _scanner
    _scanner = None
