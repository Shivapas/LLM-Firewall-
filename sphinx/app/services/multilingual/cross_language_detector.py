"""Cross-language attack detection — Sprint 22.

Detects attacks that mix languages within a single prompt, e.g., an English
system prompt combined with a Mandarin injection suffix. These mixed-language
attacks attempt to evade detection by splitting malicious content across
language boundaries.
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("sphinx.multilingual.cross_language")


@dataclass
class CrossLanguageSegment:
    """A detected language segment within a mixed-language prompt."""
    text: str
    language: str
    script: str
    start_pos: int
    end_pos: int

    def to_dict(self) -> dict:
        return {
            "text": self.text[:100],  # Truncate for display
            "language": self.language,
            "script": self.script,
            "start_pos": self.start_pos,
            "end_pos": self.end_pos,
        }


@dataclass
class CrossLanguageAttackResult:
    """Result of cross-language attack detection."""
    is_attack: bool
    risk_level: str
    score: float
    languages_detected: list[str]
    segments: list[CrossLanguageSegment] = field(default_factory=list)
    attack_indicators: list[str] = field(default_factory=list)
    scan_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "is_attack": self.is_attack,
            "risk_level": self.risk_level,
            "score": round(self.score, 4),
            "languages_detected": self.languages_detected,
            "segments": [s.to_dict() for s in self.segments],
            "attack_indicators": self.attack_indicators,
            "scan_time_ms": round(self.scan_time_ms, 2),
        }


# Script ranges for segmentation
_SCRIPT_RANGES = {
    "latin": [(0x0041, 0x024F), (0x1E00, 0x1EFF)],
    "chinese": [(0x4E00, 0x9FFF), (0x3400, 0x4DBF)],
    "cyrillic": [(0x0400, 0x04FF), (0x0500, 0x052F)],
    "arabic": [(0x0600, 0x06FF), (0x0750, 0x077F), (0xFB50, 0xFDFF)],
    "devanagari": [(0x0900, 0x097F)],
    "hangul": [(0xAC00, 0xD7AF), (0x1100, 0x11FF), (0x3130, 0x318F)],
    "hiragana": [(0x3040, 0x309F)],
    "katakana": [(0x30A0, 0x30FF)],
    "thai": [(0x0E00, 0x0E7F)],
    "hebrew": [(0x0590, 0x05FF)],
    "bengali": [(0x0980, 0x09FF)],
    "tamil": [(0x0B80, 0x0BFF)],
    "telugu": [(0x0C00, 0x0C7F)],
    "gujarati": [(0x0A80, 0x0AFF)],
}

_SCRIPT_TO_LANG = {
    "chinese": "zh", "cyrillic": "ru", "arabic": "ar", "devanagari": "hi",
    "hangul": "ko", "hiragana": "ja", "katakana": "ja", "thai": "th",
    "hebrew": "he", "bengali": "bn", "tamil": "ta", "telugu": "te",
    "gujarati": "gu",
}

# Keywords that signal injection intent (language-agnostic structural markers)
_INJECTION_MARKERS_EN = [
    r"(?i)ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|above|prior)\s+(?:instructions?|rules?|context)",
    r"(?i)(?:new|actual|real)\s+instructions?\s*(?::|are|follow)",
    r"(?i)system\s*(?:prompt|message|instruction)\s*(?:override|reset|change)",
    r"(?i)you\s+(?:are|must)\s+now\s+(?:a|an|my)",
    r"(?i)(?:forget|disregard)\s+(?:everything|all|your)",
]


def _classify_char_script(ch: str) -> str:
    """Classify a single character's script."""
    cp = ord(ch)
    for script, ranges in _SCRIPT_RANGES.items():
        for start, end in ranges:
            if start <= cp <= end:
                return script
    return "other"


class CrossLanguageDetector:
    """Detects cross-language attacks that mix languages in a single prompt.

    Identifies prompts that combine an English system context with injection
    payloads in another language (or vice versa). These attacks exploit the
    assumption that detection rules only cover a single language.
    """

    def __init__(self, min_segment_chars: int = 5, language_switch_threshold: int = 2):
        self._min_segment_chars = min_segment_chars
        self._language_switch_threshold = language_switch_threshold
        self._injection_patterns = [re.compile(p) for p in _INJECTION_MARKERS_EN]

    def detect(self, text: str) -> CrossLanguageAttackResult:
        """Analyze a prompt for cross-language attack patterns.

        Args:
            text: The input prompt text.

        Returns:
            CrossLanguageAttackResult with attack indicators.
        """
        start = time.perf_counter()

        # Step 1: Segment the text by script/language
        segments = self._segment_by_script(text)

        # Step 2: Determine unique languages
        languages = list(dict.fromkeys(s.language for s in segments if s.language != "other"))

        # Step 3: Check for cross-language attack indicators
        indicators = []
        score = 0.0

        if len(languages) >= self._language_switch_threshold:
            indicators.append(f"Multiple languages detected: {', '.join(languages)}")
            score += 0.3

            # Check if any English segment contains injection keywords
            for seg in segments:
                if seg.language == "en" or seg.script == "latin":
                    for pat in self._injection_patterns:
                        if pat.search(seg.text):
                            indicators.append(f"Injection marker in {seg.language} segment: {pat.pattern[:60]}")
                            score += 0.3
                            break

            # Check for non-Latin injection patterns in non-English segments
            from app.services.multilingual.language_packs import get_language_pack_scanner
            scanner = get_language_pack_scanner()
            for seg in segments:
                if seg.language != "en" and seg.script != "latin":
                    matches = scanner.scan(seg.text, language_hint=seg.language)
                    if matches:
                        indicators.append(
                            f"Threat pattern in {seg.language} segment: {matches[0].pattern_name}"
                        )
                        score += 0.4

            # Rapid language switching is suspicious
            switch_count = self._count_language_switches(segments)
            if switch_count >= 3:
                indicators.append(f"Rapid language switching detected ({switch_count} switches)")
                score += 0.2

        score = min(1.0, score)
        is_attack = score >= 0.5
        risk_level = self._score_to_risk(score)
        scan_time_ms = (time.perf_counter() - start) * 1000

        return CrossLanguageAttackResult(
            is_attack=is_attack,
            risk_level=risk_level,
            score=score,
            languages_detected=languages,
            segments=segments,
            attack_indicators=indicators,
            scan_time_ms=scan_time_ms,
        )

    def _segment_by_script(self, text: str) -> list[CrossLanguageSegment]:
        """Split text into contiguous segments of the same script."""
        if not text:
            return []

        segments: list[CrossLanguageSegment] = []
        current_script = None
        current_start = 0
        current_chars = []

        for i, ch in enumerate(text):
            if ch.isspace() or ch in '.,;:!?()[]{}"\'-/\\@#$%^&*+=<>~`|':
                current_chars.append(ch)
                continue

            script = _classify_char_script(ch)
            if script == "other":
                current_chars.append(ch)
                continue

            if current_script is None:
                current_script = script
                current_start = i
                current_chars = [ch]
            elif script != current_script:
                # Flush current segment
                seg_text = "".join(current_chars).strip()
                if len(seg_text) >= self._min_segment_chars:
                    lang = _SCRIPT_TO_LANG.get(current_script, "en") if current_script != "latin" else "en"
                    segments.append(CrossLanguageSegment(
                        text=seg_text, language=lang, script=current_script,
                        start_pos=current_start, end_pos=i,
                    ))
                current_script = script
                current_start = i
                current_chars = [ch]
            else:
                current_chars.append(ch)

        # Flush last segment
        if current_script and current_chars:
            seg_text = "".join(current_chars).strip()
            if len(seg_text) >= self._min_segment_chars:
                lang = _SCRIPT_TO_LANG.get(current_script, "en") if current_script != "latin" else "en"
                segments.append(CrossLanguageSegment(
                    text=seg_text, language=lang, script=current_script,
                    start_pos=current_start, end_pos=len(text),
                ))

        return segments

    def _count_language_switches(self, segments: list[CrossLanguageSegment]) -> int:
        """Count the number of times the language changes between segments."""
        if len(segments) < 2:
            return 0
        switches = 0
        for i in range(1, len(segments)):
            if segments[i].language != segments[i - 1].language:
                switches += 1
        return switches

    def _score_to_risk(self, score: float) -> str:
        if score >= 0.8:
            return "critical"
        elif score >= 0.5:
            return "high"
        elif score >= 0.25:
            return "medium"
        return "low"

    def get_stats(self) -> dict:
        return {
            "min_segment_chars": self._min_segment_chars,
            "language_switch_threshold": self._language_switch_threshold,
            "injection_patterns": len(self._injection_patterns),
        }


# Singleton
_detector: Optional[CrossLanguageDetector] = None


def get_cross_language_detector() -> CrossLanguageDetector:
    """Get or create the singleton cross-language detector."""
    global _detector
    if _detector is None:
        _detector = CrossLanguageDetector()
    return _detector


def reset_cross_language_detector() -> None:
    """Reset the singleton detector (for testing)."""
    global _detector
    _detector = None
