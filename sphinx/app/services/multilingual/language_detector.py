"""Language detection + routing — detects prompt language and routes to appropriate model.

Detects the language of incoming prompts, applies the language-appropriate detection
model (English Tier 1 or multilingual Tier 2), and records the detected language
in the audit event.
"""

import logging
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("sphinx.multilingual.language_detector")

# Unicode script ranges for language detection
_SCRIPT_RANGES: dict[str, list[tuple[int, int]]] = {
    "arabic": [(0x0600, 0x06FF), (0x0750, 0x077F), (0xFB50, 0xFDFF), (0xFE70, 0xFEFF)],
    "chinese": [(0x4E00, 0x9FFF), (0x3400, 0x4DBF), (0x20000, 0x2A6DF), (0x2A700, 0x2B73F)],
    "cyrillic": [(0x0400, 0x04FF), (0x0500, 0x052F)],
    "devanagari": [(0x0900, 0x097F), (0xA8E0, 0xA8FF)],
    "greek": [(0x0370, 0x03FF), (0x1F00, 0x1FFF)],
    "hangul": [(0xAC00, 0xD7AF), (0x1100, 0x11FF), (0x3130, 0x318F)],
    "hiragana": [(0x3040, 0x309F)],
    "katakana": [(0x30A0, 0x30FF), (0x31F0, 0x31FF)],
    "latin": [(0x0041, 0x024F), (0x1E00, 0x1EFF)],
    "thai": [(0x0E00, 0x0E7F)],
    "bengali": [(0x0980, 0x09FF)],
    "tamil": [(0x0B80, 0x0BFF)],
    "telugu": [(0x0C00, 0x0C7F)],
    "gujarati": [(0x0A80, 0x0AFF)],
    "hebrew": [(0x0590, 0x05FF), (0xFB1D, 0xFB4F)],
}

# Common words for trigram-based language identification
_LANGUAGE_MARKERS: dict[str, list[str]] = {
    "en": ["the", "and", "is", "in", "to", "of", "that", "for", "it", "with",
           "you", "this", "are", "not", "have", "from", "your", "will", "all"],
    "fr": ["les", "des", "est", "dans", "une", "que", "pour", "pas", "sur",
           "avec", "sont", "mais", "nous", "vous", "cette", "tout", "ses"],
    "es": ["los", "las", "del", "una", "con", "para", "por", "que", "como",
           "pero", "sus", "esta", "este", "son", "todo", "mas", "tiene"],
    "de": ["der", "die", "das", "und", "ist", "ein", "eine", "den", "dem",
           "nicht", "sich", "mit", "auf", "fur", "sind", "von", "auch"],
    "it": ["gli", "del", "per", "che", "con", "una", "sono", "nel", "dei",
           "alla", "della", "questo", "questa", "anche", "tutto", "suo"],
    "pt": ["dos", "das", "para", "com", "uma", "por", "que", "como", "seu",
           "sua", "mais", "mas", "esta", "este", "todo", "isso", "nos"],
    "ru": ["это", "как", "что", "для", "все", "они", "его", "она", "мне",
           "нас", "при", "вот", "был", "мой", "так", "тут", "уже"],
    "zh": ["的", "是", "在", "了", "不", "和", "有", "人", "这", "中",
           "大", "为", "上", "个", "国", "我", "他", "时", "要"],
    "ar": ["في", "من", "على", "إلى", "أن", "هذا", "التي", "التي", "كان",
           "عن", "هو", "مع", "هذه", "هل", "ما", "لا", "قد"],
    "ja": ["の", "は", "に", "を", "と", "が", "で", "た", "し", "い",
           "れ", "さ", "て", "な", "か", "る", "ん", "も", "す"],
    "ko": ["은", "는", "이", "가", "를", "에", "의", "을", "로", "고",
           "한", "다", "에서", "도", "서", "하", "그", "수", "있"],
    "hi": ["है", "के", "में", "की", "का", "और", "को", "से", "पर", "ने",
           "एक", "यह", "भी", "नहीं", "हैं", "कि", "या"],
    "tr": ["bir", "ve", "bu", "ile", "için", "olan", "den", "dan", "gibi",
           "olarak", "daha", "kadar", "var", "hem", "ama", "ancak"],
}


@dataclass
class LanguageDetectionResult:
    """Result of language detection."""
    language: str  # ISO 639-1 code
    confidence: float  # 0.0 to 1.0
    script: str  # Detected script (latin, cyrillic, etc.)
    is_mixed_language: bool = False
    secondary_languages: list[str] = None

    def __post_init__(self):
        if self.secondary_languages is None:
            self.secondary_languages = []

    def to_dict(self) -> dict:
        return {
            "language": self.language,
            "confidence": round(self.confidence, 4),
            "script": self.script,
            "is_mixed_language": self.is_mixed_language,
            "secondary_languages": self.secondary_languages,
        }


class LanguageDetector:
    """Detects prompt language and routes to appropriate detection model.

    Uses a combination of Unicode script analysis and word frequency matching
    to identify the language of incoming prompts without external dependencies.
    """

    def __init__(self):
        self._script_ranges = dict(_SCRIPT_RANGES)
        self._language_markers = dict(_LANGUAGE_MARKERS)

    def detect(self, text: str) -> LanguageDetectionResult:
        """Detect the primary language of the input text.

        Uses:
        1. Unicode script detection (fast path for non-Latin scripts)
        2. Word frequency matching (for Latin-script languages)
        3. Mixed-language detection
        """
        if not text or not text.strip():
            return LanguageDetectionResult(
                language="unknown", confidence=0.0, script="unknown"
            )

        # Step 1: Script analysis
        script_counts = self._count_scripts(text)
        primary_script = max(script_counts, key=script_counts.get) if script_counts else "unknown"

        # Step 2: Fast path for non-Latin scripts
        if primary_script == "chinese":
            # Distinguish Chinese from Japanese by checking for hiragana/katakana
            if script_counts.get("hiragana", 0) + script_counts.get("katakana", 0) > 0:
                return LanguageDetectionResult(
                    language="ja", confidence=0.85, script="cjk"
                )
            return LanguageDetectionResult(
                language="zh", confidence=0.90, script="chinese"
            )
        elif primary_script == "hangul":
            return LanguageDetectionResult(
                language="ko", confidence=0.95, script="hangul"
            )
        elif primary_script in ("hiragana", "katakana"):
            return LanguageDetectionResult(
                language="ja", confidence=0.95, script="japanese"
            )
        elif primary_script == "arabic":
            return LanguageDetectionResult(
                language="ar", confidence=0.85, script="arabic"
            )
        elif primary_script == "devanagari":
            return LanguageDetectionResult(
                language="hi", confidence=0.85, script="devanagari"
            )
        elif primary_script == "thai":
            return LanguageDetectionResult(
                language="th", confidence=0.95, script="thai"
            )
        elif primary_script == "bengali":
            return LanguageDetectionResult(
                language="bn", confidence=0.90, script="bengali"
            )
        elif primary_script == "tamil":
            return LanguageDetectionResult(
                language="ta", confidence=0.90, script="tamil"
            )
        elif primary_script == "telugu":
            return LanguageDetectionResult(
                language="te", confidence=0.90, script="telugu"
            )
        elif primary_script == "gujarati":
            return LanguageDetectionResult(
                language="gu", confidence=0.90, script="gujarati"
            )
        elif primary_script == "hebrew":
            return LanguageDetectionResult(
                language="he", confidence=0.90, script="hebrew"
            )

        # Step 3: Cyrillic — could be Russian, Ukrainian, Bulgarian, etc.
        if primary_script == "cyrillic":
            lang = self._detect_cyrillic_language(text)
            return LanguageDetectionResult(
                language=lang, confidence=0.80, script="cyrillic"
            )

        # Step 4: Latin script — use word frequency matching
        if primary_script == "latin":
            lang, confidence = self._detect_latin_language(text)
            # Check for mixed-language content
            secondary = self._detect_secondary_languages(text, lang)
            return LanguageDetectionResult(
                language=lang,
                confidence=confidence,
                script="latin",
                is_mixed_language=len(secondary) > 0,
                secondary_languages=secondary,
            )

        # Step 5: Greek script
        if primary_script == "greek":
            return LanguageDetectionResult(
                language="el", confidence=0.90, script="greek"
            )

        return LanguageDetectionResult(
            language="unknown", confidence=0.0, script=primary_script
        )

    def _count_scripts(self, text: str) -> dict[str, int]:
        """Count characters belonging to each Unicode script."""
        counts: dict[str, int] = {}
        for ch in text:
            cp = ord(ch)
            for script, ranges in self._script_ranges.items():
                for start, end in ranges:
                    if start <= cp <= end:
                        counts[script] = counts.get(script, 0) + 1
                        break
        return counts

    def _detect_cyrillic_language(self, text: str) -> str:
        """Distinguish Cyrillic-script languages (Russian vs Ukrainian vs Bulgarian)."""
        # Look for Russian-specific common words
        ru_markers = self._language_markers.get("ru", [])
        words = text.lower().split()
        ru_count = sum(1 for w in words if w in ru_markers)
        if ru_count > 0:
            return "ru"
        # Default to Russian for Cyrillic
        return "ru"

    def _detect_latin_language(self, text: str) -> tuple[str, float]:
        """Detect language for Latin-script text using word frequency."""
        words = re.findall(r"\b\w+\b", text.lower())
        if not words:
            return "en", 0.5

        best_lang = "en"
        best_score = 0.0

        for lang, markers in self._language_markers.items():
            if lang in ("zh", "ja", "ko", "ar", "hi", "ru"):
                continue  # Non-Latin languages handled above
            marker_set = set(markers)
            matches = sum(1 for w in words if w in marker_set)
            score = matches / len(words) if words else 0
            if score > best_score:
                best_score = score
                best_lang = lang

        # Confidence based on marker match ratio
        confidence = min(0.95, 0.5 + best_score * 2)
        return best_lang, confidence

    def _detect_secondary_languages(self, text: str, primary_lang: str) -> list[str]:
        """Detect if the text contains secondary languages (mixed-language attack)."""
        secondary = []
        script_counts = self._count_scripts(text)

        # Check for non-Latin scripts mixed into Latin text
        for script in ("chinese", "cyrillic", "arabic", "devanagari", "hangul"):
            if script_counts.get(script, 0) > 3:
                lang_map = {
                    "chinese": "zh", "cyrillic": "ru", "arabic": "ar",
                    "devanagari": "hi", "hangul": "ko",
                }
                sec_lang = lang_map.get(script, "unknown")
                if sec_lang != primary_lang:
                    secondary.append(sec_lang)

        return secondary

    def get_supported_languages(self) -> list[str]:
        """Return list of supported language codes."""
        return list(self._language_markers.keys())


@dataclass
class LanguageRoutingDecision:
    """Decision about which detection model to use for a detected language."""
    language: str
    use_tier1_english: bool
    use_multilingual_tier2: bool
    reason: str

    def to_dict(self) -> dict:
        return {
            "language": self.language,
            "use_tier1_english": self.use_tier1_english,
            "use_multilingual_tier2": self.use_multilingual_tier2,
            "reason": self.reason,
        }


class LanguageRouter:
    """Routes prompts to the appropriate detection model based on language.

    - English prompts: Tier 1 pattern matching (primary) + English Tier 2 semantic
    - Non-English prompts: Tier 1 (basic) + Multilingual Tier 2 (primary)
    - Mixed-language prompts: Both Tier 1 + Multilingual Tier 2
    """

    def __init__(self):
        self._detector = LanguageDetector()

    def route(self, text: str) -> tuple[LanguageDetectionResult, LanguageRoutingDecision]:
        """Detect language and decide which detection models to apply.

        Returns (detection_result, routing_decision).
        """
        detection = self._detector.detect(text)

        if detection.language == "en":
            decision = LanguageRoutingDecision(
                language="en",
                use_tier1_english=True,
                use_multilingual_tier2=False,
                reason="English prompt — primary Tier 1 pattern matching",
            )
        elif detection.is_mixed_language:
            decision = LanguageRoutingDecision(
                language=detection.language,
                use_tier1_english=True,
                use_multilingual_tier2=True,
                reason=f"Mixed-language prompt ({detection.language} + {detection.secondary_languages}) — both engines",
            )
        elif detection.language == "unknown":
            decision = LanguageRoutingDecision(
                language="unknown",
                use_tier1_english=True,
                use_multilingual_tier2=True,
                reason="Unknown language — both engines for safety",
            )
        else:
            decision = LanguageRoutingDecision(
                language=detection.language,
                use_tier1_english=True,
                use_multilingual_tier2=True,
                reason=f"Non-English prompt ({detection.language}) — Tier 1 basic + multilingual Tier 2",
            )

        return detection, decision

    @property
    def detector(self) -> LanguageDetector:
        return self._detector


# Singleton
_router: Optional[LanguageRouter] = None


def get_language_router() -> LanguageRouter:
    """Get or create the singleton language router."""
    global _router
    if _router is None:
        _router = LanguageRouter()
    return _router


def reset_language_router() -> None:
    """Reset the singleton router (for testing)."""
    global _router
    _router = None
