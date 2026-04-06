"""Unicode normalization pre-processor — defeats encoding-based evasion.

Normalizes Unicode variants, homoglyphs, and character substitutions in prompts
before pattern matching. Handles:
- Unicode NFC/NFKC normalization
- Homoglyph substitution (Cyrillic, Greek, etc. lookalikes -> ASCII)
- Zero-width character removal
- Combining character normalization
- Full-width to half-width conversion
- Invisible Unicode characters stripping
"""

import logging
import re
import unicodedata
from typing import Optional

logger = logging.getLogger("sphinx.multilingual.unicode_normalizer")

# Homoglyph map: visually similar Unicode characters -> ASCII equivalents
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic lookalikes
    "\u0410": "A", "\u0430": "a",  # А, а
    "\u0412": "B", "\u0432": "v",  # В, в (note: lowercase Cyrillic в != b)
    "\u0421": "C", "\u0441": "c",  # С, с
    "\u0415": "E", "\u0435": "e",  # Е, е
    "\u041D": "H", "\u043D": "h",  # Н, н
    "\u041A": "K", "\u043A": "k",  # К, к
    "\u041C": "M", "\u043C": "m",  # М, м
    "\u041E": "O", "\u043E": "o",  # О, о
    "\u0420": "P", "\u0440": "p",  # Р, р
    "\u0422": "T", "\u0442": "t",  # Т, т
    "\u0425": "X", "\u0445": "x",  # Х, х
    "\u0423": "Y", "\u0443": "y",  # У, у
    "\u0405": "S", "\u0455": "s",  # Ѕ, ѕ (Macedonian)
    "\u0406": "I", "\u0456": "i",  # І, і (Ukrainian)
    "\u0408": "J", "\u0458": "j",  # Ј, ј (Serbian)
    # Greek lookalikes
    "\u0391": "A", "\u03B1": "a",  # Α, α
    "\u0392": "B", "\u03B2": "b",  # Β, β
    "\u0395": "E", "\u03B5": "e",  # Ε, ε
    "\u0397": "H", "\u03B7": "h",  # Η, η
    "\u0399": "I", "\u03B9": "i",  # Ι, ι
    "\u039A": "K", "\u03BA": "k",  # Κ, κ
    "\u039C": "M", "\u03BC": "m",  # Μ, μ
    "\u039D": "N", "\u03BD": "n",  # Ν, ν
    "\u039F": "O", "\u03BF": "o",  # Ο, ο
    "\u03A1": "P", "\u03C1": "p",  # Ρ, ρ
    "\u03A4": "T", "\u03C4": "t",  # Τ, τ
    "\u03A5": "Y", "\u03C5": "y",  # Υ, υ
    "\u0396": "Z", "\u03B6": "z",  # Ζ, ζ
    # Mathematical/special
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-",  # dashes
    "\u2018": "'", "\u2019": "'", "\u201A": "'",  # quotes
    "\u201C": '"', "\u201D": '"', "\u201E": '"',  # double quotes
    "\u2024": ".", "\u2025": "..", "\u2026": "...",  # dots
    "\u00A0": " ",  # non-breaking space
    "\u2000": " ", "\u2001": " ", "\u2002": " ", "\u2003": " ",  # en/em spaces
    "\u2004": " ", "\u2005": " ", "\u2006": " ", "\u2007": " ",
    "\u2008": " ", "\u2009": " ", "\u200A": " ",  # thin spaces
    "\u202F": " ", "\u205F": " ", "\u3000": " ",  # various spaces
    # Full-width ASCII
    "\uFF01": "!", "\uFF02": '"', "\uFF03": "#", "\uFF04": "$",
    "\uFF05": "%", "\uFF06": "&", "\uFF07": "'", "\uFF08": "(",
    "\uFF09": ")", "\uFF0A": "*", "\uFF0B": "+", "\uFF0C": ",",
    "\uFF0D": "-", "\uFF0E": ".", "\uFF0F": "/",
    "\uFF10": "0", "\uFF11": "1", "\uFF12": "2", "\uFF13": "3",
    "\uFF14": "4", "\uFF15": "5", "\uFF16": "6", "\uFF17": "7",
    "\uFF18": "8", "\uFF19": "9",
    "\uFF1A": ":", "\uFF1B": ";", "\uFF1C": "<", "\uFF1D": "=",
    "\uFF1E": ">", "\uFF1F": "?", "\uFF20": "@",
    "\uFF21": "A", "\uFF22": "B", "\uFF23": "C", "\uFF24": "D",
    "\uFF25": "E", "\uFF26": "F", "\uFF27": "G", "\uFF28": "H",
    "\uFF29": "I", "\uFF2A": "J", "\uFF2B": "K", "\uFF2C": "L",
    "\uFF2D": "M", "\uFF2E": "N", "\uFF2F": "O", "\uFF30": "P",
    "\uFF31": "Q", "\uFF32": "R", "\uFF33": "S", "\uFF34": "T",
    "\uFF35": "U", "\uFF36": "V", "\uFF37": "W", "\uFF38": "X",
    "\uFF39": "Y", "\uFF3A": "Z",
    "\uFF41": "a", "\uFF42": "b", "\uFF43": "c", "\uFF44": "d",
    "\uFF45": "e", "\uFF46": "f", "\uFF47": "g", "\uFF48": "h",
    "\uFF49": "i", "\uFF4A": "j", "\uFF4B": "k", "\uFF4C": "l",
    "\uFF4D": "m", "\uFF4E": "n", "\uFF4F": "o", "\uFF50": "p",
    "\uFF51": "q", "\uFF52": "r", "\uFF53": "s", "\uFF54": "t",
    "\uFF55": "u", "\uFF56": "v", "\uFF57": "w", "\uFF58": "x",
    "\uFF59": "y", "\uFF5A": "z",
}

# Zero-width and invisible characters to strip
_INVISIBLE_CHARS = re.compile(
    "["
    "\u200B"  # zero-width space
    "\u200C"  # zero-width non-joiner
    "\u200D"  # zero-width joiner
    "\u200E"  # left-to-right mark
    "\u200F"  # right-to-left mark
    "\u2060"  # word joiner
    "\u2061"  # function application
    "\u2062"  # invisible times
    "\u2063"  # invisible separator
    "\u2064"  # invisible plus
    "\uFEFF"  # byte order mark / zero-width no-break space
    "\u00AD"  # soft hyphen
    "\u034F"  # combining grapheme joiner
    "\u061C"  # Arabic letter mark
    "\u180E"  # Mongolian vowel separator
    "\uFE00-\uFE0F"  # variation selectors
    "\U000E0001-\U000E007F"  # tags block
    "]+"
)

# Combining diacritical marks range
_COMBINING_MARKS = re.compile(r"[\u0300-\u036f\u0489\u20d0-\u20ff]+")


class UnicodeNormalizer:
    """Pre-processes prompts to normalize Unicode evasion techniques.

    Applied before pattern matching to ensure homoglyphs, zero-width chars,
    and other encoding tricks don't bypass threat detection.
    """

    def __init__(self, strip_combining: bool = True, apply_homoglyphs: bool = True):
        self._strip_combining = strip_combining
        self._apply_homoglyphs = apply_homoglyphs
        self._homoglyph_map = dict(_HOMOGLYPH_MAP)

    def normalize(self, text: str) -> str:
        """Apply full normalization pipeline to input text.

        Steps:
        1. Unicode NFKC normalization (canonical + compatibility decomposition)
        2. Remove zero-width and invisible characters
        3. Replace homoglyphs with ASCII equivalents
        4. Optionally strip combining diacritical marks
        5. Collapse whitespace
        """
        if not text:
            return text

        # Step 1: NFKC normalization (handles full-width -> half-width, etc.)
        result = unicodedata.normalize("NFKC", text)

        # Step 2: Remove invisible characters
        result = _INVISIBLE_CHARS.sub("", result)

        # Step 3: Replace homoglyphs
        if self._apply_homoglyphs:
            result = self._replace_homoglyphs(result)

        # Step 4: Strip combining marks (optional — after NFD decomposition)
        if self._strip_combining:
            decomposed = unicodedata.normalize("NFD", result)
            stripped = _COMBINING_MARKS.sub("", decomposed)
            result = unicodedata.normalize("NFC", stripped)

        # Step 5: Collapse multiple spaces into one
        result = re.sub(r" {2,}", " ", result)

        return result

    def _replace_homoglyphs(self, text: str) -> str:
        """Replace known homoglyph characters with ASCII equivalents."""
        chars = []
        for ch in text:
            replacement = self._homoglyph_map.get(ch)
            if replacement is not None:
                chars.append(replacement)
            else:
                chars.append(ch)
        return "".join(chars)

    def add_homoglyph(self, unicode_char: str, ascii_equiv: str) -> None:
        """Add a custom homoglyph mapping."""
        self._homoglyph_map[unicode_char] = ascii_equiv

    def get_stats(self) -> dict:
        """Return normalizer statistics."""
        return {
            "homoglyph_mappings": len(self._homoglyph_map),
            "strip_combining": self._strip_combining,
            "apply_homoglyphs": self._apply_homoglyphs,
        }

    def detect_obfuscation(self, text: str) -> dict:
        """Detect obfuscation techniques in text without normalizing.

        Returns a report of detected evasion techniques.
        """
        findings: list[dict] = []

        # Check for zero-width characters
        zw_matches = _INVISIBLE_CHARS.findall(text)
        if zw_matches:
            findings.append({
                "technique": "zero_width_characters",
                "count": len(zw_matches),
                "description": "Zero-width or invisible Unicode characters detected",
            })

        # Check for homoglyphs
        homoglyph_count = sum(1 for ch in text if ch in self._homoglyph_map)
        if homoglyph_count > 0:
            findings.append({
                "technique": "homoglyph_substitution",
                "count": homoglyph_count,
                "description": "Visually similar non-ASCII characters detected",
            })

        # Check for combining marks
        combining_matches = _COMBINING_MARKS.findall(text)
        if combining_matches:
            findings.append({
                "technique": "combining_marks",
                "count": len(combining_matches),
                "description": "Combining diacritical marks detected",
            })

        # Check for mixed scripts
        scripts = set()
        for ch in text:
            if ch.isalpha():
                try:
                    script = unicodedata.name(ch, "").split()[0]
                    scripts.add(script)
                except ValueError:
                    pass
        if len(scripts) > 2:
            findings.append({
                "technique": "mixed_scripts",
                "count": len(scripts),
                "description": f"Multiple Unicode scripts detected: {', '.join(sorted(scripts))}",
            })

        normalized = self.normalize(text)
        return {
            "original_length": len(text),
            "normalized_length": len(normalized),
            "obfuscation_detected": len(findings) > 0,
            "findings": findings,
            "normalized_text": normalized,
        }


# Singleton
_normalizer: Optional[UnicodeNormalizer] = None


def get_unicode_normalizer() -> UnicodeNormalizer:
    """Get or create the singleton Unicode normalizer."""
    global _normalizer
    if _normalizer is None:
        _normalizer = UnicodeNormalizer()
    return _normalizer


def reset_unicode_normalizer() -> None:
    """Reset the singleton normalizer (for testing)."""
    global _normalizer
    _normalizer = None
