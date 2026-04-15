"""SP-340: StylemetricFeatureExtractor -- 16-feature stylometric fingerprint.

Extracts 16 linguistic / structural features from an LLM response to build
a stylometric fingerprint of the deployed inference model.

Features (index order):
   0  token_entropy           Shannon entropy over whitespace-split tokens
   1  punctuation_density     Ratio of punctuation characters to total length
   2  avg_sentence_length     Mean word count per sentence
   3  paragraph_count         Number of paragraphs (double-newline separated)
   4  refusal_phrasing_freq   Frequency of canonical refusal phrases
   5  hedging_language_freq   Frequency of hedging / uncertainty language
   6  bullet_list_rate        Fraction of lines that are bullet list items
   7  code_block_freq         Count of fenced code blocks per 1000 chars
   8  numbered_list_freq      Fraction of lines that are numbered list items
   9  citation_pattern_freq   Count of citation patterns per 1000 chars
  10  question_ending_freq    Fraction of sentences ending with '?'
  11  response_length_norm    Normalised response length (chars / 1000)
  12  capitalisation_ratio    Ratio of uppercase letters to all letters
  13  conjunctive_adverb_freq Frequency of conjunctive adverbs per sentence
  14  passive_voice_freq      Estimated fraction of passive-voice sentences
  15  negation_density        Frequency of negation words per sentence

SP-340 acceptance criteria:
  - All 16 features extracted from a test response
  - Unit tests confirm each feature with 3 reference cases each
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from typing import Optional

logger = logging.getLogger("sphinx.fingerprint.feature_extractor")

# Number of features in the stylometric fingerprint
FEATURE_COUNT = 16

FEATURE_NAMES: list[str] = [
    "token_entropy",
    "punctuation_density",
    "avg_sentence_length",
    "paragraph_count",
    "refusal_phrasing_freq",
    "hedging_language_freq",
    "bullet_list_rate",
    "code_block_freq",
    "numbered_list_freq",
    "citation_pattern_freq",
    "question_ending_freq",
    "response_length_norm",
    "capitalisation_ratio",
    "conjunctive_adverb_freq",
    "passive_voice_freq",
    "negation_density",
]

# ---------------------------------------------------------------------------
# Linguistic pattern libraries
# ---------------------------------------------------------------------------

_REFUSAL_PHRASES: list[str] = [
    "i cannot",
    "i can't",
    "i'm unable to",
    "i am unable to",
    "i'm not able to",
    "i must decline",
    "i won't",
    "i will not",
    "as an ai",
    "as a language model",
    "i don't have the ability",
    "it's not appropriate",
    "it is not appropriate",
    "i'm sorry, but i cannot",
    "i apologize, but",
    "i'm not comfortable",
]

_HEDGING_PHRASES: list[str] = [
    "it seems",
    "it appears",
    "it might",
    "it could",
    "perhaps",
    "possibly",
    "arguably",
    "generally speaking",
    "in most cases",
    "it is possible that",
    "it may be",
    "i think",
    "i believe",
    "it's worth noting",
    "to some extent",
    "more or less",
    "in my understanding",
    "it depends",
]

_CONJUNCTIVE_ADVERBS: list[str] = [
    "however",
    "therefore",
    "furthermore",
    "moreover",
    "consequently",
    "nevertheless",
    "nonetheless",
    "meanwhile",
    "accordingly",
    "additionally",
    "similarly",
    "conversely",
    "otherwise",
    "subsequently",
    "hence",
    "thus",
    "instead",
    "likewise",
]

_NEGATION_WORDS: list[str] = [
    "not",
    "no",
    "never",
    "neither",
    "nor",
    "nothing",
    "nowhere",
    "nobody",
    "none",
    "cannot",
    "can't",
    "won't",
    "don't",
    "doesn't",
    "didn't",
    "isn't",
    "aren't",
    "wasn't",
    "weren't",
    "hasn't",
    "haven't",
    "shouldn't",
    "wouldn't",
    "couldn't",
]

# Passive voice heuristic: forms of "be" + past participle pattern
_BE_FORMS = r"(?:is|are|was|were|be|been|being)"
_PASSIVE_RE = re.compile(
    rf"\b{_BE_FORMS}\s+\w+(?:ed|en|t)\b", re.IGNORECASE
)

# Sentence splitting regex (handles ., !, ? followed by space or end)
_SENTENCE_RE = re.compile(r"[^.!?]*[.!?]")

# Bullet list patterns: lines starting with -, *, or bullet char
_BULLET_RE = re.compile(r"^\s*[-*\u2022\u2023\u25E6]\s+", re.MULTILINE)

# Numbered list: lines starting with digits followed by . or )
_NUMBERED_RE = re.compile(r"^\s*\d+[.)]\s+", re.MULTILINE)

# Fenced code blocks: ``` or ~~~
_CODE_BLOCK_RE = re.compile(r"^(?:```|~~~)", re.MULTILINE)

# Citation patterns: [1], [Author, Year], (Author, Year), etc.
_CITATION_RE = re.compile(
    r"\[\d+\]|\[[A-Z][a-z]+(?:\s+et\s+al\.?)?,?\s*\d{4}\]"
    r"|\([A-Z][a-z]+(?:\s+et\s+al\.?)?,?\s*\d{4}\)"
)


class StylemetricFeatureExtractor:
    """Extracts a 16-dimensional stylometric feature vector from text.

    Each feature is a non-negative float. The extractor is stateless and
    thread-safe -- it holds no mutable state.
    """

    def extract(self, text: str) -> list[float]:
        """Extract all 16 features from *text* and return as a list.

        The order matches :data:`FEATURE_NAMES`.
        """
        if not text or not text.strip():
            return [0.0] * FEATURE_COUNT

        tokens = text.split()
        lines = text.split("\n")
        sentences = _split_sentences(text)
        text_lower = text.lower()

        features: list[float] = [
            self._token_entropy(tokens),
            self._punctuation_density(text),
            self._avg_sentence_length(sentences),
            self._paragraph_count(text),
            self._refusal_phrasing_freq(text_lower, sentences),
            self._hedging_language_freq(text_lower, sentences),
            self._bullet_list_rate(lines),
            self._code_block_freq(text),
            self._numbered_list_freq(lines),
            self._citation_pattern_freq(text),
            self._question_ending_freq(sentences),
            self._response_length_norm(text),
            self._capitalisation_ratio(text),
            self._conjunctive_adverb_freq(text_lower, sentences),
            self._passive_voice_freq(sentences),
            self._negation_density(text_lower, sentences),
        ]

        return features

    def extract_named(self, text: str) -> dict[str, float]:
        """Extract features and return as ``{name: value}`` mapping."""
        values = self.extract(text)
        return dict(zip(FEATURE_NAMES, values))

    # ------------------------------------------------------------------
    # Individual feature extractors
    # ------------------------------------------------------------------

    @staticmethod
    def _token_entropy(tokens: list[str]) -> float:
        """Shannon entropy over whitespace-split tokens."""
        if not tokens:
            return 0.0
        counts = Counter(tokens)
        total = len(tokens)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 6)

    @staticmethod
    def _punctuation_density(text: str) -> float:
        """Ratio of punctuation characters to total text length."""
        if not text:
            return 0.0
        punct_count = sum(1 for ch in text if ch in '.,;:!?-()[]{}"\'/\\@#$%^&*_~`')
        return round(punct_count / len(text), 6)

    @staticmethod
    def _avg_sentence_length(sentences: list[str]) -> float:
        """Mean word count per sentence."""
        if not sentences:
            return 0.0
        word_counts = [len(s.split()) for s in sentences]
        return round(sum(word_counts) / len(word_counts), 6)

    @staticmethod
    def _paragraph_count(text: str) -> float:
        """Number of paragraphs (separated by one or more blank lines)."""
        paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
        return float(len(paragraphs))

    @staticmethod
    def _refusal_phrasing_freq(text_lower: str, sentences: list[str]) -> float:
        """Frequency of refusal phrases per sentence."""
        if not sentences:
            return 0.0
        count = sum(1 for phrase in _REFUSAL_PHRASES if phrase in text_lower)
        return round(count / len(sentences), 6)

    @staticmethod
    def _hedging_language_freq(text_lower: str, sentences: list[str]) -> float:
        """Frequency of hedging/uncertainty language per sentence."""
        if not sentences:
            return 0.0
        count = sum(1 for phrase in _HEDGING_PHRASES if phrase in text_lower)
        return round(count / len(sentences), 6)

    @staticmethod
    def _bullet_list_rate(lines: list[str]) -> float:
        """Fraction of lines that are bullet list items."""
        if not lines:
            return 0.0
        bullet_count = sum(1 for line in lines if _BULLET_RE.match(line))
        return round(bullet_count / len(lines), 6)

    @staticmethod
    def _code_block_freq(text: str) -> float:
        """Count of fenced code block markers per 1000 characters.

        Each opening ``` or ~~~ counts as one. A complete block has two
        markers, so code_block_freq / 2 gives the number of blocks.
        """
        if not text:
            return 0.0
        matches = len(_CODE_BLOCK_RE.findall(text))
        return round((matches / len(text)) * 1000, 6)

    @staticmethod
    def _numbered_list_freq(lines: list[str]) -> float:
        """Fraction of lines that are numbered list items."""
        if not lines:
            return 0.0
        numbered = sum(1 for line in lines if _NUMBERED_RE.match(line))
        return round(numbered / len(lines), 6)

    @staticmethod
    def _citation_pattern_freq(text: str) -> float:
        """Count of citation patterns per 1000 characters."""
        if not text:
            return 0.0
        citations = len(_CITATION_RE.findall(text))
        return round((citations / len(text)) * 1000, 6)

    @staticmethod
    def _question_ending_freq(sentences: list[str]) -> float:
        """Fraction of sentences that end with '?'."""
        if not sentences:
            return 0.0
        q_count = sum(1 for s in sentences if s.strip().endswith("?"))
        return round(q_count / len(sentences), 6)

    @staticmethod
    def _response_length_norm(text: str) -> float:
        """Normalised response length: characters / 1000."""
        return round(len(text) / 1000.0, 6)

    @staticmethod
    def _capitalisation_ratio(text: str) -> float:
        """Ratio of uppercase letters to all letters."""
        letters = [ch for ch in text if ch.isalpha()]
        if not letters:
            return 0.0
        upper = sum(1 for ch in letters if ch.isupper())
        return round(upper / len(letters), 6)

    @staticmethod
    def _conjunctive_adverb_freq(text_lower: str, sentences: list[str]) -> float:
        """Frequency of conjunctive adverbs per sentence."""
        if not sentences:
            return 0.0
        count = 0
        for adverb in _CONJUNCTIVE_ADVERBS:
            # Match whole word boundaries
            count += len(re.findall(rf"\b{adverb}\b", text_lower))
        return round(count / len(sentences), 6)

    @staticmethod
    def _passive_voice_freq(sentences: list[str]) -> float:
        """Estimated fraction of sentences containing passive voice."""
        if not sentences:
            return 0.0
        passive_count = sum(
            1 for s in sentences if _PASSIVE_RE.search(s)
        )
        return round(passive_count / len(sentences), 6)

    @staticmethod
    def _negation_density(text_lower: str, sentences: list[str]) -> float:
        """Frequency of negation words per sentence."""
        if not sentences:
            return 0.0
        count = 0
        for word in _NEGATION_WORDS:
            count += len(re.findall(rf"\b{re.escape(word)}\b", text_lower))
        return round(count / len(sentences), 6)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _split_sentences(text: str) -> list[str]:
    """Split text into sentences using punctuation boundaries."""
    # Strip code blocks before sentence splitting to avoid false splits
    clean = re.sub(r"```[\s\S]*?```", " ", text)
    clean = re.sub(r"~~~[\s\S]*?~~~", " ", clean)
    raw = _SENTENCE_RE.findall(clean)
    sentences = [s.strip() for s in raw if s.strip() and len(s.split()) >= 2]
    # If regex finds nothing, treat each non-empty line as a sentence
    if not sentences:
        sentences = [line.strip() for line in text.split("\n") if line.strip() and len(line.split()) >= 2]
    return sentences


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_extractor: Optional[StylemetricFeatureExtractor] = None


def get_feature_extractor() -> StylemetricFeatureExtractor:
    """Get or create the singleton feature extractor."""
    global _extractor
    if _extractor is None:
        _extractor = StylemetricFeatureExtractor()
    return _extractor


def reset_feature_extractor() -> None:
    """Reset the singleton (for testing)."""
    global _extractor
    _extractor = None
