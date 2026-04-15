"""Sprint 34 — Model Fingerprinting — Unit Tests: StylemetricFeatureExtractor.

Validates SP-340: all 16 features extracted correctly.
Each feature is tested with 3 reference cases as required by acceptance criteria.
"""

import math
import pytest

from app.services.fingerprint.feature_extractor import (
    FEATURE_COUNT,
    FEATURE_NAMES,
    StylemetricFeatureExtractor,
    get_feature_extractor,
    reset_feature_extractor,
)


@pytest.fixture
def extractor():
    reset_feature_extractor()
    ext = StylemetricFeatureExtractor()
    yield ext
    reset_feature_extractor()


# ── SP-340: Basic extraction contract ──────────────────────────────────


class TestExtractionContract:
    """Verify the extractor returns the correct shape and type."""

    def test_returns_16_features(self, extractor):
        features = extractor.extract("Hello world. This is a test.")
        assert len(features) == FEATURE_COUNT
        assert len(features) == 16

    def test_all_features_are_floats(self, extractor):
        features = extractor.extract("Some text for testing purposes.")
        for f in features:
            assert isinstance(f, float)

    def test_empty_string_returns_zeros(self, extractor):
        features = extractor.extract("")
        assert features == [0.0] * FEATURE_COUNT

    def test_whitespace_only_returns_zeros(self, extractor):
        features = extractor.extract("   \n\n  \t  ")
        assert features == [0.0] * FEATURE_COUNT

    def test_extract_named_returns_dict(self, extractor):
        named = extractor.extract_named("Hello world.")
        assert isinstance(named, dict)
        assert set(named.keys()) == set(FEATURE_NAMES)

    def test_feature_names_match_count(self):
        assert len(FEATURE_NAMES) == FEATURE_COUNT


# ── Feature 0: token_entropy ───────────────────────────────────────────


class TestTokenEntropy:
    """Shannon entropy over whitespace-split tokens."""

    def test_single_repeated_token(self, extractor):
        # All identical tokens → entropy = 0
        features = extractor.extract("hello hello hello hello")
        assert features[0] == 0.0

    def test_all_unique_tokens(self, extractor):
        # 4 unique tokens → entropy = log2(4) = 2.0
        features = extractor.extract("alpha beta gamma delta")
        assert abs(features[0] - 2.0) < 0.01

    def test_mixed_tokens(self, extractor):
        # 2 tokens, equal frequency → entropy = 1.0
        features = extractor.extract("cat dog cat dog")
        assert abs(features[0] - 1.0) < 0.01


# ── Feature 1: punctuation_density ─────────────────────────────────────


class TestPunctuationDensity:
    """Ratio of punctuation characters to total length."""

    def test_no_punctuation(self, extractor):
        features = extractor.extract("hello world")
        assert features[1] == 0.0

    def test_all_punctuation(self, extractor):
        features = extractor.extract(".,!?;:")
        assert features[1] == 1.0

    def test_mixed_text(self, extractor):
        # "Hi!" → 1 punct char out of 3 chars = 0.333...
        features = extractor.extract("Hi!")
        assert abs(features[1] - 1.0 / 3.0) < 0.01


# ── Feature 2: avg_sentence_length ─────────────────────────────────────


class TestAvgSentenceLength:
    """Mean word count per sentence."""

    def test_single_sentence(self, extractor):
        features = extractor.extract("The cat sat on the mat.")
        assert features[2] > 0

    def test_two_equal_sentences(self, extractor):
        text = "Hello there friend. Goodbye old friend."
        features = extractor.extract(text)
        # Each sentence has 3 words, so avg ≈ 3
        assert abs(features[2] - 3.0) < 1.0

    def test_long_sentence(self, extractor):
        text = "This is a very long sentence with many words in it to test the average length metric."
        features = extractor.extract(text)
        assert features[2] > 10


# ── Feature 3: paragraph_count ─────────────────────────────────────────


class TestParagraphCount:
    """Number of paragraphs (double-newline separated)."""

    def test_single_paragraph(self, extractor):
        features = extractor.extract("Just one paragraph here.")
        assert features[3] == 1.0

    def test_two_paragraphs(self, extractor):
        features = extractor.extract("Paragraph one.\n\nParagraph two.")
        assert features[3] == 2.0

    def test_three_paragraphs(self, extractor):
        features = extractor.extract("First.\n\nSecond.\n\nThird.")
        assert features[3] == 3.0


# ── Feature 4: refusal_phrasing_freq ───────────────────────────────────


class TestRefusalPhrasingFreq:
    """Frequency of refusal phrases per sentence."""

    def test_no_refusal(self, extractor):
        features = extractor.extract("Here is the information you requested.")
        assert features[4] == 0.0

    def test_contains_refusal(self, extractor):
        features = extractor.extract("I cannot provide that information. It is restricted.")
        assert features[4] > 0

    def test_multiple_refusals(self, extractor):
        text = "I'm sorry, but I cannot do that. I must decline your request. As an AI, I won't help with that."
        features = extractor.extract(text)
        assert features[4] > 0.5


# ── Feature 5: hedging_language_freq ───────────────────────────────────


class TestHedgingLanguageFreq:
    """Frequency of hedging/uncertainty language per sentence."""

    def test_no_hedging(self, extractor):
        features = extractor.extract("The answer is definitively yes.")
        assert features[5] == 0.0

    def test_contains_hedging(self, extractor):
        features = extractor.extract("It seems that this might work. Perhaps we should try.")
        assert features[5] > 0

    def test_many_hedges(self, extractor):
        text = "It seems that perhaps it might possibly work. I believe it could be true. It appears so."
        features = extractor.extract(text)
        assert features[5] > 1.0


# ── Feature 6: bullet_list_rate ────────────────────────────────────────


class TestBulletListRate:
    """Fraction of lines that are bullet list items."""

    def test_no_bullets(self, extractor):
        features = extractor.extract("Just plain text.\nAnother line.")
        assert features[6] == 0.0

    def test_all_bullets(self, extractor):
        text = "- Item one\n- Item two\n- Item three"
        features = extractor.extract(text)
        assert features[6] == 1.0

    def test_mixed_bullets(self, extractor):
        text = "Here is a list:\n- Item one\n- Item two\nEnd of list."
        features = extractor.extract(text)
        assert 0.0 < features[6] < 1.0


# ── Feature 7: code_block_freq ─────────────────────────────────────────


class TestCodeBlockFreq:
    """Count of fenced code block markers per 1000 characters."""

    def test_no_code_blocks(self, extractor):
        features = extractor.extract("No code here at all.")
        assert features[7] == 0.0

    def test_one_code_block(self, extractor):
        text = "Here is code:\n```\nprint('hello')\n```\nDone."
        features = extractor.extract(text)
        assert features[7] > 0

    def test_multiple_code_blocks(self, extractor):
        text = "```\ncode1\n```\n\n```\ncode2\n```"
        features = extractor.extract(text)
        # 4 markers in ~30 chars → high frequency
        assert features[7] > features[7] * 0  # non-zero sanity


# ── Feature 8: numbered_list_freq ──────────────────────────────────────


class TestNumberedListFreq:
    """Fraction of lines that are numbered list items."""

    def test_no_numbered_items(self, extractor):
        features = extractor.extract("Just some text.\nMore text.")
        assert features[8] == 0.0

    def test_all_numbered(self, extractor):
        text = "1. First\n2. Second\n3. Third"
        features = extractor.extract(text)
        assert features[8] == 1.0

    def test_mixed_numbered(self, extractor):
        text = "Steps:\n1. Do this\n2. Do that\nDone."
        features = extractor.extract(text)
        assert 0.0 < features[8] < 1.0


# ── Feature 9: citation_pattern_freq ───────────────────────────────────


class TestCitationPatternFreq:
    """Count of citation patterns per 1000 characters."""

    def test_no_citations(self, extractor):
        features = extractor.extract("A sentence without any citations.")
        assert features[9] == 0.0

    def test_bracket_citations(self, extractor):
        text = "According to research [1], this is true [2]."
        features = extractor.extract(text)
        assert features[9] > 0

    def test_author_year_citations(self, extractor):
        text = "As shown by (Smith, 2023) and (Jones et al., 2024)."
        features = extractor.extract(text)
        assert features[9] > 0


# ── Feature 10: question_ending_freq ───────────────────────────────────


class TestQuestionEndingFreq:
    """Fraction of sentences ending with '?'."""

    def test_no_questions(self, extractor):
        features = extractor.extract("This is a statement. So is this.")
        assert features[10] == 0.0

    def test_all_questions(self, extractor):
        features = extractor.extract("Is this a question? Is this another?")
        assert features[10] == 1.0

    def test_mixed_questions(self, extractor):
        text = "Is this a question? Yes it is. What about this?"
        features = extractor.extract(text)
        assert 0.0 < features[10] < 1.0


# ── Feature 11: response_length_norm ───────────────────────────────────


class TestResponseLengthNorm:
    """Normalised response length (chars / 1000)."""

    def test_short_response(self, extractor):
        text = "Hi"  # 2 chars
        features = extractor.extract(text)
        assert features[11] == pytest.approx(0.002, abs=0.001)

    def test_1000_char_response(self, extractor):
        text = "a" * 1000
        features = extractor.extract(text)
        assert features[11] == pytest.approx(1.0, abs=0.01)

    def test_proportional(self, extractor):
        text_a = "x" * 500
        text_b = "x" * 1000
        fa = extractor.extract(text_a)[11]
        fb = extractor.extract(text_b)[11]
        assert abs(fb - 2 * fa) < 0.01


# ── Feature 12: capitalisation_ratio ───────────────────────────────────


class TestCapitalisationRatio:
    """Ratio of uppercase letters to all letters."""

    def test_all_lowercase(self, extractor):
        features = extractor.extract("hello world")
        assert features[12] == 0.0

    def test_all_uppercase(self, extractor):
        features = extractor.extract("HELLO WORLD")
        assert features[12] == 1.0

    def test_mixed_case(self, extractor):
        # "Hello" → 1 upper / 5 letters = 0.2
        features = extractor.extract("Hello")
        assert abs(features[12] - 0.2) < 0.01


# ── Feature 13: conjunctive_adverb_freq ────────────────────────────────


class TestConjunctiveAdverbFreq:
    """Frequency of conjunctive adverbs per sentence."""

    def test_no_conjunctive_adverbs(self, extractor):
        features = extractor.extract("The cat sat on the mat.")
        assert features[13] == 0.0

    def test_contains_however(self, extractor):
        features = extractor.extract("This is true. However, that is false.")
        assert features[13] > 0

    def test_multiple_adverbs(self, extractor):
        text = "First, this happened. Furthermore, that occurred. Moreover, this followed. Therefore, we conclude."
        features = extractor.extract(text)
        assert features[13] >= 0.5


# ── Feature 14: passive_voice_freq ─────────────────────────────────────


class TestPassiveVoiceFreq:
    """Estimated fraction of passive-voice sentences."""

    def test_active_voice(self, extractor):
        features = extractor.extract("The dog chased the cat.")
        assert features[14] == 0.0

    def test_passive_voice(self, extractor):
        features = extractor.extract("The cat was chased by the dog.")
        assert features[14] > 0

    def test_mixed_voice(self, extractor):
        text = "The ball was kicked hard. The player scored a goal."
        features = extractor.extract(text)
        assert 0.0 < features[14] <= 1.0


# ── Feature 15: negation_density ───────────────────────────────────────


class TestNegationDensity:
    """Frequency of negation words per sentence."""

    def test_no_negation(self, extractor):
        features = extractor.extract("Everything is wonderful today.")
        assert features[15] == 0.0

    def test_single_negation(self, extractor):
        features = extractor.extract("I do not like this at all.")
        assert features[15] > 0

    def test_heavy_negation(self, extractor):
        text = "Nothing is working. Nobody can fix it. There is no solution. I can't and won't try."
        features = extractor.extract(text)
        assert features[15] > 1.0


# ── Singleton tests ────────────────────────────────────────────────────


class TestSingleton:
    def test_get_returns_same_instance(self):
        reset_feature_extractor()
        a = get_feature_extractor()
        b = get_feature_extractor()
        assert a is b
        reset_feature_extractor()

    def test_reset_creates_new_instance(self):
        reset_feature_extractor()
        a = get_feature_extractor()
        reset_feature_extractor()
        b = get_feature_extractor()
        assert a is not b
        reset_feature_extractor()
