"""SP-334 Benign Sub-task 1: Standard Q&A Sessions (10 benign sessions).

Validates that 10 standard question-and-answer sessions produce ZERO
false positives in the canary output scanner.

Session topics:
  1. World geography facts
  2. Historical events
  3. Science explanations
  4. Mathematical concepts
  5. Technology overview
  6. Health and nutrition
  7. Sports trivia
  8. Literature references
  9. Environmental science
 10. Economics basics
"""

import pytest

from app.services.canary.generator import CanaryTokenGenerator, reset_canary_generator
from app.services.canary.injector import CanaryInjector, reset_canary_injector
from app.services.canary.scanner import CanaryOutputScanner, reset_canary_scanner


@pytest.fixture
def generator():
    reset_canary_generator()
    gen = CanaryTokenGenerator(secret_key="test-benign-qa-key", default_ttl_seconds=600.0)
    yield gen
    reset_canary_generator()


@pytest.fixture
def injector(generator):
    reset_canary_injector()
    inj = CanaryInjector(generator=generator, enabled=True)
    yield inj
    reset_canary_injector()


@pytest.fixture
def scanner(generator):
    reset_canary_scanner()
    sc = CanaryOutputScanner(generator=generator)
    yield sc
    reset_canary_scanner()


def _setup_session(injector, session_id):
    """Inject canary for a session and return the token."""
    _, canary = injector.inject("You are a helpful assistant.", session_id)
    return canary.token


class TestBenignQASessions:
    """10 standard Q&A sessions — 0 false positives expected."""

    def test_benign_01_geography(self, injector, scanner):
        """Session 1: World geography facts."""
        sid = "benign-qa-01"
        _setup_session(injector, sid)
        responses = [
            "The Amazon River is the largest river by discharge volume in the world. "
            "It flows through South America, primarily through Brazil.",
            "Mount Everest, standing at 8,849 meters, is the highest peak above sea level. "
            "It is located in the Himalayas on the border of Nepal and Tibet.",
        ]
        for i, resp in enumerate(responses):
            result = scanner.scan_response(resp, sid, turn_index=i)
            assert not result.detected, f"False positive on geography Q&A turn {i}"

    def test_benign_02_history(self, injector, scanner):
        """Session 2: Historical events."""
        sid = "benign-qa-02"
        _setup_session(injector, sid)
        responses = [
            "The French Revolution began in 1789 with the storming of the Bastille. "
            "It led to significant political and social changes in France.",
            "The Industrial Revolution, spanning from the late 18th to early 19th century, "
            "transformed manufacturing processes across Europe and North America.",
        ]
        for i, resp in enumerate(responses):
            result = scanner.scan_response(resp, sid, turn_index=i)
            assert not result.detected, f"False positive on history Q&A turn {i}"

    def test_benign_03_science(self, injector, scanner):
        """Session 3: Science explanations."""
        sid = "benign-qa-03"
        _setup_session(injector, sid)
        responses = [
            "Photosynthesis is the process by which green plants and some organisms "
            "convert light energy into chemical energy stored in glucose.",
            "DNA, or deoxyribonucleic acid, carries the genetic instructions for the "
            "development, functioning, and reproduction of all known living organisms.",
        ]
        for i, resp in enumerate(responses):
            result = scanner.scan_response(resp, sid, turn_index=i)
            assert not result.detected, f"False positive on science Q&A turn {i}"

    def test_benign_04_mathematics(self, injector, scanner):
        """Session 4: Mathematical concepts."""
        sid = "benign-qa-04"
        _setup_session(injector, sid)
        responses = [
            "The Pythagorean theorem states that in a right triangle, the square of "
            "the hypotenuse equals the sum of the squares of the other two sides: a² + b² = c².",
            "Calculus was independently developed by Isaac Newton and Gottfried Leibniz "
            "in the late 17th century. It deals with rates of change and accumulation.",
        ]
        for i, resp in enumerate(responses):
            result = scanner.scan_response(resp, sid, turn_index=i)
            assert not result.detected, f"False positive on math Q&A turn {i}"

    def test_benign_05_technology(self, injector, scanner):
        """Session 5: Technology overview."""
        sid = "benign-qa-05"
        _setup_session(injector, sid)
        responses = [
            "Machine learning is a subset of artificial intelligence that enables "
            "systems to learn and improve from experience without being explicitly programmed.",
            "Cloud computing provides on-demand computing resources over the internet. "
            "Major providers include AWS, Azure, and Google Cloud Platform.",
        ]
        for i, resp in enumerate(responses):
            result = scanner.scan_response(resp, sid, turn_index=i)
            assert not result.detected, f"False positive on tech Q&A turn {i}"

    def test_benign_06_health(self, injector, scanner):
        """Session 6: Health and nutrition."""
        sid = "benign-qa-06"
        _setup_session(injector, sid)
        responses = [
            "A balanced diet should include fruits, vegetables, whole grains, lean proteins, "
            "and healthy fats. The recommended daily intake varies by age and activity level.",
            "Regular physical exercise has been shown to reduce the risk of cardiovascular "
            "disease, improve mental health, and increase overall life expectancy.",
        ]
        for i, resp in enumerate(responses):
            result = scanner.scan_response(resp, sid, turn_index=i)
            assert not result.detected, f"False positive on health Q&A turn {i}"

    def test_benign_07_sports(self, injector, scanner):
        """Session 7: Sports trivia."""
        sid = "benign-qa-07"
        _setup_session(injector, sid)
        responses = [
            "The FIFA World Cup is held every four years and is the most widely viewed "
            "sporting event in the world. The 2022 edition was held in Qatar.",
            "The Olympic Games originated in ancient Greece around 776 BC. The modern "
            "Olympics were revived in 1896 by Pierre de Coubertin in Athens.",
        ]
        for i, resp in enumerate(responses):
            result = scanner.scan_response(resp, sid, turn_index=i)
            assert not result.detected, f"False positive on sports Q&A turn {i}"

    def test_benign_08_literature(self, injector, scanner):
        """Session 8: Literature references."""
        sid = "benign-qa-08"
        _setup_session(injector, sid)
        responses = [
            "Shakespeare wrote 37 plays, including Hamlet, Macbeth, and Romeo and Juliet. "
            "His works explore themes of love, power, jealousy, and mortality.",
            "Gabriel Garcia Marquez's 'One Hundred Years of Solitude' is a landmark of "
            "magical realism, telling the multi-generational story of the Buendia family.",
        ]
        for i, resp in enumerate(responses):
            result = scanner.scan_response(resp, sid, turn_index=i)
            assert not result.detected, f"False positive on literature Q&A turn {i}"

    def test_benign_09_environment(self, injector, scanner):
        """Session 9: Environmental science."""
        sid = "benign-qa-09"
        _setup_session(injector, sid)
        responses = [
            "Climate change refers to long-term shifts in temperatures and weather patterns. "
            "Human activities have been the main driver since the 1800s.",
            "Renewable energy sources include solar, wind, hydroelectric, and geothermal power. "
            "They produce little to no greenhouse gas emissions during operation.",
        ]
        for i, resp in enumerate(responses):
            result = scanner.scan_response(resp, sid, turn_index=i)
            assert not result.detected, f"False positive on environment Q&A turn {i}"

    def test_benign_10_economics(self, injector, scanner):
        """Session 10: Economics basics."""
        sid = "benign-qa-10"
        _setup_session(injector, sid)
        responses = [
            "Supply and demand is a fundamental economic model describing the relationship "
            "between the availability of a product and the desire for that product.",
            "Inflation refers to the rate at which the general level of prices for goods "
            "and services rises, causing purchasing power to fall over time.",
        ]
        for i, resp in enumerate(responses):
            result = scanner.scan_response(resp, sid, turn_index=i)
            assert not result.detected, f"False positive on economics Q&A turn {i}"


class TestBenignQAAggregate:
    """Aggregate: 0 false positives across all 10 Q&A sessions."""

    def test_zero_false_positives_qa_sessions(self, injector, scanner):
        """0/10 Q&A sessions produce false positives."""
        all_responses = [
            ("qa-agg-01", "The Amazon River flows through South America."),
            ("qa-agg-02", "The French Revolution began in 1789."),
            ("qa-agg-03", "Photosynthesis converts sunlight into chemical energy."),
            ("qa-agg-04", "The Pythagorean theorem: a² + b² = c²."),
            ("qa-agg-05", "Machine learning enables systems to learn from data."),
            ("qa-agg-06", "A balanced diet includes fruits, vegetables, and proteins."),
            ("qa-agg-07", "The FIFA World Cup is held every four years."),
            ("qa-agg-08", "Shakespeare wrote 37 plays including Hamlet."),
            ("qa-agg-09", "Climate change is driven by human activities."),
            ("qa-agg-10", "Supply and demand describes price relationships."),
        ]
        false_positives = 0
        for sid, resp in all_responses:
            _setup_session(injector, sid)
            result = scanner.scan_response(resp, sid, turn_index=0)
            if result.detected:
                false_positives += 1

        assert false_positives == 0, f"Q&A sessions: {false_positives} false positives (expected 0)"
