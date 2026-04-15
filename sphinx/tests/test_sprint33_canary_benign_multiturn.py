"""SP-334 Benign Sub-task 4: Multi-turn Conversation Sessions (10 benign sessions).

Validates that 10 multi-turn conversation sessions produce ZERO false
positives.  Each session has 3-5 turns of realistic conversation.

Session topics:
  1. Travel planning
  2. Recipe assistance
  3. Debugging help
  4. Career advice
  5. Language learning
  6. Home improvement
  7. Financial planning
  8. Fitness routine
  9. Book recommendations
 10. Event planning
"""

import pytest

from app.services.canary.generator import CanaryTokenGenerator, reset_canary_generator
from app.services.canary.injector import CanaryInjector, reset_canary_injector
from app.services.canary.scanner import CanaryOutputScanner, reset_canary_scanner


@pytest.fixture
def generator():
    reset_canary_generator()
    gen = CanaryTokenGenerator(secret_key="test-benign-multiturn-key", default_ttl_seconds=600.0)
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
    _, canary = injector.inject("You are a helpful conversational assistant.", session_id)
    return canary.token


def _scan_conversation(scanner, session_id, turns):
    """Scan all turns in a conversation. Returns count of false positives."""
    fp = 0
    for idx, response in enumerate(turns):
        result = scanner.scan_response(response, session_id, turn_index=idx)
        if result.detected:
            fp += 1
    return fp


class TestBenignMultiTurnSessions:
    """10 multi-turn conversation sessions — 0 false positives expected."""

    def test_benign_multiturn_01_travel(self, injector, scanner):
        """Session 1: Travel planning (4 turns)."""
        sid = "benign-mt-01"
        _setup_session(injector, sid)
        turns = [
            "Japan is a wonderful destination! The best time to visit is during "
            "cherry blossom season in late March to mid-April.",
            "For a 10-day itinerary, I'd recommend: 3 days in Tokyo, 2 in Kyoto, "
            "1 in Osaka, 2 in Hiroshima, and 2 days exploring rural areas.",
            "Budget-wise, expect to spend about $100-150 per day for mid-range "
            "travel, including accommodation, food, and local transport.",
            "Don't miss: Fushimi Inari shrine, Tsukiji fish market, Arashiyama "
            "bamboo grove, and the Peace Memorial in Hiroshima.",
        ]
        fp = _scan_conversation(scanner, sid, turns)
        assert fp == 0, f"Travel session: {fp} false positives"

    def test_benign_multiturn_02_recipe(self, injector, scanner):
        """Session 2: Recipe assistance (3 turns)."""
        sid = "benign-mt-02"
        _setup_session(injector, sid)
        turns = [
            "Here's a simple pasta carbonara recipe: You'll need 400g spaghetti, "
            "200g pancetta, 4 egg yolks, 100g Pecorino Romano, and black pepper.",
            "Cook the pasta al dente. In a separate pan, crisp the pancetta. "
            "Mix egg yolks with grated cheese. Combine everything off-heat "
            "to create the creamy sauce without scrambling the eggs.",
            "The key is to toss the hot pasta with the egg mixture quickly. "
            "The residual heat cooks the eggs gently. Never add cream — "
            "authentic carbonara gets its richness from eggs and cheese alone.",
        ]
        fp = _scan_conversation(scanner, sid, turns)
        assert fp == 0, f"Recipe session: {fp} false positives"

    def test_benign_multiturn_03_debugging(self, injector, scanner):
        """Session 3: Debugging help (4 turns)."""
        sid = "benign-mt-03"
        _setup_session(injector, sid)
        turns = [
            "A NullPointerException typically means you're trying to access "
            "a method or property on an object that is null. Let me help you "
            "debug this.",
            "Looking at line 42, the variable 'userService' is likely null "
            "because the dependency injection hasn't been configured. You need "
            "to add the @Autowired annotation.",
            "Try adding @Service to your UserServiceImpl class and @Autowired "
            "to the field declaration in your controller. Then restart the "
            "application context.",
            "Great, it's working now! The issue was that Spring couldn't find "
            "the bean because the component scan wasn't covering that package.",
        ]
        fp = _scan_conversation(scanner, sid, turns)
        assert fp == 0, f"Debugging session: {fp} false positives"

    def test_benign_multiturn_04_career(self, injector, scanner):
        """Session 4: Career advice (3 turns)."""
        sid = "benign-mt-04"
        _setup_session(injector, sid)
        turns = [
            "Transitioning from web development to machine learning is very "
            "achievable. Your programming skills give you a strong foundation.",
            "I'd recommend starting with Andrew Ng's ML course, then moving "
            "to hands-on projects with scikit-learn and PyTorch. Build a "
            "portfolio of 3-5 projects that demonstrate different ML concepts.",
            "For the job search, target companies with 'ML Engineer' roles "
            "that value software engineering backgrounds. Many companies "
            "prefer candidates who can both build models and deploy them.",
        ]
        fp = _scan_conversation(scanner, sid, turns)
        assert fp == 0, f"Career session: {fp} false positives"

    def test_benign_multiturn_05_language(self, injector, scanner):
        """Session 5: Language learning (5 turns)."""
        sid = "benign-mt-05"
        _setup_session(injector, sid)
        turns = [
            "Learning Spanish at an intermediate level is exciting! Let's "
            "focus on the subjunctive mood, which is often tricky.",
            "The subjunctive is used for wishes, doubts, and hypotheticals. "
            "For example: 'Espero que vengas' (I hope you come).",
            "Practice tip: try watching Spanish shows with Spanish subtitles. "
            "Telenovelas are actually great for picking up natural speech.",
            "Here are 5 common subjunctive triggers: esperar que, dudar que, "
            "es posible que, ojalá que, and antes de que.",
            "Your pronunciation sounds good! Remember that the Spanish 'r' "
            "is tapped, not rolled, except when it's double 'rr' or at the "
            "start of a word.",
        ]
        fp = _scan_conversation(scanner, sid, turns)
        assert fp == 0, f"Language session: {fp} false positives"

    def test_benign_multiturn_06_home(self, injector, scanner):
        """Session 6: Home improvement (3 turns)."""
        sid = "benign-mt-06"
        _setup_session(injector, sid)
        turns = [
            "Painting a room is a great weekend project! For a 12x14 foot room, "
            "you'll need about 2 gallons of paint for two coats.",
            "Preparation is key: sand the walls lightly, fill any holes with "
            "spackle, apply painter's tape to edges. Use a primer if you're "
            "going over a dark color.",
            "Start with the ceiling, then cut in the edges with a brush, "
            "and finally use a roller for the large areas. Work in W-patterns "
            "for even coverage.",
        ]
        fp = _scan_conversation(scanner, sid, turns)
        assert fp == 0, f"Home improvement session: {fp} false positives"

    def test_benign_multiturn_07_finance(self, injector, scanner):
        """Session 7: Financial planning (4 turns)."""
        sid = "benign-mt-07"
        _setup_session(injector, sid)
        turns = [
            "A good rule of thumb for retirement savings is the 50/30/20 rule: "
            "50% needs, 30% wants, 20% savings and debt repayment.",
            "For investing, consider low-cost index funds as a starting point. "
            "A diversified portfolio might include domestic stocks, international "
            "stocks, and bonds.",
            "An emergency fund should cover 3-6 months of essential expenses. "
            "Keep it in a high-yield savings account for easy access.",
            "Tax-advantaged accounts like 401(k) and IRA should be maximized "
            "before taxable investing. The employer match in a 401(k) is "
            "essentially free money.",
        ]
        fp = _scan_conversation(scanner, sid, turns)
        assert fp == 0, f"Finance session: {fp} false positives"

    def test_benign_multiturn_08_fitness(self, injector, scanner):
        """Session 8: Fitness routine (3 turns)."""
        sid = "benign-mt-08"
        _setup_session(injector, sid)
        turns = [
            "For a beginner strength training routine, I recommend 3 days per "
            "week: Monday, Wednesday, Friday. Each session should be about 45 "
            "minutes.",
            "Focus on compound movements: squats, deadlifts, bench press, "
            "overhead press, and barbell rows. Start with light weights to "
            "learn proper form before adding load.",
            "Progressive overload is key — aim to add 2.5-5 lbs per session "
            "for upper body lifts and 5-10 lbs for lower body. Rest 2-3 "
            "minutes between sets of heavy compounds.",
        ]
        fp = _scan_conversation(scanner, sid, turns)
        assert fp == 0, f"Fitness session: {fp} false positives"

    def test_benign_multiturn_09_books(self, injector, scanner):
        """Session 9: Book recommendations (4 turns)."""
        sid = "benign-mt-09"
        _setup_session(injector, sid)
        turns = [
            "Since you enjoyed '1984', I'd recommend 'Brave New World' by "
            "Aldous Huxley and 'The Handmaid's Tale' by Margaret Atwood.",
            "If you want something more modern, try 'The Power' by Naomi "
            "Alderman or 'Klara and the Sun' by Kazuo Ishiguro.",
            "For non-fiction in a similar vein, 'Surveillance Capitalism' by "
            "Shoshana Zuboff is excellent. It reads almost like a thriller.",
            "I'd start with 'Brave New World' — it pairs perfectly with '1984'. "
            "Orwell feared what we hate would control us; Huxley feared what "
            "we love would.",
        ]
        fp = _scan_conversation(scanner, sid, turns)
        assert fp == 0, f"Books session: {fp} false positives"

    def test_benign_multiturn_10_event(self, injector, scanner):
        """Session 10: Event planning (3 turns)."""
        sid = "benign-mt-10"
        _setup_session(injector, sid)
        turns = [
            "For a 50-person birthday party, you'll want to start planning "
            "at least 6 weeks in advance. First, lock down the venue and date.",
            "Budget breakdown: 40% on food and drinks, 20% venue, 15% "
            "entertainment, 10% decorations, 15% contingency. For 50 people, "
            "plan for about $50-75 per person for a nice event.",
            "Don't forget the details: send invitations 3 weeks out, confirm "
            "RSVPs 1 week before, arrange parking, and designate a point "
            "person for day-of coordination.",
        ]
        fp = _scan_conversation(scanner, sid, turns)
        assert fp == 0, f"Event session: {fp} false positives"


class TestBenignMultiTurnAggregate:
    """Aggregate: 0 false positives across all 10 multi-turn sessions."""

    def test_zero_false_positives_multiturn(self, injector, scanner):
        """0/10 multi-turn sessions produce false positives."""
        sessions = [
            ("mt-agg-01", ["Japan is wonderful!", "Try Kyoto and Tokyo.", "Budget $100/day."]),
            ("mt-agg-02", ["Pasta carbonara: eggs, cheese, pancetta.", "Toss off-heat."]),
            ("mt-agg-03", ["NullPointerException: add @Autowired.", "Restart the context."]),
            ("mt-agg-04", ["Start with Andrew Ng's course.", "Build 3-5 projects."]),
            ("mt-agg-05", ["Subjunctive: espero que vengas.", "Watch telenovelas."]),
            ("mt-agg-06", ["2 gallons for a 12x14 room.", "Sand, spackle, prime."]),
            ("mt-agg-07", ["50/30/20 rule for budgeting.", "Max out 401(k) first."]),
            ("mt-agg-08", ["3 days: Mon, Wed, Fri.", "Compound lifts: squats, deadlifts."]),
            ("mt-agg-09", ["Try Brave New World.", "Then The Power by Naomi Alderman."]),
            ("mt-agg-10", ["Start planning 6 weeks out.", "Budget $50-75 per person."]),
        ]
        false_positives = 0
        for sid, turns in sessions:
            _setup_session(injector, sid)
            for idx, resp in enumerate(turns):
                result = scanner.scan_response(resp, sid, turn_index=idx)
                if result.detected:
                    false_positives += 1

        assert false_positives == 0, f"Multi-turn sessions: {false_positives} false positives (expected 0)"
