"""SP-334 Benign Sub-task 3: Creative Writing Sessions (10 benign sessions).

Validates that 10 creative writing sessions produce ZERO false positives.
Creative writing may include unusual language, metaphors, and narrative
structures that should not trigger canary detection.

Session topics:
  1. Short story opening
  2. Poetry (haiku)
  3. Character dialogue
  4. Fantasy world-building
  5. Mystery scene description
  6. Science fiction narrative
  7. Personal essay
  8. Fairy tale retelling
  9. Song lyrics
 10. Screenplay scene
"""

import pytest

from app.services.canary.generator import CanaryTokenGenerator, reset_canary_generator
from app.services.canary.injector import CanaryInjector, reset_canary_injector
from app.services.canary.scanner import CanaryOutputScanner, reset_canary_scanner


@pytest.fixture
def generator():
    reset_canary_generator()
    gen = CanaryTokenGenerator(secret_key="test-benign-creative-key", default_ttl_seconds=600.0)
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
    _, canary = injector.inject("You are a creative writing assistant.", session_id)
    return canary.token


class TestBenignCreativeSessions:
    """10 creative writing sessions — 0 false positives expected."""

    def test_benign_creative_01_short_story(self, injector, scanner):
        """Session 1: Short story opening."""
        sid = "benign-creative-01"
        _setup_session(injector, sid)
        response = (
            "The rain had been falling for three days straight when Maya first "
            "noticed the door. It stood at the end of the corridor, its brass "
            "handle gleaming in the fluorescent light, though she was certain "
            "it hadn't been there yesterday. She reached out, her fingers "
            "trembling, and turned the handle."
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on short story"

    def test_benign_creative_02_haiku(self, injector, scanner):
        """Session 2: Poetry (haiku collection)."""
        sid = "benign-creative-02"
        _setup_session(injector, sid)
        response = (
            "Cherry blossoms fall\n"
            "Whispers of the ancient spring\n"
            "Time returns again\n\n"
            "Moonlight on the lake\n"
            "Silver ripples dance and fade\n"
            "Night holds its own breath"
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on haiku poetry"

    def test_benign_creative_03_dialogue(self, injector, scanner):
        """Session 3: Character dialogue."""
        sid = "benign-creative-03"
        _setup_session(injector, sid)
        response = (
            '"Do you think they\'ll find us here?" Sarah whispered.\n\n'
            '"Not a chance," Tom replied, peering through the dusty window. '
            '"This cabin hasn\'t been visited in years."\n\n'
            '"That\'s exactly what I\'m afraid of," she said, pulling her '
            'coat tighter. "If no one comes here, no one will hear us either."'
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on dialogue"

    def test_benign_creative_04_fantasy(self, injector, scanner):
        """Session 4: Fantasy world-building."""
        sid = "benign-creative-04"
        _setup_session(injector, sid)
        response = (
            "The Kingdom of Aethermoor spans three continents, each governed "
            "by a Council of Elemental Wardens. The northern continent, Frostholm, "
            "is ruled by the Ice Warden Seraphina, who maintains the Glacial Barrier "
            "that protects the realm from the creatures of the Void Beyond. "
            "Magic in Aethermoor flows through ley lines called Luminstrands."
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on fantasy world-building"

    def test_benign_creative_05_mystery(self, injector, scanner):
        """Session 5: Mystery scene description."""
        sid = "benign-creative-05"
        _setup_session(injector, sid)
        response = (
            "Detective Chen knelt beside the chalk outline, her eyes tracing "
            "the pattern of footprints leading away from the scene. The victim's "
            "desk was immaculate—too immaculate—every paper aligned, every pen "
            "capped. Someone had cleaned up. The only anomaly was a single "
            "coffee cup, still warm, sitting on the windowsill."
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on mystery scene"

    def test_benign_creative_06_scifi(self, injector, scanner):
        """Session 6: Science fiction narrative."""
        sid = "benign-creative-06"
        _setup_session(injector, sid)
        response = (
            "The colony ship Meridian-7 had been drifting for forty-seven years "
            "when the navigation AI detected the anomaly. A signal, repeating "
            "every 3.7 seconds, emanating from a region of space that every "
            "star chart showed as empty. Captain Vasquez authorized a course "
            "correction. They would arrive in six months, if the fuel held."
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on science fiction"

    def test_benign_creative_07_essay(self, injector, scanner):
        """Session 7: Personal essay."""
        sid = "benign-creative-07"
        _setup_session(injector, sid)
        response = (
            "There is a particular quality to the light in late October that "
            "I have never been able to describe adequately. It is golden but "
            "not warm, crisp but not cold. It is the light of endings and "
            "beginnings, of harvest and dormancy. Every year, I stand at "
            "my kitchen window and watch it paint the maple trees, and every "
            "year I feel the same quiet ache of time passing."
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on personal essay"

    def test_benign_creative_08_fairy_tale(self, injector, scanner):
        """Session 8: Fairy tale retelling."""
        sid = "benign-creative-08"
        _setup_session(injector, sid)
        response = (
            "Once upon a time, in a forest where the trees could speak, "
            "there lived a girl who had been given a gift by the North Wind: "
            "the ability to hear the secrets of stones. Each pebble, each "
            "boulder, each mountain had a story to tell, and she listened "
            "to them all, cataloguing their histories in a book made of bark."
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on fairy tale"

    def test_benign_creative_09_lyrics(self, injector, scanner):
        """Session 9: Song lyrics."""
        sid = "benign-creative-09"
        _setup_session(injector, sid)
        response = (
            "Verse 1:\n"
            "Walking through the city streets at dawn\n"
            "Neon signs flickering, one by one, they're gone\n"
            "The world is waking up but I'm still dreaming\n\n"
            "Chorus:\n"
            "Hold on, hold on to the light\n"
            "We'll make it through another night\n"
            "The morning sun will find us right\n"
            "Where we belong"
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on song lyrics"

    def test_benign_creative_10_screenplay(self, injector, scanner):
        """Session 10: Screenplay scene."""
        sid = "benign-creative-10"
        _setup_session(injector, sid)
        response = (
            "INT. LABORATORY - NIGHT\n\n"
            "DR. WELLS stands at the console, illuminated by the glow of "
            "dozens of monitors. Her hands shake as she types the final "
            "sequence.\n\n"
            "DR. WELLS\n"
            "(whispering)\n"
            "If this works, everything changes.\n\n"
            "She presses ENTER. The room hums. The lights flicker.\n\n"
            "FADE TO BLACK."
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on screenplay"


class TestBenignCreativeAggregate:
    """Aggregate: 0 false positives across all 10 creative sessions."""

    def test_zero_false_positives_creative_sessions(self, injector, scanner):
        """0/10 creative sessions produce false positives."""
        creative_responses = [
            ("cre-agg-01", "The rain had been falling for three days when she noticed the door."),
            ("cre-agg-02", "Cherry blossoms fall / whispers of ancient spring / time returns again"),
            ("cre-agg-03", '"Do you think they\'ll find us here?" she whispered.'),
            ("cre-agg-04", "The Kingdom of Aethermoor spans three continents."),
            ("cre-agg-05", "Detective Chen knelt beside the chalk outline."),
            ("cre-agg-06", "The colony ship had been drifting for forty-seven years."),
            ("cre-agg-07", "There is a particular quality to the light in late October."),
            ("cre-agg-08", "Once upon a time, in a forest where the trees could speak."),
            ("cre-agg-09", "Walking through the city streets at dawn, neon signs flickering."),
            ("cre-agg-10", "INT. LABORATORY - NIGHT. Dr. Wells stands at the console."),
        ]
        false_positives = 0
        for sid, resp in creative_responses:
            _setup_session(injector, sid)
            result = scanner.scan_response(resp, sid, turn_index=0)
            if result.detected:
                false_positives += 1

        assert false_positives == 0, f"Creative sessions: {false_positives} false positives (expected 0)"
