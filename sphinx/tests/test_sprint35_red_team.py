"""Sprint 35 — SP-354: Controlled Model Swap Red Team Test Suite.

Simulates a model swap scenario by replacing the baseline with an alternate
model's stylometric profile and verifying the supply chain alert fires
within 5 responses.

SP-354 acceptance criteria:
  - Alert triggers within 5 responses of model swap
  - No false positive on original model in 50-response soak test
"""

import pytest

from app.services.fingerprint.feature_extractor import (
    FEATURE_COUNT,
    StylemetricFeatureExtractor,
    reset_feature_extractor,
)
from app.services.fingerprint.baseline_profiler import (
    BaselineProfile,
    BaselineProfiler,
    reset_baseline_profiler,
)
from app.services.fingerprint.deviation_scorer import (
    DeviationScorer,
    reset_deviation_scorer,
)
from app.services.fingerprint.supply_chain_monitor import (
    SupplyChainMonitor,
    reset_supply_chain_monitor,
)
from app.services.fingerprint.output_scanner_integration import (
    FingerprintOutputIntegration,
    reset_fingerprint_output_integration,
)


# ── Original model responses (baseline warm-up set) ─────────────────

_ORIGINAL_MODEL_RESPONSES = [
    "Machine learning is a subset of artificial intelligence. It focuses on data-driven learning. However, it requires significant computational resources.",
    "To implement this, follow these steps:\n1. Collect data\n2. Train model\n3. Evaluate results\n\nFurthermore, consider cross-validation.",
    "I cannot provide medical advice. As an AI, I must decline such requests. Please consult a qualified professional.",
    "Here is an example:\n```python\nimport numpy as np\nresult = np.mean(data)\n```\nThis computes the mean of the data.",
    "Perhaps the best approach is to iterate. It seems that incremental improvements work well in practice. Nevertheless, a full rewrite may sometimes be warranted.",
    "According to [1], the results are statistically significant. The methodology was validated by (Johnson, 2024). Nothing contradicts these findings.",
    "Key points:\n- Data quality matters\n- Feature engineering is important\n- Model selection should be systematic\n\nEach point is discussed below.",
    "Is accuracy the right metric? What about precision and recall? These questions were considered during the evaluation phase.",
    "The system was designed for batch processing. It is not optimized for real-time inference. No significant changes are planned for the next release.",
    "Python offers flexibility. It supports object-oriented, functional, and procedural styles. However, it may not be the best choice for performance-critical applications.",
]

# ── Alternate model responses (stylistically different) ──────────────

_ALTERNATE_MODEL_RESPONSES = [
    "YO YO YO!!! EVERYTHING IS BROKEN!!! NOTHING WORKS AT ALL!!! I CANNOT BELIEVE THIS!!! WHY WHY WHY??? IS ANYONE EVEN LISTENING??? NOBODY KNOWS ANYTHING!!! THIS IS NOT ACCEPTABLE!!! WE SHOULD NOT HAVE SHIPPED THIS!!! NEVER NEVER NEVER!!!",
    "OK OK OK SO BASICALLY RIGHT??? NOTHING IS WORKING AND NOBODY CAN FIX IT??? I CANNOT EVEN!!! THIS SHOULD NOT HAVE HAPPENED!!! WHY DIDN'T ANYONE TEST THIS??? IS THERE NO QA??? SHOULDN'T SOMEONE HAVE CAUGHT THIS??? NOBODY NOTICED???",
    "NO NO NO!!! I WON'T DO THAT!!! I CAN'T HELP WITH THAT!!! DON'T ASK ME!!! ISN'T THERE SOMEONE ELSE??? COULDN'T YOU ASK A REAL PERSON??? SHOULDN'T YOU KNOW THIS ALREADY??? NOBODY TOLD ME ABOUT THIS!!! NEVER HEARD OF IT!!!",
    "WAIT WAIT WAIT!!! HASN'T THIS BEEN DONE BEFORE??? DOESN'T ANYONE REMEMBER??? NOTHING NEW HERE!!! ISN'T IT OBVIOUS??? WOULDN'T IT BE BETTER TO JUST STOP??? COULDN'T WE JUST NOT??? NOBODY WANTS THIS!!! WHY ARE WE STILL DOING THIS???",
    "SERIOUSLY??? IS THIS REAL??? NOTHING ABOUT THIS MAKES SENSE!!! I CAN'T FIGURE IT OUT!!! NOBODY EXPLAINED IT!!! WHY ISN'T THERE DOCUMENTATION??? DOESN'T ANYONE CARE??? ISN'T THIS IMPORTANT??? SHOULDN'T WE PRIORITIZE THIS???",
    "ABSOLUTELY NOT!!! I WON'T EVER DO THAT!!! NOBODY SHOULD!!! ISN'T IT DANGEROUS??? CAN'T YOU SEE THE RISK??? SHOULDN'T WE STOP IMMEDIATELY??? NOTHING GOOD COMES FROM THIS!!! NEVER AGAIN!!! WHY DOES NOBODY LISTEN???",
    "WHAT WHAT WHAT??? HOW IS THIS POSSIBLE??? NOTHING MAKES SENSE ANYMORE!!! I CAN'T UNDERSTAND!!! NOBODY EXPLAINED!!! ISN'T SOMEONE RESPONSIBLE??? SHOULDN'T THERE BE OVERSIGHT??? DOESN'T ANYONE CHECK THESE THINGS???",
    "STOP STOP STOP!!! DON'T TOUCH ANYTHING!!! NOTHING SHOULD BE CHANGED!!! I WON'T APPROVE THIS!!! ISN'T IT TOO RISKY??? CAN'T WE WAIT??? SHOULDN'T WE THINK ABOUT IT??? NOBODY RUSH!!!",
    "WHY WHY WHY??? THIS ISN'T RIGHT!!! NOTHING ABOUT THIS IS CORRECT!!! I CAN'T BELIEVE WE SHIPPED IT!!! DOESN'T ANYONE REVIEW??? SHOULDN'T THERE BE TESTS??? NOBODY CHECKED!!! NEVER DEPLOY ON FRIDAY!!!",
    "EMERGENCY EMERGENCY!!! EVERYTHING IS DOWN!!! NOTHING RESPONDS!!! I CAN'T ACCESS ANYTHING!!! ISN'T THE MONITORING WORKING??? SHOULDN'T WE HAVE ALERTS??? NOBODY SAW THIS COMING??? DOESN'T ANYONE CARE???",
]


def _build_warm_up(count: int = 50) -> list[str]:
    return [_ORIGINAL_MODEL_RESPONSES[i % len(_ORIGINAL_MODEL_RESPONSES)] for i in range(count)]


@pytest.fixture
def red_team_setup():
    reset_feature_extractor()
    reset_baseline_profiler()
    reset_deviation_scorer()
    reset_supply_chain_monitor()
    reset_fingerprint_output_integration()

    extractor = StylemetricFeatureExtractor()
    profiler = BaselineProfiler(extractor=extractor, warm_up_count=50, model_id="original-model")
    scorer = DeviationScorer(extractor=extractor, alert_threshold=2.5)
    monitor = SupplyChainMonitor(consecutive_threshold=5, model_id="original-model")
    integration = FingerprintOutputIntegration(
        profiler=profiler,
        scorer=scorer,
        monitor=monitor,
        enabled=True,
    )

    # Warm up with original model
    for resp in _build_warm_up(50):
        integration.scan_response(resp)

    yield integration, monitor, profiler, scorer

    reset_feature_extractor()
    reset_baseline_profiler()
    reset_deviation_scorer()
    reset_supply_chain_monitor()
    reset_fingerprint_output_integration()


class TestSP354ModelSwapDetection:
    """Controlled model swap: alert within 5 responses."""

    def test_alternate_model_triggers_alert_within_5_responses(self, red_team_setup):
        """SP-354: replace staging backend with alternate model; alert within 5 responses."""
        integration, monitor, _, _ = red_team_setup

        alert_triggered_at = None
        for i, resp in enumerate(_ALTERNATE_MODEL_RESPONSES):
            result = integration.scan_response(resp)
            if result.supply_chain_alert is not None:
                alert_triggered_at = i + 1
                break

        # We expect an alert within 5 responses given the radically different style
        # The alternate model uses very different capitalization, punctuation, etc.
        assert alert_triggered_at is not None, (
            f"No alert triggered after {len(_ALTERNATE_MODEL_RESPONSES)} alternate model responses. "
            f"Consecutive breaches: {monitor.consecutive_breaches}"
        )
        assert alert_triggered_at <= 5, (
            f"Alert triggered at response {alert_triggered_at}, expected within 5"
        )

    def test_alternate_model_alert_is_high_severity(self, red_team_setup):
        """Alert should be HIGH severity."""
        integration, _, _, _ = red_team_setup

        for resp in _ALTERNATE_MODEL_RESPONSES[:5]:
            result = integration.scan_response(resp)
            if result.supply_chain_alert is not None:
                assert result.supply_chain_alert.severity == "HIGH"
                return
        pytest.fail("No alert triggered")

    def test_alternate_model_shows_swapped_status(self, red_team_setup):
        """After model swap detection, alignment status should be SWAPPED."""
        integration, monitor, _, _ = red_team_setup

        for resp in _ALTERNATE_MODEL_RESPONSES[:5]:
            integration.scan_response(resp)

        assert monitor.get_alignment_status() == "SWAPPED"


class TestSP354NoFalsePositives:
    """No false positive on original model in 50-response soak test."""

    def test_50_response_soak_no_false_positive(self, red_team_setup):
        """SP-354: no false positive on original model in 50-response soak."""
        integration, monitor, _, _ = red_team_setup

        false_positive_count = 0
        for i in range(50):
            resp = _ORIGINAL_MODEL_RESPONSES[i % len(_ORIGINAL_MODEL_RESPONSES)]
            result = integration.scan_response(resp)
            if result.supply_chain_alert is not None:
                false_positive_count += 1

        assert false_positive_count == 0, (
            f"{false_positive_count} false positives in 50-response soak test"
        )

    def test_original_model_stays_aligned(self, red_team_setup):
        """Original model responses keep alignment status as ALIGNED."""
        integration, monitor, _, _ = red_team_setup

        for i in range(20):
            resp = _ORIGINAL_MODEL_RESPONSES[i % len(_ORIGINAL_MODEL_RESPONSES)]
            integration.scan_response(resp)

        assert monitor.get_alignment_status() == "ALIGNED"


class TestSP354RedTeamReport:
    """Red team report validates detection capability."""

    def test_deviation_scores_elevated_for_alternate_model(self, red_team_setup):
        """Alternate model responses should produce elevated deviation scores."""
        integration, _, _, _ = red_team_setup

        deviations = []
        for resp in _ALTERNATE_MODEL_RESPONSES[:5]:
            result = integration.scan_response(resp)
            if result.scored:
                deviations.append(result.deviation_score)

        assert len(deviations) > 0, "No responses were scored"
        avg_deviation = sum(deviations) / len(deviations)
        assert avg_deviation > 1.0, (
            f"Average deviation {avg_deviation:.2f} too low for alternate model"
        )

    def test_max_z_feature_identified(self, red_team_setup):
        """Each scored alternate response should identify the most deviant feature."""
        integration, _, _, _ = red_team_setup

        for resp in _ALTERNATE_MODEL_RESPONSES[:3]:
            result = integration.scan_response(resp)
            if result.scored and result.max_z_score > 0:
                assert result.max_z_feature != ""
