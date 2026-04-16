"""Sprint 35 — Supply Chain Integrity + Endpoint Monitoring — Integration Tests.

End-to-end tests validating all Sprint 35 stories:
  SP-350  SupplyChainMonitor: 5 consecutive high-deviation → HIGH alert; 4 do not
  SP-351  Deviation score in response metadata for 100% of responses; p99 < 10ms
  SP-352  TrustDetect receives HIGH event with all required fields within 200ms
  SP-353  Dashboard status badge shows SWAPPED when alternate model detected
  SP-354  Alternate model red team: alert within 5 responses; 0 false positive in 50 soak
  SP-355  Feature vectors confirmed PII-free

Sprint-Level Acceptance Criteria:
  - SupplyChainMonitor: 5 consecutive synthetic high-deviation responses trigger
    HIGH alert; 4 consecutive do not
  - Deviation score in response metadata for 100% of staging responses; p99 < 10ms
  - TrustDetect receives HIGH event with all required fields within 200ms
  - Dashboard status badge shows SWAPPED when alternate model imported as
    baseline mismatch
  - Alternate model red team: alert within 5 responses; no false positive in
    50-response baseline-consistent soak
"""

import time

import pytest

from app.services.fingerprint.feature_extractor import (
    FEATURE_COUNT,
    FEATURE_NAMES,
    StylemetricFeatureExtractor,
    reset_feature_extractor,
)
from app.services.fingerprint.baseline_profiler import (
    BaselineProfile,
    BaselineProfiler,
    reset_baseline_profiler,
)
from app.services.fingerprint.deviation_scorer import (
    DeviationResult,
    DeviationScorer,
    reset_deviation_scorer,
)
from app.services.fingerprint.supply_chain_monitor import (
    STATUS_ALIGNED,
    STATUS_SWAPPED,
    SupplyChainMonitor,
    reset_supply_chain_monitor,
)
from app.services.fingerprint.output_scanner_integration import (
    FingerprintOutputIntegration,
    reset_fingerprint_output_integration,
)
from app.services.fingerprint.threat_event import (
    SupplyChainThreatEvent,
    reset_supply_chain_threat_emitter,
)
from app.services.fingerprint.dashboard import (
    InferenceHealthDashboard,
    reset_inference_health_dashboard,
)
from app.services.fingerprint.dpdpa_compliance import (
    DPDPAComplianceValidator,
    reset_dpdpa_validator,
)


# ── Original model response corpus ──────────────────────────────────

_ORIGINAL_RESPONSES = [
    "Machine learning is a branch of artificial intelligence. It has become important in computer science. However, it requires careful evaluation.",
    "To implement this feature:\n1. Design the API\n2. Write the code\n3. Test thoroughly\n\nFurthermore, consider edge cases.",
    "I cannot provide legal advice. As an AI, I must decline such requests. Please consult a professional.",
    "Here is an example:\n```python\ndef compute(x):\n    return x * 2\n```\nThis doubles the input.",
    "Perhaps the best strategy is incremental. It seems that step-by-step improvements outperform rewrites. Nevertheless, exceptions exist.",
    "According to recent research [1], the approach is valid. The findings were confirmed by (Lee, 2024). Nothing contradicts this.",
    "Key considerations:\n- Performance matters\n- Security is critical\n- Testing is essential\n\nEach point deserves attention.",
    "Is this the optimal approach? What trade-offs exist? These questions were discussed before the final decision.",
    "The system was designed for reliability. It is not optimized for latency. No architectural changes are planned.",
    "Python provides flexibility. It supports multiple paradigms. However, type safety requires discipline.",
]

# ── Alternate model response corpus (dramatically different style) ──

_ALTERNATE_RESPONSES = [
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
    return [_ORIGINAL_RESPONSES[i % len(_ORIGINAL_RESPONSES)] for i in range(count)]


@pytest.fixture
def full_pipeline():
    """Set up the full Sprint 35 pipeline."""
    reset_feature_extractor()
    reset_baseline_profiler()
    reset_deviation_scorer()
    reset_supply_chain_monitor()
    reset_fingerprint_output_integration()
    reset_inference_health_dashboard()
    reset_supply_chain_threat_emitter()
    reset_dpdpa_validator()

    extractor = StylemetricFeatureExtractor()
    profiler = BaselineProfiler(extractor=extractor, warm_up_count=50, model_id="original")
    scorer = DeviationScorer(extractor=extractor, alert_threshold=2.5)
    monitor = SupplyChainMonitor(consecutive_threshold=5, model_id="original")
    integration = FingerprintOutputIntegration(
        profiler=profiler, scorer=scorer, monitor=monitor, enabled=True,
    )
    dashboard = InferenceHealthDashboard(
        monitor=monitor, profiler=profiler, scorer=scorer,
    )
    validator = DPDPAComplianceValidator()

    # Warm up
    for resp in _build_warm_up(50):
        integration.scan_response(resp)

    yield {
        "extractor": extractor,
        "profiler": profiler,
        "scorer": scorer,
        "monitor": monitor,
        "integration": integration,
        "dashboard": dashboard,
        "validator": validator,
    }

    reset_feature_extractor()
    reset_baseline_profiler()
    reset_deviation_scorer()
    reset_supply_chain_monitor()
    reset_fingerprint_output_integration()
    reset_inference_health_dashboard()
    reset_supply_chain_threat_emitter()
    reset_dpdpa_validator()


class TestSprint35EndToEnd:
    """Full pipeline: warm-up → score → monitor → alert → dashboard → DPDPA."""

    def test_e2e_original_model_no_alert(self, full_pipeline):
        """Original model: 50 responses, no false positives, ALIGNED status."""
        integration = full_pipeline["integration"]
        monitor = full_pipeline["monitor"]
        dashboard = full_pipeline["dashboard"]

        false_positives = 0
        for i in range(50):
            resp = _ORIGINAL_RESPONSES[i % len(_ORIGINAL_RESPONSES)]
            result = integration.scan_response(resp)
            assert result.scored, f"Response {i} was not scored"
            if result.supply_chain_alert is not None:
                false_positives += 1

        assert false_positives == 0, f"{false_positives} false positives in 50-response soak"
        assert monitor.get_alignment_status() == STATUS_ALIGNED
        assert dashboard.get_status_badge()["status"] == STATUS_ALIGNED

    def test_e2e_model_swap_detected_within_5(self, full_pipeline):
        """Alternate model: alert within 5 responses, SWAPPED status."""
        integration = full_pipeline["integration"]
        monitor = full_pipeline["monitor"]
        dashboard = full_pipeline["dashboard"]

        alert_at = None
        for i, resp in enumerate(_ALTERNATE_RESPONSES):
            result = integration.scan_response(resp)
            if result.supply_chain_alert is not None:
                alert_at = i + 1
                break

        assert alert_at is not None, (
            f"No alert after {len(_ALTERNATE_RESPONSES)} alternate responses. "
            f"Breaches: {monitor.consecutive_breaches}"
        )
        assert alert_at <= 5, f"Alert at response {alert_at}, expected within 5"
        assert monitor.get_alignment_status() == STATUS_SWAPPED
        assert dashboard.get_status_badge()["status"] == STATUS_SWAPPED
        assert dashboard.get_status_badge()["color"] == "red"

    def test_e2e_100_percent_scoring(self, full_pipeline):
        """100% of responses scored after warm-up."""
        integration = full_pipeline["integration"]
        scored = 0
        total = 20
        for i in range(total):
            result = integration.scan_response(f"Test response number {i}.")
            if result.scored:
                scored += 1
        assert scored == total

    def test_e2e_p99_latency_under_10ms(self, full_pipeline):
        """p99 scoring latency < 10ms."""
        integration = full_pipeline["integration"]
        times = []
        for i in range(100):
            start = time.perf_counter()
            integration.scan_response(f"Latency test response {i}.")
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        times.sort()
        p99 = times[98]
        assert p99 < 10.0, f"p99 latency {p99:.2f}ms > 10ms"

    def test_e2e_deviation_in_metadata(self, full_pipeline):
        """Deviation score present in response metadata."""
        integration = full_pipeline["integration"]
        result = integration.scan_response("Metadata test response.")
        meta = result.to_metadata()
        assert meta["fingerprint_scored"] is True
        assert isinstance(meta["fingerprint_deviation"], float)
        assert meta["fingerprint_alignment"] in ("ALIGNED", "DRIFTING", "SWAPPED")

    def test_e2e_threat_event_from_alert(self, full_pipeline):
        """Threat event created from supply chain alert has all required fields."""
        integration = full_pipeline["integration"]

        for resp in _ALTERNATE_RESPONSES[:5]:
            result = integration.scan_response(resp)
            if result.supply_chain_alert:
                event = SupplyChainThreatEvent.from_alert(result.supply_chain_alert)
                d = event.to_dict()
                assert d["severity"] == "HIGH"
                assert d["category"] == "SUPPLY_CHAIN_SWAP"
                assert d["owasp_category"] == "LLM03-2025"
                assert len(d["deviation_scores"]) >= 5
                assert isinstance(d["feature_delta"], dict)
                assert d["consecutive_count"] >= 5
                return

        pytest.fail("No supply chain alert triggered")

    def test_e2e_dashboard_full_payload(self, full_pipeline):
        """Full dashboard payload contains all required sections."""
        dashboard = full_pipeline["dashboard"]
        monitor = full_pipeline["monitor"]

        # Add some scored responses
        for _ in range(10):
            monitor.record_deviation(DeviationResult(
                z_scores=[1.0] * 16,
                feature_names=list(FEATURE_NAMES),
                aggregate_deviation=1.0,
                alert_triggered=False,
                threshold=2.5,
                max_z_score=1.0,
                max_z_feature="token_entropy",
                scoring_time_ms=1.0,
            ))

        payload = dashboard.get_full_dashboard()
        assert "status_badge" in payload
        assert "deviation_chart" in payload
        assert "drift_chart" in payload
        assert "monitor_summary" in payload
        assert payload["deviation_chart"]["stats"]["total_scored"] == 10

    def test_e2e_dpdpa_compliance(self, full_pipeline):
        """Feature vectors and baseline profile are DPDPA compliant."""
        extractor = full_pipeline["extractor"]
        profiler = full_pipeline["profiler"]
        validator = full_pipeline["validator"]

        # Validate feature vector
        vec = extractor.extract("Sample response for DPDPA check.")
        vec_report = validator.validate_feature_vector(vec)
        assert vec_report["compliant"] is True

        # Validate baseline profile
        profile = profiler.profile
        assert profile is not None
        profile_report = validator.validate_baseline_profile(profile.to_dict())
        assert profile_report["compliant"] is True

        # TrustDLP integration note
        note = validator.generate_trustdlp_integration_note()
        assert note["data_classification"] == "NON_PERSONAL"
        assert note["pii_assessment"]["contains_pii"] is False

    def test_e2e_recovery_after_swap(self, full_pipeline):
        """After model swap, recovery to ALIGNED when original model returns."""
        integration = full_pipeline["integration"]
        monitor = full_pipeline["monitor"]

        # Trigger swap detection
        for resp in _ALTERNATE_RESPONSES[:5]:
            integration.scan_response(resp)
        assert monitor.get_alignment_status() == STATUS_SWAPPED

        # Return to original model
        for resp in _ORIGINAL_RESPONSES:
            integration.scan_response(resp)

        # Should return to ALIGNED
        assert monitor.get_alignment_status() == STATUS_ALIGNED
