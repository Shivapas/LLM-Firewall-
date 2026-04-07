"""Cascading Failure Anomaly Detector.

Detects deviations from agent behavioral baselines and implements a
threshold-based circuit breaker per agent:
- Open on N consecutive anomalous actions within a time window
- Half-open after recovery timeout to probe
- Closed on successful probe

Anomaly types:
- volume_spike: Output volume > mean + k*std
- frequency_spike: API call frequency > mean + k*std
- pattern_deviation: Tool call sequence not in known baseline patterns
- unknown_tool: Tool not seen during observation period
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from app.services.hitl.baseline_engine import AgentBaseline, AgentBehavioralBaselineEngine

logger = logging.getLogger("sphinx.hitl.anomaly_detector")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class AnomalyResult:
    """Result of anomaly detection on a single behavioral event."""
    is_anomalous: bool
    anomaly_types: list[str] = field(default_factory=list)
    deviation_scores: dict[str, float] = field(default_factory=dict)
    overall_deviation: float = 0.0
    circuit_state: str = "closed"
    action: str = "allow"  # allow, block, alert
    details: str = ""


@dataclass
class AgentCircuitBreaker:
    """Per-agent circuit breaker state for cascading failure detection."""
    agent_id: str
    state: CircuitState = CircuitState.CLOSED
    consecutive_anomalies: int = 0
    last_anomaly_at: Optional[datetime] = None
    opened_at: Optional[datetime] = None
    half_open_at: Optional[datetime] = None
    total_anomalies: int = 0
    total_checks: int = 0


class CascadingFailureAnomalyDetector:
    """Detects anomalous agent behavior and manages per-agent circuit breakers."""

    def __init__(
        self,
        baseline_engine: AgentBehavioralBaselineEngine,
        anomaly_threshold: float = 2.5,  # z-score threshold
        consecutive_anomalies_to_open: int = 5,
        anomaly_window_seconds: int = 300,  # 5 minutes
        recovery_timeout_seconds: int = 60,
        half_open_max_probes: int = 2,
    ):
        self._baseline_engine = baseline_engine
        self.anomaly_threshold = anomaly_threshold
        self.consecutive_to_open = consecutive_anomalies_to_open
        self.anomaly_window = timedelta(seconds=anomaly_window_seconds)
        self.recovery_timeout = timedelta(seconds=recovery_timeout_seconds)
        self.half_open_max_probes = half_open_max_probes

        self._breakers: dict[str, AgentCircuitBreaker] = {}
        self._anomaly_history: list[dict] = []

    def _get_breaker(self, agent_id: str) -> AgentCircuitBreaker:
        if agent_id not in self._breakers:
            self._breakers[agent_id] = AgentCircuitBreaker(agent_id=agent_id)
        return self._breakers[agent_id]

    def check(
        self,
        agent_id: str,
        tool_calls: list[str] | None = None,
        output_tokens: int = 0,
        api_call_count: int = 1,
    ) -> AnomalyResult:
        """Check an agent's current behavior against its baseline.

        Returns AnomalyResult with detection details and circuit breaker action.
        """
        now = datetime.now(timezone.utc)
        breaker = self._get_breaker(agent_id)
        breaker.total_checks += 1

        # Check circuit breaker state first
        if breaker.state == CircuitState.OPEN:
            # Check if recovery timeout has elapsed
            if breaker.opened_at and (now - breaker.opened_at) >= self.recovery_timeout:
                breaker.state = CircuitState.HALF_OPEN
                breaker.half_open_at = now
                logger.info("Agent %s circuit breaker -> half_open", agent_id)
            else:
                return AnomalyResult(
                    is_anomalous=True,
                    circuit_state=CircuitState.OPEN.value,
                    action="block",
                    details=f"Circuit breaker OPEN for agent {agent_id}; requests blocked",
                )

        # Get baseline
        baseline = self._baseline_engine.get_baseline(agent_id)
        if not baseline:
            # No baseline yet — allow through, still in observation period
            return AnomalyResult(
                is_anomalous=False,
                circuit_state=breaker.state.value,
                action="allow",
                details="No baseline available; agent in observation period",
            )

        # Detect anomalies
        anomaly_types = []
        deviation_scores = {}

        # 1. Output volume spike
        if baseline.std_output_volume > 0:
            z_vol = (output_tokens - baseline.avg_output_volume) / baseline.std_output_volume
            deviation_scores["volume"] = round(z_vol, 4)
            if z_vol > self.anomaly_threshold:
                anomaly_types.append("volume_spike")

        # 2. API call frequency spike
        if baseline.std_api_call_frequency > 0:
            z_freq = (api_call_count - baseline.avg_api_call_frequency) / baseline.std_api_call_frequency
            deviation_scores["frequency"] = round(z_freq, 4)
            if z_freq > self.anomaly_threshold:
                anomaly_types.append("frequency_spike")

        # 3. Tool call pattern deviation
        if tool_calls and baseline.tool_call_ngrams:
            unknown_tools = [t for t in tool_calls if t not in baseline.known_tools]
            if unknown_tools:
                anomaly_types.append("unknown_tool")
                deviation_scores["unknown_tools"] = len(unknown_tools)

            # Check n-gram patterns
            ngram_size = 2
            for i in range(len(tool_calls) - ngram_size + 1):
                ngram_key = "->".join(tool_calls[i:i + ngram_size])
                if ngram_key not in baseline.tool_call_ngrams:
                    if "pattern_deviation" not in anomaly_types:
                        anomaly_types.append("pattern_deviation")
                    deviation_scores.setdefault("unseen_ngrams", 0)
                    deviation_scores["unseen_ngrams"] += 1

        is_anomalous = len(anomaly_types) > 0
        overall_deviation = max(
            abs(deviation_scores.get("volume", 0)),
            abs(deviation_scores.get("frequency", 0)),
            deviation_scores.get("unknown_tools", 0),
            deviation_scores.get("unseen_ngrams", 0),
        )

        # Update circuit breaker
        if is_anomalous:
            breaker.total_anomalies += 1
            breaker.last_anomaly_at = now

            # Check if within anomaly window
            if breaker.consecutive_anomalies == 0 or (
                breaker.last_anomaly_at
                and (now - breaker.last_anomaly_at) <= self.anomaly_window
            ):
                breaker.consecutive_anomalies += 1
            else:
                breaker.consecutive_anomalies = 1

            # Trip circuit breaker if threshold reached
            if breaker.consecutive_anomalies >= self.consecutive_to_open:
                if breaker.state == CircuitState.HALF_OPEN:
                    # Probe failed, reopen
                    breaker.state = CircuitState.OPEN
                    breaker.opened_at = now
                    logger.warning(
                        "Agent %s circuit breaker -> OPEN (probe failed, %d consecutive anomalies)",
                        agent_id, breaker.consecutive_anomalies,
                    )
                elif breaker.state == CircuitState.CLOSED:
                    breaker.state = CircuitState.OPEN
                    breaker.opened_at = now
                    logger.warning(
                        "Agent %s circuit breaker -> OPEN (%d consecutive anomalies in window)",
                        agent_id, breaker.consecutive_anomalies,
                    )

            self._anomaly_history.append({
                "agent_id": agent_id,
                "anomaly_types": anomaly_types,
                "deviation_scores": deviation_scores,
                "circuit_state": breaker.state.value,
                "timestamp": now.isoformat(),
            })
        else:
            # Normal behavior
            if breaker.state == CircuitState.HALF_OPEN:
                breaker.consecutive_anomalies = 0
                breaker.state = CircuitState.CLOSED
                logger.info("Agent %s circuit breaker -> CLOSED (probe succeeded)", agent_id)
            elif breaker.state == CircuitState.CLOSED:
                breaker.consecutive_anomalies = 0

        action = "allow"
        if breaker.state == CircuitState.OPEN:
            action = "block"
        elif is_anomalous:
            action = "alert"

        return AnomalyResult(
            is_anomalous=is_anomalous,
            anomaly_types=anomaly_types,
            deviation_scores=deviation_scores,
            overall_deviation=overall_deviation,
            circuit_state=breaker.state.value,
            action=action,
            details=f"Detected {len(anomaly_types)} anomaly type(s)" if is_anomalous
            else "Behavior within baseline norms",
        )

    def get_circuit_state(self, agent_id: str) -> str:
        breaker = self._breakers.get(agent_id)
        return breaker.state.value if breaker else CircuitState.CLOSED.value

    def force_circuit_state(self, agent_id: str, state: str) -> None:
        """Admin override: force a circuit breaker state."""
        breaker = self._get_breaker(agent_id)
        breaker.state = CircuitState(state)
        now = datetime.now(timezone.utc)
        if state == "open":
            breaker.opened_at = now
        elif state == "half_open":
            breaker.half_open_at = now
        elif state == "closed":
            breaker.consecutive_anomalies = 0
        logger.info("Agent %s circuit breaker forced to %s", agent_id, state)

    def get_all_breakers(self) -> dict[str, dict]:
        """Return all circuit breaker states."""
        result = {}
        for agent_id, breaker in self._breakers.items():
            result[agent_id] = {
                "agent_id": breaker.agent_id,
                "state": breaker.state.value,
                "consecutive_anomalies": breaker.consecutive_anomalies,
                "total_anomalies": breaker.total_anomalies,
                "total_checks": breaker.total_checks,
                "last_anomaly_at": breaker.last_anomaly_at.isoformat() if breaker.last_anomaly_at else None,
                "opened_at": breaker.opened_at.isoformat() if breaker.opened_at else None,
            }
        return result

    def get_anomaly_history(self, limit: int = 100) -> list[dict]:
        return self._anomaly_history[-limit:]

    def anomaly_count(self) -> int:
        return len(self._anomaly_history)


# ── Singleton ─────────────────────────────────────────────────────────

_anomaly_detector: Optional[CascadingFailureAnomalyDetector] = None


def get_anomaly_detector(
    baseline_engine: Optional[AgentBehavioralBaselineEngine] = None,
) -> CascadingFailureAnomalyDetector:
    global _anomaly_detector
    if _anomaly_detector is None:
        if baseline_engine is None:
            from app.services.hitl.baseline_engine import get_baseline_engine
            baseline_engine = get_baseline_engine()
        _anomaly_detector = CascadingFailureAnomalyDetector(
            baseline_engine=baseline_engine,
        )
    return _anomaly_detector
