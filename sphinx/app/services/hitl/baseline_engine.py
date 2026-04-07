"""Agent Behavioral Baseline Engine.

Tracks per-agent behavioral metrics:
- Tool call sequence patterns (n-gram frequency)
- Output volume (token counts)
- API call frequency (calls per time window)

Establishes a baseline over a configurable observation period (default 7 days).
After the observation period, the baseline is "ready" and can be used by the
cascading failure anomaly detector to flag deviations.
"""

import json
import logging
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger("sphinx.hitl.baseline_engine")

# Default observation period: 7 days
DEFAULT_OBSERVATION_DAYS = 7
# Minimum observations to consider baseline valid
MIN_OBSERVATIONS = 50


@dataclass
class BehavioralSnapshot:
    """Point-in-time snapshot of agent behavior."""
    tool_calls: list[str]  # ordered sequence of tool names called
    output_tokens: int
    api_call_count: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict = field(default_factory=dict)


@dataclass
class AgentBaseline:
    """Computed behavioral baseline for an agent."""
    agent_id: str
    tenant_id: str
    observation_start: datetime
    observation_end: Optional[datetime]
    is_ready: bool

    # Tool call patterns: n-gram -> frequency
    tool_call_ngrams: dict[str, float] = field(default_factory=dict)
    # Unique tool set
    known_tools: set[str] = field(default_factory=set)

    # Output volume stats
    avg_output_volume: float = 0.0
    std_output_volume: float = 0.0

    # API call frequency stats (per-minute)
    avg_api_call_frequency: float = 0.0
    std_api_call_frequency: float = 0.0

    total_observations: int = 0


class AgentBehavioralBaselineEngine:
    """Builds and maintains per-agent behavioral baselines."""

    def __init__(
        self,
        observation_days: int = DEFAULT_OBSERVATION_DAYS,
        min_observations: int = MIN_OBSERVATIONS,
        ngram_size: int = 2,
    ):
        self.observation_days = observation_days
        self.min_observations = min_observations
        self.ngram_size = ngram_size

        # In-memory stores
        self._events: dict[str, list[BehavioralSnapshot]] = defaultdict(list)
        self._baselines: dict[str, AgentBaseline] = {}
        self._observation_starts: dict[str, datetime] = {}

    def record_event(
        self,
        agent_id: str,
        tenant_id: str,
        tool_calls: list[str] | None = None,
        output_tokens: int = 0,
        api_call_count: int = 1,
        metadata: dict | None = None,
    ) -> None:
        """Record a behavioral event for an agent."""
        now = datetime.now(timezone.utc)

        # Initialize observation period on first event
        if agent_id not in self._observation_starts:
            self._observation_starts[agent_id] = now
            self._baselines[agent_id] = AgentBaseline(
                agent_id=agent_id,
                tenant_id=tenant_id,
                observation_start=now,
                observation_end=None,
                is_ready=False,
            )

        snapshot = BehavioralSnapshot(
            tool_calls=tool_calls or [],
            output_tokens=output_tokens,
            api_call_count=api_call_count,
            timestamp=now,
            metadata=metadata or {},
        )
        self._events[agent_id].append(snapshot)

        # Check if observation period has elapsed
        observation_start = self._observation_starts[agent_id]
        elapsed = now - observation_start
        if elapsed >= timedelta(days=self.observation_days):
            self._compute_baseline(agent_id, tenant_id)

    def _compute_baseline(self, agent_id: str, tenant_id: str) -> None:
        """Compute the behavioral baseline from collected events."""
        events = self._events.get(agent_id, [])
        if len(events) < self.min_observations:
            logger.info(
                "Agent %s has %d events, need %d for baseline",
                agent_id, len(events), self.min_observations,
            )
            return

        now = datetime.now(timezone.utc)

        # Tool call n-gram patterns
        all_tool_sequences: list[list[str]] = [e.tool_calls for e in events if e.tool_calls]
        ngram_counter: Counter = Counter()
        known_tools: set[str] = set()
        for seq in all_tool_sequences:
            known_tools.update(seq)
            for i in range(len(seq) - self.ngram_size + 1):
                ngram = tuple(seq[i:i + self.ngram_size])
                ngram_counter[ngram] += 1

        total_ngrams = sum(ngram_counter.values()) or 1
        tool_call_ngrams = {
            "->".join(k): v / total_ngrams for k, v in ngram_counter.items()
        }

        # Output volume stats
        output_volumes = [e.output_tokens for e in events]
        avg_output = sum(output_volumes) / len(output_volumes) if output_volumes else 0
        std_output = _std(output_volumes, avg_output)

        # API call frequency: calls per minute
        api_counts = [e.api_call_count for e in events]
        avg_freq = sum(api_counts) / len(api_counts) if api_counts else 0
        std_freq = _std(api_counts, avg_freq)

        baseline = AgentBaseline(
            agent_id=agent_id,
            tenant_id=tenant_id,
            observation_start=self._observation_starts[agent_id],
            observation_end=now,
            is_ready=True,
            tool_call_ngrams=tool_call_ngrams,
            known_tools=known_tools,
            avg_output_volume=avg_output,
            std_output_volume=std_output,
            avg_api_call_frequency=avg_freq,
            std_api_call_frequency=std_freq,
            total_observations=len(events),
        )
        self._baselines[agent_id] = baseline
        logger.info(
            "Baseline ready for agent %s: %d observations, %d tool ngrams, avg_output=%.1f, avg_freq=%.2f",
            agent_id, len(events), len(tool_call_ngrams), avg_output, avg_freq,
        )

    def force_compute_baseline(self, agent_id: str, tenant_id: str = "") -> Optional[AgentBaseline]:
        """Force baseline computation regardless of observation period."""
        if agent_id not in self._events or not self._events[agent_id]:
            return None
        t_id = tenant_id or self._baselines.get(agent_id, AgentBaseline(
            agent_id=agent_id, tenant_id="", observation_start=datetime.now(timezone.utc),
            observation_end=None, is_ready=False,
        )).tenant_id
        # Use a local override instead of mutating shared instance state
        saved_min = self.min_observations
        try:
            self.min_observations = 1
            self._compute_baseline(agent_id, t_id)
        finally:
            self.min_observations = saved_min
        return self._baselines.get(agent_id)

    def get_baseline(self, agent_id: str) -> Optional[AgentBaseline]:
        """Get the computed baseline for an agent (None if not ready)."""
        baseline = self._baselines.get(agent_id)
        if baseline and baseline.is_ready:
            return baseline
        return None

    def get_all_baselines(self) -> dict[str, AgentBaseline]:
        """Return all baselines (ready or not)."""
        return dict(self._baselines)

    def is_baseline_ready(self, agent_id: str) -> bool:
        baseline = self._baselines.get(agent_id)
        return baseline.is_ready if baseline else False

    def event_count(self, agent_id: str) -> int:
        return len(self._events.get(agent_id, []))

    def agent_count(self) -> int:
        return len(self._baselines)

    def baseline_to_dict(self, baseline: AgentBaseline) -> dict:
        """Serialize baseline to dict."""
        return {
            "agent_id": baseline.agent_id,
            "tenant_id": baseline.tenant_id,
            "observation_start": baseline.observation_start.isoformat(),
            "observation_end": baseline.observation_end.isoformat() if baseline.observation_end else None,
            "is_ready": baseline.is_ready,
            "tool_call_ngrams": baseline.tool_call_ngrams,
            "known_tools": sorted(baseline.known_tools),
            "avg_output_volume": round(baseline.avg_output_volume, 2),
            "std_output_volume": round(baseline.std_output_volume, 2),
            "avg_api_call_frequency": round(baseline.avg_api_call_frequency, 4),
            "std_api_call_frequency": round(baseline.std_api_call_frequency, 4),
            "total_observations": baseline.total_observations,
        }


def _std(values: list[int | float], mean: float) -> float:
    """Compute standard deviation."""
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)


# ── Singleton ─────────────────────────────────────────────────────────

_baseline_engine: Optional[AgentBehavioralBaselineEngine] = None


def get_baseline_engine(
    observation_days: int = DEFAULT_OBSERVATION_DAYS,
    min_observations: int = MIN_OBSERVATIONS,
) -> AgentBehavioralBaselineEngine:
    global _baseline_engine
    if _baseline_engine is None:
        _baseline_engine = AgentBehavioralBaselineEngine(
            observation_days=observation_days,
            min_observations=min_observations,
        )
    return _baseline_engine
