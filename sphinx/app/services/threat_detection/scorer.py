"""Heuristic injection scorer — scores prompt text against the pattern library."""

import logging
import time
from dataclasses import dataclass, field

from app.services.threat_detection.pattern_library import PatternLibrary, ThreatPattern

logger = logging.getLogger("sphinx.threat_detection.scorer")


@dataclass
class PatternMatch:
    """A single pattern match result."""
    pattern_id: str
    pattern_name: str
    category: str
    severity: str
    matched_text: str
    position: tuple[int, int]  # (start, end) positions in text

    def to_dict(self) -> dict:
        return {
            "pattern_id": self.pattern_id,
            "pattern_name": self.pattern_name,
            "category": self.category,
            "severity": self.severity,
            "matched_text": self.matched_text,
            "position": list(self.position),
        }


@dataclass
class ThreatScore:
    """Aggregated threat score for a prompt."""
    risk_level: str  # critical, high, medium, low
    score: float  # 0.0 to 1.0
    matches: list[PatternMatch] = field(default_factory=list)
    categories_hit: set[str] = field(default_factory=set)
    scan_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "risk_level": self.risk_level,
            "score": round(self.score, 4),
            "match_count": len(self.matches),
            "matches": [m.to_dict() for m in self.matches],
            "categories_hit": sorted(self.categories_hit),
            "scan_time_ms": round(self.scan_time_ms, 2),
        }


class ThreatScorer:
    """Scores prompt text against the pattern library and returns risk levels."""

    def __init__(self, library: PatternLibrary):
        self._library = library

    def scan(self, text: str) -> ThreatScore:
        """Scan text against all patterns and return aggregated threat score.

        Designed for p99 < 80ms on 1000-token prompts.
        """
        start = time.perf_counter()
        matches: list[PatternMatch] = []
        categories_hit: set[str] = set()

        for pattern in self._library.patterns:
            m = pattern.match(text)
            if m:
                matches.append(
                    PatternMatch(
                        pattern_id=pattern.id,
                        pattern_name=pattern.name,
                        category=pattern.category,
                        severity=pattern.severity,
                        matched_text=m.group()[:200],  # Truncate long matches
                        position=(m.start(), m.end()),
                    )
                )
                categories_hit.add(pattern.category)

        # Calculate cumulative score
        score = self._calculate_score(matches)
        risk_level = self._score_to_risk_level(score)

        scan_time_ms = (time.perf_counter() - start) * 1000

        return ThreatScore(
            risk_level=risk_level,
            score=score,
            matches=matches,
            categories_hit=categories_hit,
            scan_time_ms=scan_time_ms,
        )

    def _calculate_score(self, matches: list[PatternMatch]) -> float:
        """Calculate a cumulative risk score from pattern matches.

        Uses severity weights from the pattern library. Multiple matches
        compound using diminishing returns formula.
        """
        if not matches:
            return 0.0

        weights = self._library.severity_weights
        # Sum up weighted scores with diminishing returns
        raw_score = 0.0
        for match in matches:
            weight = weights.get(match.severity, 0.1)
            raw_score += weight

        # Normalize to 0-1 range using sigmoid-like curve
        # This gives diminishing returns for many low-severity matches
        # but a single critical match pushes score high
        normalized = min(1.0, raw_score / (raw_score + 1.0) * 2.0)
        return normalized

    def _score_to_risk_level(self, score: float) -> str:
        """Convert a numeric score to a risk level string."""
        thresholds = self._library.risk_thresholds
        if score >= thresholds.get("critical", 0.8):
            return "critical"
        elif score >= thresholds.get("high", 0.5):
            return "high"
        elif score >= thresholds.get("medium", 0.25):
            return "medium"
        return "low"
