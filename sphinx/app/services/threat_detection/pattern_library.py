"""Threat pattern library — loads and manages YAML-configurable regex + keyword patterns."""

import logging
import os
import re
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger("sphinx.threat_detection.patterns")

DEFAULT_PATTERNS_PATH = Path(__file__).parent.parent.parent.parent / "config" / "threat_patterns.yaml"




# Maximum time in seconds for a single regex match (ReDoS protection)
_REGEX_MATCH_TIMEOUT_SECONDS = 1.0


def _validate_regex_safety(pattern: str) -> None:
    """Basic check for potentially catastrophic backtracking patterns.

    Raises ValueError for patterns with known dangerous constructs.
    """
    # Detect nested quantifiers like (a+)+, (a*)+, (a+)*, etc.
    import re as _re
    dangerous = _re.compile(r'\([^)]*[+*]\)[+*]')
    if dangerous.search(pattern):
        raise ValueError(f"Potentially catastrophic regex pattern detected (nested quantifiers): {pattern[:100]}")


class ThreatPattern:
    """A compiled threat detection pattern."""

    __slots__ = ("id", "name", "category", "severity", "pattern", "regex", "description", "tags")

    def __init__(
        self,
        id: str,
        name: str,
        category: str,
        severity: str,
        pattern: str,
        description: str = "",
        tags: list[str] | None = None,
    ):
        self.id = id
        self.name = name
        self.category = category
        self.severity = severity
        self.pattern = pattern
        _validate_regex_safety(pattern)
        self.regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        self.description = description
        self.tags = tags or []

    def match(self, text: str) -> Optional[re.Match]:
        """Test if pattern matches the given text. Returns the match object or None.

        Uses a length limit on input to mitigate ReDoS on complex patterns.
        """
        # Limit input length to prevent excessive backtracking
        truncated = text[:100_000] if len(text) > 100_000 else text
        return self.regex.search(truncated)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "pattern": self.pattern,
            "description": self.description,
            "tags": self.tags,
        }


class PatternLibrary:
    """Manages the collection of threat detection patterns loaded from YAML config."""

    def __init__(self):
        self._patterns: list[ThreatPattern] = []
        self._categories: dict[str, dict] = {}
        self._patterns_by_id: dict[str, ThreatPattern] = {}
        self._patterns_by_category: dict[str, list[ThreatPattern]] = {}
        self._patterns_by_severity: dict[str, list[ThreatPattern]] = {}
        self._default_actions: dict[str, str] = {}
        self._severity_weights: dict[str, float] = {}
        self._risk_thresholds: dict[str, float] = {}

    @property
    def patterns(self) -> list[ThreatPattern]:
        return self._patterns

    @property
    def default_actions(self) -> dict[str, str]:
        return self._default_actions

    @property
    def severity_weights(self) -> dict[str, float]:
        return self._severity_weights

    @property
    def risk_thresholds(self) -> dict[str, float]:
        return self._risk_thresholds

    def load_from_yaml(self, path: str | Path | None = None) -> int:
        """Load patterns from a YAML file. Returns the number of patterns loaded."""
        path = Path(path) if path else DEFAULT_PATTERNS_PATH
        if not path.exists():
            logger.warning("Threat patterns file not found: %s", path)
            return 0

        with open(path, "r") as f:
            config = yaml.safe_load(f)

        self._categories = config.get("categories", {})
        self._default_actions = config.get("default_actions", {})
        self._severity_weights = config.get("severity_weights", {})
        self._risk_thresholds = config.get("risk_thresholds", {})

        raw_patterns = config.get("patterns", [])
        self._patterns = []
        self._patterns_by_id = {}
        self._patterns_by_category = {}
        self._patterns_by_severity = {}

        for raw in raw_patterns:
            try:
                tp = ThreatPattern(
                    id=raw["id"],
                    name=raw["name"],
                    category=raw["category"],
                    severity=raw["severity"],
                    pattern=raw["pattern"],
                    description=raw.get("description", ""),
                    tags=raw.get("tags", []),
                )
                self._patterns.append(tp)
                self._patterns_by_id[tp.id] = tp
                self._patterns_by_category.setdefault(tp.category, []).append(tp)
                self._patterns_by_severity.setdefault(tp.severity, []).append(tp)
            except re.error as e:
                logger.error("Invalid regex in pattern %s: %s", raw.get("id", "?"), e)
            except KeyError as e:
                logger.error("Missing required field in pattern: %s", e)

        logger.info("Loaded %d threat patterns from %s", len(self._patterns), path)
        return len(self._patterns)

    def add_pattern(self, pattern: ThreatPattern) -> None:
        """Add a pattern dynamically (e.g. from a policy rule in DB)."""
        self._patterns.append(pattern)
        self._patterns_by_id[pattern.id] = pattern
        self._patterns_by_category.setdefault(pattern.category, []).append(pattern)
        self._patterns_by_severity.setdefault(pattern.severity, []).append(pattern)

    def remove_pattern(self, pattern_id: str) -> bool:
        """Remove a pattern by ID. Returns True if found and removed."""
        pattern = self._patterns_by_id.pop(pattern_id, None)
        if pattern is None:
            return False
        self._patterns = [p for p in self._patterns if p.id != pattern_id]
        cat_list = self._patterns_by_category.get(pattern.category, [])
        self._patterns_by_category[pattern.category] = [p for p in cat_list if p.id != pattern_id]
        sev_list = self._patterns_by_severity.get(pattern.severity, [])
        self._patterns_by_severity[pattern.severity] = [p for p in sev_list if p.id != pattern_id]
        return True

    def get_pattern(self, pattern_id: str) -> Optional[ThreatPattern]:
        return self._patterns_by_id.get(pattern_id)

    def get_by_category(self, category: str) -> list[ThreatPattern]:
        return self._patterns_by_category.get(category, [])

    def get_by_severity(self, severity: str) -> list[ThreatPattern]:
        return self._patterns_by_severity.get(severity, [])

    def count(self) -> int:
        return len(self._patterns)
