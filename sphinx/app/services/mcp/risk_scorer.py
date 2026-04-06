"""MCP Risk Scoring Engine — Sprint 15.

Scores each MCP tool/capability based on:
- Capability category (read/write/outbound/delete/admin)
- Data access scope (none/local/sensitive/external)
- External network access flag
- Destructive operations flag

Risk levels:
- Critical: outbound HTTP, write+delete
- High: write access, external data
- Medium: read + sensitive fields
- Low: read only
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger("sphinx.mcp.risk_scorer")


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class CapabilityRiskInput:
    """Input data for scoring a single capability."""
    tool_name: str
    capability_category: str = "read"  # read, write, outbound, delete, admin
    data_access_scope: str = "none"  # none, local, sensitive, external
    has_external_network_access: bool = False
    is_destructive: bool = False
    description: str = ""


@dataclass
class RiskScoreResult:
    """Result of risk scoring for a capability."""
    risk_score: float
    risk_level: RiskLevel
    factors: list[str]


# ── Category inference heuristics ────────────────────────────────────────

# Keywords that hint at capability categories
_OUTBOUND_KEYWORDS = {
    "http", "fetch", "request", "curl", "webhook", "send", "post",
    "upload", "email", "notify", "push", "publish", "forward",
}
_WRITE_KEYWORDS = {
    "write", "create", "insert", "update", "put", "set", "modify",
    "save", "store", "add", "append",
}
_DELETE_KEYWORDS = {
    "delete", "remove", "drop", "destroy", "purge", "truncate",
    "clear", "wipe", "erase",
}
_ADMIN_KEYWORDS = {
    "admin", "configure", "manage", "provision", "grant", "revoke",
    "escalate", "sudo", "root", "permission",
}
_SENSITIVE_KEYWORDS = {
    "password", "secret", "credential", "token", "key", "pii",
    "ssn", "credit_card", "phi", "hipaa", "gdpr",
}
_EXTERNAL_KEYWORDS = {
    "external", "remote", "api", "third_party", "cloud", "s3",
    "bucket", "endpoint",
}


def infer_capability_category(tool_name: str, description: str = "") -> str:
    """Infer capability category from tool name and description."""
    text = f"{tool_name} {description}".lower()
    # Order matters: more dangerous categories first
    if any(kw in text for kw in _ADMIN_KEYWORDS):
        return "admin"
    if any(kw in text for kw in _DELETE_KEYWORDS):
        return "delete"
    if any(kw in text for kw in _OUTBOUND_KEYWORDS):
        return "outbound"
    if any(kw in text for kw in _WRITE_KEYWORDS):
        return "write"
    return "read"


def infer_data_access_scope(tool_name: str, description: str = "") -> str:
    """Infer data access scope from tool name and description."""
    text = f"{tool_name} {description}".lower()
    if any(kw in text for kw in _SENSITIVE_KEYWORDS):
        return "sensitive"
    if any(kw in text for kw in _EXTERNAL_KEYWORDS):
        return "external"
    if any(kw in text for kw in _WRITE_KEYWORDS | _DELETE_KEYWORDS):
        return "local"
    return "none"


def infer_external_network_access(tool_name: str, description: str = "") -> bool:
    """Infer whether tool accesses external networks."""
    text = f"{tool_name} {description}".lower()
    return any(kw in text for kw in _OUTBOUND_KEYWORDS | _EXTERNAL_KEYWORDS)


def infer_destructive(tool_name: str, description: str = "") -> bool:
    """Infer whether tool performs destructive operations."""
    text = f"{tool_name} {description}".lower()
    return any(kw in text for kw in _DELETE_KEYWORDS)


# ── Scoring engine ───────────────────────────────────────────────────────

# Score weights per category
_CATEGORY_SCORES = {
    "read": 0.1,
    "write": 0.4,
    "outbound": 0.7,
    "delete": 0.8,
    "admin": 0.9,
}

_SCOPE_SCORES = {
    "none": 0.0,
    "local": 0.1,
    "sensitive": 0.3,
    "external": 0.4,
}


def score_capability(inp: CapabilityRiskInput) -> RiskScoreResult:
    """Score a single MCP capability and assign a risk level.

    Score is 0.0–1.0; risk level thresholds:
    - >= 0.7  → Critical
    - >= 0.4  → High
    - >= 0.2  → Medium
    - <  0.2  → Low
    """
    factors: list[str] = []
    score = 0.0

    # Category contribution
    cat_score = _CATEGORY_SCORES.get(inp.capability_category, 0.1)
    score += cat_score
    factors.append(f"category={inp.capability_category} (+{cat_score:.1f})")

    # Data access scope
    scope_score = _SCOPE_SCORES.get(inp.data_access_scope, 0.0)
    score += scope_score
    if scope_score > 0:
        factors.append(f"data_scope={inp.data_access_scope} (+{scope_score:.1f})")

    # External network access
    if inp.has_external_network_access:
        score += 0.2
        factors.append("external_network (+0.2)")

    # Destructive flag
    if inp.is_destructive:
        score += 0.2
        factors.append("destructive (+0.2)")

    # Clamp
    score = min(score, 1.0)

    # Determine level
    if score >= 0.7:
        level = RiskLevel.CRITICAL
    elif score >= 0.4:
        level = RiskLevel.HIGH
    elif score >= 0.2:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW

    return RiskScoreResult(risk_score=round(score, 2), risk_level=level, factors=factors)


def compute_server_aggregate_risk(capability_scores: list[RiskScoreResult]) -> tuple[float, RiskLevel]:
    """Compute aggregate risk for a server from its capabilities.

    Takes the maximum capability score as the server aggregate.
    """
    if not capability_scores:
        return 0.0, RiskLevel.LOW

    max_score = max(r.risk_score for r in capability_scores)
    if max_score >= 0.7:
        level = RiskLevel.CRITICAL
    elif max_score >= 0.4:
        level = RiskLevel.HIGH
    elif max_score >= 0.2:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW

    return round(max_score, 2), level
