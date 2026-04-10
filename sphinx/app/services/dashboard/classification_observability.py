"""Sprint 5 — Thoth Classification Observability Dashboard.

Implements all five dashboard analytics surfaces required by Sprint 5:

  S5-T3  Intent category breakdown  — pie/bar chart of intent distribution
  S5-T4  Risk level heatmap         — risk_level × time-bucket for trends
  S5-T5  Confidence histogram        — distribution of confidence scores
  S5-T6  PII detection frequency    — PII type breakdown + trend over time
  S5-T7  Classification latency     — P50/P95/P99 Thoth API latency

All queries operate against the new classification_* columns added in
migration 024 (audit_logs schema v2).  Pre-Sprint-5 rows with NULL
classification columns are excluded from aggregations — no backfill needed.

Functional requirements addressed:
  FR-AUD-02  Audit records include classification timestamp, latency,
             classification version/model, intent label, risk label,
             confidence score, and enforcement decision.
  FR-AUD-04  Dashboard surfaces intent breakdown, risk heatmap, confidence
             histogram, and PII detection frequency.
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("sphinx.dashboard.classification_observability")

# ── Time-bucket granularities for heatmap ─────────────────────────────────

BUCKET_HOUR = "hour"
BUCKET_DAY = "day"

_VALID_BUCKETS = {BUCKET_HOUR, BUCKET_DAY}

# ── Response models ────────────────────────────────────────────────────────


class IntentCategoryCount(BaseModel):
    """Single intent category with request count (S5-T3)."""
    intent: str
    count: int
    percentage: float = 0.0


class IntentBreakdown(BaseModel):
    """Pie/bar chart data for intent category distribution (S5-T3)."""
    period_hours: int = 24
    generated_at: str = ""
    total_classified: int = 0
    categories: list[IntentCategoryCount] = Field(default_factory=list)


class RiskHeatmapCell(BaseModel):
    """One cell in the risk_level × time heatmap (S5-T4)."""
    time_bucket: str          # ISO-8601 timestamp of bucket start
    risk_level: str           # LOW | MEDIUM | HIGH | CRITICAL | UNKNOWN
    count: int


class RiskLevelHeatmap(BaseModel):
    """Risk level × time heatmap for trend detection (S5-T4)."""
    period_hours: int = 24
    bucket_size: str = BUCKET_HOUR  # "hour" | "day"
    generated_at: str = ""
    cells: list[RiskHeatmapCell] = Field(default_factory=list)


class ConfidenceBucket(BaseModel):
    """One bin in the confidence score histogram (S5-T5)."""
    bucket_label: str    # e.g. "0.80-0.90"
    lower: float
    upper: float
    count: int
    percentage: float = 0.0


class ConfidenceHistogram(BaseModel):
    """Distribution of Thoth classification confidence scores (S5-T5)."""
    period_hours: int = 24
    generated_at: str = ""
    total_classified: int = 0
    bucket_width: float = 0.10
    buckets: list[ConfidenceBucket] = Field(default_factory=list)
    mean_confidence: float = 0.0
    median_confidence: float = 0.0


class PIITypeCount(BaseModel):
    """Single PII type with detection count (S5-T6)."""
    pii_type: str
    count: int
    percentage: float = 0.0


class PIITrendPoint(BaseModel):
    """PII detection count at a time bucket (S5-T6)."""
    time_bucket: str
    count: int


class PIIDetectionFrequency(BaseModel):
    """PII type breakdown and trend over time (S5-T6)."""
    period_hours: int = 24
    bucket_size: str = BUCKET_HOUR
    generated_at: str = ""
    total_requests: int = 0
    pii_detected_count: int = 0
    pii_detection_rate: float = 0.0  # percentage
    type_breakdown: list[PIITypeCount] = Field(default_factory=list)
    trend: list[PIITrendPoint] = Field(default_factory=list)


class ClassificationLatencyPercentiles(BaseModel):
    """P50/P95/P99 Thoth API latency tracking (S5-T7)."""
    period_hours: int = 24
    generated_at: str = ""
    sample_count: int = 0
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    mean_ms: float = 0.0
    max_ms: float = 0.0
    # Fraction of requests that timed out (latency_ms == 0 from fallback)
    timeout_rate: float = 0.0


class ClassificationDashboardData(BaseModel):
    """Combined Sprint 5 classification dashboard payload."""
    generated_at: str = ""
    period_hours: int = 24
    intent_breakdown: IntentBreakdown = Field(default_factory=IntentBreakdown)
    risk_heatmap: RiskLevelHeatmap = Field(default_factory=RiskLevelHeatmap)
    confidence_histogram: ConfidenceHistogram = Field(default_factory=ConfidenceHistogram)
    pii_detection: PIIDetectionFrequency = Field(default_factory=PIIDetectionFrequency)
    latency_percentiles: ClassificationLatencyPercentiles = Field(
        default_factory=ClassificationLatencyPercentiles
    )


# ── Service ────────────────────────────────────────────────────────────────


class ClassificationObservabilityService:
    """Aggregates Thoth classification signals from audit_logs for dashboard.

    Implements FR-AUD-04: intent category breakdown, risk level heatmap,
    confidence score histogram, and PII detection frequency.
    """

    def __init__(self, session_factory=None):
        self._session_factory = session_factory

    # ── Public API ─────────────────────────────────────────────────────────

    async def get_full_dashboard(
        self,
        period_hours: int = 24 * 30,  # Default: 30-day window per sprint spec
        bucket_size: str = BUCKET_HOUR,
    ) -> ClassificationDashboardData:
        """Return all five dashboard views in one call."""
        now_iso = datetime.now(timezone.utc).isoformat()
        intent, risk, confidence, pii, latency = await _gather(
            self._get_intent_breakdown(period_hours),
            self._get_risk_heatmap(period_hours, bucket_size),
            self._get_confidence_histogram(period_hours),
            self._get_pii_detection(period_hours, bucket_size),
            self._get_latency_percentiles(period_hours),
        )
        return ClassificationDashboardData(
            generated_at=now_iso,
            period_hours=period_hours,
            intent_breakdown=intent,
            risk_heatmap=risk,
            confidence_histogram=confidence,
            pii_detection=pii,
            latency_percentiles=latency,
        )

    async def get_intent_breakdown(self, period_hours: int = 720) -> IntentBreakdown:
        return await self._get_intent_breakdown(period_hours)

    async def get_risk_heatmap(
        self, period_hours: int = 720, bucket_size: str = BUCKET_HOUR
    ) -> RiskLevelHeatmap:
        return await self._get_risk_heatmap(period_hours, bucket_size)

    async def get_confidence_histogram(self, period_hours: int = 720) -> ConfidenceHistogram:
        return await self._get_confidence_histogram(period_hours)

    async def get_pii_detection(
        self, period_hours: int = 720, bucket_size: str = BUCKET_HOUR
    ) -> PIIDetectionFrequency:
        return await self._get_pii_detection(period_hours, bucket_size)

    async def get_latency_percentiles(self, period_hours: int = 720) -> ClassificationLatencyPercentiles:
        return await self._get_latency_percentiles(period_hours)

    # ── S5-T3: Intent category breakdown ──────────────────────────────────

    async def _get_intent_breakdown(self, period_hours: int) -> IntentBreakdown:
        now = datetime.now(timezone.utc)
        result = IntentBreakdown(
            period_hours=period_hours,
            generated_at=now.isoformat(),
        )

        if not self._session_factory:
            return result

        cutoff_ts = (now - timedelta(hours=period_hours)).timestamp()

        from sqlalchemy import select, func
        from app.models.api_key import AuditLog

        async with self._session_factory() as db:
            rows = await db.execute(
                select(
                    AuditLog.classification_intent,
                    func.count(AuditLog.id).label("cnt"),
                )
                .where(AuditLog.event_timestamp >= cutoff_ts)
                .where(AuditLog.classification_intent.isnot(None))
                .where(AuditLog.classification_intent != "")
                .group_by(AuditLog.classification_intent)
                .order_by(func.count(AuditLog.id).desc())
            )
            rows = rows.all()

        total = sum(int(r[1]) for r in rows)
        result.total_classified = total
        for r in rows:
            count = int(r[1])
            result.categories.append(IntentCategoryCount(
                intent=r[0] or "unknown",
                count=count,
                percentage=round((count / total * 100) if total > 0 else 0.0, 2),
            ))
        return result

    # ── S5-T4: Risk level heatmap ──────────────────────────────────────────

    async def _get_risk_heatmap(
        self, period_hours: int, bucket_size: str
    ) -> RiskLevelHeatmap:
        if bucket_size not in _VALID_BUCKETS:
            bucket_size = BUCKET_HOUR
        now = datetime.now(timezone.utc)
        result = RiskLevelHeatmap(
            period_hours=period_hours,
            bucket_size=bucket_size,
            generated_at=now.isoformat(),
        )

        if not self._session_factory:
            return result

        cutoff_ts = (now - timedelta(hours=period_hours)).timestamp()
        bucket_seconds = 3600 if bucket_size == BUCKET_HOUR else 86400

        from sqlalchemy import select, func, cast, Integer
        from app.models.api_key import AuditLog

        async with self._session_factory() as db:
            # Bucket timestamps by flooring to bucket_seconds granularity
            bucket_expr = (
                cast(AuditLog.event_timestamp / bucket_seconds, Integer) * bucket_seconds
            )
            rows = await db.execute(
                select(
                    bucket_expr.label("bucket"),
                    AuditLog.classification_risk_level,
                    func.count(AuditLog.id).label("cnt"),
                )
                .where(AuditLog.event_timestamp >= cutoff_ts)
                .where(AuditLog.classification_risk_level.isnot(None))
                .where(AuditLog.classification_risk_level != "")
                .group_by(bucket_expr, AuditLog.classification_risk_level)
                .order_by(bucket_expr.asc())
            )
            for r in rows.all():
                bucket_ts = int(r[0])
                bucket_dt = datetime.fromtimestamp(bucket_ts, tz=timezone.utc)
                result.cells.append(RiskHeatmapCell(
                    time_bucket=bucket_dt.isoformat(),
                    risk_level=r[1] or "UNKNOWN",
                    count=int(r[2]),
                ))
        return result

    # ── S5-T5: Confidence histogram ────────────────────────────────────────

    async def _get_confidence_histogram(self, period_hours: int) -> ConfidenceHistogram:
        bucket_width = 0.10
        now = datetime.now(timezone.utc)
        result = ConfidenceHistogram(
            period_hours=period_hours,
            generated_at=now.isoformat(),
            bucket_width=bucket_width,
        )

        if not self._session_factory:
            return result

        cutoff_ts = (now - timedelta(hours=period_hours)).timestamp()

        from sqlalchemy import select
        from app.models.api_key import AuditLog

        async with self._session_factory() as db:
            rows = await db.execute(
                select(AuditLog.classification_confidence)
                .where(AuditLog.event_timestamp >= cutoff_ts)
                .where(AuditLog.classification_confidence.isnot(None))
            )
            scores = [float(r[0]) for r in rows.all() if r[0] is not None]

        if not scores:
            return result

        result.total_classified = len(scores)
        # Build 10 buckets: [0.0,0.10), [0.10,0.20), ..., [0.90,1.00]
        bins: dict[int, int] = defaultdict(int)
        for s in scores:
            idx = min(int(s / bucket_width), 9)
            bins[idx] += 1

        total = len(scores)
        for i in range(10):
            lower = round(i * bucket_width, 2)
            upper = round((i + 1) * bucket_width, 2)
            count = bins.get(i, 0)
            result.buckets.append(ConfidenceBucket(
                bucket_label=f"{lower:.2f}-{upper:.2f}",
                lower=lower,
                upper=upper,
                count=count,
                percentage=round((count / total * 100) if total > 0 else 0.0, 2),
            ))

        result.mean_confidence = round(sum(scores) / total, 4)
        sorted_scores = sorted(scores)
        result.median_confidence = round(_percentile(sorted_scores, 50), 4)
        return result

    # ── S5-T6: PII detection frequency ────────────────────────────────────

    async def _get_pii_detection(
        self, period_hours: int, bucket_size: str
    ) -> PIIDetectionFrequency:
        if bucket_size not in _VALID_BUCKETS:
            bucket_size = BUCKET_HOUR
        now = datetime.now(timezone.utc)
        result = PIIDetectionFrequency(
            period_hours=period_hours,
            bucket_size=bucket_size,
            generated_at=now.isoformat(),
        )

        if not self._session_factory:
            return result

        cutoff_ts = (now - timedelta(hours=period_hours)).timestamp()
        bucket_seconds = 3600 if bucket_size == BUCKET_HOUR else 86400

        from sqlalchemy import select, func, cast, Integer
        from app.models.api_key import AuditLog

        async with self._session_factory() as db:
            # Total classified rows in window
            total_row = await db.execute(
                select(func.count(AuditLog.id))
                .where(AuditLog.event_timestamp >= cutoff_ts)
                .where(AuditLog.classification_source.isnot(None))
            )
            result.total_requests = int(total_row.scalar() or 0)

            # PII-detected count
            pii_row = await db.execute(
                select(func.count(AuditLog.id))
                .where(AuditLog.event_timestamp >= cutoff_ts)
                .where(AuditLog.classification_pii_detected.is_(True))
            )
            result.pii_detected_count = int(pii_row.scalar() or 0)

            # PII types breakdown — stored as JSON-encoded list strings
            pii_rows = await db.execute(
                select(AuditLog.classification_pii_types)
                .where(AuditLog.event_timestamp >= cutoff_ts)
                .where(AuditLog.classification_pii_detected.is_(True))
                .where(AuditLog.classification_pii_types.isnot(None))
            )
            type_counts: dict[str, int] = defaultdict(int)
            for (pii_json,) in pii_rows.all():
                try:
                    types = json.loads(pii_json) if pii_json else []
                except (json.JSONDecodeError, TypeError):
                    types = []
                for t in types:
                    type_counts[str(t)] += 1

            total_type_hits = sum(type_counts.values())
            result.type_breakdown = [
                PIITypeCount(
                    pii_type=ptype,
                    count=cnt,
                    percentage=round(
                        (cnt / total_type_hits * 100) if total_type_hits > 0 else 0.0, 2
                    ),
                )
                for ptype, cnt in sorted(type_counts.items(), key=lambda x: -x[1])
            ]

            # PII trend over time
            bucket_expr = (
                cast(AuditLog.event_timestamp / bucket_seconds, Integer) * bucket_seconds
            )
            trend_rows = await db.execute(
                select(
                    bucket_expr.label("bucket"),
                    func.count(AuditLog.id).label("cnt"),
                )
                .where(AuditLog.event_timestamp >= cutoff_ts)
                .where(AuditLog.classification_pii_detected.is_(True))
                .group_by(bucket_expr)
                .order_by(bucket_expr.asc())
            )
            for r in trend_rows.all():
                bucket_dt = datetime.fromtimestamp(int(r[0]), tz=timezone.utc)
                result.trend.append(PIITrendPoint(
                    time_bucket=bucket_dt.isoformat(),
                    count=int(r[1]),
                ))

        if result.total_requests > 0:
            result.pii_detection_rate = round(
                result.pii_detected_count / result.total_requests * 100, 2
            )
        return result

    # ── S5-T7: Classification latency percentiles ──────────────────────────

    async def _get_latency_percentiles(self, period_hours: int) -> ClassificationLatencyPercentiles:
        now = datetime.now(timezone.utc)
        result = ClassificationLatencyPercentiles(
            period_hours=period_hours,
            generated_at=now.isoformat(),
        )

        if not self._session_factory:
            return result

        cutoff_ts = (now - timedelta(hours=period_hours)).timestamp()

        from sqlalchemy import select
        from app.models.api_key import AuditLog

        async with self._session_factory() as db:
            rows = await db.execute(
                select(AuditLog.classification_latency_ms, AuditLog.classification_source)
                .where(AuditLog.event_timestamp >= cutoff_ts)
                .where(AuditLog.classification_source.isnot(None))
                .where(AuditLog.classification_source != "")
            )
            all_rows = rows.all()

        if not all_rows:
            return result

        result.sample_count = len(all_rows)
        # Rows where source == structural_fallback and latency == 0 → timeout
        timeout_count = sum(
            1 for r in all_rows
            if r[1] == "structural_fallback" and (r[0] is None or r[0] == 0)
        )
        # Only include real Thoth latency values for percentile calculation
        latencies = [
            float(r[0]) for r in all_rows
            if r[0] is not None and r[0] > 0 and r[1] == "thoth"
        ]

        if latencies:
            sorted_lat = sorted(latencies)
            result.p50_ms = round(_percentile(sorted_lat, 50), 2)
            result.p95_ms = round(_percentile(sorted_lat, 95), 2)
            result.p99_ms = round(_percentile(sorted_lat, 99), 2)
            result.mean_ms = round(sum(latencies) / len(latencies), 2)
            result.max_ms = round(max(latencies), 2)

        result.timeout_rate = round(
            (timeout_count / result.sample_count * 100)
            if result.sample_count > 0 else 0.0,
            2,
        )
        return result


# ── Helpers ────────────────────────────────────────────────────────────────


def _percentile(sorted_values: list[float], p: float) -> float:
    """Compute the p-th percentile of a pre-sorted list (nearest-rank method)."""
    if not sorted_values:
        return 0.0
    n = len(sorted_values)
    rank = math.ceil(p / 100.0 * n) - 1
    return sorted_values[max(0, min(rank, n - 1))]


async def _gather(*coros):
    """Run coroutines concurrently and return results in order."""
    import asyncio
    return await asyncio.gather(*coros)


# ── Singleton ──────────────────────────────────────────────────────────────

_service: Optional[ClassificationObservabilityService] = None


def get_classification_observability(
    session_factory=None,
) -> ClassificationObservabilityService:
    global _service
    if _service is None:
        _service = ClassificationObservabilityService(session_factory=session_factory)
    return _service
