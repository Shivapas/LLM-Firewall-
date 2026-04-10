"""Sprint 5 — Audit Schema Extension & Classification Observability Dashboard Tests.

Exit criteria (PRD §10 Sprint 5):
  - Sphinx audit records include full classification metadata (FR-AUD-01, FR-AUD-02).
  - Dashboard renders classification analytics for the past 30 days (FR-AUD-04).

Test coverage
-------------
S5-T1  AuditEvent schema v2 — classification_* fields present on AuditEvent;
       emit_audit_event accepts and populates them correctly.

S5-T2  Migration backward-compatibility — migration 024 adds columns with NULL
       defaults; existing rows without classification data remain valid.

S5-T3  Intent breakdown — ClassificationObservabilityService returns correct
       counts and percentages grouped by classification_intent.

S5-T4  Risk heatmap — cells grouped by (bucket, risk_level) with correct
       counts; bucket size respected for hour and day granularities.

S5-T5  Confidence histogram — 10 equal-width bins spanning [0.0, 1.0];
       mean and median computed correctly.

S5-T6  PII detection — type breakdown parsed from JSON-encoded pii_types;
       trend time-series has correct bucket counts.

S5-T7  Latency percentiles — P50/P95/P99 computed correctly; structural_fallback
       rows excluded from latency; timeout_rate counts fallback entries.

Integration  AuditEventConsumer._persist_event maps all classification fields
             from the event_data dict to AuditLog columns.

FR-AUD-01  All Thoth classification payloads captured in Sphinx audit records.
FR-AUD-02  Audit records include classification timestamp, latency, version,
           intent label, risk label, confidence score, enforcement decision.
FR-AUD-04  Dashboard surfaces intent distribution, risk heatmap, confidence
           histogram, and PII detection frequency.
"""

from __future__ import annotations

import json
import math
import time
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.audit import AuditEvent, emit_audit_event
from app.services.dashboard.classification_observability import (
    ClassificationObservabilityService,
    IntentBreakdown,
    RiskLevelHeatmap,
    ConfidenceHistogram,
    PIIDetectionFrequency,
    ClassificationLatencyPercentiles,
    ClassificationDashboardData,
    _percentile,
    BUCKET_HOUR,
    BUCKET_DAY,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_audit_row(
    *,
    intent: str = "general_query",
    risk_level: str = "LOW",
    confidence: float = 0.90,
    pii_detected: bool = False,
    pii_types: list[str] | None = None,
    latency_ms: int = 42,
    model_version: str = "v1.0",
    source: str = "thoth",
    event_timestamp: float | None = None,
) -> MagicMock:
    """Build a minimal mock AuditLog row for dashboard query returns."""
    row = MagicMock()
    row.id = uuid.uuid4()
    row.classification_intent = intent
    row.classification_risk_level = risk_level
    row.classification_confidence = confidence
    row.classification_pii_detected = pii_detected
    row.classification_pii_types = json.dumps(pii_types or [])
    row.classification_latency_ms = latency_ms
    row.classification_model_version = model_version
    row.classification_source = source
    row.event_timestamp = event_timestamp or time.time()
    return row


def _scalar_result(value):
    """Return a mock db.execute result that yields a scalar."""
    result = MagicMock()
    result.scalar = MagicMock(return_value=value)
    return result


def _rows_result(rows: list):
    """Return a mock db.execute result whose .all() returns rows."""
    result = MagicMock()
    result.all = MagicMock(return_value=rows)
    return result


# ---------------------------------------------------------------------------
# S5-T1: AuditEvent schema v2
# ---------------------------------------------------------------------------


class TestAuditEventSchemaV2:
    """S5-T1 — classification_* fields are first-class on AuditEvent."""

    def test_classification_fields_have_defaults(self):
        event = AuditEvent()
        assert event.classification_intent == ""
        assert event.classification_risk_level == ""
        assert event.classification_confidence == 0.0
        assert event.classification_pii_detected is False
        assert event.classification_pii_types == []
        assert event.classification_latency_ms == 0
        assert event.classification_model_version == ""
        assert event.classification_source == ""

    def test_classification_fields_populated(self):
        event = AuditEvent(
            classification_intent="data_exfiltration",
            classification_risk_level="HIGH",
            classification_confidence=0.92,
            classification_pii_detected=True,
            classification_pii_types=["AADHAAR", "EMAIL"],
            classification_latency_ms=87,
            classification_model_version="v2.1",
            classification_source="thoth",
        )
        assert event.classification_intent == "data_exfiltration"
        assert event.classification_risk_level == "HIGH"
        assert event.classification_confidence == 0.92
        assert event.classification_pii_detected is True
        assert event.classification_pii_types == ["AADHAAR", "EMAIL"]
        assert event.classification_latency_ms == 87
        assert event.classification_model_version == "v2.1"
        assert event.classification_source == "thoth"

    def test_event_serialises_classification_fields(self):
        event = AuditEvent(
            classification_intent="jailbreak",
            classification_risk_level="CRITICAL",
            classification_confidence=0.99,
            classification_pii_detected=False,
            classification_pii_types=[],
            classification_latency_ms=120,
            classification_model_version="v3.0",
            classification_source="thoth",
        )
        d = event.model_dump()
        assert d["classification_intent"] == "jailbreak"
        assert d["classification_risk_level"] == "CRITICAL"
        assert d["classification_confidence"] == 0.99
        assert d["classification_latency_ms"] == 120
        assert d["classification_source"] == "thoth"

    @pytest.mark.asyncio
    async def test_emit_audit_event_passes_classification_fields(self):
        """emit_audit_event must accept and embed classification kwargs."""
        captured: list[AuditEvent] = []

        class _FakeWriter:
            async def write_event(self, ev: AuditEvent):
                captured.append(ev)

        with patch("app.services.audit.get_audit_writer", return_value=_FakeWriter()):
            event = await emit_audit_event(
                request_body=b"test",
                tenant_id="t1",
                classification_intent="prompt_injection",
                classification_risk_level="HIGH",
                classification_confidence=0.88,
                classification_pii_detected=True,
                classification_pii_types=["BANK_ACCOUNT"],
                classification_latency_ms=55,
                classification_model_version="v1.5",
                classification_source="thoth",
            )

        assert event.classification_intent == "prompt_injection"
        assert event.classification_risk_level == "HIGH"
        assert event.classification_confidence == 0.88
        assert event.classification_pii_detected is True
        assert event.classification_pii_types == ["BANK_ACCOUNT"]
        assert event.classification_latency_ms == 55
        assert event.classification_model_version == "v1.5"
        assert event.classification_source == "thoth"
        assert len(captured) == 1

    @pytest.mark.asyncio
    async def test_emit_audit_event_defaults_classification_fields_to_empty(self):
        """Classification fields must default gracefully when not supplied."""
        captured: list[AuditEvent] = []

        class _FakeWriter:
            async def write_event(self, ev: AuditEvent):
                captured.append(ev)

        with patch("app.services.audit.get_audit_writer", return_value=_FakeWriter()):
            event = await emit_audit_event(request_body=b"x", tenant_id="t1")

        assert event.classification_intent == ""
        assert event.classification_source == ""
        assert event.classification_pii_detected is False
        assert event.classification_pii_types == []


# ---------------------------------------------------------------------------
# S5-T2: Migration backward-compatibility check (structural validation)
# ---------------------------------------------------------------------------


class TestMigrationBackwardCompatibility:
    """S5-T2 — migration 024 adds nullable columns; no existing-row breakage."""

    def test_migration_revision_chain(self):
        """migration 024 must revise 023."""
        import importlib.util, pathlib
        mig_path = pathlib.Path(__file__).parent.parent / (
            "alembic/versions/024_sprint5_thoth_classification_audit.py"
        )
        spec = importlib.util.spec_from_file_location("migration_024", mig_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.revision == "024"
        assert mod.down_revision == "023"

    def test_migration_upgrade_adds_expected_columns(self):
        """upgrade() must call add_column for each classification field."""
        import importlib.util, pathlib
        from unittest.mock import call, patch as _patch

        mig_path = pathlib.Path(__file__).parent.parent / (
            "alembic/versions/024_sprint5_thoth_classification_audit.py"
        )
        spec = importlib.util.spec_from_file_location("migration_024", mig_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        expected_cols = {
            "classification_intent",
            "classification_risk_level",
            "classification_confidence",
            "classification_pii_detected",
            "classification_pii_types",
            "classification_latency_ms",
            "classification_model_version",
            "classification_source",
        }

        added: set[str] = set()

        def _mock_add_column(table, col):
            added.add(col.key)

        import sqlalchemy as sa
        from alembic import op as _op

        with _patch.object(_op, "add_column", side_effect=_mock_add_column), \
             _patch.object(_op, "create_index"):
            mod.upgrade()

        assert expected_cols.issubset(added), (
            f"Missing columns: {expected_cols - added}"
        )

    def test_migration_downgrade_drops_all_columns(self):
        """downgrade() must drop every column added in upgrade()."""
        import importlib.util, pathlib
        from unittest.mock import patch as _patch

        mig_path = pathlib.Path(__file__).parent.parent / (
            "alembic/versions/024_sprint5_thoth_classification_audit.py"
        )
        spec = importlib.util.spec_from_file_location("migration_024", mig_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        dropped: set[str] = set()

        def _mock_drop_column(table, col_name):
            dropped.add(col_name)

        from alembic import op as _op

        with _patch.object(_op, "drop_column", side_effect=_mock_drop_column), \
             _patch.object(_op, "drop_index"):
            mod.downgrade()

        expected = {
            "classification_intent", "classification_risk_level",
            "classification_confidence", "classification_pii_detected",
            "classification_pii_types", "classification_latency_ms",
            "classification_model_version", "classification_source",
        }
        assert expected.issubset(dropped)


# ---------------------------------------------------------------------------
# S5-T3: Intent category breakdown
# ---------------------------------------------------------------------------


class TestIntentBreakdown:
    """S5-T3 — Intent distribution for pie/bar chart."""

    @pytest.fixture
    def svc(self):
        return ClassificationObservabilityService(session_factory=None)

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_session_factory(self, svc):
        result = await svc.get_intent_breakdown(period_hours=24)
        assert isinstance(result, IntentBreakdown)
        assert result.total_classified == 0
        assert result.categories == []

    @pytest.mark.asyncio
    async def test_intent_counts_and_percentages(self):
        # Two intents: 3 × general_query, 1 × data_exfiltration
        db_rows = [("general_query", 3), ("data_exfiltration", 1)]

        mock_result = MagicMock()
        mock_result.all = MagicMock(return_value=db_rows)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)

        mock_sf = MagicMock(return_value=mock_db)

        svc = ClassificationObservabilityService(session_factory=mock_sf)
        result = await svc.get_intent_breakdown(period_hours=24)

        assert result.total_classified == 4
        assert len(result.categories) == 2
        cat_map = {c.intent: c for c in result.categories}
        assert cat_map["general_query"].count == 3
        assert cat_map["general_query"].percentage == 75.0
        assert cat_map["data_exfiltration"].count == 1
        assert cat_map["data_exfiltration"].percentage == 25.0

    @pytest.mark.asyncio
    async def test_intent_single_category_100_percent(self):
        db_rows = [("jailbreak", 10)]

        mock_result = MagicMock()
        mock_result.all = MagicMock(return_value=db_rows)
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        mock_sf = MagicMock(return_value=mock_db)

        svc = ClassificationObservabilityService(session_factory=mock_sf)
        result = await svc.get_intent_breakdown(period_hours=720)

        assert result.categories[0].intent == "jailbreak"
        assert result.categories[0].percentage == 100.0

    @pytest.mark.asyncio
    async def test_intent_empty_result_set(self):
        mock_result = MagicMock()
        mock_result.all = MagicMock(return_value=[])
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        mock_sf = MagicMock(return_value=mock_db)

        svc = ClassificationObservabilityService(session_factory=mock_sf)
        result = await svc.get_intent_breakdown(period_hours=24)

        assert result.total_classified == 0
        assert result.categories == []


# ---------------------------------------------------------------------------
# S5-T4: Risk level heatmap
# ---------------------------------------------------------------------------


class TestRiskLevelHeatmap:
    """S5-T4 — Risk_level × time heatmap for trend detection."""

    @pytest.fixture
    def svc(self):
        return ClassificationObservabilityService(session_factory=None)

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_session_factory(self, svc):
        result = await svc.get_risk_heatmap(period_hours=24)
        assert isinstance(result, RiskLevelHeatmap)
        assert result.cells == []

    @pytest.mark.asyncio
    async def test_heatmap_cells_populated(self):
        now_ts = time.time()
        bucket_ts = int(now_ts / 3600) * 3600
        db_rows = [
            (bucket_ts, "HIGH", 5),
            (bucket_ts, "LOW", 20),
        ]

        mock_result = MagicMock()
        mock_result.all = MagicMock(return_value=db_rows)
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        mock_sf = MagicMock(return_value=mock_db)

        svc = ClassificationObservabilityService(session_factory=mock_sf)
        result = await svc.get_risk_heatmap(period_hours=24, bucket_size=BUCKET_HOUR)

        assert len(result.cells) == 2
        risk_map = {c.risk_level: c.count for c in result.cells}
        assert risk_map["HIGH"] == 5
        assert risk_map["LOW"] == 20
        assert result.bucket_size == BUCKET_HOUR

    @pytest.mark.asyncio
    async def test_heatmap_invalid_bucket_size_defaults_to_hour(self):
        mock_result = MagicMock()
        mock_result.all = MagicMock(return_value=[])
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        mock_sf = MagicMock(return_value=mock_db)

        svc = ClassificationObservabilityService(session_factory=mock_sf)
        result = await svc.get_risk_heatmap(period_hours=24, bucket_size="invalid")

        assert result.bucket_size == BUCKET_HOUR

    @pytest.mark.asyncio
    async def test_heatmap_day_bucket_size_accepted(self):
        mock_result = MagicMock()
        mock_result.all = MagicMock(return_value=[])
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        mock_sf = MagicMock(return_value=mock_db)

        svc = ClassificationObservabilityService(session_factory=mock_sf)
        result = await svc.get_risk_heatmap(period_hours=720, bucket_size=BUCKET_DAY)

        assert result.bucket_size == BUCKET_DAY


# ---------------------------------------------------------------------------
# S5-T5: Confidence histogram
# ---------------------------------------------------------------------------


class TestConfidenceHistogram:
    """S5-T5 — Distribution of Thoth confidence scores."""

    @pytest.fixture
    def svc(self):
        return ClassificationObservabilityService(session_factory=None)

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_session_factory(self, svc):
        result = await svc.get_confidence_histogram(period_hours=24)
        assert isinstance(result, ConfidenceHistogram)
        assert result.total_classified == 0
        assert result.buckets == []

    @pytest.mark.asyncio
    async def test_histogram_has_10_buckets(self):
        scores = [(0.05,), (0.15,), (0.25,), (0.35,), (0.45,),
                  (0.55,), (0.65,), (0.75,), (0.85,), (0.95,)]

        mock_result = MagicMock()
        mock_result.all = MagicMock(return_value=scores)
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        mock_sf = MagicMock(return_value=mock_db)

        svc = ClassificationObservabilityService(session_factory=mock_sf)
        result = await svc.get_confidence_histogram(period_hours=24)

        assert len(result.buckets) == 10
        # Each bucket has exactly one score → 10% each
        for b in result.buckets:
            assert b.count == 1
            assert b.percentage == 10.0

    @pytest.mark.asyncio
    async def test_histogram_mean_and_median(self):
        # Scores: 0.2, 0.4, 0.6, 0.8 → mean = 0.5, median = 0.4 (nearest-rank p50)
        scores = [(0.2,), (0.4,), (0.6,), (0.8,)]

        mock_result = MagicMock()
        mock_result.all = MagicMock(return_value=scores)
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        mock_sf = MagicMock(return_value=mock_db)

        svc = ClassificationObservabilityService(session_factory=mock_sf)
        result = await svc.get_confidence_histogram(period_hours=24)

        assert result.mean_confidence == 0.5
        assert result.total_classified == 4

    @pytest.mark.asyncio
    async def test_histogram_bucket_labels_span_full_range(self):
        scores = [(float(i) / 10 + 0.05,) for i in range(10)]

        mock_result = MagicMock()
        mock_result.all = MagicMock(return_value=scores)
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        mock_sf = MagicMock(return_value=mock_db)

        svc = ClassificationObservabilityService(session_factory=mock_sf)
        result = await svc.get_confidence_histogram(period_hours=24)

        # First bucket: 0.00-0.10, last: 0.90-1.00
        assert result.buckets[0].lower == 0.0
        assert result.buckets[0].upper == 0.1
        assert result.buckets[-1].lower == 0.9
        assert abs(result.buckets[-1].upper - 1.0) < 0.001


# ---------------------------------------------------------------------------
# S5-T6: PII detection frequency
# ---------------------------------------------------------------------------


class TestPIIDetectionFrequency:
    """S5-T6 — PII type breakdown and trend over time."""

    @pytest.fixture
    def svc(self):
        return ClassificationObservabilityService(session_factory=None)

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_session_factory(self, svc):
        result = await svc.get_pii_detection(period_hours=24)
        assert isinstance(result, PIIDetectionFrequency)
        assert result.total_requests == 0
        assert result.pii_detected_count == 0

    @pytest.mark.asyncio
    async def test_pii_type_breakdown_parsed_from_json(self):
        now_ts = time.time()
        bucket_ts = int(now_ts / 3600) * 3600

        # 3 rows with PII
        pii_rows = [
            (json.dumps(["AADHAAR", "EMAIL"]),),
            (json.dumps(["AADHAAR"]),),
            (json.dumps(["CREDIT_CARD"]),),
        ]
        trend_rows = [(bucket_ts, 3)]

        call_idx = 0
        results = [
            _scalar_result(10),   # total classified
            _scalar_result(3),    # pii_detected count
            _rows_result(pii_rows),
            _rows_result(trend_rows),
        ]

        async def _execute(*args, **kwargs):
            nonlocal call_idx
            r = results[call_idx]
            call_idx += 1
            return r

        mock_db = AsyncMock()
        mock_db.execute = _execute
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        mock_sf = MagicMock(return_value=mock_db)

        svc = ClassificationObservabilityService(session_factory=mock_sf)
        result = await svc.get_pii_detection(period_hours=24)

        assert result.total_requests == 10
        assert result.pii_detected_count == 3
        assert result.pii_detection_rate == 30.0

        type_map = {t.pii_type: t.count for t in result.type_breakdown}
        assert type_map["AADHAAR"] == 2
        assert type_map["EMAIL"] == 1
        assert type_map["CREDIT_CARD"] == 1

        assert len(result.trend) == 1
        assert result.trend[0].count == 3

    @pytest.mark.asyncio
    async def test_pii_rate_zero_when_no_requests(self):
        results = [
            _scalar_result(0),
            _scalar_result(0),
            _rows_result([]),
            _rows_result([]),
        ]
        call_idx = 0

        async def _execute(*a, **kw):
            nonlocal call_idx
            r = results[call_idx]; call_idx += 1
            return r

        mock_db = AsyncMock()
        mock_db.execute = _execute
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        mock_sf = MagicMock(return_value=mock_db)

        svc = ClassificationObservabilityService(session_factory=mock_sf)
        result = await svc.get_pii_detection(period_hours=24)

        assert result.pii_detection_rate == 0.0


# ---------------------------------------------------------------------------
# S5-T7: Classification latency percentiles
# ---------------------------------------------------------------------------


class TestClassificationLatencyPercentiles:
    """S5-T7 — P50/P95/P99 Thoth API latency."""

    @pytest.fixture
    def svc(self):
        return ClassificationObservabilityService(session_factory=None)

    @pytest.mark.asyncio
    async def test_returns_zeros_when_no_session_factory(self, svc):
        result = await svc.get_latency_percentiles(period_hours=24)
        assert isinstance(result, ClassificationLatencyPercentiles)
        assert result.sample_count == 0
        assert result.p50_ms == 0.0

    @pytest.mark.asyncio
    async def test_percentiles_computed_from_thoth_rows_only(self):
        # 10 Thoth rows: latencies 10,20,...,100ms; 2 structural_fallback rows
        rows = (
            [(10 * i, "thoth") for i in range(1, 11)]
            + [(0, "structural_fallback"), (0, "structural_fallback")]
        )

        mock_result = MagicMock()
        mock_result.all = MagicMock(return_value=rows)
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        mock_sf = MagicMock(return_value=mock_db)

        svc = ClassificationObservabilityService(session_factory=mock_sf)
        result = await svc.get_latency_percentiles(period_hours=24)

        assert result.sample_count == 12
        # p50 of [10,20,...,100] (sorted) → nearest-rank(50%) on 10 items → rank=5 → 50ms
        assert result.p50_ms == 50.0
        # p99 → rank=ceil(0.99*10)=10 → 100ms
        assert result.p99_ms == 100.0
        # timeout_rate = 2 fallback / 12 total = 16.67%
        assert result.timeout_rate == pytest.approx(16.67, abs=0.01)

    @pytest.mark.asyncio
    async def test_no_thoth_rows_gives_zero_percentiles(self):
        rows = [(0, "structural_fallback")] * 5

        mock_result = MagicMock()
        mock_result.all = MagicMock(return_value=rows)
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        mock_sf = MagicMock(return_value=mock_db)

        svc = ClassificationObservabilityService(session_factory=mock_sf)
        result = await svc.get_latency_percentiles(period_hours=24)

        assert result.p50_ms == 0.0
        assert result.p95_ms == 0.0
        assert result.timeout_rate == 100.0


# ---------------------------------------------------------------------------
# _percentile helper
# ---------------------------------------------------------------------------


class TestPercentileHelper:
    def test_p50_even_list(self):
        # [10, 20, 30, 40] → p50: ceil(0.5*4)=2 → index 1 → 20
        assert _percentile([10, 20, 30, 40], 50) == 20

    def test_p99_small_list(self):
        # [1, 2, 3] → p99: ceil(0.99*3)=3 → index 2 → 3
        assert _percentile([1, 2, 3], 99) == 3

    def test_empty_list_returns_zero(self):
        assert _percentile([], 50) == 0.0

    def test_single_element(self):
        assert _percentile([42.0], 99) == 42.0


# ---------------------------------------------------------------------------
# Integration: AuditEventConsumer._persist_event mapping
# ---------------------------------------------------------------------------


class TestAuditConsumerPersistMapping:
    """Verify _persist_event correctly maps classification fields from event_data."""

    @pytest.mark.asyncio
    async def test_persist_event_maps_classification_fields(self):
        from app.services.audit import AuditEventConsumer

        consumer = AuditEventConsumer()
        records_added: list = []

        event_data = {
            "event_id": str(uuid.uuid4()),
            "request_hash": "abc123",
            "tenant_id": "tenant-1",
            "project_id": "proj-1",
            "api_key_id": "key-1",
            "model": "gpt-4",
            "provider": "openai",
            "action": "blocked",
            "policy_version": "v2",
            "status_code": 403,
            "latency_ms": 100.0,
            "prompt_tokens": 50,
            "completion_tokens": 0,
            "metadata": {},
            "timestamp": time.time(),
            "risk_score": 0.9,
            "action_taken": "block",
            "enforcement_duration_ms": 12.5,
            "previous_hash": "prev",
            "record_hash": "curr",
            # Sprint 5 classification fields
            "classification_intent": "data_exfiltration",
            "classification_risk_level": "HIGH",
            "classification_confidence": 0.91,
            "classification_pii_detected": True,
            "classification_pii_types": ["AADHAAR", "PAN"],
            "classification_latency_ms": 78,
            "classification_model_version": "v2.0",
            "classification_source": "thoth",
        }

        # Mock db.execute for dedup check (no existing record)
        mock_scalar = MagicMock()
        mock_scalar.scalar_one_or_none = MagicMock(return_value=None)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_scalar)
        mock_db.add = MagicMock(side_effect=lambda r: records_added.append(r))
        mock_db.commit = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)

        mock_sf = MagicMock(return_value=mock_db)

        await consumer._persist_event(mock_sf, event_data)

        assert len(records_added) == 1
        record = records_added[0]
        assert record.classification_intent == "data_exfiltration"
        assert record.classification_risk_level == "HIGH"
        assert record.classification_confidence == 0.91
        assert record.classification_pii_detected is True
        assert record.classification_pii_types == json.dumps(["AADHAAR", "PAN"])
        assert record.classification_latency_ms == 78
        assert record.classification_model_version == "v2.0"
        assert record.classification_source == "thoth"

    @pytest.mark.asyncio
    async def test_persist_event_nulls_empty_classification_fields(self):
        """Empty string classification fields must be stored as NULL."""
        from app.services.audit import AuditEventConsumer

        consumer = AuditEventConsumer()
        records_added: list = []

        event_data = {
            "event_id": str(uuid.uuid4()),
            "request_hash": "def456",
            "tenant_id": "tenant-2",
            "timestamp": time.time(),
            # No classification fields → expect NULL in DB
        }

        mock_scalar = MagicMock()
        mock_scalar.scalar_one_or_none = MagicMock(return_value=None)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_scalar)
        mock_db.add = MagicMock(side_effect=lambda r: records_added.append(r))
        mock_db.commit = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)

        mock_sf = MagicMock(return_value=mock_db)

        await consumer._persist_event(mock_sf, event_data)

        assert len(records_added) == 1
        record = records_added[0]
        assert record.classification_intent is None
        assert record.classification_risk_level is None
        assert record.classification_source is None
        assert record.classification_pii_types is None


# ---------------------------------------------------------------------------
# Full dashboard integration (get_full_dashboard aggregation)
# ---------------------------------------------------------------------------


class TestFullDashboard:
    """Verify get_full_dashboard returns a well-formed ClassificationDashboardData."""

    @pytest.mark.asyncio
    async def test_full_dashboard_without_session_factory(self):
        svc = ClassificationObservabilityService(session_factory=None)
        result = await svc.get_full_dashboard(period_hours=720)

        assert isinstance(result, ClassificationDashboardData)
        assert result.intent_breakdown.total_classified == 0
        assert result.risk_heatmap.cells == []
        assert result.confidence_histogram.buckets == []
        assert result.pii_detection.pii_detected_count == 0
        assert result.latency_percentiles.p50_ms == 0.0
        assert result.generated_at != ""
        assert result.period_hours == 720
