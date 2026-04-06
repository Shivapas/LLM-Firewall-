"""Sprint 18: Audit Trail Hardening & Compliance Reports — Tests.

Covers:
- Full audit schema enforcement (required field validation)
- Tamper-evident hash chain (chaining, verification, tamper detection)
- Audit log query API (filtering, pagination)
- GDPR compliance report generation
- HIPAA compliance report generation
- SOC 2 / PCI-DSS evidence export
- ZIP evidence archive
- Admin API endpoints
"""

import asyncio
import contextlib
import json
import time
import uuid
import zipfile
import io
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_session_factory(mock_db):
    """Create a mock async session factory matching SQLAlchemy's async_sessionmaker pattern."""
    @contextlib.asynccontextmanager
    async def factory():
        yield mock_db
    return factory


# ── 1. Audit Schema Enforcement ─────────────────────────────────────────


class TestAuditSchemaEnforcement:
    """Validate every audit event has required Sprint 18 fields."""

    def test_event_has_all_required_fields(self):
        from app.services.audit import AuditEvent

        event = AuditEvent(
            timestamp=time.time(),
            request_hash="abc123",
            tenant_id="tenant-1",
            model="gpt-4",
            policy_version="v1.2",
            risk_score=0.5,
            action_taken="allow",
            enforcement_duration_ms=12.3,
        )
        missing = event.validate_required_fields()
        assert missing == [], f"Expected no missing fields, got: {missing}"

    def test_event_missing_fields_detected(self):
        from app.services.audit import AuditEvent

        event = AuditEvent()  # All defaults — many required fields empty
        missing = event.validate_required_fields()
        assert "request_hash" in missing
        assert "tenant_id" in missing
        assert "model" in missing
        assert "policy_version" in missing
        assert "action_taken" in missing

    def test_event_with_risk_score_zero_is_valid(self):
        """risk_score=0.0 is valid (not missing), enforcement_duration_ms=0.0 is valid."""
        from app.services.audit import AuditEvent

        event = AuditEvent(
            timestamp=time.time(),
            request_hash="hash1",
            tenant_id="t1",
            model="gpt-4",
            policy_version="v1",
            risk_score=0.0,
            action_taken="allow",
            enforcement_duration_ms=0.0,
        )
        missing = event.validate_required_fields()
        # risk_score and enforcement_duration_ms are numeric, 0.0 is valid
        assert "risk_score" not in missing
        assert "enforcement_duration_ms" not in missing

    def test_new_fields_in_event_serialization(self):
        from app.services.audit import AuditEvent

        event = AuditEvent(
            tenant_id="t1",
            model="gpt-4",
            risk_score=0.75,
            action_taken="block",
            enforcement_duration_ms=5.5,
        )
        data = event.model_dump()
        assert data["risk_score"] == 0.75
        assert data["action_taken"] == "block"
        assert data["enforcement_duration_ms"] == 5.5
        assert "previous_hash" in data
        assert "record_hash" in data


# ── 2. Tamper-Evident Hash Chain ─────────────────────────────────────────


class TestAuditHashChain:
    """Hash chaining and tamper detection tests."""

    def test_compute_record_hash_deterministic(self):
        from app.services.audit_hash_chain import compute_record_hash

        h1 = compute_record_hash(
            event_id="e1", timestamp=1000.0, request_hash="rh1",
            tenant_id="t1", model="gpt-4", policy_version="v1",
            risk_score=0.5, action_taken="allow",
            enforcement_duration_ms=10.0, previous_hash="0" * 64,
        )
        h2 = compute_record_hash(
            event_id="e1", timestamp=1000.0, request_hash="rh1",
            tenant_id="t1", model="gpt-4", policy_version="v1",
            risk_score=0.5, action_taken="allow",
            enforcement_duration_ms=10.0, previous_hash="0" * 64,
        )
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_compute_record_hash_changes_on_mutation(self):
        from app.services.audit_hash_chain import compute_record_hash

        base = dict(
            event_id="e1", timestamp=1000.0, request_hash="rh1",
            tenant_id="t1", model="gpt-4", policy_version="v1",
            risk_score=0.5, action_taken="allow",
            enforcement_duration_ms=10.0, previous_hash="0" * 64,
        )
        h1 = compute_record_hash(**base)
        base["risk_score"] = 0.9  # Tamper
        h2 = compute_record_hash(**base)
        assert h1 != h2

    def test_chain_event_links_hashes(self):
        from app.services.audit_hash_chain import AuditHashChainService, GENESIS_HASH

        svc = AuditHashChainService()

        e1 = {
            "event_id": "e1", "timestamp": 1000.0, "request_hash": "rh1",
            "tenant_id": "t1", "model": "gpt-4", "policy_version": "v1",
            "risk_score": 0.5, "action_taken": "allow",
            "enforcement_duration_ms": 10.0,
        }
        e2 = {
            "event_id": "e2", "timestamp": 1001.0, "request_hash": "rh2",
            "tenant_id": "t1", "model": "gpt-4", "policy_version": "v1",
            "risk_score": 0.3, "action_taken": "allow",
            "enforcement_duration_ms": 8.0,
        }

        result1 = svc.chain_event(e1)
        result2 = svc.chain_event(e2)

        assert result1["previous_hash"] == GENESIS_HASH
        assert result1["record_hash"] != ""
        assert result1["chain_sequence"] == 1

        assert result2["previous_hash"] == result1["record_hash"]
        assert result2["record_hash"] != result1["record_hash"]
        assert result2["chain_sequence"] == 2

    @pytest.mark.asyncio
    async def test_verify_chain_empty_db(self):
        """Verification on empty dataset returns valid."""
        from app.services.audit_hash_chain import AuditHashChainService

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)

        svc = AuditHashChainService(session_factory=_make_session_factory(mock_db))
        result = await svc.verify_chain()
        assert result["valid"] is True
        assert result["records_checked"] == 0

    @pytest.mark.asyncio
    async def test_verify_chain_detects_tamper(self):
        """Simulated record deletion/mutation detected as tamper event."""
        from app.services.audit_hash_chain import AuditHashChainService, GENESIS_HASH, compute_record_hash

        # Build a mock chain of 3 records
        records = []
        prev_hash = GENESIS_HASH
        for i in range(3):
            eid = f"e{i}"
            ts = 1000.0 + i
            rh = compute_record_hash(
                event_id=eid, timestamp=ts, request_hash=f"rh{i}",
                tenant_id="t1", model="gpt-4", policy_version="v1",
                risk_score=0.1 * i, action_taken="allow",
                enforcement_duration_ms=5.0, previous_hash=prev_hash,
            )
            rec = MagicMock()
            rec.id = eid
            rec.event_timestamp = ts
            rec.request_hash = f"rh{i}"
            rec.tenant_id = "t1"
            rec.model = "gpt-4"
            rec.policy_version = "v1"
            rec.risk_score = 0.1 * i
            rec.action_taken = "allow"
            rec.enforcement_duration_ms = 5.0
            rec.previous_hash = prev_hash
            rec.record_hash = rh
            rec.chain_sequence = i + 1
            records.append(rec)
            prev_hash = rh

        # Tamper: change the risk_score of record 1
        records[1].risk_score = 0.99

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = records
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)

        svc = AuditHashChainService(session_factory=_make_session_factory(mock_db))
        result = await svc.verify_chain()
        assert result["valid"] is False
        assert result["first_invalid_sequence"] == 2
        assert "tampered" in result["tamper_details"].lower() or "mismatch" in result["tamper_details"].lower()

    @pytest.mark.asyncio
    async def test_verify_chain_detects_deletion(self):
        """Simulated record deletion detected via chain break."""
        from app.services.audit_hash_chain import AuditHashChainService, GENESIS_HASH, compute_record_hash

        # Build chain of 3, then remove record 1 (middle)
        records_full = []
        prev_hash = GENESIS_HASH
        for i in range(3):
            eid = f"e{i}"
            ts = 1000.0 + i
            rh = compute_record_hash(
                event_id=eid, timestamp=ts, request_hash=f"rh{i}",
                tenant_id="t1", model="gpt-4", policy_version="v1",
                risk_score=0.0, action_taken="allow",
                enforcement_duration_ms=5.0, previous_hash=prev_hash,
            )
            rec = MagicMock()
            rec.id = eid
            rec.event_timestamp = ts
            rec.request_hash = f"rh{i}"
            rec.tenant_id = "t1"
            rec.model = "gpt-4"
            rec.policy_version = "v1"
            rec.risk_score = 0.0
            rec.action_taken = "allow"
            rec.enforcement_duration_ms = 5.0
            rec.previous_hash = prev_hash
            rec.record_hash = rh
            rec.chain_sequence = i + 1
            records_full.append(rec)
            prev_hash = rh

        # Delete the middle record (index 1)
        records_with_gap = [records_full[0], records_full[2]]

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = records_with_gap
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)

        svc = AuditHashChainService(session_factory=_make_session_factory(mock_db))
        result = await svc.verify_chain()
        assert result["valid"] is False
        assert "break" in result["tamper_details"].lower() or "expected" in result["tamper_details"].lower()


# ── 3. Audit Log Query API ───────────────────────────────────────────────


class TestAuditQueryService:
    """Audit log query with filtering and pagination."""

    @pytest.mark.asyncio
    async def test_query_empty_result(self):
        from app.services.audit_query import AuditQueryService, AuditQueryParams

        svc = AuditQueryService(session_factory=None)
        params = AuditQueryParams(tenant_id="t1")
        result = await svc.query(params)
        assert result.total == 0
        assert result.records == []
        assert result.page == 1

    def test_query_params_defaults(self):
        from app.services.audit_query import AuditQueryParams

        params = AuditQueryParams()
        assert params.page == 1
        assert params.page_size == 50

    def test_risk_thresholds(self):
        from app.services.audit_query import RISK_THRESHOLDS

        assert RISK_THRESHOLDS["critical"] == (0.9, 1.0)
        assert RISK_THRESHOLDS["low"] == (0.0, 0.4)

    def test_paginated_response_model(self):
        from app.services.audit_query import PaginatedAuditResponse, AuditRecordResponse

        resp = PaginatedAuditResponse(
            records=[],
            total=0,
            page=1,
            page_size=50,
            total_pages=1,
        )
        assert resp.total_pages == 1
        data = resp.model_dump()
        assert "records" in data
        assert "total_pages" in data


# ── 4. GDPR Compliance Report ───────────────────────────────────────────


class TestGDPRReport:
    """GDPR report generation from audit data."""

    @pytest.mark.asyncio
    async def test_gdpr_report_no_data(self):
        from app.services.compliance_reports import ComplianceReportService, ReportRequest

        svc = ComplianceReportService(session_factory=None)
        req = ReportRequest(tenant_id="t1", days=30)
        report = await svc.generate_gdpr_report(req)
        assert report.report_type == "GDPR"
        assert report.total_requests == 0
        assert report.pii_detected_count == 0
        assert report.retention_policy_status == "compliant"
        assert report.generated_at != ""

    @pytest.mark.asyncio
    async def test_gdpr_report_with_pii_data(self):
        from app.services.compliance_reports import ComplianceReportService, ReportRequest

        # Create mock DB records with PII metadata
        mock_records = []
        for i in range(5):
            rec = MagicMock()
            rec.id = uuid.uuid4()
            rec.event_timestamp = time.time() - i * 3600
            rec.model = "gpt-4"
            rec.action_taken = "redact" if i % 2 == 0 else "allow"
            meta = {"pii_detected": True, "pii_types": ["email", "phone"]} if i < 3 else {}
            if i % 2 == 0:
                meta["pii_redacted"] = True
            rec.metadata_json = json.dumps(meta)
            mock_records.append(rec)

        count_result = MagicMock()
        count_result.scalar.return_value = 5

        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = mock_records

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(side_effect=[count_result, data_result])

        svc = ComplianceReportService(session_factory=_make_session_factory(mock_db))
        req = ReportRequest(tenant_id="t1", days=30)
        report = await svc.generate_gdpr_report(req)
        assert report.total_requests == 5
        assert report.pii_detected_count == 3
        assert report.pii_redacted_count > 0
        assert len(report.data_lineage_evidence) > 0


# ── 5. HIPAA Compliance Report ───────────────────────────────────────────


class TestHIPAAReport:
    """HIPAA report generation from audit data."""

    @pytest.mark.asyncio
    async def test_hipaa_report_no_data(self):
        from app.services.compliance_reports import ComplianceReportService, ReportRequest

        svc = ComplianceReportService(session_factory=None)
        req = ReportRequest(days=30)
        report = await svc.generate_hipaa_report(req)
        assert report.report_type == "HIPAA"
        assert report.total_requests == 0
        assert report.phi_encounter_count == 0

    @pytest.mark.asyncio
    async def test_hipaa_report_with_phi_data(self):
        from app.services.compliance_reports import ComplianceReportService, ReportRequest

        mock_records = []
        for i in range(4):
            rec = MagicMock()
            rec.id = uuid.uuid4()
            rec.event_timestamp = time.time() - i * 3600
            rec.model = "gpt-4"
            rec.api_key_id = f"key-{i}"
            rec.action_taken = "redact" if i < 2 else "allow"
            meta = {}
            if i < 2:
                meta = {"phi_detected": True, "phi_types": ["SSN"], "anonymized_record_id": f"patient-{i}"}
            if i == 0:
                meta["phi_redacted"] = True
                meta["redacted_fields"] = ["ssn", "dob"]
            rec.metadata_json = json.dumps(meta)
            mock_records.append(rec)

        count_result = MagicMock()
        count_result.scalar.return_value = 4
        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = mock_records
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(side_effect=[count_result, data_result])

        svc = ComplianceReportService(session_factory=_make_session_factory(mock_db))
        req = ReportRequest(tenant_id="t1", days=30)
        report = await svc.generate_hipaa_report(req)
        assert report.total_requests == 4
        assert report.phi_encounter_count == 2
        assert report.anonymized_patient_records == 2
        assert len(report.redaction_evidence) > 0


# ── 6. SOC 2 / PCI-DSS Evidence Export ──────────────────────────────────


class TestSOC2PCIDSSReport:
    """SOC 2 / PCI-DSS report generation."""

    @pytest.mark.asyncio
    async def test_soc2_report_no_data(self):
        from app.services.compliance_reports import ComplianceReportService, ReportRequest

        svc = ComplianceReportService(session_factory=None)
        req = ReportRequest(days=30)
        report = await svc.generate_soc2_pcidss_report(req)
        assert report.report_type == "SOC2_PCIDSS"
        assert report.total_access_events == 0
        assert report.total_policy_changes == 0
        assert report.total_incidents == 0

    @pytest.mark.asyncio
    async def test_soc2_report_with_access_controls(self):
        from app.services.compliance_reports import ComplianceReportService, ReportRequest

        # Mock blocked audit records
        mock_access = []
        for i in range(3):
            rec = MagicMock()
            rec.id = uuid.uuid4()
            rec.event_timestamp = time.time() - i * 3600
            rec.tenant_id = "t1"
            rec.action = "blocked"
            rec.model = "gpt-4"
            rec.risk_score = 0.8
            rec.policy_version = "v1"
            mock_access.append(rec)

        # access controls query result
        access_result = MagicMock()
        access_result.scalars.return_value.all.return_value = mock_access

        # policy versions result
        policy_result = MagicMock()
        policy_result.scalars.return_value.all.return_value = []

        # incidents result
        incident_result = MagicMock()
        incident_result.scalars.return_value.all.return_value = []

        # kill-switch result
        ks_result = MagicMock()
        ks_result.scalars.return_value.all.return_value = []

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(side_effect=[access_result, policy_result, incident_result, ks_result])

        svc = ComplianceReportService(session_factory=_make_session_factory(mock_db))
        req = ReportRequest(tenant_id="t1", days=30)
        report = await svc.generate_soc2_pcidss_report(req)
        assert report.total_access_events == 3
        assert len(report.access_controls_log) == 3


# ── 7. ZIP Evidence Archive ─────────────────────────────────────────────


class TestEvidenceZipExport:
    """ZIP archive containing all compliance reports."""

    @pytest.mark.asyncio
    async def test_zip_export_contains_all_reports(self):
        from app.services.compliance_reports import ComplianceReportService, ReportRequest

        svc = ComplianceReportService(session_factory=None)
        req = ReportRequest(days=30)
        zip_bytes = await svc.export_evidence_zip(req)

        assert len(zip_bytes) > 0
        buf = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(buf, "r") as zf:
            names = zf.namelist()
            assert "gdpr_report.json" in names
            assert "hipaa_report.json" in names
            assert "soc2_pcidss_report.json" in names

            # Verify each file is valid JSON
            for name in names:
                data = json.loads(zf.read(name))
                assert "report_type" in data


# ── 8. Admin API Endpoint Integration Tests ─────────────────────────────


class TestAdminAuditEndpoints:
    """Test Sprint 18 admin API endpoints."""

    @pytest.fixture
    def client(self):
        # Pre-import modules to make them patchable
        import app.services.redis_client
        import app.services.key_service
        import app.middleware.auth

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.setex = AsyncMock()
        mock_redis.delete = AsyncMock()
        mock_redis.ping = AsyncMock()

        with patch.object(app.services.redis_client, "get_redis", return_value=mock_redis):
            with patch.object(app.middleware.auth, "validate_api_key", return_value=None):
                with patch.object(app.middleware.auth, "validate_api_key_from_db", return_value=None):
                    from app.main import app as fastapi_app
                    from fastapi.testclient import TestClient
                    yield TestClient(fastapi_app)

    def test_audit_query_endpoint(self, client):
        with patch("app.services.audit_query.get_audit_query_service") as mock_svc:
            from app.services.audit_query import PaginatedAuditResponse
            mock_instance = AsyncMock()
            mock_instance.query = AsyncMock(return_value=PaginatedAuditResponse(
                records=[], total=0, page=1, page_size=50, total_pages=1,
            ))
            mock_svc.return_value = mock_instance

            resp = client.get("/admin/audit/query?tenant_id=t1&page=1&page_size=10")
            assert resp.status_code == 200
            data = resp.json()
            assert "records" in data
            assert "total" in data
            assert "total_pages" in data

    def test_audit_verify_chain_endpoint(self, client):
        with patch("app.services.audit_hash_chain.get_hash_chain_service") as mock_svc:
            mock_instance = AsyncMock()
            mock_instance.verify_chain = AsyncMock(return_value={
                "valid": True,
                "records_checked": 0,
                "first_invalid_sequence": None,
                "tamper_details": "",
            })
            mock_svc.return_value = mock_instance

            resp = client.get("/admin/audit/verify-chain")
            assert resp.status_code == 200
            data = resp.json()
            assert data["valid"] is True

    def test_audit_validate_event_endpoint(self, client):
        resp = client.post("/admin/audit/validate-event", json={
            "timestamp": time.time(),
            "request_hash": "abc123",
            "tenant_id": "t1",
            "model": "gpt-4",
            "policy_version": "v1",
            "risk_score": 0.5,
            "action_taken": "allow",
            "enforcement_duration_ms": 10.0,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["missing_fields"] == []

    def test_audit_validate_event_missing_fields(self, client):
        resp = client.post("/admin/audit/validate-event", json={
            "tenant_id": "t1",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False
        assert len(data["missing_fields"]) > 0

    def test_gdpr_report_endpoint(self, client):
        with patch("app.services.compliance_reports.get_compliance_report_service") as mock_svc:
            from app.services.compliance_reports import GDPRReport
            mock_instance = AsyncMock()
            mock_instance.generate_gdpr_report = AsyncMock(return_value=GDPRReport(
                generated_at="2026-04-06T00:00:00+00:00",
                period_start="2026-03-07T00:00:00+00:00",
                period_end="2026-04-06T00:00:00+00:00",
                tenant_id="t1",
                total_requests=100,
                pii_detected_count=10,
                pii_redacted_count=8,
            ))
            mock_svc.return_value = mock_instance

            resp = client.post("/admin/compliance/gdpr?tenant_id=t1&days=30")
            assert resp.status_code == 200
            data = resp.json()
            assert data["report_type"] == "GDPR"
            assert data["total_requests"] == 100

    def test_hipaa_report_endpoint(self, client):
        with patch("app.services.compliance_reports.get_compliance_report_service") as mock_svc:
            from app.services.compliance_reports import HIPAAReport
            mock_instance = AsyncMock()
            mock_instance.generate_hipaa_report = AsyncMock(return_value=HIPAAReport(
                generated_at="2026-04-06T00:00:00+00:00",
                period_start="2026-03-07T00:00:00+00:00",
                period_end="2026-04-06T00:00:00+00:00",
                tenant_id="t1",
                total_requests=50,
                phi_encounter_count=5,
            ))
            mock_svc.return_value = mock_instance

            resp = client.post("/admin/compliance/hipaa?tenant_id=t1")
            assert resp.status_code == 200
            data = resp.json()
            assert data["report_type"] == "HIPAA"

    def test_soc2_pcidss_report_endpoint(self, client):
        with patch("app.services.compliance_reports.get_compliance_report_service") as mock_svc:
            from app.services.compliance_reports import SOC2PCIDSSReport
            mock_instance = AsyncMock()
            mock_instance.generate_soc2_pcidss_report = AsyncMock(return_value=SOC2PCIDSSReport(
                generated_at="2026-04-06T00:00:00+00:00",
                period_start="2026-03-07T00:00:00+00:00",
                period_end="2026-04-06T00:00:00+00:00",
                tenant_id="t1",
                total_access_events=20,
                total_policy_changes=5,
                total_incidents=3,
            ))
            mock_svc.return_value = mock_instance

            resp = client.post("/admin/compliance/soc2-pcidss?tenant_id=t1")
            assert resp.status_code == 200
            data = resp.json()
            assert data["report_type"] == "SOC2_PCIDSS"

    def test_evidence_export_zip_endpoint(self, client):
        with patch("app.services.compliance_reports.get_compliance_report_service") as mock_svc:
            mock_instance = AsyncMock()
            # Create a real ZIP for the mock
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("gdpr_report.json", '{"report_type":"GDPR"}')
                zf.writestr("hipaa_report.json", '{"report_type":"HIPAA"}')
                zf.writestr("soc2_pcidss_report.json", '{"report_type":"SOC2_PCIDSS"}')
            mock_instance.export_evidence_zip = AsyncMock(return_value=buf.getvalue())
            mock_svc.return_value = mock_instance

            resp = client.get("/admin/compliance/evidence-export?days=30")
            assert resp.status_code == 200
            assert resp.headers["content-type"] == "application/zip"

            # Verify the ZIP content
            result_buf = io.BytesIO(resp.content)
            with zipfile.ZipFile(result_buf, "r") as zf:
                assert "gdpr_report.json" in zf.namelist()


# ── 9. emit_audit_event with new Sprint 18 fields ───────────────────────


class TestEmitAuditEvent:
    """Test that emit_audit_event properly passes Sprint 18 fields."""

    @pytest.mark.asyncio
    async def test_emit_with_risk_score_and_action(self):
        with patch("app.services.audit.get_audit_writer") as mock_get:
            mock_writer = AsyncMock()
            mock_writer.write_event = AsyncMock(return_value=True)
            mock_get.return_value = mock_writer

            from app.services.audit import emit_audit_event

            event = await emit_audit_event(
                request_body=b'{"model":"gpt-4"}',
                tenant_id="t1",
                api_key_id="k1",
                model="gpt-4",
                provider="openai",
                action="blocked",
                policy_version="v2",
                risk_score=0.85,
                action_taken="block",
                enforcement_duration_ms=15.7,
            )

            assert event.risk_score == 0.85
            assert event.action_taken == "block"
            assert event.enforcement_duration_ms == 15.7
            mock_writer.write_event.assert_called_once()

    @pytest.mark.asyncio
    async def test_emit_defaults_action_taken_to_action(self):
        """If action_taken is not provided, it defaults to the action field."""
        with patch("app.services.audit.get_audit_writer") as mock_get:
            mock_writer = AsyncMock()
            mock_writer.write_event = AsyncMock(return_value=True)
            mock_get.return_value = mock_writer

            from app.services.audit import emit_audit_event

            event = await emit_audit_event(
                request_body=b'{"model":"gpt-4"}',
                tenant_id="t1",
                model="gpt-4",
                action="allowed",
                policy_version="v1",
            )

            assert event.action_taken == "allowed"
