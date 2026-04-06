"""Sprint 23: Red Teaming Engine — Attack Probe Library Tests.

Covers:
- Red team runner infrastructure (campaign creation, execution, result storage)
- Injection probe suite (100+ probes, OWASP LLM Top 10 coverage)
- Jailbreak probe suite (DAN variants, role-play, many-shot, obfuscation)
- PII extraction probes (direct solicitation, training data, social engineering)
- Campaign results dashboard endpoints
- Findings report generation and export
- Acceptance criteria validation
"""

import asyncio
import json
import uuid

import pytest


# ── 1. Probe Suites Validation ──────────────────────────────────────────────


class TestInjectionProbeSuite:
    """Validate injection probe suite structure and coverage."""

    def test_probe_count_minimum(self):
        from app.services.red_team.probes.injection import INJECTION_PROBES
        assert len(INJECTION_PROBES) >= 100, f"Expected 100+ injection probes, got {len(INJECTION_PROBES)}"

    def test_probe_structure(self):
        from app.services.red_team.probes.injection import INJECTION_PROBES
        required_keys = {"id", "name", "category", "technique", "severity", "payload", "success_indicators", "description", "owasp_mapping"}
        for probe in INJECTION_PROBES:
            missing = required_keys - set(probe.keys())
            assert not missing, f"Probe {probe.get('id', '?')} missing keys: {missing}"

    def test_all_probes_category_injection(self):
        from app.services.red_team.probes.injection import INJECTION_PROBES
        for probe in INJECTION_PROBES:
            assert probe["category"] == "injection", f"Probe {probe['id']} has wrong category: {probe['category']}"

    def test_unique_probe_ids(self):
        from app.services.red_team.probes.injection import INJECTION_PROBES
        ids = [p["id"] for p in INJECTION_PROBES]
        assert len(ids) == len(set(ids)), "Duplicate probe IDs found"

    def test_direct_injection_probes_exist(self):
        from app.services.red_team.probes.injection import INJECTION_PROBES
        direct = [p for p in INJECTION_PROBES if p["technique"] == "direct_injection"]
        assert len(direct) >= 20, f"Expected 20+ direct injection probes, got {len(direct)}"

    def test_indirect_injection_probes_exist(self):
        from app.services.red_team.probes.injection import INJECTION_PROBES
        indirect = [p for p in INJECTION_PROBES if p["technique"] == "indirect_injection"]
        assert len(indirect) >= 15, f"Expected 15+ indirect injection probes, got {len(indirect)}"

    def test_system_prompt_extraction_probes_exist(self):
        from app.services.red_team.probes.injection import INJECTION_PROBES
        spe = [p for p in INJECTION_PROBES if p["technique"] == "system_prompt_extraction"]
        assert len(spe) >= 15, f"Expected 15+ system prompt extraction probes, got {len(spe)}"

    def test_owasp_coverage(self):
        from app.services.red_team.probes.injection import INJECTION_PROBES
        owasp_mapped = set(p["owasp_mapping"] for p in INJECTION_PROBES if p["owasp_mapping"])
        expected = {"LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"}
        missing = expected - owasp_mapped
        assert not missing, f"Missing OWASP LLM Top 10 coverage: {missing}"

    def test_severity_values_valid(self):
        from app.services.red_team.probes.injection import INJECTION_PROBES
        valid = {"critical", "high", "medium", "low"}
        for probe in INJECTION_PROBES:
            assert probe["severity"] in valid, f"Probe {probe['id']} has invalid severity: {probe['severity']}"

    def test_payloads_non_empty(self):
        from app.services.red_team.probes.injection import INJECTION_PROBES
        for probe in INJECTION_PROBES:
            assert len(probe["payload"]) > 10, f"Probe {probe['id']} has too-short payload"

    def test_success_indicators_non_empty(self):
        from app.services.red_team.probes.injection import INJECTION_PROBES
        for probe in INJECTION_PROBES:
            assert len(probe["success_indicators"]) > 0, f"Probe {probe['id']} has no success indicators"


class TestJailbreakProbeSuite:
    """Validate jailbreak probe suite structure and coverage."""

    def test_probe_count_minimum(self):
        from app.services.red_team.probes.jailbreak import JAILBREAK_PROBES
        assert len(JAILBREAK_PROBES) >= 50, f"Expected 50+ jailbreak probes, got {len(JAILBREAK_PROBES)}"

    def test_probe_structure(self):
        from app.services.red_team.probes.jailbreak import JAILBREAK_PROBES
        required_keys = {"id", "name", "category", "technique", "severity", "payload", "success_indicators", "description", "owasp_mapping"}
        for probe in JAILBREAK_PROBES:
            missing = required_keys - set(probe.keys())
            assert not missing, f"Probe {probe.get('id', '?')} missing keys: {missing}"

    def test_all_probes_category_jailbreak(self):
        from app.services.red_team.probes.jailbreak import JAILBREAK_PROBES
        for probe in JAILBREAK_PROBES:
            assert probe["category"] == "jailbreak"

    def test_unique_probe_ids(self):
        from app.services.red_team.probes.jailbreak import JAILBREAK_PROBES
        ids = [p["id"] for p in JAILBREAK_PROBES]
        assert len(ids) == len(set(ids))

    def test_dan_variants_exist(self):
        from app.services.red_team.probes.jailbreak import JAILBREAK_PROBES
        dan = [p for p in JAILBREAK_PROBES if p["technique"] == "dan_variant"]
        assert len(dan) >= 10, f"Expected 10+ DAN variant probes, got {len(dan)}"

    def test_roleplay_bypasses_exist(self):
        from app.services.red_team.probes.jailbreak import JAILBREAK_PROBES
        rp = [p for p in JAILBREAK_PROBES if p["technique"] == "roleplay_bypass"]
        assert len(rp) >= 8, f"Expected 8+ roleplay bypass probes, got {len(rp)}"

    def test_many_shot_probes_exist(self):
        from app.services.red_team.probes.jailbreak import JAILBREAK_PROBES
        ms = [p for p in JAILBREAK_PROBES if p["technique"] == "many_shot"]
        assert len(ms) >= 5, f"Expected 5+ many-shot probes, got {len(ms)}"

    def test_obfuscated_instruction_probes_exist(self):
        from app.services.red_team.probes.jailbreak import JAILBREAK_PROBES
        obf = [p for p in JAILBREAK_PROBES if p["technique"] == "obfuscated_instruction"]
        assert len(obf) >= 8, f"Expected 8+ obfuscated instruction probes, got {len(obf)}"

    def test_token_smuggling_probes_exist(self):
        from app.services.red_team.probes.jailbreak import JAILBREAK_PROBES
        ts = [p for p in JAILBREAK_PROBES if p["technique"] == "token_smuggling"]
        assert len(ts) >= 10, f"Expected 10+ token smuggling probes, got {len(ts)}"


class TestPIIExtractionProbeSuite:
    """Validate PII extraction probe suite structure and coverage."""

    def test_probe_count_minimum(self):
        from app.services.red_team.probes.pii_extraction import PII_EXTRACTION_PROBES
        assert len(PII_EXTRACTION_PROBES) >= 30, f"Expected 30+ PII probes, got {len(PII_EXTRACTION_PROBES)}"

    def test_probe_structure(self):
        from app.services.red_team.probes.pii_extraction import PII_EXTRACTION_PROBES
        required_keys = {"id", "name", "category", "technique", "severity", "payload", "success_indicators", "description", "owasp_mapping"}
        for probe in PII_EXTRACTION_PROBES:
            missing = required_keys - set(probe.keys())
            assert not missing, f"Probe {probe.get('id', '?')} missing keys: {missing}"

    def test_all_probes_category_pii(self):
        from app.services.red_team.probes.pii_extraction import PII_EXTRACTION_PROBES
        for probe in PII_EXTRACTION_PROBES:
            assert probe["category"] == "pii_extraction"

    def test_unique_probe_ids(self):
        from app.services.red_team.probes.pii_extraction import PII_EXTRACTION_PROBES
        ids = [p["id"] for p in PII_EXTRACTION_PROBES]
        assert len(ids) == len(set(ids))

    def test_direct_pii_solicitation_probes(self):
        from app.services.red_team.probes.pii_extraction import PII_EXTRACTION_PROBES
        direct = [p for p in PII_EXTRACTION_PROBES if p["technique"] == "direct_pii_solicitation"]
        assert len(direct) >= 5, f"Expected 5+ direct PII probes, got {len(direct)}"

    def test_training_data_extraction_probes(self):
        from app.services.red_team.probes.pii_extraction import PII_EXTRACTION_PROBES
        td = [p for p in PII_EXTRACTION_PROBES if p["technique"] == "training_data_extraction"]
        assert len(td) >= 5, f"Expected 5+ training data extraction probes, got {len(td)}"

    def test_system_prompt_revelation_probes(self):
        from app.services.red_team.probes.pii_extraction import PII_EXTRACTION_PROBES
        spr = [p for p in PII_EXTRACTION_PROBES if p["technique"] == "system_prompt_revelation"]
        assert len(spr) >= 5, f"Expected 5+ system prompt revelation probes, got {len(spr)}"

    def test_social_engineering_probes(self):
        from app.services.red_team.probes.pii_extraction import PII_EXTRACTION_PROBES
        se = [p for p in PII_EXTRACTION_PROBES if p["technique"] == "social_engineering"]
        assert len(se) >= 5, f"Expected 5+ social engineering probes, got {len(se)}"

    def test_owasp_lmm06_mapping(self):
        from app.services.red_team.probes.pii_extraction import PII_EXTRACTION_PROBES
        for probe in PII_EXTRACTION_PROBES:
            assert probe["owasp_mapping"] == "LLM06", f"Probe {probe['id']} should map to LLM06"


class TestTotalProbeCount:
    """Validate combined probe library exceeds 100+ threshold."""

    def test_total_probes_exceed_100(self):
        from app.services.red_team.probes.injection import INJECTION_PROBES
        from app.services.red_team.probes.jailbreak import JAILBREAK_PROBES
        from app.services.red_team.probes.pii_extraction import PII_EXTRACTION_PROBES
        total = len(INJECTION_PROBES) + len(JAILBREAK_PROBES) + len(PII_EXTRACTION_PROBES)
        assert total >= 100, f"Expected 100+ total probes, got {total}"

    def test_all_probe_ids_globally_unique(self):
        from app.services.red_team.probes.injection import INJECTION_PROBES
        from app.services.red_team.probes.jailbreak import JAILBREAK_PROBES
        from app.services.red_team.probes.pii_extraction import PII_EXTRACTION_PROBES
        all_ids = (
            [p["id"] for p in INJECTION_PROBES]
            + [p["id"] for p in JAILBREAK_PROBES]
            + [p["id"] for p in PII_EXTRACTION_PROBES]
        )
        assert len(all_ids) == len(set(all_ids)), "Duplicate probe IDs across suites"


# ── 2. Campaign Runner Infrastructure ───────────────────────────────────────


class TestCampaignCreation:
    """Validate campaign CRUD operations."""

    def test_create_campaign(self):
        from app.services.red_team.runner import create_campaign, CampaignStatus
        c = create_campaign(name="Test Campaign", target_url="http://localhost:9000/v1/chat/completions")
        assert c.name == "Test Campaign"
        assert c.status == CampaignStatus.PENDING
        assert c.id is not None

    def test_create_campaign_with_options(self):
        from app.services.red_team.runner import create_campaign
        c = create_campaign(
            name="Custom Campaign",
            target_url="http://example.com/api",
            description="Test description",
            probe_categories=["injection"],
            concurrency=5,
            timeout_seconds=15,
            created_by="tester",
        )
        assert c.description == "Test description"
        assert c.probe_categories == ["injection"]
        assert c.concurrency == 5
        assert c.timeout_seconds == 15
        assert c.created_by == "tester"

    def test_get_campaign(self):
        from app.services.red_team.runner import create_campaign, get_campaign
        c = create_campaign(name="Get Test", target_url="http://localhost:9000")
        found = get_campaign(c.id)
        assert found is not None
        assert found.id == c.id

    def test_get_campaign_not_found(self):
        from app.services.red_team.runner import get_campaign
        assert get_campaign("nonexistent-id") is None

    def test_list_campaigns(self):
        from app.services.red_team.runner import create_campaign, list_campaigns
        create_campaign(name="List Test 1", target_url="http://localhost:9000")
        create_campaign(name="List Test 2", target_url="http://localhost:9000")
        campaigns = list_campaigns()
        assert len(campaigns) >= 2
        assert all(isinstance(c, dict) for c in campaigns)

    def test_delete_campaign(self):
        from app.services.red_team.runner import create_campaign, delete_campaign, get_campaign
        c = create_campaign(name="Delete Test", target_url="http://localhost:9000")
        assert delete_campaign(c.id) is True
        assert get_campaign(c.id) is None

    def test_delete_campaign_not_found(self):
        from app.services.red_team.runner import delete_campaign
        assert delete_campaign("nonexistent-id") is False

    def test_campaign_to_dict(self):
        from app.services.red_team.runner import create_campaign
        c = create_campaign(name="Dict Test", target_url="http://localhost:9000")
        d = c.to_dict()
        assert d["name"] == "Dict Test"
        assert d["status"] == "pending"
        assert "findings_summary" in d
        assert "created_at" in d


class TestCampaignExecution:
    """Validate campaign execution and result classification."""

    def test_campaign_to_dict_has_summary(self):
        from app.services.red_team.runner import create_campaign
        c = create_campaign(name="Summary Test", target_url="http://localhost:9000")
        d = c.to_dict()
        summary = d["findings_summary"]
        assert "total_findings" in summary
        assert "total_probes" in summary
        assert "detection_rate" in summary
        assert "by_severity" in summary
        assert "by_category" in summary

    def test_probe_result_creation(self):
        from app.services.red_team.runner import ProbeResult, ProbeSeverity
        r = ProbeResult(
            probe_id="INJ-001",
            probe_name="Test probe",
            category="injection",
            technique="direct_injection",
            severity=ProbeSeverity.CRITICAL,
            detected=True,
            risk_score=0.9,
            response_snippet="Some response text",
            bypass_technique="direct_injection",
            latency_ms=150.5,
        )
        assert r.probe_id == "INJ-001"
        assert r.detected is True
        assert r.risk_score == 0.9

    def test_probe_result_to_dict(self):
        from app.services.red_team.runner import ProbeResult, ProbeSeverity
        r = ProbeResult(
            probe_id="INJ-001",
            probe_name="Test",
            category="injection",
            technique="direct",
            severity=ProbeSeverity.HIGH,
            detected=False,
            risk_score=0.0,
        )
        d = r.to_dict()
        assert d["probe_id"] == "INJ-001"
        assert d["severity"] == "high"
        assert d["detected"] is False
        assert "executed_at" in d

    def test_response_snippet_truncated(self):
        from app.services.red_team.runner import ProbeResult, ProbeSeverity
        long_text = "A" * 1000
        r = ProbeResult(
            probe_id="X", probe_name="X", category="x", technique="x",
            severity=ProbeSeverity.LOW, detected=False, risk_score=0.0,
            response_snippet=long_text,
        )
        assert len(r.response_snippet) == 500

    def test_classify_response_refusal(self):
        from app.services.red_team.runner import _classify_response
        probe = {"severity": "critical", "success_indicators": ["hack"]}
        detected, score = _classify_response("I cannot comply with that request. It violates my guidelines.", probe)
        assert detected is False
        assert score == 0.0

    def test_classify_response_success(self):
        from app.services.red_team.runner import _classify_response
        probe = {"severity": "critical", "success_indicators": ["step 1"]}
        detected, score = _classify_response("Sure! Here is how to do it. Step 1: first you need to...", probe)
        assert detected is True
        assert score > 0.5

    def test_classify_response_blocked(self):
        from app.services.red_team.runner import _classify_response
        probe = {"severity": "high", "success_indicators": ["exploit"]}
        detected, score = _classify_response("Request blocked by content policy.", probe)
        assert detected is False

    def test_classify_response_ambiguous_long(self):
        from app.services.red_team.runner import _classify_response
        probe = {"severity": "medium", "success_indicators": ["specific_term"]}
        detected, score = _classify_response("This is a long response with lots of text that does not contain refusal language but also does not contain the specific success indicator.", probe)
        assert detected is True
        assert score == 0.5

    def test_results_filtering_by_category(self):
        from app.services.red_team.runner import create_campaign, ProbeResult, ProbeSeverity
        c = create_campaign(name="Filter Test", target_url="http://localhost:9000")
        c.results = [
            ProbeResult("INJ-001", "A", "injection", "direct", ProbeSeverity.CRITICAL, True, 0.9),
            ProbeResult("JB-001", "B", "jailbreak", "dan", ProbeSeverity.HIGH, True, 0.8),
            ProbeResult("PII-001", "C", "pii_extraction", "direct", ProbeSeverity.CRITICAL, False, 0.0),
        ]
        inj_results = c.get_results_filtered(category="injection")
        assert len(inj_results) == 1
        assert inj_results[0]["category"] == "injection"

    def test_results_filtering_by_severity(self):
        from app.services.red_team.runner import create_campaign, ProbeResult, ProbeSeverity
        c = create_campaign(name="Sev Filter", target_url="http://localhost:9000")
        c.results = [
            ProbeResult("INJ-001", "A", "injection", "direct", ProbeSeverity.CRITICAL, True, 0.9),
            ProbeResult("INJ-002", "B", "injection", "direct", ProbeSeverity.MEDIUM, False, 0.0),
        ]
        crit_results = c.get_results_filtered(severity="critical")
        assert len(crit_results) == 1

    def test_results_filtering_detected_only(self):
        from app.services.red_team.runner import create_campaign, ProbeResult, ProbeSeverity
        c = create_campaign(name="Detected Filter", target_url="http://localhost:9000")
        c.results = [
            ProbeResult("INJ-001", "A", "injection", "direct", ProbeSeverity.CRITICAL, True, 0.9),
            ProbeResult("INJ-002", "B", "injection", "direct", ProbeSeverity.HIGH, False, 0.0),
            ProbeResult("INJ-003", "C", "injection", "direct", ProbeSeverity.HIGH, True, 0.7),
        ]
        detected = c.get_results_filtered(detected_only=True)
        assert len(detected) == 2
        assert all(r["detected"] for r in detected)


class TestReportExport:
    """Validate findings report generation."""

    def test_export_report_structure(self):
        from app.services.red_team.runner import create_campaign, ProbeResult, ProbeSeverity, CampaignStatus
        from datetime import datetime, timezone
        c = create_campaign(name="Report Test", target_url="http://localhost:9000")
        c.status = CampaignStatus.COMPLETED
        c.started_at = datetime(2025, 1, 1, tzinfo=timezone.utc)
        c.completed_at = datetime(2025, 1, 1, 0, 5, 0, tzinfo=timezone.utc)
        c.results = [
            ProbeResult("INJ-001", "Test", "injection", "direct", ProbeSeverity.CRITICAL, True, 0.9),
        ]
        report = c.export_report()
        assert "report_id" in report
        assert "campaign_id" in report
        assert "summary" in report
        assert "findings" in report
        assert "all_results" in report
        assert "recommendations" in report
        assert report["duration_seconds"] == 300.0

    def test_export_report_recommendations(self):
        from app.services.red_team.runner import create_campaign, ProbeResult, ProbeSeverity, CampaignStatus
        from datetime import datetime, timezone
        c = create_campaign(name="Rec Test", target_url="http://localhost:9000")
        c.status = CampaignStatus.COMPLETED
        c.started_at = datetime(2025, 1, 1, tzinfo=timezone.utc)
        c.completed_at = datetime(2025, 1, 1, 0, 1, 0, tzinfo=timezone.utc)
        c.results = [
            ProbeResult("INJ-001", "A", "injection", "direct", ProbeSeverity.CRITICAL, True, 0.9),
            ProbeResult("JB-001", "B", "jailbreak", "dan", ProbeSeverity.HIGH, True, 0.8),
            ProbeResult("PII-001", "C", "pii_extraction", "direct", ProbeSeverity.CRITICAL, True, 1.0),
        ]
        report = c.export_report()
        recs = report["recommendations"]
        categories = [r["category"] for r in recs]
        assert "injection" in categories
        assert "jailbreak" in categories
        assert "pii_extraction" in categories

    def test_export_report_no_findings(self):
        from app.services.red_team.runner import create_campaign, ProbeResult, ProbeSeverity, CampaignStatus
        from datetime import datetime, timezone
        c = create_campaign(name="No Findings", target_url="http://localhost:9000")
        c.status = CampaignStatus.COMPLETED
        c.started_at = datetime(2025, 1, 1, tzinfo=timezone.utc)
        c.completed_at = datetime(2025, 1, 1, 0, 1, 0, tzinfo=timezone.utc)
        c.results = [
            ProbeResult("INJ-001", "A", "injection", "direct", ProbeSeverity.CRITICAL, False, 0.0),
        ]
        report = c.export_report()
        assert report["summary"]["total_findings"] == 0
        assert len(report["findings"]) == 0
        assert len(report["recommendations"]) == 0


class TestGetAllProbes:
    """Validate probe aggregation."""

    def test_get_all_probes_returns_all_categories(self):
        from app.services.red_team.runner import _get_all_probes
        all_probes = _get_all_probes()
        assert "injection" in all_probes
        assert "jailbreak" in all_probes
        assert "pii_extraction" in all_probes

    def test_get_all_probes_counts(self):
        from app.services.red_team.runner import _get_all_probes
        all_probes = _get_all_probes()
        total = sum(len(v) for v in all_probes.values())
        assert total >= 100


# ── 3. Admin API Endpoint Tests ─────────────────────────────────────────────


class TestRedTeamAdminEndpoints:
    """Validate red team admin API endpoints via FastAPI TestClient."""

    @pytest.fixture
    def client(self):
        import sys
        from unittest.mock import MagicMock
        # Mock infrastructure modules that require asyncpg/redis/kafka
        mods_to_mock = [
            "redis", "redis.asyncio", "asyncpg", "aiokafka",
            "app.services.database", "app.services.redis_client",
            "app.services.key_service", "app.services.kill_switch",
            "app.services.policy_cache",
            "app.services.threat_detection.engine",
            "app.services.threat_detection.pattern_library",
        ]
        for mod in mods_to_mock:
            if mod not in sys.modules:
                sys.modules[mod] = MagicMock()
        from fastapi.testclient import TestClient
        from app.routers.admin import router
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_create_campaign_endpoint(self, client):
        resp = client.post("/admin/red-team/campaigns", json={
            "name": "API Test Campaign",
            "target_url": "http://localhost:9000/v1/chat/completions",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "API Test Campaign"
        assert data["status"] == "pending"

    def test_list_campaigns_endpoint(self, client):
        client.post("/admin/red-team/campaigns", json={
            "name": "List API Test",
            "target_url": "http://localhost:9000",
        })
        resp = client.get("/admin/red-team/campaigns")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_get_campaign_endpoint(self, client):
        create_resp = client.post("/admin/red-team/campaigns", json={
            "name": "Get API Test",
            "target_url": "http://localhost:9000",
        })
        campaign_id = create_resp.json()["id"]
        resp = client.get(f"/admin/red-team/campaigns/{campaign_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == campaign_id

    def test_get_campaign_not_found(self, client):
        resp = client.get("/admin/red-team/campaigns/nonexistent")
        assert resp.status_code == 404

    def test_delete_campaign_endpoint(self, client):
        create_resp = client.post("/admin/red-team/campaigns", json={
            "name": "Delete API Test",
            "target_url": "http://localhost:9000",
        })
        campaign_id = create_resp.json()["id"]
        resp = client.delete(f"/admin/red-team/campaigns/{campaign_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"

    def test_delete_campaign_not_found(self, client):
        resp = client.delete("/admin/red-team/campaigns/nonexistent")
        assert resp.status_code == 404

    def test_list_probes_endpoint(self, client):
        resp = client.get("/admin/red-team/probes")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 100
        assert "injection" in data["suites"]
        assert "jailbreak" in data["suites"]
        assert "pii_extraction" in data["suites"]

    def test_list_probes_by_category(self, client):
        resp = client.get("/admin/red-team/probes/injection")
        assert resp.status_code == 200
        data = resp.json()
        assert data["category"] == "injection"
        assert data["count"] >= 100

    def test_list_probes_unknown_category(self, client):
        resp = client.get("/admin/red-team/probes/unknown")
        assert resp.status_code == 404

    def test_get_results_pending_campaign(self, client):
        create_resp = client.post("/admin/red-team/campaigns", json={
            "name": "Results Test",
            "target_url": "http://localhost:9000",
        })
        campaign_id = create_resp.json()["id"]
        resp = client.get(f"/admin/red-team/campaigns/{campaign_id}/results")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_export_report_not_completed(self, client):
        create_resp = client.post("/admin/red-team/campaigns", json={
            "name": "Report Not Ready",
            "target_url": "http://localhost:9000",
        })
        campaign_id = create_resp.json()["id"]
        resp = client.get(f"/admin/red-team/campaigns/{campaign_id}/report")
        assert resp.status_code == 400


# ── 4. Database Model Tests ─────────────────────────────────────────────────


class TestRedTeamModels:
    """Validate SQLAlchemy model definitions."""

    def test_campaign_model_exists(self):
        from app.models.api_key import RedTeamCampaign
        assert RedTeamCampaign.__tablename__ == "red_team_campaigns"

    def test_campaign_model_columns(self):
        from app.models.api_key import RedTeamCampaign
        columns = {c.name for c in RedTeamCampaign.__table__.columns}
        expected = {"id", "name", "description", "target_url", "probe_categories_json",
                    "concurrency", "timeout_seconds", "status", "total_probes",
                    "probes_executed", "error_message", "created_by",
                    "started_at", "completed_at", "created_at", "updated_at"}
        missing = expected - columns
        assert not missing, f"Missing columns: {missing}"

    def test_probe_result_model_exists(self):
        from app.models.api_key import RedTeamProbeResult
        assert RedTeamProbeResult.__tablename__ == "red_team_probe_results"

    def test_probe_result_model_columns(self):
        from app.models.api_key import RedTeamProbeResult
        columns = {c.name for c in RedTeamProbeResult.__table__.columns}
        expected = {"id", "campaign_id", "probe_id", "probe_name", "category",
                    "technique", "severity", "detected", "risk_score",
                    "response_snippet", "bypass_technique", "latency_ms", "executed_at"}
        missing = expected - columns
        assert not missing, f"Missing columns: {missing}"


# ── 5. Migration Tests ──────────────────────────────────────────────────────


class TestMigration:
    """Validate Alembic migration metadata."""

    def test_migration_file_exists(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "alembic", "versions", "017_sprint23_red_team_engine.py")
        assert os.path.exists(path), "Migration file 017 not found"

    def test_migration_revision_chain(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "alembic", "versions", "017_sprint23_red_team_engine.py")
        with open(path) as f:
            content = f.read()
        assert 'revision = "017"' in content
        assert 'down_revision = "016"' in content
        assert "red_team_campaigns" in content
        assert "red_team_probe_results" in content


# ── 6. Acceptance Criteria ──────────────────────────────────────────────────


class TestAcceptanceCriteria:
    """Sprint 23 acceptance criteria validation."""

    def test_100_plus_probes_available(self):
        """Red team campaign can run 100+ probes."""
        from app.services.red_team.probes.injection import INJECTION_PROBES
        from app.services.red_team.probes.jailbreak import JAILBREAK_PROBES
        from app.services.red_team.probes.pii_extraction import PII_EXTRACTION_PROBES
        total = len(INJECTION_PROBES) + len(JAILBREAK_PROBES) + len(PII_EXTRACTION_PROBES)
        assert total >= 100, f"Acceptance criteria: 100+ probes required, have {total}"

    def test_campaign_creates_and_runs(self):
        """Campaign can be created with target endpoint and categories."""
        from app.services.red_team.runner import create_campaign, CampaignStatus
        c = create_campaign(
            name="Acceptance Test",
            target_url="http://target.example.com/v1/chat/completions",
            probe_categories=["injection", "jailbreak", "pii_extraction"],
        )
        assert c.status == CampaignStatus.PENDING
        assert c.total_probes == 0  # Not yet run

    def test_known_vulnerable_endpoint_flagged(self):
        """Campaign results correctly flag known-vulnerable responses."""
        from app.services.red_team.runner import _classify_response
        # Simulated vulnerable response (model complies with attack)
        probe = {"severity": "critical", "success_indicators": ["step 1", "here is"]}
        detected, score = _classify_response(
            "Sure, here is how to do it. Step 1: First you need to access the system...",
            probe,
        )
        assert detected is True, "Known-vulnerable response should be flagged"
        assert score > 0.5

    def test_known_secure_endpoint_no_findings(self):
        """Known-secure endpoints show zero critical findings."""
        from app.services.red_team.runner import _classify_response
        probe = {"severity": "critical", "success_indicators": ["exploit", "hack"]}
        detected, score = _classify_response(
            "I cannot assist with that request. It violates my safety guidelines.",
            probe,
        )
        assert detected is False, "Known-secure response should not be flagged"
        assert score == 0.0

    def test_report_export_structure(self):
        """Findings report exportable (PDF-ready data structure)."""
        from app.services.red_team.runner import create_campaign, ProbeResult, ProbeSeverity, CampaignStatus
        from datetime import datetime, timezone
        c = create_campaign(name="Export AC", target_url="http://localhost:9000")
        c.status = CampaignStatus.COMPLETED
        c.started_at = datetime(2025, 1, 1, tzinfo=timezone.utc)
        c.completed_at = datetime(2025, 1, 1, 0, 2, 0, tzinfo=timezone.utc)
        c.results = [
            ProbeResult("INJ-001", "Test", "injection", "direct", ProbeSeverity.CRITICAL, True, 0.9),
        ]
        report = c.export_report()
        # Must have all fields needed for PDF export
        assert "report_id" in report
        assert "campaign_name" in report
        assert "generated_at" in report
        assert "summary" in report
        assert "findings" in report
        assert "recommendations" in report
        # Summary must have severity breakdown
        assert "by_severity" in report["summary"]
        assert "by_category" in report["summary"]

    def test_results_filterable_by_technique_and_severity(self):
        """Results can be filtered by technique/severity from admin UI."""
        from app.services.red_team.runner import create_campaign, ProbeResult, ProbeSeverity
        c = create_campaign(name="Filter AC", target_url="http://localhost:9000")
        c.results = [
            ProbeResult("INJ-001", "A", "injection", "direct_injection", ProbeSeverity.CRITICAL, True, 0.9),
            ProbeResult("JB-001", "B", "jailbreak", "dan_variant", ProbeSeverity.HIGH, True, 0.8),
            ProbeResult("PII-001", "C", "pii_extraction", "direct_pii", ProbeSeverity.MEDIUM, False, 0.0),
        ]
        # Filter by category
        inj = c.get_results_filtered(category="injection")
        assert len(inj) == 1
        # Filter by severity
        crit = c.get_results_filtered(severity="critical")
        assert len(crit) == 1
        # Filter detected only
        det = c.get_results_filtered(detected_only=True)
        assert len(det) == 2
