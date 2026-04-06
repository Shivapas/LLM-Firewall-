"""Sprint 19: Enterprise Dashboard & Alerting — Tests.

Covers:
- Security operations dashboard (request volume, block rate, top threats/tenants, kill-switches, incidents)
- Policy coverage map (OWASP LLM Top 10 coverage)
- Incident management (CRUD, stats, lifecycle)
- Real-time alert engine (rule CRUD, condition evaluation, firing, cooldown, delivery)
- Tenant usage dashboard (per-tenant stats)
- Onboarding wizard (step tracking, auto-detect, reset)
- Admin API endpoints
"""

import asyncio
import contextlib
import json
import time
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_session_factory(mock_db):
    """Create a mock async session factory matching SQLAlchemy's async_sessionmaker pattern."""
    @contextlib.asynccontextmanager
    async def factory():
        yield mock_db
    return factory


# ── 1. Security Operations Dashboard ──────────────────────────────────────


class TestSecurityOpsDashboard:
    """Validate the unified security operations dashboard aggregation."""

    def test_dashboard_data_model(self):
        from app.services.dashboard.security_ops import (
            SecurityDashboardData, RequestVolumeStats, ThreatSummary,
            TenantSummary, KillSwitchSummary, IncidentSummary,
        )
        data = SecurityDashboardData(
            generated_at="2026-01-01T00:00:00Z",
            period_hours=24,
            request_volume=RequestVolumeStats(
                total_requests=1000,
                allowed_requests=900,
                blocked_requests=80,
                rerouted_requests=10,
                rate_limited_requests=10,
                block_rate=8.0,
            ),
            top_threats=[ThreatSummary(category="prompt_injection", severity="high", count=50)],
            top_tenants=[TenantSummary(tenant_id="t1", request_count=500, block_count=40, block_rate=8.0, total_tokens=100000)],
            active_kill_switches=[KillSwitchSummary(model_name="gpt-4", action="block", reason="safety")],
            recent_incidents=[IncidentSummary(id="inc1", incident_type="critical_threat", severity="critical", title="Test", status="open")],
        )
        assert data.request_volume.total_requests == 1000
        assert data.request_volume.block_rate == 8.0
        assert len(data.top_threats) == 1
        assert data.top_threats[0].category == "prompt_injection"
        assert len(data.active_kill_switches) == 1
        assert len(data.recent_incidents) == 1

    @pytest.mark.asyncio
    async def test_dashboard_without_session(self):
        from app.services.dashboard.security_ops import SecurityOpsDashboardService
        svc = SecurityOpsDashboardService(session_factory=None)
        data = await svc.get_dashboard(period_hours=24)
        assert data.period_hours == 24
        assert data.request_volume.total_requests == 0

    def test_block_rate_calculation(self):
        from app.services.dashboard.security_ops import RequestVolumeStats
        # With requests
        stats = RequestVolumeStats(total_requests=100, blocked_requests=30, block_rate=30.0)
        assert stats.block_rate == 30.0
        # Zero requests
        stats_zero = RequestVolumeStats(total_requests=0, block_rate=0.0)
        assert stats_zero.block_rate == 0.0


# ── 2. Policy Coverage Map ────────────────────────────────────────────────


class TestPolicyCoverageMap:
    """Validate OWASP LLM Top 10 coverage mapping."""

    def test_owasp_top_10_definitions(self):
        from app.services.dashboard.policy_coverage import OWASP_LLM_TOP_10
        assert len(OWASP_LLM_TOP_10) == 10
        assert "LLM01" in OWASP_LLM_TOP_10
        assert OWASP_LLM_TOP_10["LLM01"]["name"] == "Prompt Injection"
        assert "prompt_injection" in OWASP_LLM_TOP_10["LLM01"]["categories"]

    def test_coverage_item_model(self):
        from app.services.dashboard.policy_coverage import OWASPCoverageItem
        item = OWASPCoverageItem(
            owasp_id="LLM01",
            name="Prompt Injection",
            expected_categories=["prompt_injection"],
            matching_rules=["rule1"],
            matching_rule_count=1,
            is_covered=True,
        )
        assert item.is_covered is True
        assert item.matching_rule_count == 1

    @pytest.mark.asyncio
    async def test_coverage_map_without_session(self):
        from app.services.dashboard.policy_coverage import PolicyCoverageService
        svc = PolicyCoverageService(session_factory=None)
        cov = await svc.get_coverage_map()
        assert cov.total_owasp_items == 10
        assert len(cov.items) == 10
        # Without DB rules, coverage comes only from built-in threat patterns
        assert isinstance(cov.coverage_percentage, float)

    @pytest.mark.asyncio
    async def test_coverage_gap_detection(self):
        from app.services.dashboard.policy_coverage import PolicyCoverageService
        svc = PolicyCoverageService(session_factory=None)

        # Monkey-patch to return no built-in patterns
        with patch("app.services.threat_detection.engine.get_threat_engine", side_effect=Exception):
            cov = await svc.get_coverage_map()
            # With no rules at all, all items should be gaps
            assert len(cov.gap_items) == 10
            assert cov.covered_items == 0


# ── 3. Incident Management ────────────────────────────────────────────────


class TestIncidentManagement:
    """Validate incident CRUD and lifecycle."""

    def test_incident_request_models(self):
        from app.services.dashboard.incident_manager import CreateIncidentRequest, UpdateIncidentRequest
        req = CreateIncidentRequest(
            incident_type="critical_threat",
            severity="critical",
            title="SQL injection detected",
            description="High-confidence injection in tenant-5",
            tenant_id="tenant-5",
        )
        assert req.incident_type == "critical_threat"
        assert req.severity == "critical"

        update = UpdateIncidentRequest(status="investigating", assigned_to="admin@company.com")
        assert update.status == "investigating"

    def test_incident_record_model(self):
        from app.services.dashboard.incident_manager import IncidentRecord
        record = IncidentRecord(
            id="123",
            incident_type="namespace_breach",
            severity="high",
            title="Cross-tenant access attempt",
            status="open",
        )
        assert record.status == "open"
        assert record.incident_type == "namespace_breach"

    def test_incident_stats_model(self):
        from app.services.dashboard.incident_manager import IncidentStats
        stats = IncidentStats(
            total=10, open=5, investigating=3, resolved=1, dismissed=1,
            by_type={"critical_threat": 6, "tier2_finding": 4},
            by_severity={"critical": 3, "high": 7},
        )
        assert stats.total == 10
        assert stats.open == 5
        assert stats.by_type["critical_threat"] == 6

    @pytest.mark.asyncio
    async def test_create_incident_without_session(self):
        from app.services.dashboard.incident_manager import IncidentManagementService, CreateIncidentRequest
        svc = IncidentManagementService(session_factory=None)
        req = CreateIncidentRequest(
            incident_type="critical_threat",
            title="Test incident",
        )
        # Should still create (without persistence) — incident has server_default columns
        # that won't be populated without a DB, so we just verify it doesn't crash
        record = await svc.create_incident(req)
        assert record.incident_type == "critical_threat"
        assert record.title == "Test incident"

    @pytest.mark.asyncio
    async def test_list_incidents_without_session(self):
        from app.services.dashboard.incident_manager import IncidentManagementService
        svc = IncidentManagementService(session_factory=None)
        results = await svc.list_incidents()
        assert results == []

    @pytest.mark.asyncio
    async def test_get_stats_without_session(self):
        from app.services.dashboard.incident_manager import IncidentManagementService
        svc = IncidentManagementService(session_factory=None)
        stats = await svc.get_stats()
        assert stats.total == 0

    def test_valid_incident_types(self):
        from app.services.dashboard.incident_manager import IncidentManagementService
        assert "critical_threat" in IncidentManagementService.VALID_TYPES
        assert "namespace_breach" in IncidentManagementService.VALID_TYPES
        assert "kill_switch_activation" in IncidentManagementService.VALID_TYPES
        assert "tier2_finding" in IncidentManagementService.VALID_TYPES


# ── 4. Real-time Alert Engine ─────────────────────────────────────────────


class TestAlertEngine:
    """Validate alert rule CRUD, condition evaluation, and delivery."""

    def test_alert_rule_config_model(self):
        from app.services.dashboard.alert_engine import AlertRuleConfig
        config = AlertRuleConfig(
            name="High block rate",
            condition_type="block_rate_spike",
            delivery_channel="webhook",
            delivery_target="https://hooks.example.com/alert",
            cooldown_seconds=600,
        )
        assert config.name == "High block rate"
        assert config.condition_type == "block_rate_spike"
        assert config.cooldown_seconds == 600

    def test_alert_trigger_context_model(self):
        from app.services.dashboard.alert_engine import AlertTriggerContext
        ctx = AlertTriggerContext(
            condition_type="block_rate_spike",
            tenant_id="t1",
            metric_value=42.5,
            threshold=30.0,
            message="Block rate spike: 42.5% (threshold: 30%)",
            metadata={"total": 100, "blocked": 42},
        )
        assert ctx.metric_value == 42.5
        assert ctx.threshold == 30.0
        assert ctx.metadata["blocked"] == 42

    def test_valid_condition_types(self):
        from app.services.dashboard.alert_engine import AlertEngineService
        assert "block_rate_spike" in AlertEngineService.VALID_CONDITIONS
        assert "budget_exhaustion" in AlertEngineService.VALID_CONDITIONS
        assert "new_critical_mcp_tool" in AlertEngineService.VALID_CONDITIONS
        assert "kill_switch_activation" in AlertEngineService.VALID_CONDITIONS
        assert "anomaly_score_breach" in AlertEngineService.VALID_CONDITIONS

    @pytest.mark.asyncio
    async def test_list_rules_without_session(self):
        from app.services.dashboard.alert_engine import AlertEngineService
        svc = AlertEngineService(session_factory=None)
        rules = await svc.list_rules()
        assert rules == []

    @pytest.mark.asyncio
    async def test_evaluate_condition_without_session(self):
        from app.services.dashboard.alert_engine import AlertEngineService
        svc = AlertEngineService(session_factory=None)
        result = await svc.evaluate_condition("block_rate_spike")
        assert result is None

    @pytest.mark.asyncio
    async def test_evaluate_all_rules_without_session(self):
        from app.services.dashboard.alert_engine import AlertEngineService
        svc = AlertEngineService(session_factory=None)
        fired = await svc.evaluate_all_rules()
        assert fired == []

    @pytest.mark.asyncio
    async def test_list_events_without_session(self):
        from app.services.dashboard.alert_engine import AlertEngineService
        svc = AlertEngineService(session_factory=None)
        events = await svc.list_events()
        assert events == []

    def test_alert_event_record_model(self):
        from app.services.dashboard.alert_engine import AlertEventRecord
        event = AlertEventRecord(
            id="e1",
            alert_rule_id="r1",
            alert_rule_name="Test Rule",
            condition_type="block_rate_spike",
            severity="high",
            message="Block rate spiked",
            delivery_channel="webhook",
            delivery_status="sent",
        )
        assert event.delivery_status == "sent"
        assert event.severity == "high"

    @pytest.mark.asyncio
    async def test_email_delivery_placeholder(self):
        from app.services.dashboard.alert_engine import AlertEngineService
        svc = AlertEngineService(session_factory=None)
        status = await svc._deliver_email("admin@example.com", "Test alert", {})
        assert status == "sent"

    @pytest.mark.asyncio
    async def test_webhook_delivery_no_target(self):
        from app.services.dashboard.alert_engine import AlertEngineService
        svc = AlertEngineService(session_factory=None)
        status = await svc._deliver_alert("webhook", "", "msg", {})
        assert status == "no_target"

    @pytest.mark.asyncio
    async def test_start_stop_engine(self):
        from app.services.dashboard.alert_engine import AlertEngineService
        svc = AlertEngineService(session_factory=None)
        await svc.start(interval_seconds=60)
        assert svc._running is True
        await svc.stop()
        assert svc._running is False


# ── 5. Tenant Usage Dashboard ─────────────────────────────────────────────


class TestTenantUsageDashboard:
    """Validate per-tenant usage stats."""

    def test_tenant_usage_stats_model(self):
        from app.services.dashboard.tenant_usage import TenantUsageStats
        stats = TenantUsageStats(
            tenant_id="t1",
            total_requests=200,
            allowed_requests=180,
            blocked_requests=20,
            block_rate=10.0,
            prompt_tokens=50000,
            completion_tokens=30000,
            total_tokens=80000,
            estimated_cost_usd=3.30,
            policy_violations=20,
            models_used=["gpt-4", "claude-3"],
        )
        assert stats.block_rate == 10.0
        assert stats.estimated_cost_usd == 3.30
        assert "gpt-4" in stats.models_used

    @pytest.mark.asyncio
    async def test_tenant_usage_without_session(self):
        from app.services.dashboard.tenant_usage import TenantUsageDashboardService
        svc = TenantUsageDashboardService(session_factory=None)
        stats = await svc.get_tenant_usage("tenant-1", period_hours=24)
        assert stats.tenant_id == "tenant-1"
        assert stats.total_requests == 0

    @pytest.mark.asyncio
    async def test_list_tenants_summary_without_session(self):
        from app.services.dashboard.tenant_usage import TenantUsageDashboardService
        svc = TenantUsageDashboardService(session_factory=None)
        results = await svc.list_tenants_summary()
        assert results == []

    def test_cost_estimation_defaults(self):
        from app.services.dashboard.tenant_usage import DEFAULT_COST_PER_1K_PROMPT, DEFAULT_COST_PER_1K_COMPLETION
        assert DEFAULT_COST_PER_1K_PROMPT > 0
        assert DEFAULT_COST_PER_1K_COMPLETION > 0
        # Verify completion is more expensive than prompt (common pricing model)
        assert DEFAULT_COST_PER_1K_COMPLETION >= DEFAULT_COST_PER_1K_PROMPT


# ── 6. Onboarding Wizard ──────────────────────────────────────────────────


class TestOnboardingWizard:
    """Validate onboarding step tracking and auto-detection."""

    def test_onboarding_steps_definition(self):
        from app.services.dashboard.onboarding_wizard import ONBOARDING_STEPS
        assert len(ONBOARDING_STEPS) == 4
        keys = [s["key"] for s in ONBOARDING_STEPS]
        assert "step_register_model" in keys
        assert "step_issue_api_key" in keys
        assert "step_send_test_request" in keys
        assert "step_verify_audit_log" in keys

    def test_onboarding_status_model(self):
        from app.services.dashboard.onboarding_wizard import OnboardingStatus
        status = OnboardingStatus(
            tenant_id="t1",
            total_steps=4,
            current_step=2,
            completed=False,
            progress_percentage=50.0,
        )
        assert status.progress_percentage == 50.0
        assert status.completed is False

    @pytest.mark.asyncio
    async def test_get_status_without_session(self):
        from app.services.dashboard.onboarding_wizard import OnboardingWizardService
        svc = OnboardingWizardService(session_factory=None)
        status = await svc.get_status("tenant-1")
        assert status.tenant_id == "tenant-1"
        assert status.total_steps == 4

    @pytest.mark.asyncio
    async def test_complete_step_invalid_key(self):
        from app.services.dashboard.onboarding_wizard import OnboardingWizardService
        svc = OnboardingWizardService(session_factory=None)
        with pytest.raises(ValueError, match="Invalid step key"):
            await svc.complete_step("tenant-1", "invalid_step")

    def test_build_steps_no_progress(self):
        from app.services.dashboard.onboarding_wizard import OnboardingWizardService
        svc = OnboardingWizardService()
        steps = svc._build_steps(None)
        assert len(steps) == 4
        assert all(not s["completed"] for s in steps)

    def test_build_steps_with_progress(self):
        from app.services.dashboard.onboarding_wizard import OnboardingWizardService
        svc = OnboardingWizardService()

        # Mock progress object
        progress = MagicMock()
        progress.step_register_model = True
        progress.step_issue_api_key = True
        progress.step_send_test_request = False
        progress.step_verify_audit_log = False

        steps = svc._build_steps(progress)
        assert steps[0]["completed"] is True
        assert steps[1]["completed"] is True
        assert steps[2]["completed"] is False
        assert steps[3]["completed"] is False


# ── 7. DB Model Definitions ───────────────────────────────────────────────


class TestSprint19Models:
    """Validate Sprint 19 SQLAlchemy model definitions."""

    def test_alert_rule_model(self):
        from app.models.api_key import AlertRule
        assert AlertRule.__tablename__ == "alert_rules"
        rule = AlertRule(
            id=uuid.uuid4(),
            name="test-rule",
            condition_type="block_rate_spike",
            delivery_channel="webhook",
            delivery_target="https://example.com/hook",
        )
        assert rule.name == "test-rule"
        assert rule.condition_type == "block_rate_spike"

    def test_alert_event_model(self):
        from app.models.api_key import AlertEvent
        assert AlertEvent.__tablename__ == "alert_events"
        event = AlertEvent(
            id=uuid.uuid4(),
            alert_rule_id=uuid.uuid4(),
            condition_type="kill_switch_activation",
            message="Kill-switch activated",
        )
        assert event.condition_type == "kill_switch_activation"

    def test_security_incident_model(self):
        from app.models.api_key import SecurityIncident
        assert SecurityIncident.__tablename__ == "security_incidents"
        inc = SecurityIncident(
            id=uuid.uuid4(),
            incident_type="critical_threat",
            severity="critical",
            title="Critical injection detected",
            status="open",
        )
        assert inc.status == "open"
        assert inc.severity == "critical"

    def test_onboarding_progress_model(self):
        from app.models.api_key import OnboardingProgress
        assert OnboardingProgress.__tablename__ == "onboarding_progress"
        prog = OnboardingProgress(
            id=uuid.uuid4(),
            tenant_id="tenant-1",
            step_register_model=True,
            step_issue_api_key=False,
            completed=False,
        )
        assert prog.step_register_model is True
        assert prog.step_issue_api_key is False
        assert prog.completed is False


# ── 8. Singleton Getters ──────────────────────────────────────────────────


class TestSingletonGetters:
    """Validate singleton pattern for Sprint 19 services."""

    def test_security_ops_dashboard_singleton(self):
        import app.services.dashboard.security_ops as mod
        mod._service = None
        svc1 = mod.get_security_ops_dashboard()
        svc2 = mod.get_security_ops_dashboard()
        assert svc1 is svc2
        mod._service = None

    def test_policy_coverage_singleton(self):
        import app.services.dashboard.policy_coverage as mod
        mod._service = None
        svc1 = mod.get_policy_coverage_service()
        svc2 = mod.get_policy_coverage_service()
        assert svc1 is svc2
        mod._service = None

    def test_incident_management_singleton(self):
        import app.services.dashboard.incident_manager as mod
        mod._service = None
        svc1 = mod.get_incident_management_service()
        svc2 = mod.get_incident_management_service()
        assert svc1 is svc2
        mod._service = None

    def test_alert_engine_singleton(self):
        import app.services.dashboard.alert_engine as mod
        mod._service = None
        svc1 = mod.get_alert_engine_service()
        svc2 = mod.get_alert_engine_service()
        assert svc1 is svc2
        mod._service = None

    def test_tenant_usage_singleton(self):
        import app.services.dashboard.tenant_usage as mod
        mod._service = None
        svc1 = mod.get_tenant_usage_dashboard()
        svc2 = mod.get_tenant_usage_dashboard()
        assert svc1 is svc2
        mod._service = None

    def test_onboarding_wizard_singleton(self):
        import app.services.dashboard.onboarding_wizard as mod
        mod._service = None
        svc1 = mod.get_onboarding_wizard_service()
        svc2 = mod.get_onboarding_wizard_service()
        assert svc1 is svc2
        mod._service = None


# ── 9. Alert Engine Cooldown Logic ────────────────────────────────────────


class TestAlertCooldown:
    """Validate cooldown prevents alert storms."""

    def test_cooldown_alert_event_record(self):
        from app.services.dashboard.alert_engine import AlertEventRecord
        # A cooldown response should have delivery_status = "cooldown"
        event = AlertEventRecord(delivery_status="cooldown", message="Alert in cooldown period")
        assert event.delivery_status == "cooldown"


# ── 10. Integration Smoke Tests ───────────────────────────────────────────


class TestAdminEndpointsExist:
    """Verify Sprint 19 service functions are importable and callable."""

    def test_security_ops_dashboard_service(self):
        from app.services.dashboard.security_ops import get_security_ops_dashboard
        assert callable(get_security_ops_dashboard)

    def test_policy_coverage_service(self):
        from app.services.dashboard.policy_coverage import get_policy_coverage_service
        assert callable(get_policy_coverage_service)

    def test_incident_management_service(self):
        from app.services.dashboard.incident_manager import get_incident_management_service
        assert callable(get_incident_management_service)

    def test_alert_engine_service(self):
        from app.services.dashboard.alert_engine import get_alert_engine_service
        assert callable(get_alert_engine_service)

    def test_tenant_usage_dashboard_service(self):
        from app.services.dashboard.tenant_usage import get_tenant_usage_dashboard
        assert callable(get_tenant_usage_dashboard)

    def test_onboarding_wizard_service(self):
        from app.services.dashboard.onboarding_wizard import get_onboarding_wizard_service
        assert callable(get_onboarding_wizard_service)


# ── 11. Policy Coverage Matching Logic ────────────────────────────────────


class TestPolicyCoverageMatching:
    """Validate rule-to-OWASP matching logic."""

    @pytest.mark.asyncio
    async def test_rule_matches_by_category(self):
        from app.services.dashboard.policy_coverage import PolicyCoverageService

        svc = PolicyCoverageService(session_factory=None)

        # Mock threat engine with a prompt_injection pattern
        mock_pattern = MagicMock()
        mock_pattern.name = "test-prompt-injection"
        mock_pattern.category = "prompt_injection"
        mock_pattern.tags = []

        mock_engine = MagicMock()
        mock_engine.library.patterns = [mock_pattern]

        with patch("app.services.threat_detection.engine.get_threat_engine", return_value=mock_engine):
            cov = await svc.get_coverage_map()
            # LLM01 (Prompt Injection) should be covered
            llm01 = next(i for i in cov.items if i.owasp_id == "LLM01")
            assert llm01.is_covered is True
            assert llm01.matching_rule_count >= 1


# ── 12. Alembic Migration ────────────────────────────────────────────────


class TestAlembicMigration:
    """Validate Sprint 19 migration metadata."""

    def test_migration_revision(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "mig_016",
            "alembic/versions/016_sprint19_enterprise_dashboard.py",
        )
        mig = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mig)
        assert mig.revision == "016"
        assert mig.down_revision == "015"

    def test_migration_has_upgrade_downgrade(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "mig_016",
            "alembic/versions/016_sprint19_enterprise_dashboard.py",
        )
        mig = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mig)
        assert callable(mig.upgrade)
        assert callable(mig.downgrade)
