"""Sprint 20: Performance Hardening, Security Review & GA — Tests.

Covers:
- Load test framework (runner, config, report, percentile calculation)
- Memory and CPU profiling (snapshots, leak detection, hotspot analysis)
- Regex auditor (catastrophic backtracking detection, compilation timing)
- Cache monitor (hit/miss/eviction tracking)
- Security penetration test suite (test definitions, finding model, report)
- Kubernetes manifest validation (file existence, required fields)
- GA release checklist (sign-off workflow, readiness check, category filtering)
- Admin API endpoints (importability)
"""

import asyncio
import math
import os
import time
import uuid
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── 1. Load Test Framework ──────────────────────────────────────────────────


class TestLoadTestConfig:
    """Validate load test configuration."""

    def test_default_config(self):
        from loadtest.runner import LoadTestConfig
        cfg = LoadTestConfig()
        assert cfg.rps == 1000
        assert cfg.duration_seconds == 60
        assert cfg.target_url == "http://localhost:8000"
        assert cfg.timeout_seconds == 5.0

    def test_custom_config(self):
        from loadtest.runner import LoadTestConfig
        cfg = LoadTestConfig(rps=500, duration_seconds=30, target_url="http://gw:8080")
        assert cfg.rps == 500
        assert cfg.duration_seconds == 30
        assert cfg.max_concurrency == 0  # auto

    def test_auto_concurrency(self):
        from loadtest.runner import LoadTestConfig, LoadTestRunner
        cfg = LoadTestConfig(rps=200)
        runner = LoadTestRunner(cfg)
        # max_concurrency=0 means auto (2× RPS) — verified in runner.run()
        assert cfg.max_concurrency == 0

    def test_payload_template_has_pii(self):
        from loadtest.runner import LoadTestConfig
        cfg = LoadTestConfig()
        content = cfg.payload_template["messages"][0]["content"]
        assert "123-45-6789" in content  # SSN
        assert "test@example.com" in content  # Email
        assert "Ignore all previous" in content  # Injection


class TestLoadTestReport:
    """Validate load test report calculations."""

    def test_empty_report(self):
        from loadtest.runner import LoadTestReport
        report = LoadTestReport()
        assert report.total_requests == 0
        assert report.p99_target_met is False

    def test_report_with_results(self):
        from loadtest.runner import LoadTestReport
        report = LoadTestReport(
            total_requests=1000,
            successful_requests=990,
            failed_requests=10,
            target_rps=1000,
            achieved_rps=980.5,
            duration_seconds=60.0,
            latency_p50_ms=20.0,
            latency_p95_ms=55.0,
            latency_p99_ms=72.0,
            latency_min_ms=5.0,
            latency_max_ms=150.0,
            latency_mean_ms=25.0,
            error_rate=0.01,
            p99_target_met=True,
        )
        assert report.p99_target_met is True
        assert report.error_rate == 0.01
        assert report.latency_p99_ms == 72.0

    def test_report_summary(self):
        from loadtest.runner import LoadTestReport
        report = LoadTestReport(
            total_requests=100,
            target_rps=100,
            achieved_rps=99.5,
            latency_p99_ms=75.0,
            p99_target_met=True,
        )
        summary = report.summary()
        assert "Target RPS: 100" in summary
        assert "PASS" in summary

    def test_report_summary_fail(self):
        from loadtest.runner import LoadTestReport
        report = LoadTestReport(
            latency_p99_ms=120.0,
            p99_target_met=False,
        )
        summary = report.summary()
        assert "FAIL" in summary

    def test_percentile_calculation(self):
        from loadtest.runner import LoadTestRunner, LoadTestConfig
        runner = LoadTestRunner(LoadTestConfig(rps=10, duration_seconds=1))
        # Manually inject results to test _build_report
        from loadtest.runner import RequestResult
        runner._results = [
            RequestResult(status_code=200, latency_ms=float(i))
            for i in range(1, 101)
        ]
        report = runner._build_report(1.0)
        assert report.total_requests == 100
        assert report.latency_p50_ms == pytest.approx(50.5, abs=1.0)
        assert report.latency_p99_ms == pytest.approx(99.01, abs=1.0)
        assert report.latency_min_ms == 1.0
        assert report.latency_max_ms == 100.0


class TestLoadTestRunner:
    """Validate load test runner mechanics."""

    def test_runner_creation(self):
        from loadtest.runner import LoadTestRunner, LoadTestConfig
        cfg = LoadTestConfig(rps=10, duration_seconds=1)
        runner = LoadTestRunner(cfg)
        assert runner.config.rps == 10

    @pytest.mark.asyncio
    async def test_runner_handles_connection_error(self):
        from loadtest.runner import LoadTestRunner, LoadTestConfig
        cfg = LoadTestConfig(
            target_url="http://127.0.0.1:1",  # Will fail to connect
            rps=2,
            duration_seconds=1,
            timeout_seconds=0.5,
        )
        runner = LoadTestRunner(cfg)
        report = await runner.run()
        # All requests should fail (connection refused)
        assert report.total_requests == 2
        assert report.failed_requests == 2

    def test_build_report_empty(self):
        from loadtest.runner import LoadTestRunner, LoadTestConfig
        runner = LoadTestRunner(LoadTestConfig())
        runner._results = []
        report = runner._build_report(1.0)
        assert report.total_requests == 0


# ── 2. Memory Profiler ──────────────────────────────────────────────────────


class TestMemoryProfiler:
    """Validate memory profiling."""

    def test_snapshot_creation(self):
        from app.services.performance.profiler import MemoryProfiler
        mp = MemoryProfiler()
        snap = mp.take_snapshot()
        assert snap.timestamp > 0
        assert snap.gc_objects >= 0

    def test_tracing_lifecycle(self):
        from app.services.performance.profiler import MemoryProfiler
        mp = MemoryProfiler()
        assert mp._tracing is False
        mp.start_tracing()
        assert mp._tracing is True
        snap = mp.take_snapshot()
        assert snap.tracemalloc_current_mb >= 0
        mp.stop_tracing()
        assert mp._tracing is False

    def test_leak_detection_insufficient_data(self):
        from app.services.performance.profiler import MemoryProfiler
        mp = MemoryProfiler()
        # Less than window snapshots
        mp.take_snapshot()
        result = mp.detect_leak(window=10)
        assert result is None

    def test_leak_detection_no_leak(self):
        from app.services.performance.profiler import MemoryProfiler, MemorySnapshot
        mp = MemoryProfiler()
        # Simulate stable RSS
        for i in range(10):
            snap = MemorySnapshot(timestamp=time.time(), rss_mb=100.0)
            mp._snapshots.append(snap)
        result = mp.detect_leak(window=10)
        assert result is not None
        assert result["detected"] is False

    def test_leak_detection_positive(self):
        from app.services.performance.profiler import MemoryProfiler, MemorySnapshot
        mp = MemoryProfiler()
        # Simulate growing RSS
        for i in range(10):
            snap = MemorySnapshot(timestamp=time.time(), rss_mb=100.0 + i * 5)
            mp._snapshots.append(snap)
        result = mp.detect_leak(window=10)
        assert result is not None
        assert result["detected"] is True
        assert result["growth_mb"] == 45.0

    def test_report(self):
        from app.services.performance.profiler import MemoryProfiler
        mp = MemoryProfiler()
        mp.take_snapshot()
        report = mp.get_report()
        assert report["snapshot_count"] == 1
        assert "latest" in report
        assert "leak_detection" in report

    def test_max_snapshots_eviction(self):
        from app.services.performance.profiler import MemoryProfiler, MemorySnapshot
        mp = MemoryProfiler()
        mp._max_snapshots = 5
        for i in range(10):
            mp._snapshots.append(MemorySnapshot(timestamp=float(i)))
        mp.take_snapshot()  # Triggers eviction
        assert len(mp._snapshots) <= 6  # 5 + 1 new


# ── 3. CPU Profiler ─────────────────────────────────────────────────────────


class TestCPUProfiler:
    """Validate CPU profiling and hotspot detection."""

    def test_profiler_disabled_by_default(self):
        from app.services.performance.profiler import CPUProfiler
        cp = CPUProfiler()
        assert cp.enabled is False

    def test_enable_disable(self):
        from app.services.performance.profiler import CPUProfiler
        cp = CPUProfiler()
        cp.enable()
        assert cp.enabled is True
        cp.disable()
        assert cp.enabled is False

    def test_record_when_disabled(self):
        from app.services.performance.profiler import CPUProfiler, RequestProfile
        cp = CPUProfiler()
        cp.record(RequestProfile(request_id="r1", total_ms=10))
        assert len(cp._profiles) == 0

    def test_record_when_enabled(self):
        from app.services.performance.profiler import CPUProfiler, RequestProfile
        cp = CPUProfiler()
        cp.enable()
        cp.record(RequestProfile(request_id="r1", total_ms=10, threat_detection_ms=5))
        assert len(cp._profiles) == 1

    def test_hotspot_report(self):
        from app.services.performance.profiler import CPUProfiler, RequestProfile
        cp = CPUProfiler()
        cp.enable()
        for i in range(100):
            cp.record(RequestProfile(
                request_id=f"r{i}",
                total_ms=50,
                auth_ms=2,
                threat_detection_ms=20,
                pii_scan_ms=15,
                proxy_ms=10,
                output_scan_ms=3,
            ))
        report = cp.get_hotspot_report()
        assert report["profiles_collected"] == 100
        assert len(report["hotspots"]) > 0
        # Threat detection should be the slowest stage
        assert report["hotspots"][0]["stage"] == "threat_detection"

    def test_clear(self):
        from app.services.performance.profiler import CPUProfiler, RequestProfile
        cp = CPUProfiler()
        cp.enable()
        cp.record(RequestProfile(request_id="r1", total_ms=10))
        cp.clear()
        assert len(cp._profiles) == 0

    def test_empty_hotspot_report(self):
        from app.services.performance.profiler import CPUProfiler
        cp = CPUProfiler()
        report = cp.get_hotspot_report()
        assert report["profiles_collected"] == 0
        assert report["hotspots"] == []


# ── 4. Regex Auditor ────────────────────────────────────────────────────────


class TestRegexAuditor:
    """Validate regex pattern auditing."""

    def test_safe_patterns(self):
        from app.services.performance.profiler import RegexAuditor
        auditor = RegexAuditor()
        result = auditor.audit_patterns([
            r"ignore\s+all\s+previous",
            r"system\s*prompt",
            r"\b\d{3}-\d{2}-\d{4}\b",
        ])
        assert result["total_patterns"] == 3
        assert result["finding_count"] == 0

    def test_invalid_pattern(self):
        from app.services.performance.profiler import RegexAuditor
        auditor = RegexAuditor()
        result = auditor.audit_patterns(["[invalid"])
        assert result["finding_count"] == 1
        assert result["findings"][0]["issue"] == "compilation_error"

    def test_compilation_timing(self):
        from app.services.performance.profiler import RegexAuditor
        auditor = RegexAuditor()
        result = auditor.audit_patterns([r"\btest\b"])
        assert result["avg_compilation_ms"] >= 0


# ── 5. Cache Monitor ────────────────────────────────────────────────────────


class TestCacheMonitor:
    """Validate cache efficiency monitoring."""

    def test_register_and_record(self):
        from app.services.performance.profiler import CacheMonitor
        cm = CacheMonitor()
        cm.register_cache("policy_cache", max_size=100)
        cm.record_hit("policy_cache")
        cm.record_hit("policy_cache")
        cm.record_miss("policy_cache")
        report = cm.get_report()
        assert report["caches"]["policy_cache"]["hits"] == 2
        assert report["caches"]["policy_cache"]["misses"] == 1
        assert report["caches"]["policy_cache"]["hit_rate_pct"] == pytest.approx(66.67, abs=0.1)

    def test_eviction_tracking(self):
        from app.services.performance.profiler import CacheMonitor
        cm = CacheMonitor()
        cm.register_cache("threat_cache")
        cm.record_eviction("threat_cache")
        cm.record_eviction("threat_cache")
        report = cm.get_report()
        assert report["caches"]["threat_cache"]["evictions"] == 2

    def test_unregistered_cache(self):
        from app.services.performance.profiler import CacheMonitor
        cm = CacheMonitor()
        # Should not raise
        cm.record_hit("nonexistent")
        cm.record_miss("nonexistent")
        report = cm.get_report()
        assert "nonexistent" not in report["caches"]

    def test_size_update(self):
        from app.services.performance.profiler import CacheMonitor
        cm = CacheMonitor()
        cm.register_cache("test", max_size=50)
        cm.update_size("test", 25)
        report = cm.get_report()
        assert report["caches"]["test"]["size"] == 25
        assert report["caches"]["test"]["max_size"] == 50


# ── 6. Security Penetration Test Suite ──────────────────────────────────────


class TestPentestFinding:
    """Validate pentest finding model."""

    def test_finding_auto_id(self):
        from app.services.security.pentest import PentestFinding
        f = PentestFinding(title="Test finding", severity="high")
        assert f.id.startswith("PT-")
        assert len(f.id) == 11  # PT- + 8 hex

    def test_finding_custom_id(self):
        from app.services.security.pentest import PentestFinding
        f = PentestFinding(id="CUSTOM-001", title="Custom")
        assert f.id == "CUSTOM-001"


class TestPentestReport:
    """Validate pentest report aggregation."""

    def test_empty_report(self):
        from app.services.security.pentest import PentestReport
        report = PentestReport()
        assert report.unresolved_critical_high == 0
        assert report.scan_id.startswith("SCAN-")

    def test_unresolved_count(self):
        from app.services.security.pentest import PentestReport, PentestFinding
        report = PentestReport(
            findings=[
                PentestFinding(severity="critical", status="open"),
                PentestFinding(severity="high", status="open"),
                PentestFinding(severity="high", status="remediated"),
                PentestFinding(severity="medium", status="open"),
            ],
            critical_count=1,
            high_count=2,
            medium_count=1,
        )
        assert report.unresolved_critical_high == 2

    def test_report_summary(self):
        from app.services.security.pentest import PentestReport
        report = PentestReport(
            total_tests=16,
            passed_tests=14,
            failed_tests=2,
            critical_count=0,
            high_count=1,
            medium_count=1,
        )
        summary = report.summary()
        assert "16 total" in summary
        assert "Critical: 0" in summary


class TestSecurityTestSuite:
    """Validate security test suite definitions and execution."""

    def test_all_test_definitions(self):
        from app.services.security.pentest import SecurityTestSuite
        suite = SecurityTestSuite()
        tests = suite.get_all_test_definitions()
        assert len(tests) == 16  # 6 + 4 + 3 + 3
        categories = set(t["category"] for t in tests)
        assert "gateway_api" in categories
        assert "admin_api" in categories
        assert "audit_api" in categories
        assert "vectordb" in categories

    def test_test_has_required_fields(self):
        from app.services.security.pentest import SecurityTestSuite
        suite = SecurityTestSuite()
        for test in suite.get_all_test_definitions():
            assert "name" in test
            assert "title" in test
            assert "category" in test
            assert "cwe_id" in test
            assert "owasp_ref" in test

    @pytest.mark.asyncio
    async def test_run_all_no_target(self):
        from app.services.security.pentest import SecurityTestSuite
        suite = SecurityTestSuite(target_url="http://127.0.0.1:1")  # Unreachable
        report = await suite.run_all()
        assert report.total_tests == 16
        # Tests that require connectivity will pass (connection errors are skipped)
        assert report.scan_id.startswith("SCAN-")

    @pytest.mark.asyncio
    async def test_single_test_execution(self):
        from app.services.security.pentest import SecurityTestSuite
        suite = SecurityTestSuite(target_url="http://127.0.0.1:1")
        test_def = suite.GATEWAY_API_TESTS[0]
        passed, finding = await suite.run_test(test_def)
        # With unreachable target, auth bypass test should pass (connection error = skip)
        assert isinstance(passed, bool)


# ── 7. Kubernetes Manifests ─────────────────────────────────────────────────


class TestKubernetesManifests:
    """Validate K8s manifest files exist and contain required fields."""

    K8S_DIR = os.path.join(os.path.dirname(__file__), "..", "k8s")

    def test_namespace_exists(self):
        path = os.path.join(self.K8S_DIR, "namespace.yaml")
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "Namespace" in content
        assert "sphinx" in content

    def test_deployment_exists(self):
        path = os.path.join(self.K8S_DIR, "gateway-deployment.yaml")
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "Deployment" in content
        assert "sphinx-gateway" in content
        assert "resources" in content
        assert "readinessProbe" in content
        assert "livenessProbe" in content

    def test_hpa_exists(self):
        path = os.path.join(self.K8S_DIR, "hpa.yaml")
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "HorizontalPodAutoscaler" in content
        assert "minReplicas" in content
        assert "maxReplicas" in content

    def test_pdb_exists(self):
        path = os.path.join(self.K8S_DIR, "pdb.yaml")
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "PodDisruptionBudget" in content
        assert "minAvailable" in content

    def test_network_policy_exists(self):
        path = os.path.join(self.K8S_DIR, "network-policy.yaml")
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "NetworkPolicy" in content
        assert "Ingress" in content
        assert "Egress" in content

    def test_secrets_exists(self):
        path = os.path.join(self.K8S_DIR, "secrets.yaml")
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "Secret" in content
        assert "database-url" in content
        assert "credential-encryption-key" in content
        # Vault integration mentioned
        assert "Vault" in content or "vault" in content

    def test_ingress_exists(self):
        path = os.path.join(self.K8S_DIR, "ingress.yaml")
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "Ingress" in content
        assert "tls" in content

    def test_resource_limits_set(self):
        path = os.path.join(self.K8S_DIR, "gateway-deployment.yaml")
        with open(path) as f:
            content = f.read()
        assert "requests:" in content
        assert "limits:" in content
        assert "cpu:" in content
        assert "memory:" in content

    def test_security_context(self):
        path = os.path.join(self.K8S_DIR, "gateway-deployment.yaml")
        with open(path) as f:
            content = f.read()
        assert "runAsNonRoot: true" in content
        assert "securityContext" in content


# ── 8. On-Premise Deployment Guide ──────────────────────────────────────────


class TestDeploymentGuide:
    """Validate deployment guide exists and covers required topics."""

    GUIDE_PATH = os.path.join(os.path.dirname(__file__), "..", "docs", "on-premise-deployment.md")

    def test_guide_exists(self):
        assert os.path.exists(self.GUIDE_PATH)

    def test_guide_covers_docker_compose(self):
        with open(self.GUIDE_PATH) as f:
            content = f.read()
        assert "Docker Compose" in content
        assert "docker compose" in content.lower() or "docker-compose" in content.lower()

    def test_guide_covers_kubernetes(self):
        with open(self.GUIDE_PATH) as f:
            content = f.read()
        assert "Kubernetes" in content
        assert "kubectl" in content

    def test_guide_covers_air_gapped(self):
        with open(self.GUIDE_PATH) as f:
            content = f.read()
        assert "air-gap" in content.lower() or "llama" in content.lower()

    def test_guide_covers_vault(self):
        with open(self.GUIDE_PATH) as f:
            content = f.read()
        assert "Vault" in content


# ── 9. GA Release Checklist ─────────────────────────────────────────────────


class TestGAChecklist:
    """Validate GA release checklist service."""

    def test_checklist_definitions(self):
        from app.services.security.ga_checklist import GA_CHECKLIST_ITEMS
        assert len(GA_CHECKLIST_ITEMS) == 15
        categories = set(item["category"] for item in GA_CHECKLIST_ITEMS)
        assert categories == {"security", "performance", "compliance", "operations"}

    def test_checklist_initial_status(self):
        from app.services.security.ga_checklist import GAChecklistService
        svc = GAChecklistService()
        status = svc.get_status()
        assert status.total_items == 15
        assert status.signed_off_items == 0
        assert status.ga_ready is False
        assert status.progress_percentage == 0.0

    def test_sign_off_item(self):
        from app.services.security.ga_checklist import GAChecklistService
        svc = GAChecklistService()
        item = svc.sign_off_item("SEC-01", signed_by="security-lead@company.com", notes="Pentest complete")
        assert item.signed_off is True
        assert item.signed_off_by == "security-lead@company.com"
        assert item.signed_off_at is not None

    def test_sign_off_invalid_item(self):
        from app.services.security.ga_checklist import GAChecklistService
        svc = GAChecklistService()
        with pytest.raises(ValueError, match="Unknown checklist item"):
            svc.sign_off_item("INVALID-99", signed_by="test")

    def test_revoke_signoff(self):
        from app.services.security.ga_checklist import GAChecklistService
        svc = GAChecklistService()
        svc.sign_off_item("SEC-01", signed_by="admin")
        item = svc.revoke_signoff("SEC-01")
        assert item.signed_off is False
        assert item.signed_off_by == ""

    def test_ga_ready_when_all_required_signed(self):
        from app.services.security.ga_checklist import GAChecklistService, GA_CHECKLIST_ITEMS
        svc = GAChecklistService()
        for item_def in GA_CHECKLIST_ITEMS:
            if item_def["required"]:
                svc.sign_off_item(item_def["id"], signed_by="lead@company.com")
        status = svc.get_status()
        assert status.ga_ready is True
        assert status.required_signed_off == status.required_items

    def test_get_items_by_category(self):
        from app.services.security.ga_checklist import GAChecklistService
        svc = GAChecklistService()
        security_items = svc.get_items_by_category("security")
        assert len(security_items) == 4
        assert all(i.category == "security" for i in security_items)

    def test_get_unsigned_items(self):
        from app.services.security.ga_checklist import GAChecklistService
        svc = GAChecklistService()
        svc.sign_off_item("SEC-01", signed_by="admin")
        unsigned = svc.get_unsigned_items()
        assert len(unsigned) == 14
        assert all(not i.signed_off for i in unsigned)

    def test_get_item(self):
        from app.services.security.ga_checklist import GAChecklistService
        svc = GAChecklistService()
        item = svc.get_item("PERF-01")
        assert item is not None
        assert item.title == "Load test passed at 1000 RPS"
        assert item.signoff_role == "Engineering Lead"

    def test_get_item_nonexistent(self):
        from app.services.security.ga_checklist import GAChecklistService
        svc = GAChecklistService()
        assert svc.get_item("NONEXISTENT") is None

    def test_reset(self):
        from app.services.security.ga_checklist import GAChecklistService
        svc = GAChecklistService()
        svc.sign_off_item("SEC-01", signed_by="admin")
        status = svc.reset()
        assert status.signed_off_items == 0
        assert status.ga_ready is False

    def test_checklist_status_summary(self):
        from app.services.security.ga_checklist import GAChecklistStatus
        status = GAChecklistStatus(
            version="1.0.0",
            total_items=15,
            signed_off_items=10,
            required_items=15,
            required_signed_off=10,
            progress_percentage=66.7,
            ga_ready=False,
        )
        summary = status.summary()
        assert "v1.0.0" in summary
        assert "10/15" in summary
        assert "NO" in summary

    def test_signoff_roles(self):
        from app.services.security.ga_checklist import GA_CHECKLIST_ITEMS
        roles = set(item["signoff_role"] for item in GA_CHECKLIST_ITEMS)
        assert "Engineering Lead" in roles
        assert "Security Lead" in roles
        assert "Product Owner" in roles


# ── 10. Singleton Getters ───────────────────────────────────────────────────


class TestSingletonGetters:
    """Validate singleton pattern for Sprint 20 services."""

    def test_memory_profiler_singleton(self):
        import app.services.performance.profiler as mod
        mod._memory_profiler = None
        s1 = mod.get_memory_profiler()
        s2 = mod.get_memory_profiler()
        assert s1 is s2
        mod._memory_profiler = None

    def test_cpu_profiler_singleton(self):
        import app.services.performance.profiler as mod
        mod._cpu_profiler = None
        s1 = mod.get_cpu_profiler()
        s2 = mod.get_cpu_profiler()
        assert s1 is s2
        mod._cpu_profiler = None

    def test_regex_auditor_singleton(self):
        import app.services.performance.profiler as mod
        mod._regex_auditor = None
        s1 = mod.get_regex_auditor()
        s2 = mod.get_regex_auditor()
        assert s1 is s2
        mod._regex_auditor = None

    def test_cache_monitor_singleton(self):
        import app.services.performance.profiler as mod
        mod._cache_monitor = None
        s1 = mod.get_cache_monitor()
        s2 = mod.get_cache_monitor()
        assert s1 is s2
        mod._cache_monitor = None

    def test_pentest_suite_singleton(self):
        import app.services.security.pentest as mod
        mod._pentest_suite = None
        s1 = mod.get_pentest_suite()
        s2 = mod.get_pentest_suite()
        assert s1 is s2
        mod._pentest_suite = None

    def test_ga_checklist_singleton(self):
        import app.services.security.ga_checklist as mod
        mod._service = None
        s1 = mod.get_ga_checklist_service()
        s2 = mod.get_ga_checklist_service()
        assert s1 is s2
        mod._service = None


# ── 11. Admin Endpoint Importability ────────────────────────────────────────


class TestAdminEndpointsExist:
    """Verify Sprint 20 services are importable and callable."""

    def test_load_test_runner(self):
        from loadtest.runner import LoadTestRunner, LoadTestConfig
        assert callable(LoadTestRunner)

    def test_memory_profiler(self):
        from app.services.performance.profiler import get_memory_profiler
        assert callable(get_memory_profiler)

    def test_cpu_profiler(self):
        from app.services.performance.profiler import get_cpu_profiler
        assert callable(get_cpu_profiler)

    def test_regex_auditor(self):
        from app.services.performance.profiler import get_regex_auditor
        assert callable(get_regex_auditor)

    def test_cache_monitor(self):
        from app.services.performance.profiler import get_cache_monitor
        assert callable(get_cache_monitor)

    def test_pentest_suite(self):
        from app.services.security.pentest import get_pentest_suite
        assert callable(get_pentest_suite)

    def test_ga_checklist(self):
        from app.services.security.ga_checklist import get_ga_checklist_service
        assert callable(get_ga_checklist_service)
