import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.middleware.auth import APIKeyAuthMiddleware
from app.routers import health, proxy, admin, memory_firewall, a2a_firewall, hitl, model_security, ipia
from app.services.redis_client import close_redis
from app.services.proxy import close_http_client
from app.services.database import async_session
from app.services.policy_cache import load_policies, start_background_refresh, stop_background_refresh
from app.services.kill_switch import sync_kill_switches_to_cache, start_kill_switch_subscriber, stop_kill_switch_subscriber
from app.services.routing import initialize_registry
from app.services.credential_store import list_providers, get_provider_credential
from app.services.audit import get_audit_writer, get_audit_consumer
from app.services.threat_detection.engine import get_threat_engine, reset_threat_engine
from app.services.threat_detection.tier2_scanner import get_tier2_scanner
from app.services.health_probe import get_health_probe
from app.services.circuit_breaker import sync_circuit_breakers_from_db
from app.services.failover_policy import get_failover_engine
from app.services.mcp.discovery import get_mcp_discovery_service
from app.services.mcp.agent_scope import get_agent_scope_service
from app.services.mcp.tool_call_audit import get_tool_call_audit_service
from app.services.mcp.compliance_tagger import get_compliance_tagging_service
from app.services.mcp.agent_risk_score import get_agent_risk_score_service
from app.services.mcp.bulk_import import get_bulk_import_service
from app.services.mcp.dashboard import get_guardrail_dashboard_service
from app.services.audit_hash_chain import get_hash_chain_service
from app.services.audit_query import get_audit_query_service
from app.services.compliance_reports import get_compliance_report_service
from app.services.dashboard.security_ops import get_security_ops_dashboard
from app.services.dashboard.policy_coverage import get_policy_coverage_service
from app.services.dashboard.incident_manager import get_incident_management_service
from app.services.dashboard.alert_engine import get_alert_engine_service
from app.services.dashboard.tenant_usage import get_tenant_usage_dashboard
from app.services.dashboard.onboarding_wizard import get_onboarding_wizard_service
from app.services.performance.profiler import (
    get_memory_profiler,
    get_cpu_profiler,
    get_regex_auditor,
    get_cache_monitor,
)
from app.services.security.ga_checklist import get_ga_checklist_service
from app.services.multilingual.unicode_normalizer import get_unicode_normalizer
from app.services.multilingual.multilingual_detector import get_multilingual_detector
from app.services.multilingual.language_detector import get_language_router
from app.services.multilingual.eu_ai_act import get_eu_ai_act_service
from app.services.red_team.scheduler import start_scheduler, stop_scheduler
from app.services.memory_firewall.proxy import get_memory_store_proxy
from app.services.memory_firewall.read_anomaly import get_read_anomaly_detector
from app.services.memory_firewall.lifecycle import get_memory_lifecycle_manager
from app.services.memory_firewall.integrity import get_memory_integrity_verifier
from app.services.memory_firewall.isolation import get_memory_isolation_enforcer
from app.services.hitl.approval_workflow import get_approval_workflow_service
from app.services.hitl.notification import get_notification_service
from app.services.hitl.baseline_engine import get_baseline_engine
from app.services.hitl.anomaly_detector import get_anomaly_detector
from app.services.model_scanner.artifact_scanner import get_model_artifact_scanner
from app.services.model_scanner.provenance_registry import get_model_provenance_registry
from app.services.session_security.context_store import get_session_context_store
from app.services.session_security.cross_turn_risk import get_cross_turn_risk_accumulator
from app.services.ai_spm.discovery import get_ai_spm_service
from app.services.semantic_cache.cache_layer import get_semantic_cache_layer
from app.services.semantic_cache.cache_security import get_cache_security_controller
from app.services.semantic_cache.cache_audit import get_cache_audit_logger
from app.services.release.v2_checklist import get_v2_release_checklist
from app.services.thoth.client import initialize_thoth_client, close_thoth_client
from app.services.thoth.circuit_breaker import initialize_thoth_circuit_breaker
from app.services.siem_export import initialize_siem_exporter, close_siem_exporter
from app.services.ipia.embedding_service import get_ipia_service

logger = logging.getLogger("sphinx.main")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)


async def _shutdown_approval_svc():
    svc = get_approval_workflow_service()
    await svc.stop_expiry_monitor()


async def _shutdown_alert_engine():
    engine = get_alert_engine_service()
    await engine.stop()


async def _shutdown_health_failover():
    probe = get_health_probe()
    await probe.stop()
    fe = get_failover_engine()
    await fe.stop()


async def _shutdown_audit():
    writer = get_audit_writer()
    await writer.close()
    consumer = get_audit_consumer()
    await consumer.stop()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Critical security services (must succeed or abort startup) ──
    try:
        async with async_session() as db:
            await load_policies(db)
            await sync_kill_switches_to_cache(db)

            # Initialize provider registry from stored credentials
            providers = []
            provider_list = await list_providers(db)
            for p in provider_list:
                if p.get("is_enabled"):
                    cred = await get_provider_credential(db, p["provider_name"])
                    if cred:
                        providers.append(cred)
            if providers:
                await initialize_registry(providers)
                logger.info("Provider registry initialized with %d providers", len(providers))

        start_background_refresh(async_session)

        # Initialize Tier 1 Threat Detection Engine (CRITICAL)
        threat_engine = get_threat_engine()
        logger.info(
            "Threat detection engine initialized: %d patterns loaded",
            threat_engine.library.count(),
        )

        # Initialize Tier 2 ML semantic scanner (CRITICAL)
        tier2_scanner = get_tier2_scanner()
        logger.info(
            "Tier 2 semantic scanner initialized: %d threat embeddings in index",
            tier2_scanner.index_size,
        )

        # Start kill-switch pub/sub subscriber (CRITICAL)
        await start_kill_switch_subscriber()
    except Exception:
        logger.critical("CRITICAL: Core security services failed to initialize. Aborting startup.", exc_info=True)
        raise

    # ── Audit system (important but non-fatal) ──
    try:
        audit_writer = get_audit_writer()
        await audit_writer.initialize()

        audit_consumer = get_audit_consumer()
        await audit_consumer.start(async_session)
    except Exception:
        logger.error("Audit system failed to initialize — events may be lost", exc_info=True)

    # ── Load custom security rules from DB ──
    try:
        from app.models.api_key import SecurityRule
        from sqlalchemy import select
        import json as _json

        async with async_session() as db:
            result = await db.execute(
                select(SecurityRule).where(SecurityRule.is_active.is_(True))
            )
            custom_rules = result.scalars().all()
            if custom_rules:
                rule_dicts = [
                    {
                        "id": f"custom-{r.id}",
                        "name": r.name,
                        "category": r.category,
                        "severity": r.severity,
                        "pattern": r.pattern,
                        "description": r.description,
                        "tags": _json.loads(r.tags_json) if r.tags_json else [],
                    }
                    for r in custom_rules
                ]
                threat_engine.load_policy_rules(rule_dicts)
                logger.info("Loaded %d custom security rules from DB", len(custom_rules))
    except Exception:
        logger.warning("Failed to load custom security rules (table may not exist)", exc_info=True)

    # ── Provider health monitoring & failover ──
    try:
        async with async_session() as db:
            await sync_circuit_breakers_from_db(db)

        health_probe = get_health_probe(async_session)
        await health_probe.start()

        failover_engine = get_failover_engine(async_session)
        await failover_engine.start()
    except Exception:
        logger.error("Health probe / failover engine failed to start", exc_info=True)

    # ── MCP, Agent Scope, Dashboard services ──
    try:
        mcp_discovery = get_mcp_discovery_service(session_factory=async_session)
        agent_scope = get_agent_scope_service(session_factory=async_session)
        tool_call_audit = get_tool_call_audit_service(session_factory=async_session)
        compliance_tagger = get_compliance_tagging_service()
        agent_risk_scorer = get_agent_risk_score_service(
            discovery_service=mcp_discovery,
            scope_service=agent_scope,
            audit_service=tool_call_audit,
        )
        bulk_importer = get_bulk_import_service(scope_service=agent_scope)
        dashboard = get_guardrail_dashboard_service(
            scope_service=agent_scope,
            discovery_service=mcp_discovery,
            audit_service=tool_call_audit,
            risk_score_service=agent_risk_scorer,
        )
        logger.info("MCP services initialized")
    except Exception:
        logger.warning("MCP services failed to initialize", exc_info=True)

    # ── Audit trail hardening & compliance ──
    try:
        hash_chain = get_hash_chain_service(session_factory=async_session)
        await hash_chain.initialize()
        audit_query = get_audit_query_service(session_factory=async_session)
        compliance_reports = get_compliance_report_service(session_factory=async_session)
        logger.info("Audit hardening and compliance services initialized")
    except Exception:
        logger.warning("Audit hardening services failed to initialize", exc_info=True)

    # ── Enterprise dashboard & alerting ──
    try:
        sec_ops_dashboard = get_security_ops_dashboard(session_factory=async_session)
        policy_coverage = get_policy_coverage_service(session_factory=async_session)
        incident_mgr = get_incident_management_service(session_factory=async_session)
        alert_engine = get_alert_engine_service(session_factory=async_session)
        await alert_engine.start(interval_seconds=30)
        tenant_dashboard = get_tenant_usage_dashboard(session_factory=async_session)
        onboarding = get_onboarding_wizard_service(session_factory=async_session)
        logger.info("Enterprise dashboard and alerting initialized")
    except Exception:
        logger.warning("Enterprise dashboard services failed to initialize", exc_info=True)

    # ── Performance profiling & GA checklist ──
    try:
        memory_profiler = get_memory_profiler()
        cpu_profiler = get_cpu_profiler()
        regex_auditor = get_regex_auditor()
        cache_monitor = get_cache_monitor()
        cache_monitor.register_cache("policy_cache", max_size=1000)
        cache_monitor.register_cache("threat_pattern_cache", max_size=500)
        cache_monitor.register_cache("pii_cache", max_size=200)
        ga_checklist = get_ga_checklist_service(session_factory=async_session)
        logger.info("Performance profiling and GA checklist initialized")
    except Exception:
        logger.warning("Performance profiling services failed to initialize", exc_info=True)

    # ── Multilingual threat detection & EU AI Act ──
    try:
        unicode_normalizer = get_unicode_normalizer()
        multilingual_detector = get_multilingual_detector()
        language_router = get_language_router()
        eu_ai_act = get_eu_ai_act_service()
        logger.info("Multilingual and EU AI Act services initialized")
    except Exception:
        logger.warning("Multilingual services failed to initialize", exc_info=True)

    # ── Red team scheduler ──
    try:
        start_scheduler()
        logger.info("Red team continuous scheduler started")
    except Exception:
        logger.warning("Red team scheduler failed to start", exc_info=True)

    # ── Memory firewall ──
    try:
        memory_firewall_proxy = get_memory_store_proxy()
        read_anomaly_detector = get_read_anomaly_detector()
        lifecycle_manager = get_memory_lifecycle_manager()
        integrity_verifier = get_memory_integrity_verifier()
        isolation_enforcer = get_memory_isolation_enforcer()
        logger.info("Memory firewall services initialized")
    except Exception:
        logger.warning("Memory firewall services failed to initialize", exc_info=True)

    # ── HITL approval workflow & anomaly detection ──
    try:
        notification_svc = get_notification_service()
        approval_svc = get_approval_workflow_service(notification_service=notification_svc)
        await approval_svc.start_expiry_monitor(interval_seconds=10)
        baseline_engine = get_baseline_engine()
        anomaly_detector = get_anomaly_detector(baseline_engine=baseline_engine)
        logger.info("HITL and cascading failure detection initialized")
    except Exception:
        logger.warning("HITL services failed to initialize", exc_info=True)

    # ── Model scanning, session security, AI-SPM ──
    try:
        model_scanner = get_model_artifact_scanner()
        model_registry = get_model_provenance_registry()
        session_store = get_session_context_store()
        cross_turn_risk = get_cross_turn_risk_accumulator()
        ai_spm = get_ai_spm_service()
        logger.info("Model scanning, session security, and AI-SPM initialized")
    except Exception:
        logger.warning("Model scanning services failed to initialize", exc_info=True)

    # ── Semantic cache & release checklist ──
    try:
        semantic_cache = get_semantic_cache_layer()
        cache_security = get_cache_security_controller(cache=semantic_cache)
        cache_audit = get_cache_audit_logger()
        release_checklist = get_v2_release_checklist()
        release_checklist.initialize()
        logger.info("Semantic cache and release checklist initialized")
    except Exception:
        logger.warning("Semantic cache services failed to initialize", exc_info=True)

    # ── Thoth Semantic Classification client + circuit breaker (Sprint 1 & 2) ──
    try:
        from app.config import get_settings as _get_settings
        _settings = _get_settings()

        # S2-T2: Initialize circuit breaker regardless of thoth_enabled so it
        # is available on first use if Thoth is enabled at runtime.
        if _settings.thoth_circuit_breaker_enabled:
            initialize_thoth_circuit_breaker(
                error_threshold=_settings.thoth_circuit_breaker_error_threshold,
                recovery_timeout_s=_settings.thoth_circuit_breaker_recovery_timeout_s,
            )

        if _settings.thoth_enabled and _settings.thoth_api_url:
            initialize_thoth_client(
                api_url=_settings.thoth_api_url,
                api_key=_settings.thoth_api_key,
                timeout_ms=_settings.thoth_timeout_ms,
                max_retries=_settings.thoth_max_retries,
            )
            logger.info(
                "Thoth classification client initialized: url=%s timeout_ms=%d "
                "fail_closed=%s circuit_breaker_enabled=%s "
                "post_inference_enabled=%s post_inference_timeout_ms=%d",
                _settings.thoth_api_url,
                _settings.thoth_timeout_ms,
                _settings.thoth_fail_closed_enabled,
                _settings.thoth_circuit_breaker_enabled,
                _settings.thoth_post_inference_enabled,
                _settings.thoth_post_inference_timeout_ms,
            )
        else:
            logger.info("Thoth classification disabled (THOTH_ENABLED=false or no URL configured)")
    except Exception:
        logger.warning("Thoth client failed to initialize — classification disabled", exc_info=True)

    # ── SIEM / Data Lake Export (Sprint 4 / S4-T5 — FR-POST-05) ──
    try:
        from app.config import get_settings as _get_siem_settings
        _siem_settings = _get_siem_settings()
        if _siem_settings.siem_export_enabled and _siem_settings.siem_export_url:
            siem_exporter = initialize_siem_exporter(
                export_url=_siem_settings.siem_export_url,
                api_key=_siem_settings.siem_export_api_key,
                export_format=_siem_settings.siem_export_format,
                timeout_ms=_siem_settings.siem_export_timeout_ms,
                batch_size=_siem_settings.siem_export_batch_size,
                flush_interval_s=_siem_settings.siem_export_flush_interval_s,
            )
            await siem_exporter.start()
            logger.info(
                "SIEM exporter initialized: url=%s format=%s batch_size=%d "
                "flush_interval=%.1fs",
                _siem_settings.siem_export_url,
                _siem_settings.siem_export_format,
                _siem_settings.siem_export_batch_size,
                _siem_settings.siem_export_flush_interval_s,
            )
        else:
            logger.info("SIEM export disabled (SIEM_EXPORT_ENABLED=false or no URL configured)")
    except Exception:
        logger.warning("SIEM exporter failed to initialize — export disabled", exc_info=True)

    # ── IPIA Embedding Service (Sprint 31 — Module E15) ──
    try:
        ipia_service = get_ipia_service()
        logger.info(
            "IPIA embedding service initialized: backend=%s dim=%d references=%d",
            ipia_service.backend.name,
            ipia_service.backend.dimension,
            ipia_service.scorer.reference_count,
        )
    except Exception:
        logger.warning("IPIA embedding service failed to initialize", exc_info=True)

    logger.info("Startup complete: all security-critical services operational")

    yield

    # Shutdown — each block is independent to ensure all resources are released
    logger.info("Shutting down...")

    for shutdown_name, shutdown_coro in [
        ("approval expiry monitor", _shutdown_approval_svc()),
        ("alert engine", _shutdown_alert_engine()),
        ("kill-switch subscriber", stop_kill_switch_subscriber()),
        ("health probe / failover", _shutdown_health_failover()),
        ("audit system", _shutdown_audit()),
        ("siem exporter", close_siem_exporter()),
        ("thoth client", close_thoth_client()),
        ("redis", close_redis()),
        ("http client", close_http_client()),
    ]:
        try:
            await shutdown_coro
        except Exception:
            logger.warning("Error shutting down %s", shutdown_name, exc_info=True)

    try:
        stop_background_refresh()
    except Exception:
        logger.warning("Error stopping background refresh", exc_info=True)

    try:
        stop_scheduler()
    except Exception:
        logger.warning("Error stopping red team scheduler", exc_info=True)

    logger.info("Shutdown complete")


app = FastAPI(
    title="Sphinx AI Mesh Firewall",
    description="Gateway proxy for LLM provider traffic with multi-provider routing and audit",
    version="2.0.0",
    lifespan=lifespan,
)

# Middleware
app.add_middleware(APIKeyAuthMiddleware)

# Routers
app.include_router(health.router)
app.include_router(proxy.router)
app.include_router(admin.router)
app.include_router(memory_firewall.router)
app.include_router(a2a_firewall.router)
app.include_router(hitl.router)
app.include_router(model_security.router)
app.include_router(ipia.router)
