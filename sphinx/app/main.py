import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.middleware.auth import APIKeyAuthMiddleware
from app.routers import health, proxy, admin, memory_firewall, a2a_firewall, hitl, model_security
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

logger = logging.getLogger("sphinx.main")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: load policy cache, sync kill-switches, init providers, start audit
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

        # Initialize audit writer (Kafka producer)
        audit_writer = get_audit_writer()
        await audit_writer.initialize()

        # Start audit consumer (Kafka -> Postgres)
        audit_consumer = get_audit_consumer()
        await audit_consumer.start(async_session)

        # Initialize Tier 1 Threat Detection Engine
        threat_engine = get_threat_engine()
        logger.info(
            "Threat detection engine initialized: %d patterns loaded",
            threat_engine.library.count(),
        )

        # Load custom security rules from DB into threat engine
        from app.models.api_key import SecurityRule
        try:
            async with async_session() as db:
                from sqlalchemy import select
                result = await db.execute(
                    select(SecurityRule).where(SecurityRule.is_active == True)
                )
                custom_rules = result.scalars().all()
                if custom_rules:
                    import json as _json
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

        # Initialize Tier 2 ML semantic scanner
        tier2_scanner = get_tier2_scanner()
        logger.info(
            "Tier 2 semantic scanner initialized: %d threat embeddings in index",
            tier2_scanner.index_size,
        )

        # Start kill-switch pub/sub subscriber for sub-5s propagation
        await start_kill_switch_subscriber()

        # Sprint 13: Initialize provider health monitoring & failover
        async with async_session() as db:
            await sync_circuit_breakers_from_db(db)

        health_probe = get_health_probe(async_session)
        await health_probe.start()

        failover_engine = get_failover_engine(async_session)
        await failover_engine.start()

        # Sprint 15: Initialize MCP Discovery Service
        mcp_discovery = get_mcp_discovery_service(session_factory=async_session)
        logger.info("MCP discovery service initialized")

        # Sprint 16: Initialize Agent Scope Enforcement Service
        agent_scope = get_agent_scope_service(session_factory=async_session)
        logger.info("Agent scope enforcement service initialized")

        # Sprint 17: Initialize MCP Guardrails Dashboard & Compliance Tagging
        tool_call_audit = get_tool_call_audit_service(session_factory=async_session)
        logger.info("Tool call audit service initialized")

        compliance_tagger = get_compliance_tagging_service()
        logger.info("Compliance tagging service initialized")

        agent_risk_scorer = get_agent_risk_score_service(
            discovery_service=mcp_discovery,
            scope_service=agent_scope,
            audit_service=tool_call_audit,
        )
        logger.info("Agent risk score service initialized")

        bulk_importer = get_bulk_import_service(scope_service=agent_scope)
        logger.info("Bulk import service initialized")

        dashboard = get_guardrail_dashboard_service(
            scope_service=agent_scope,
            discovery_service=mcp_discovery,
            audit_service=tool_call_audit,
            risk_score_service=agent_risk_scorer,
        )
        logger.info("MCP guardrails dashboard service initialized")

        # Sprint 18: Initialize Audit Trail Hardening & Compliance Reports
        hash_chain = get_hash_chain_service(session_factory=async_session)
        await hash_chain.initialize()
        logger.info("Audit hash chain service initialized")

        audit_query = get_audit_query_service(session_factory=async_session)
        logger.info("Audit query service initialized")

        compliance_reports = get_compliance_report_service(session_factory=async_session)
        logger.info("Compliance report service initialized")

        # Sprint 19: Enterprise Dashboard & Alerting
        sec_ops_dashboard = get_security_ops_dashboard(session_factory=async_session)
        logger.info("Security operations dashboard initialized")

        policy_coverage = get_policy_coverage_service(session_factory=async_session)
        logger.info("Policy coverage map service initialized")

        incident_mgr = get_incident_management_service(session_factory=async_session)
        logger.info("Incident management service initialized")

        alert_engine = get_alert_engine_service(session_factory=async_session)
        await alert_engine.start(interval_seconds=30)
        logger.info("Real-time alert engine started")

        tenant_dashboard = get_tenant_usage_dashboard(session_factory=async_session)
        logger.info("Tenant usage dashboard initialized")

        onboarding = get_onboarding_wizard_service(session_factory=async_session)
        logger.info("Onboarding wizard service initialized")

        # Sprint 20: Performance profiling & GA checklist
        memory_profiler = get_memory_profiler()
        cpu_profiler = get_cpu_profiler()
        regex_auditor = get_regex_auditor()
        cache_monitor = get_cache_monitor()
        cache_monitor.register_cache("policy_cache", max_size=1000)
        cache_monitor.register_cache("threat_pattern_cache", max_size=500)
        cache_monitor.register_cache("pii_cache", max_size=200)
        ga_checklist = get_ga_checklist_service(session_factory=async_session)
        logger.info("Sprint 20: Performance profiling and GA checklist initialized")

        # Sprint 21: Multilingual Threat Detection + EU AI Act Controls
        unicode_normalizer = get_unicode_normalizer()
        logger.info("Unicode normalizer initialized: %d homoglyph mappings",
                     unicode_normalizer.get_stats()["homoglyph_mappings"])

        multilingual_detector = get_multilingual_detector()
        logger.info("Multilingual threat detector initialized: %d embeddings, %d languages",
                     multilingual_detector.index_size, multilingual_detector.supported_language_count)

        language_router = get_language_router()
        logger.info("Language detection and routing initialized")

        eu_ai_act = get_eu_ai_act_service()
        logger.info("EU AI Act risk classification and transparency logging initialized")

        # Sprint 24B: Start continuous red team scheduler
        start_scheduler()
        logger.info("Red team continuous scheduler started")

        # Sprint 25: Initialize Agent Memory Store Firewall
        memory_firewall_proxy = get_memory_store_proxy()
        logger.info(
            "Memory store firewall initialized: %d scanner patterns, default policy=%s",
            memory_firewall_proxy.scanner.pattern_count,
            memory_firewall_proxy.policy_store.default_policy.value,
        )

        # Sprint 26: Initialize Memory Read Controls + Lifecycle
        read_anomaly_detector = get_read_anomaly_detector()
        logger.info("Memory read anomaly detector initialized: stale_threshold=%d days",
                     read_anomaly_detector.stale_threshold_days)

        lifecycle_manager = get_memory_lifecycle_manager()
        logger.info("Memory lifecycle cap manager initialized: default_max_tokens=%d",
                     lifecycle_manager.default_max_tokens)

        integrity_verifier = get_memory_integrity_verifier()
        logger.info("Memory integrity verifier initialized: %d records tracked",
                     integrity_verifier.record_count())

        isolation_enforcer = get_memory_isolation_enforcer()
        logger.info("Memory isolation enforcer initialized: %d permissions configured",
                     isolation_enforcer.permission_count())

        # Sprint 28: HITL Enforcement Checkpoints + Cascading Failure Detection
        notification_svc = get_notification_service()
        approval_svc = get_approval_workflow_service(notification_service=notification_svc)
        await approval_svc.start_expiry_monitor(interval_seconds=10)
        logger.info("HITL approval workflow initialized with expiry monitor")

        baseline_engine = get_baseline_engine()
        logger.info("Agent behavioral baseline engine initialized: observation_period=%d days",
                     baseline_engine.observation_days)

        anomaly_detector = get_anomaly_detector(baseline_engine=baseline_engine)
        logger.info("Cascading failure anomaly detector initialized: threshold=%.1f, consecutive_to_open=%d",
                     anomaly_detector.anomaly_threshold, anomaly_detector.consecutive_to_open)

        # Sprint 29: Model Scanning + Multi-Turn Security + AI-SPM
        model_scanner = get_model_artifact_scanner()
        logger.info("Model artifact scanner initialized: %d scans in history",
                     len(model_scanner.get_scan_history()))

        model_registry = get_model_provenance_registry()
        logger.info("Model provenance registry initialized: %d registrations",
                     model_registry.registration_count())

        session_store = get_session_context_store()
        logger.info("Session context store initialized: max_turns=%d, timeout=%ds",
                     session_store.max_turns, int(session_store.inactivity_timeout.total_seconds()))

        cross_turn_risk = get_cross_turn_risk_accumulator()
        logger.info("Cross-turn risk accumulator initialized: threshold=%.1f, action=%s",
                     cross_turn_risk.escalation_threshold, cross_turn_risk.escalation_action)

        ai_spm = get_ai_spm_service()
        logger.info("AI-SPM discovery service initialized: %d assets tracked",
                     ai_spm.asset_count())

        # Sprint 30: Semantic Cache + Release Checklist
        semantic_cache = get_semantic_cache_layer()
        logger.info("Semantic cache layer initialized: threshold=%.2f",
                     semantic_cache.similarity_threshold)

        cache_security = get_cache_security_controller(cache=semantic_cache)
        logger.info("Cache security controller initialized: %d poison patterns",
                     len(cache_security._compiled_patterns))

        cache_audit = get_cache_audit_logger()
        logger.info("Cache audit logger initialized")

        release_checklist = get_v2_release_checklist()
        release_checklist.initialize()
        logger.info("v2.0 release checklist initialized: %d items",
                     release_checklist.item_count())

        logger.info("Startup complete: policy cache loaded, kill-switches synced, pub/sub active, audit system ready, health probe active, MCP discovery ready, agent scope ready, Sprint 17 services ready, Sprint 18 audit hardening ready, Sprint 19 dashboard & alerting ready, Sprint 20 performance & GA ready, Sprint 21 multilingual & EU AI Act ready, Sprint 24B red team scheduler ready, Sprint 25 memory firewall ready, Sprint 26 memory read controls & lifecycle ready, Sprint 28 HITL + cascading failure ready, Sprint 29 model scanner + session security + AI-SPM ready, Sprint 30 semantic cache + release checklist ready")
    except Exception:
        logger.warning("Startup cache loading failed (DB may not be ready)", exc_info=True)

    yield

    # Shutdown
    # Stop Sprint 28 approval expiry monitor
    try:
        approval_svc = get_approval_workflow_service()
        await approval_svc.stop_expiry_monitor()
    except Exception:
        logger.warning("Error shutting down approval expiry monitor", exc_info=True)

    # Stop Sprint 19 alert engine
    try:
        alert_engine = get_alert_engine_service()
        await alert_engine.stop()
    except Exception:
        logger.warning("Error shutting down alert engine", exc_info=True)

    # Stop Sprint 24B red team scheduler
    stop_scheduler()

    await stop_kill_switch_subscriber()
    stop_background_refresh()

    # Stop Sprint 13 services
    try:
        health_probe = get_health_probe()
        await health_probe.stop()
        failover_engine = get_failover_engine()
        await failover_engine.stop()
    except Exception:
        logger.warning("Error shutting down health probe / failover engine", exc_info=True)

    # Close audit system
    try:
        audit_writer = get_audit_writer()
        await audit_writer.close()
        audit_consumer = get_audit_consumer()
        await audit_consumer.stop()
    except Exception:
        logger.warning("Error shutting down audit system", exc_info=True)

    await close_redis()
    await close_http_client()


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
