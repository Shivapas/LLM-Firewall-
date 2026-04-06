import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.middleware.auth import APIKeyAuthMiddleware
from app.routers import health, proxy, admin
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

        logger.info("Startup complete: policy cache loaded, kill-switches synced, pub/sub active, audit system ready, health probe active, MCP discovery ready, agent scope ready, Sprint 17 services ready, Sprint 18 audit hardening ready, Sprint 19 dashboard & alerting ready, Sprint 20 performance & GA ready")
    except Exception:
        logger.warning("Startup cache loading failed (DB may not be ready)", exc_info=True)

    yield

    # Shutdown
    # Stop Sprint 19 alert engine
    try:
        alert_engine = get_alert_engine_service()
        await alert_engine.stop()
    except Exception:
        logger.warning("Error shutting down alert engine", exc_info=True)

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
    version="1.0.0",
    lifespan=lifespan,
)

# Middleware
app.add_middleware(APIKeyAuthMiddleware)

# Routers
app.include_router(health.router)
app.include_router(proxy.router)
app.include_router(admin.router)
