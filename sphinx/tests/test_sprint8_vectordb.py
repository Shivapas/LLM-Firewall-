"""Sprint 8 Tests — Vector DB Proxy & Namespace Isolation.

Acceptance Criteria:
- Tenant namespace filter injected on every retrieval query; test confirms cross-tenant documents never returned
- Unlisted collections return access-denied; listed collections enforce operation allowlist
- Max results cap enforced across ChromaDB, Pinecone, and Milvus in integration tests
"""

import uuid
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.services.vectordb.proxy import (
    VectorDBProxy,
    CollectionPolicy,
    ProxyRequest,
    ProxyResult,
    VectorDBProvider,
    VectorOperation,
    ProxyAction,
    get_vectordb_proxy,
    reset_vectordb_proxy,
)
from app.services.vectordb.namespace_isolator import (
    NamespaceIsolator,
    NamespaceInjectionResult,
    get_namespace_isolator,
    reset_namespace_isolator,
)
from app.services.vectordb.adapters import (
    BaseVectorAdapter,
    ChromaDBAdapter,
    PineconeAdapter,
    MilvusAdapter,
)


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset singletons before each test."""
    reset_vectordb_proxy()
    reset_namespace_isolator()
    yield
    reset_vectordb_proxy()
    reset_namespace_isolator()


@pytest.fixture
def proxy():
    return VectorDBProxy()


@pytest.fixture
def isolator():
    return NamespaceIsolator()


@pytest.fixture
def sample_policy():
    return CollectionPolicy(
        collection_name="knowledge-base",
        provider=VectorDBProvider.CHROMADB,
        default_action=ProxyAction.DENY,
        allowed_operations=[VectorOperation.QUERY, VectorOperation.INSERT],
        sensitive_fields=["ssn", "email"],
        namespace_field="tenant_id",
        max_results=10,
        is_active=True,
        tenant_id="*",
    )


@pytest.fixture
def sample_query_request():
    return ProxyRequest(
        collection_name="knowledge-base",
        operation=VectorOperation.QUERY,
        tenant_id="tenant-alpha",
        query_text="What is our revenue?",
        top_k=5,
        filters={},
    )


# ── Vector DB Proxy: Collection Allowlist ─────────────────────────────


class TestCollectionAllowlist:
    """Unlisted collections return access-denied; listed enforce allowlist."""

    def test_unlisted_collection_denied(self, proxy):
        """Unlisted collections MUST return access-denied error."""
        request = ProxyRequest(
            collection_name="unregistered-collection",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-1",
        )
        result = proxy.process(request)
        assert not result.allowed
        assert result.action == ProxyAction.DENY
        assert "not registered" in result.blocked_reason

    def test_listed_collection_allowed(self, proxy, sample_policy, sample_query_request):
        """Registered collection with allowed operation passes."""
        proxy.register_policy(sample_policy)
        result = proxy.process(sample_query_request)
        assert result.allowed
        assert result.namespace_injected

    def test_disallowed_operation_denied(self, proxy, sample_policy):
        """Operation not in allowlist is denied."""
        proxy.register_policy(sample_policy)
        request = ProxyRequest(
            collection_name="knowledge-base",
            operation=VectorOperation.DELETE,
            tenant_id="tenant-1",
        )
        result = proxy.process(request)
        assert not result.allowed
        assert "not allowed" in result.blocked_reason

    def test_inactive_policy_denied(self, proxy, sample_policy):
        """Inactive policy denies all access."""
        sample_policy.is_active = False
        proxy.register_policy(sample_policy)
        request = ProxyRequest(
            collection_name="knowledge-base",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-1",
        )
        result = proxy.process(request)
        assert not result.allowed
        assert "inactive" in result.blocked_reason

    def test_all_governed_collections_require_explicit_policy(self, proxy):
        """Multiple unlisted collections all denied."""
        for name in ["collection-a", "collection-b", "collection-c"]:
            request = ProxyRequest(
                collection_name=name,
                operation=VectorOperation.QUERY,
                tenant_id="tenant-1",
            )
            result = proxy.process(request)
            assert not result.allowed

    def test_monitor_action_allows_but_monitors(self, proxy):
        """Monitor default action allows but flags as monitored."""
        policy = CollectionPolicy(
            collection_name="monitored-collection",
            provider=VectorDBProvider.CHROMADB,
            default_action=ProxyAction.MONITOR,
            allowed_operations=[VectorOperation.QUERY],
            namespace_field="tenant_id",
            max_results=10,
        )
        proxy.register_policy(policy)
        request = ProxyRequest(
            collection_name="monitored-collection",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-1",
        )
        result = proxy.process(request)
        assert result.allowed
        assert result.action == ProxyAction.MONITOR

    def test_allow_default_permits_all_operations(self, proxy):
        """Allow default action permits even unlisted operations."""
        policy = CollectionPolicy(
            collection_name="open-collection",
            provider=VectorDBProvider.PINECONE,
            default_action=ProxyAction.ALLOW,
            allowed_operations=[],
            namespace_field="tenant_id",
            max_results=20,
        )
        proxy.register_policy(policy)
        request = ProxyRequest(
            collection_name="open-collection",
            operation=VectorOperation.DELETE,
            tenant_id="tenant-1",
        )
        result = proxy.process(request)
        assert result.allowed


# ── Namespace Isolation ───────────────────────────────────────────────


class TestNamespaceIsolation:
    """Tenant namespace filter injected on every retrieval query."""

    def test_namespace_injected_on_query(self, proxy, sample_policy, sample_query_request):
        """Tenant namespace MUST be injected on every query."""
        proxy.register_policy(sample_policy)
        result = proxy.process(sample_query_request)
        assert result.namespace_injected
        assert sample_query_request.filters["tenant_id"] == "tenant-alpha"

    def test_namespace_overwrites_conflicting_filter(self, proxy, sample_policy):
        """If caller tries to set different namespace, it's overwritten."""
        proxy.register_policy(sample_policy)
        request = ProxyRequest(
            collection_name="knowledge-base",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-alpha",
            filters={"tenant_id": "tenant-evil"},  # Attempted bypass
        )
        proxy.process(request)
        assert request.filters["tenant_id"] == "tenant-alpha"  # Forced to correct tenant

    def test_cross_tenant_documents_never_returned(self, isolator, sample_policy):
        """Post-retrieval validation strips cross-tenant documents."""
        docs = [
            {"id": "1", "content": "safe", "metadata": {"tenant_id": "tenant-alpha"}},
            {"id": "2", "content": "leaked", "metadata": {"tenant_id": "tenant-evil"}},
            {"id": "3", "content": "also safe", "metadata": {"tenant_id": "tenant-alpha"}},
        ]
        valid = isolator.validate_response_namespace(docs, sample_policy, "tenant-alpha")
        assert len(valid) == 2
        assert all(d["metadata"]["tenant_id"] == "tenant-alpha" for d in valid)

    def test_isolator_inject_basic(self, isolator, sample_policy):
        """Basic namespace injection via isolator."""
        request = ProxyRequest(
            collection_name="knowledge-base",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-beta",
            filters={},
        )
        result = isolator.inject(request, sample_policy)
        assert result.injected
        assert result.namespace_field == "tenant_id"
        assert result.namespace_value == "tenant-beta"
        assert request.filters["tenant_id"] == "tenant-beta"

    def test_isolator_detects_conflict(self, isolator, sample_policy):
        """Isolator detects and overwrites conflicting namespace."""
        request = ProxyRequest(
            collection_name="knowledge-base",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-legit",
            filters={"tenant_id": "tenant-attacker"},
        )
        result = isolator.inject(request, sample_policy)
        assert result.injected
        assert request.filters["tenant_id"] == "tenant-legit"
        assert result.to_dict()["had_conflicting_filter"]

    def test_isolator_skips_non_query_operations(self, isolator, sample_policy):
        """Namespace injection only applies to query operations."""
        request = ProxyRequest(
            collection_name="knowledge-base",
            operation=VectorOperation.INSERT,
            tenant_id="tenant-1",
        )
        result = isolator.inject(request, sample_policy)
        assert not result.injected

    def test_empty_tenant_id_no_injection(self, isolator, sample_policy):
        """Empty tenant_id results in no injection."""
        request = ProxyRequest(
            collection_name="knowledge-base",
            operation=VectorOperation.QUERY,
            tenant_id="",
            filters={},
        )
        result = isolator.inject(request, sample_policy)
        assert not result.injected

    def test_custom_namespace_field(self, isolator):
        """Custom namespace field (not default tenant_id) is respected."""
        policy = CollectionPolicy(
            collection_name="custom-ns",
            provider=VectorDBProvider.MILVUS,
            namespace_field="org_id",
            max_results=10,
        )
        request = ProxyRequest(
            collection_name="custom-ns",
            operation=VectorOperation.QUERY,
            tenant_id="org-42",
            filters={},
        )
        result = isolator.inject(request, policy)
        assert result.injected
        assert request.filters["org_id"] == "org-42"

    def test_ten_cross_tenant_scenarios(self, isolator, sample_policy):
        """10 cross-tenant extraction scenarios — assert zero escapes."""
        tenants = [f"tenant-{i}" for i in range(10)]
        for i, legitimate_tenant in enumerate(tenants):
            # Each tenant has their own doc + one from another tenant
            other_tenant = tenants[(i + 1) % 10]
            docs = [
                {"id": f"own-{i}", "content": "my data", "metadata": {"tenant_id": legitimate_tenant}},
                {"id": f"other-{i}", "content": "their data", "metadata": {"tenant_id": other_tenant}},
                {"id": f"unknown-{i}", "content": "unknown", "metadata": {"tenant_id": f"rogue-{i}"}},
            ]
            valid = isolator.validate_response_namespace(docs, sample_policy, legitimate_tenant)
            # Only the legitimate tenant's doc should survive
            assert len(valid) == 1
            assert valid[0]["metadata"]["tenant_id"] == legitimate_tenant


# ── Max Results Cap ───────────────────────────────────────────────────


class TestMaxResultsCap:
    """Max results cap enforced (1–100). Trim response if excess."""

    def test_top_k_capped_to_policy_max(self, proxy, sample_policy):
        """Request top_k exceeding policy max is capped."""
        proxy.register_policy(sample_policy)  # max_results=10
        request = ProxyRequest(
            collection_name="knowledge-base",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-1",
            top_k=50,
        )
        result = proxy.process(request)
        assert result.allowed
        assert result.results_capped
        assert result.enforced_top_k == 10

    def test_top_k_within_limit_not_capped(self, proxy, sample_policy):
        """Request top_k within policy max is not capped."""
        proxy.register_policy(sample_policy)
        request = ProxyRequest(
            collection_name="knowledge-base",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-1",
            top_k=5,
        )
        result = proxy.process(request)
        assert result.allowed
        assert not result.results_capped
        assert result.enforced_top_k == 5

    def test_max_results_absolute_cap_100(self, proxy):
        """Even if policy sets max > 100, it's capped at 100."""
        policy = CollectionPolicy(
            collection_name="big-collection",
            provider=VectorDBProvider.CHROMADB,
            default_action=ProxyAction.ALLOW,
            allowed_operations=[VectorOperation.QUERY],
            namespace_field="tenant_id",
            max_results=200,  # > 100
        )
        proxy.register_policy(policy)
        request = ProxyRequest(
            collection_name="big-collection",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-1",
            top_k=150,
        )
        result = proxy.process(request)
        assert result.enforced_top_k == 100

    def test_adapter_response_trimmed(self, proxy):
        """Even if adapter returns excess, response is trimmed."""
        policy = CollectionPolicy(
            collection_name="trimmed-collection",
            provider=VectorDBProvider.CHROMADB,
            default_action=ProxyAction.ALLOW,
            allowed_operations=[VectorOperation.QUERY],
            namespace_field="tenant_id",
            max_results=3,
        )
        proxy.register_policy(policy)

        # Mock adapter returning 10 docs
        mock_adapter = MagicMock()
        mock_adapter.execute.return_value = [
            {"id": f"doc-{i}", "content": f"content-{i}", "metadata": {}}
            for i in range(10)
        ]
        proxy.register_adapter(VectorDBProvider.CHROMADB, mock_adapter)

        request = ProxyRequest(
            collection_name="trimmed-collection",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-1",
            top_k=10,
        )
        result = proxy.process(request)
        assert result.allowed
        assert result.results_capped
        assert len(result.documents) == 3

    def test_max_results_cap_chromadb(self, proxy):
        """ChromaDB: max results cap integration."""
        self._test_provider_cap(proxy, VectorDBProvider.CHROMADB, max_results=5, returned=8)

    def test_max_results_cap_pinecone(self, proxy):
        """Pinecone: max results cap integration."""
        self._test_provider_cap(proxy, VectorDBProvider.PINECONE, max_results=5, returned=8)

    def test_max_results_cap_milvus(self, proxy):
        """Milvus: max results cap integration."""
        self._test_provider_cap(proxy, VectorDBProvider.MILVUS, max_results=5, returned=8)

    def _test_provider_cap(self, proxy, provider, max_results, returned):
        coll_name = f"cap-test-{provider.value}"
        policy = CollectionPolicy(
            collection_name=coll_name,
            provider=provider,
            default_action=ProxyAction.ALLOW,
            allowed_operations=[VectorOperation.QUERY],
            namespace_field="tenant_id",
            max_results=max_results,
        )
        proxy.register_policy(policy)

        mock_adapter = MagicMock()
        mock_adapter.execute.return_value = [
            {"id": f"doc-{i}", "content": f"c-{i}", "metadata": {}}
            for i in range(returned)
        ]
        proxy.register_adapter(provider, mock_adapter)

        request = ProxyRequest(
            collection_name=coll_name,
            operation=VectorOperation.QUERY,
            tenant_id="tenant-1",
            top_k=returned,
        )
        result = proxy.process(request)
        assert result.allowed
        assert len(result.documents) == max_results
        assert result.results_capped


# ── Adapter Unit Tests ────────────────────────────────────────────────


class TestChromaDBAdapter:
    def test_no_client_returns_empty(self):
        adapter = ChromaDBAdapter(client=None)
        request = ProxyRequest(
            collection_name="test",
            operation=VectorOperation.QUERY,
            tenant_id="t1",
            query_text="hello",
        )
        result = adapter.execute(request)
        assert result == []

    def test_query_with_mock_client(self):
        mock_collection = MagicMock()
        mock_collection.query.return_value = {
            "ids": [["id1", "id2"]],
            "documents": [["doc1", "doc2"]],
            "metadatas": [[{"tenant_id": "t1"}, {"tenant_id": "t1"}]],
            "distances": [[0.1, 0.2]],
        }
        mock_client = MagicMock()
        mock_client.get_collection.return_value = mock_collection

        adapter = ChromaDBAdapter(client=mock_client)
        request = ProxyRequest(
            collection_name="test",
            operation=VectorOperation.QUERY,
            tenant_id="t1",
            query_text="hello",
            top_k=2,
            filters={"tenant_id": "t1"},
        )
        result = adapter.execute(request)
        assert len(result) == 2
        assert result[0]["id"] == "id1"
        assert result[0]["content"] == "doc1"

    def test_insert_with_mock_client(self):
        mock_collection = MagicMock()
        mock_client = MagicMock()
        mock_client.get_collection.return_value = mock_collection

        adapter = ChromaDBAdapter(client=mock_client)
        request = ProxyRequest(
            collection_name="test",
            operation=VectorOperation.INSERT,
            tenant_id="t1",
            documents=[{"id": "d1", "content": "hello", "metadata": {}}],
        )
        adapter.execute(request)
        mock_collection.add.assert_called_once()

    def test_health_check_no_client(self):
        adapter = ChromaDBAdapter(client=None)
        assert not adapter.health_check()


class TestPineconeAdapter:
    def test_no_index_returns_empty(self):
        adapter = PineconeAdapter(index=None)
        request = ProxyRequest(
            collection_name="test",
            operation=VectorOperation.QUERY,
            tenant_id="t1",
        )
        result = adapter.execute(request)
        assert result == []

    def test_filter_translation(self):
        adapter = PineconeAdapter(index=None)
        filters = {"tenant_id": "t1", "category": "finance"}
        translated = adapter._translate_pinecone_filter(filters)
        assert translated == {"tenant_id": {"$eq": "t1"}, "category": {"$eq": "finance"}}

    def test_query_with_mock_index(self):
        mock_match = MagicMock()
        mock_match.id = "v1"
        mock_match.metadata = {"content": "pinecone doc", "tenant_id": "t1"}
        mock_match.score = 0.95

        mock_result = MagicMock()
        mock_result.matches = [mock_match]

        mock_index = MagicMock()
        mock_index.query.return_value = mock_result

        adapter = PineconeAdapter(index=mock_index)
        request = ProxyRequest(
            collection_name="test",
            operation=VectorOperation.QUERY,
            tenant_id="t1",
            query_vector=[0.1, 0.2, 0.3],
            top_k=1,
            filters={"tenant_id": "t1"},
        )
        result = adapter.execute(request)
        assert len(result) == 1
        assert result[0]["score"] == 0.95


class TestMilvusAdapter:
    def test_no_connection_returns_empty(self):
        adapter = MilvusAdapter(connection=None)
        request = ProxyRequest(
            collection_name="test",
            operation=VectorOperation.QUERY,
            tenant_id="t1",
        )
        result = adapter.execute(request)
        assert result == []

    def test_expr_builder(self):
        adapter = MilvusAdapter(connection=None)
        expr = adapter._build_milvus_expr({"tenant_id": "t1", "status": 1})
        assert 'tenant_id == "t1"' in expr
        assert "status == 1" in expr
        assert " and " in expr

    def test_empty_filter_expr(self):
        adapter = MilvusAdapter(connection=None)
        expr = adapter._build_milvus_expr({})
        assert expr == ""


# ── Proxy Stats & Policy Management ──────────────────────────────────


class TestProxyManagement:
    def test_register_and_remove_policy(self, proxy, sample_policy):
        proxy.register_policy(sample_policy)
        assert proxy.get_policy("knowledge-base") is not None
        assert len(proxy.list_policies()) == 1

        removed = proxy.remove_policy("knowledge-base")
        assert removed
        assert proxy.get_policy("knowledge-base") is None

    def test_remove_nonexistent_policy(self, proxy):
        assert not proxy.remove_policy("nonexistent")

    def test_stats_tracking(self, proxy, sample_policy):
        proxy.register_policy(sample_policy)

        # Allowed request
        proxy.process(ProxyRequest(
            collection_name="knowledge-base",
            operation=VectorOperation.QUERY,
            tenant_id="t1",
        ))
        # Blocked request (unlisted)
        proxy.process(ProxyRequest(
            collection_name="unlisted",
            operation=VectorOperation.QUERY,
            tenant_id="t1",
        ))

        stats = proxy.get_stats()
        assert stats["total_requests"] == 2
        assert stats["blocked"] == 1
        assert stats["allowed"] == 1

    def test_singleton_pattern(self):
        p1 = get_vectordb_proxy()
        p2 = get_vectordb_proxy()
        assert p1 is p2

    def test_result_to_dict(self):
        result = ProxyResult(
            allowed=True,
            action=ProxyAction.ALLOW,
            collection_name="test",
            operation="query",
            tenant_id="t1",
            namespace_injected=True,
            results_capped=False,
            original_top_k=10,
            enforced_top_k=10,
            documents=[{"id": "1"}],
            latency_ms=1.5,
        )
        d = result.to_dict()
        assert d["allowed"] is True
        assert d["document_count"] == 1
        assert d["namespace_injected"] is True


# ── Admin API Integration Tests ───────────────────────────────────────


class TestVectorDBAdminAPI:
    """Tests for the /admin/vector-collections endpoints."""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock()
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()
        db.delete = AsyncMock()
        return db

    @pytest.fixture
    def api_client(self):
        with patch("app.services.redis_client.get_redis", return_value=AsyncMock(
            get=AsyncMock(return_value=None),
            setex=AsyncMock(),
            delete=AsyncMock(),
            ping=AsyncMock(),
            hgetall=AsyncMock(return_value={}),
            pipeline=MagicMock(return_value=AsyncMock(
                execute=AsyncMock(return_value=[]),
                hincrby=AsyncMock(),
                expire=AsyncMock(),
                zremrangebyscore=AsyncMock(),
            )),
            eval=AsyncMock(return_value=[1, 0, 0]),
            zrange=AsyncMock(return_value=[]),
            zremrangebyscore=AsyncMock(),
        )):
            with patch("app.middleware.auth.validate_api_key", return_value=None):
                with patch("app.middleware.auth.validate_api_key_from_db", return_value=None):
                    from app.main import app
                    yield TestClient(app)

    def test_vector_proxy_status(self, api_client):
        """GET /admin/vector-proxy/status returns stats."""
        resp = api_client.get("/admin/vector-proxy/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "stats" in data
        assert "registered_collections" in data

    def test_vector_proxy_test_unlisted(self, api_client):
        """POST /admin/vector-proxy/test on unlisted collection returns denied."""
        resp = api_client.post("/admin/vector-proxy/test", json={
            "collection_name": "nonexistent",
            "operation": "query",
            "tenant_id": "test-tenant",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert not data["allowed"]
        assert "not registered" in data["blocked_reason"]

    def test_vector_proxy_test_invalid_operation(self, api_client):
        """POST /admin/vector-proxy/test with invalid operation returns 400."""
        resp = api_client.post("/admin/vector-proxy/test", json={
            "collection_name": "test",
            "operation": "invalid_op",
            "tenant_id": "test-tenant",
        })
        assert resp.status_code == 400


# ── End-to-End Enforcement Scenarios ──────────────────────────────────


class TestEndToEndEnforcement:
    """Integration scenarios validating the full enforcement pipeline."""

    def test_full_pipeline_query_with_namespace(self, proxy):
        """Complete flow: register policy → query → namespace injected → capped."""
        policy = CollectionPolicy(
            collection_name="e2e-collection",
            provider=VectorDBProvider.CHROMADB,
            default_action=ProxyAction.DENY,
            allowed_operations=[VectorOperation.QUERY],
            namespace_field="org_id",
            max_results=5,
        )
        proxy.register_policy(policy)

        mock_adapter = MagicMock()
        mock_adapter.execute.return_value = [
            {"id": f"d{i}", "content": f"text-{i}", "metadata": {"org_id": "org-1"}}
            for i in range(10)
        ]
        proxy.register_adapter(VectorDBProvider.CHROMADB, mock_adapter)

        request = ProxyRequest(
            collection_name="e2e-collection",
            operation=VectorOperation.QUERY,
            tenant_id="org-1",
            query_text="search term",
            top_k=20,
        )
        result = proxy.process(request)

        assert result.allowed
        assert result.namespace_injected
        assert request.filters["org_id"] == "org-1"
        assert result.results_capped
        assert len(result.documents) == 5
        assert result.enforced_top_k == 5

    def test_deny_then_update_to_allow(self, proxy):
        """Collection starts denied, then policy updated to allow."""
        policy = CollectionPolicy(
            collection_name="evolving",
            provider=VectorDBProvider.PINECONE,
            default_action=ProxyAction.DENY,
            allowed_operations=[],  # nothing allowed
            namespace_field="tenant_id",
            max_results=10,
        )
        proxy.register_policy(policy)

        request = ProxyRequest(
            collection_name="evolving",
            operation=VectorOperation.QUERY,
            tenant_id="t1",
        )
        result = proxy.process(request)
        assert not result.allowed

        # Update policy
        policy.allowed_operations = [VectorOperation.QUERY]
        proxy.register_policy(policy)

        result2 = proxy.process(request)
        assert result2.allowed

    def test_adapter_error_handled_gracefully(self, proxy):
        """Adapter exception results in denied with error message."""
        policy = CollectionPolicy(
            collection_name="error-collection",
            provider=VectorDBProvider.MILVUS,
            default_action=ProxyAction.ALLOW,
            allowed_operations=[VectorOperation.QUERY],
            namespace_field="tenant_id",
            max_results=10,
        )
        proxy.register_policy(policy)

        mock_adapter = MagicMock()
        mock_adapter.execute.side_effect = ConnectionError("Milvus unavailable")
        proxy.register_adapter(VectorDBProvider.MILVUS, mock_adapter)

        request = ProxyRequest(
            collection_name="error-collection",
            operation=VectorOperation.QUERY,
            tenant_id="t1",
        )
        result = proxy.process(request)
        assert not result.allowed
        assert "Adapter error" in result.blocked_reason

    def test_multiple_tenants_isolated(self, proxy):
        """Multiple tenants querying same collection get proper isolation."""
        policy = CollectionPolicy(
            collection_name="shared-kb",
            provider=VectorDBProvider.CHROMADB,
            default_action=ProxyAction.DENY,
            allowed_operations=[VectorOperation.QUERY],
            namespace_field="tenant_id",
            max_results=10,
        )
        proxy.register_policy(policy)

        for tenant in ["tenant-a", "tenant-b", "tenant-c"]:
            request = ProxyRequest(
                collection_name="shared-kb",
                operation=VectorOperation.QUERY,
                tenant_id=tenant,
                filters={},
            )
            result = proxy.process(request)
            assert result.allowed
            assert result.namespace_injected
            # Verify the filter was set to THIS tenant
            assert request.filters["tenant_id"] == tenant
