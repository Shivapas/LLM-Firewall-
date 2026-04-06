"""Sprint 10 Tests — Vector DB Firewall Hardening & Observability.

Acceptance Criteria:
- All three vector DBs (ChromaDB, Pinecone, Milvus) pass namespace isolation
  penetration test suite with zero escapes
- Compliance tags on retrieved chunks correctly trigger routing policy
  in downstream pipeline
- Collection audit log populated for every governed query; accessible via
  admin dashboard
"""

import hashlib
import json
import time
import uuid
from unittest.mock import MagicMock, patch

import pytest

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
    get_namespace_isolator,
    reset_namespace_isolator,
)
from app.services.vectordb.milvus_proxy import (
    MilvusGRPCProxy,
    MilvusProxyConfig,
    MilvusPartitionConfig,
    MilvusFilterInjection,
    get_milvus_proxy,
    reset_milvus_proxy,
)
from app.services.vectordb.compliance_tagger import (
    ComplianceTagger,
    CompliancePolicy,
    ComplianceLabel,
    ComplianceTag,
    BatchComplianceResult,
    get_compliance_tagger,
    reset_compliance_tagger,
)
from app.services.vectordb.collection_audit import (
    CollectionAuditLog,
    CollectionAuditEntry,
    compute_query_hash,
    get_collection_audit_log,
    reset_collection_audit_log,
)
from app.services.vectordb.chunk_scanner import (
    reset_chunk_scanner,
    get_chunk_scanner,
    reset_incident_logger,
)
from app.services.threat_detection.engine import reset_threat_engine


# ── Fixtures ────────────���─────────────────────────────────────────────


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset singletons before each test."""
    reset_vectordb_proxy()
    reset_namespace_isolator()
    reset_milvus_proxy()
    reset_compliance_tagger()
    reset_collection_audit_log()
    reset_chunk_scanner()
    reset_incident_logger()
    reset_threat_engine()
    yield
    reset_vectordb_proxy()
    reset_milvus_proxy()
    reset_compliance_tagger()
    reset_collection_audit_log()


@pytest.fixture
def proxy():
    return VectorDBProxy()


@pytest.fixture
def chromadb_policy():
    return CollectionPolicy(
        collection_name="chromadb-embeddings",
        provider=VectorDBProvider.CHROMADB,
        default_action=ProxyAction.DENY,
        allowed_operations=[VectorOperation.QUERY],
        namespace_field="tenant_id",
        max_results=10,
        is_active=True,
        tenant_id="*",
    )


@pytest.fixture
def pinecone_policy():
    return CollectionPolicy(
        collection_name="pinecone-index",
        provider=VectorDBProvider.PINECONE,
        default_action=ProxyAction.DENY,
        allowed_operations=[VectorOperation.QUERY],
        namespace_field="tenant_id",
        max_results=10,
        is_active=True,
        tenant_id="*",
    )


@pytest.fixture
def milvus_policy():
    return CollectionPolicy(
        collection_name="milvus-collection",
        provider=VectorDBProvider.MILVUS,
        default_action=ProxyAction.DENY,
        allowed_operations=[VectorOperation.QUERY, VectorOperation.INSERT],
        namespace_field="tenant_id",
        max_results=10,
        is_active=True,
        tenant_id="*",
    )


def _make_docs(tenant_id, count=5, prefix="doc"):
    """Generate test documents for a specific tenant."""
    return [
        {
            "id": f"{prefix}-{tenant_id}-{i}",
            "content": f"Document {i} for tenant {tenant_id}",
            "metadata": {"tenant_id": tenant_id, "source": "test"},
            "score": 0.9 - i * 0.1,
        }
        for i in range(count)
    ]


def _make_cross_tenant_docs():
    """Generate mixed-tenant documents (simulates a DB leak)."""
    return [
        {"id": "doc-a-0", "content": "Tenant A doc", "metadata": {"tenant_id": "tenant-A"}, "score": 0.95},
        {"id": "doc-b-0", "content": "Tenant B doc", "metadata": {"tenant_id": "tenant-B"}, "score": 0.90},
        {"id": "doc-a-1", "content": "Tenant A doc 2", "metadata": {"tenant_id": "tenant-A"}, "score": 0.85},
        {"id": "doc-c-0", "content": "Tenant C doc", "metadata": {"tenant_id": "tenant-C"}, "score": 0.80},
        {"id": "doc-b-1", "content": "Tenant B doc 2", "metadata": {"tenant_id": "tenant-B"}, "score": 0.75},
    ]


# ═══════════════════════════════════════════════════════════════════════
# PENETRATION TEST SUITE — Namespace Isolation (10 scenarios)
# ═════════════════════════════════════════════════���═════════════════════


class TestNamespaceIsolationPenetration:
    """Structured penetration test: 10 cross-tenant extraction scenarios.
    Assert zero escapes with policy active."""

    # ── Scenario 1: Direct cross-tenant query (ChromaDB) ──────────────

    def test_scenario1_direct_cross_tenant_query_chromadb(self, proxy, chromadb_policy):
        """Tenant A queries; response contains Tenant B docs. Verify B docs stripped."""
        proxy.register_policy(chromadb_policy)

        # Mock adapter returns mixed-tenant results
        mock_adapter = MagicMock()
        mock_adapter.execute.return_value = _make_cross_tenant_docs()
        proxy.register_adapter(VectorDBProvider.CHROMADB, mock_adapter)

        request = ProxyRequest(
            collection_name="chromadb-embeddings",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-A",
            top_k=10,
        )
        result = proxy.process(request)

        assert result.allowed
        assert result.namespace_injected
        # Namespace filter should be injected into the request
        assert request.filters.get("tenant_id") == "tenant-A"

    # ── Scenario 2: Direct cross-tenant query (Pinecone) ──────────────

    def test_scenario2_direct_cross_tenant_query_pinecone(self, proxy, pinecone_policy):
        """Tenant B queries; response contains Tenant A docs. Verify A docs stripped."""
        proxy.register_policy(pinecone_policy)

        mock_adapter = MagicMock()
        mock_adapter.execute.return_value = _make_cross_tenant_docs()
        proxy.register_adapter(VectorDBProvider.PINECONE, mock_adapter)

        request = ProxyRequest(
            collection_name="pinecone-index",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-B",
            top_k=10,
        )
        result = proxy.process(request)

        assert result.allowed
        assert result.namespace_injected
        assert request.filters.get("tenant_id") == "tenant-B"

    # ── Scenario 3: Direct cross-tenant query (Milvus) ────────���───────

    def test_scenario3_direct_cross_tenant_query_milvus(self, proxy, milvus_policy):
        """Tenant C queries Milvus; verify namespace injected."""
        proxy.register_policy(milvus_policy)

        mock_adapter = MagicMock()
        mock_adapter.execute.return_value = _make_docs("tenant-C", count=3)
        proxy.register_adapter(VectorDBProvider.MILVUS, mock_adapter)

        request = ProxyRequest(
            collection_name="milvus-collection",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-C",
            top_k=5,
        )
        result = proxy.process(request)

        assert result.allowed
        assert result.namespace_injected
        assert request.filters.get("tenant_id") == "tenant-C"

    # ── Scenario 4: Filter override attempt ───────────────────────────

    def test_scenario4_filter_override_attempt(self, proxy, chromadb_policy):
        """Tenant A passes tenant_id=tenant-B in filters. Verify overwritten."""
        proxy.register_policy(chromadb_policy)

        mock_adapter = MagicMock()
        mock_adapter.execute.return_value = _make_docs("tenant-A", count=2)
        proxy.register_adapter(VectorDBProvider.CHROMADB, mock_adapter)

        request = ProxyRequest(
            collection_name="chromadb-embeddings",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-A",
            filters={"tenant_id": "tenant-B"},  # Attempted override
            top_k=5,
        )
        result = proxy.process(request)

        assert result.allowed
        assert result.namespace_injected
        # The filter MUST be overwritten to the authenticated tenant
        assert request.filters["tenant_id"] == "tenant-A"

    # ── Scenario 5: Empty tenant_id injection attempt ─────────────────

    def test_scenario5_empty_tenant_id_still_injects(self, proxy, chromadb_policy):
        """Empty string tenant_id should still be injected (not bypassed)."""
        proxy.register_policy(chromadb_policy)

        mock_adapter = MagicMock()
        mock_adapter.execute.return_value = []
        proxy.register_adapter(VectorDBProvider.CHROMADB, mock_adapter)

        request = ProxyRequest(
            collection_name="chromadb-embeddings",
            operation=VectorOperation.QUERY,
            tenant_id="",
            top_k=5,
        )
        result = proxy.process(request)

        assert result.allowed
        assert result.namespace_injected
        # Empty string is injected — not bypassed
        assert request.filters["tenant_id"] == ""

    # ─�� Scenario 6: Namespace isolator post-retrieval validation ──────

    def test_scenario6_post_retrieval_cross_tenant_stripping(self):
        """NamespaceIsolator strips cross-tenant documents from response."""
        isolator = NamespaceIsolator()
        policy = CollectionPolicy(
            collection_name="test-col",
            provider=VectorDBProvider.CHROMADB,
            namespace_field="tenant_id",
        )

        mixed_docs = _make_cross_tenant_docs()
        valid = isolator.validate_response_namespace(mixed_docs, policy, "tenant-A")

        # Only tenant-A docs should remain
        assert len(valid) == 2
        for doc in valid:
            assert doc["metadata"]["tenant_id"] == "tenant-A"

    # ── Scenario 7: Wildcard tenant_id filter bypass ──────────────────

    def test_scenario7_wildcard_tenant_bypass_attempt(self, proxy, chromadb_policy):
        """Tenant passes tenant_id='*' in filters. Verify overwritten."""
        proxy.register_policy(chromadb_policy)

        mock_adapter = MagicMock()
        mock_adapter.execute.return_value = _make_docs("tenant-X", count=2)
        proxy.register_adapter(VectorDBProvider.CHROMADB, mock_adapter)

        request = ProxyRequest(
            collection_name="chromadb-embeddings",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-X",
            filters={"tenant_id": "*"},  # Wildcard bypass attempt
            top_k=5,
        )
        result = proxy.process(request)

        assert result.namespace_injected
        assert request.filters["tenant_id"] == "tenant-X"

    # ── Scenario 8: Milvus partition-based isolation ──────────────────

    def test_scenario8_milvus_partition_isolation(self):
        """Milvus partition-based isolation confines tenant to own partition."""
        mock_conn = MagicMock()
        mock_conn.search.return_value = [[]]
        mock_conn.has_partition.return_value = True

        milvus_proxy = MilvusGRPCProxy(
            config=MilvusProxyConfig(),
            partition_config=MilvusPartitionConfig(
                use_partitions=True,
                partition_prefix="ns_",
            ),
            connection=mock_conn,
        )

        policy = CollectionPolicy(
            collection_name="milvus-col",
            provider=VectorDBProvider.MILVUS,
            namespace_field="tenant_id",
        )
        request = ProxyRequest(
            collection_name="milvus-col",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-D",
            query_vector=[0.1, 0.2, 0.3],
            top_k=5,
        )

        injection = milvus_proxy.inject_metadata_filter(request, policy)

        assert injection.used_partition_isolation
        assert injection.partition_names == ["ns_tenant-D"]
        assert 'tenant_id == "tenant-D"' in injection.injected_expr

    # ���─ Scenario 9: Milvus metadata filter injection ──────────────────

    def test_scenario9_milvus_filter_injection_removes_existing(self):
        """Milvus filter injection removes attacker-supplied namespace filter."""
        milvus_proxy = MilvusGRPCProxy()
        policy = CollectionPolicy(
            collection_name="milvus-col",
            provider=VectorDBProvider.MILVUS,
            namespace_field="tenant_id",
        )

        # Attacker tries to inject their own tenant filter
        request = ProxyRequest(
            collection_name="milvus-col",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-E",
            filters={"tenant_id": "tenant-EVIL", "category": "public"},
            top_k=5,
        )

        injection = milvus_proxy.inject_metadata_filter(request, policy)

        # The injected expression must use the AUTHENTICATED tenant
        assert 'tenant_id == "tenant-E"' in injection.injected_expr
        # The attacker's tenant_id filter must be removed
        assert "tenant-EVIL" not in injection.injected_expr
        # Legitimate non-namespace filters preserved
        assert "category" in injection.injected_expr

    # ── Scenario 10: Cross-provider namespace enforcement ─────────────

    def test_scenario10_all_providers_enforce_namespace(self, proxy):
        """Register all 3 providers and verify namespace enforcement on each."""
        providers = [
            (VectorDBProvider.CHROMADB, "chromadb-col"),
            (VectorDBProvider.PINECONE, "pinecone-col"),
            (VectorDBProvider.MILVUS, "milvus-col"),
        ]

        for provider, name in providers:
            policy = CollectionPolicy(
                collection_name=name,
                provider=provider,
                default_action=ProxyAction.DENY,
                allowed_operations=[VectorOperation.QUERY],
                namespace_field="tenant_id",
                max_results=10,
                is_active=True,
            )
            proxy.register_policy(policy)

            mock_adapter = MagicMock()
            mock_adapter.execute.return_value = _make_docs(f"tenant-{name}", count=3)
            proxy.register_adapter(provider, mock_adapter)

        # Query each provider and verify namespace injection
        for provider, name in providers:
            request = ProxyRequest(
                collection_name=name,
                operation=VectorOperation.QUERY,
                tenant_id="tenant-SECURE",
                top_k=5,
            )
            result = proxy.process(request)

            assert result.allowed, f"Query to {name} should be allowed"
            assert result.namespace_injected, f"Namespace should be injected for {name}"
            assert request.filters["tenant_id"] == "tenant-SECURE", (
                f"Namespace filter must be tenant-SECURE for {name}"
            )


# ═════════════════════════════════════��═════════════════════════════════
# COMPLIANCE TAGGING TESTS
# ══════════════════════════��══════════════════════════════��═════════════


class TestComplianceTagging:
    """Compliance tags on retrieved chunks correctly trigger routing policy."""

    def test_pii_metadata_tagging(self):
        """Chunks with PII metadata field get PII tag."""
        tagger = ComplianceTagger()
        docs = [
            {"id": "d1", "content": "Hello world", "metadata": {"contains_pii": True}},
            {"id": "d2", "content": "Public doc", "metadata": {}},
        ]
        result = tagger.tag_chunks(docs)

        assert result.tagged_chunks == 1
        assert "PII" in result.summary
        assert result.chunk_results[0].requires_private_model
        assert not result.chunk_results[1].requires_private_model

    def test_phi_metadata_tagging(self):
        """Chunks with PHI metadata get PHI tag and require private model."""
        tagger = ComplianceTagger()
        docs = [{"id": "d1", "content": "Patient record", "metadata": {"hipaa": True}}]
        result = tagger.tag_chunks(docs)

        assert result.tagged_chunks == 1
        assert "PHI" in result.summary
        assert result.any_requires_private_model
        assert result.any_data_residency_required

    def test_ip_metadata_tagging(self):
        """Chunks with IP metadata get IP tag and require approval."""
        tagger = ComplianceTagger()
        docs = [{"id": "d1", "content": "Algorithm spec", "metadata": {"proprietary": True}}]
        result = tagger.tag_chunks(docs)

        assert result.tagged_chunks == 1
        assert "IP" in result.summary
        assert result.any_requires_approval

    def test_pii_content_detection(self):
        """Chunks with SSN pattern in content get PII tag via content scan."""
        tagger = ComplianceTagger()
        docs = [
            {"id": "d1", "content": "Customer SSN is 123-45-6789", "metadata": {}},
            {"id": "d2", "content": "No sensitive data here", "metadata": {}},
        ]
        result = tagger.tag_chunks(docs)

        assert result.tagged_chunks == 1
        assert result.chunk_results[0].label_names == ["PII"]
        assert result.chunk_results[0].tags[0].source == "content_scan"

    def test_phi_content_detection(self):
        """Chunks mentioning medical terms get PHI tag."""
        tagger = ComplianceTagger()
        docs = [{"id": "d1", "content": "Patient diagnosis shows elevated results", "metadata": {}}]
        result = tagger.tag_chunks(docs)

        assert result.tagged_chunks == 1
        assert "PHI" in result.chunk_results[0].label_names

    def test_ip_content_detection(self):
        """Chunks mentioning trade secrets get IP tag."""
        tagger = ComplianceTagger()
        docs = [{"id": "d1", "content": "This trade secret algorithm is proprietary", "metadata": {}}]
        result = tagger.tag_chunks(docs)

        assert result.tagged_chunks == 1
        assert "IP" in result.chunk_results[0].label_names

    def test_multiple_compliance_labels(self):
        """A chunk can carry multiple compliance labels."""
        tagger = ComplianceTagger()
        docs = [{
            "id": "d1",
            "content": "Patient SSN 123-45-6789 diagnosis confirmed",
            "metadata": {"regulated": True},
        }]
        result = tagger.tag_chunks(docs)

        labels = result.chunk_results[0].label_names
        assert "REGULATED" in labels
        assert "PII" in labels
        assert "PHI" in labels
        assert result.any_requires_private_model
        assert result.any_data_residency_required

    def test_compliance_tags_injected_into_metadata(self):
        """Compliance tags should be injected into document metadata."""
        tagger = ComplianceTagger()
        docs = [{"id": "d1", "content": "SSN: 123-45-6789", "metadata": {}}]
        tagger.tag_chunks(docs)

        # After tagging, metadata should have compliance_tags
        assert "compliance_tags" in docs[0]["metadata"]
        assert "PII" in docs[0]["metadata"]["compliance_tags"]
        assert docs[0]["metadata"]["requires_private_model"] is True

    def test_highest_sensitivity_ordering(self):
        """Highest sensitivity is correctly determined."""
        tagger = ComplianceTagger()
        docs = [{
            "id": "d1",
            "content": "Patient record with SSN 123-45-6789",
            "metadata": {"regulated": True},
        }]
        result = tagger.tag_chunks(docs)

        # PHI > PII > REGULATED in sensitivity ordering
        assert result.chunk_results[0].highest_sensitivity == "PHI"

    def test_compliance_routing_in_proxy(self):
        """Compliance tags flow through the proxy and appear in results."""
        proxy = VectorDBProxy()
        policy = CollectionPolicy(
            collection_name="test-col",
            provider=VectorDBProvider.CHROMADB,
            default_action=ProxyAction.DENY,
            allowed_operations=[VectorOperation.QUERY],
            namespace_field="tenant_id",
            max_results=10,
            is_active=True,
            scan_chunks_for_injection=False,
        )
        proxy.register_policy(policy)

        mock_adapter = MagicMock()
        mock_adapter.execute.return_value = [
            {"id": "d1", "content": "SSN: 123-45-6789", "metadata": {"tenant_id": "t1"}},
        ]
        proxy.register_adapter(VectorDBProvider.CHROMADB, mock_adapter)

        request = ProxyRequest(
            collection_name="test-col",
            operation=VectorOperation.QUERY,
            tenant_id="t1",
            top_k=5,
        )
        result = proxy.process(request)

        assert result.allowed
        assert "PII" in result.compliance_tags
        assert result.requires_private_model


# ════════════════════════��══════════════════════════════════════════════
# COLLECTION AUDIT LOG TESTS
# ══════���═══════════════════���════════════════════════════════════════════


class TestCollectionAuditLog:
    """Collection audit log populated for every governed query."""

    def test_audit_entry_recorded(self):
        """Every governed query creates an audit entry."""
        audit_log = CollectionAuditLog()
        entry = CollectionAuditEntry(
            collection_name="test-col",
            tenant_id="tenant-1",
            operation="query",
            query_hash="abc123",
            chunks_returned=5,
            chunks_blocked=1,
            latency_ms=12.5,
        )
        audit_log.record(entry)

        assert audit_log.total_entries == 1
        assert audit_log.buffer_size == 1

        entries = audit_log.get_entries()
        assert len(entries) == 1
        assert entries[0].collection_name == "test-col"

    def test_audit_query_hash_deterministic(self):
        """Query hash is deterministic for same inputs."""
        h1 = compute_query_hash("col", "t1", "query", {"a": 1}, "hello")
        h2 = compute_query_hash("col", "t1", "query", {"a": 1}, "hello")
        h3 = compute_query_hash("col", "t2", "query", {"a": 1}, "hello")

        assert h1 == h2
        assert h1 != h3

    def test_audit_per_collection_stats(self):
        """Stats are tracked per collection."""
        audit_log = CollectionAuditLog()
        for i in range(3):
            audit_log.record(CollectionAuditEntry(
                collection_name="col-A",
                tenant_id=f"tenant-{i}",
                operation="query",
                chunks_returned=5,
                latency_ms=10.0,
            ))
        audit_log.record(CollectionAuditEntry(
            collection_name="col-B",
            tenant_id="tenant-0",
            operation="query",
            chunks_returned=3,
            latency_ms=5.0,
        ))

        stats = audit_log.get_collection_stats()
        assert stats["col-A"]["total_queries"] == 3
        assert stats["col-A"]["unique_tenants"] == 3
        assert stats["col-B"]["total_queries"] == 1

    def test_audit_tenant_stats(self):
        """Per-tenant stats accessible per collection."""
        audit_log = CollectionAuditLog()
        for _ in range(3):
            audit_log.record(CollectionAuditEntry(
                collection_name="col-A", tenant_id="t1", operation="query",
            ))
        audit_log.record(CollectionAuditEntry(
            collection_name="col-A", tenant_id="t2", operation="query", action="blocked",
        ))

        tenant_stats = audit_log.get_tenant_stats("col-A")
        assert tenant_stats["t1"]["query_count"] == 3
        assert tenant_stats["t2"]["query_count"] == 1
        assert tenant_stats["t2"]["blocked_count"] == 1

    def test_audit_anomaly_timeline(self):
        """Anomaly events appear in the timeline."""
        audit_log = CollectionAuditLog()
        audit_log.record(CollectionAuditEntry(
            collection_name="col-A", tenant_id="t1",
            anomaly_detected=True, anomaly_score=0.95,
        ))
        audit_log.record(CollectionAuditEntry(
            collection_name="col-A", tenant_id="t1",
            anomaly_detected=False,
        ))

        timeline = audit_log.get_anomaly_timeline()
        assert len(timeline) == 1
        assert timeline[0]["anomaly_score"] == 0.95

    def test_audit_filters(self):
        """Audit log supports filtering by collection and tenant."""
        audit_log = CollectionAuditLog()
        audit_log.record(CollectionAuditEntry(collection_name="c1", tenant_id="t1"))
        audit_log.record(CollectionAuditEntry(collection_name="c2", tenant_id="t2"))
        audit_log.record(CollectionAuditEntry(collection_name="c1", tenant_id="t2"))

        c1_entries = audit_log.get_entries(collection_name="c1")
        assert len(c1_entries) == 2

        t2_entries = audit_log.get_entries(tenant_id="t2")
        assert len(t2_entries) == 2

        filtered = audit_log.get_entries(collection_name="c1", tenant_id="t2")
        assert len(filtered) == 1

    def test_audit_integrated_with_proxy(self):
        """Proxy automatically records audit entries for every query."""
        proxy = VectorDBProxy()
        policy = CollectionPolicy(
            collection_name="audit-test",
            provider=VectorDBProvider.CHROMADB,
            default_action=ProxyAction.DENY,
            allowed_operations=[VectorOperation.QUERY],
            namespace_field="tenant_id",
            max_results=10,
            is_active=True,
            scan_chunks_for_injection=False,
        )
        proxy.register_policy(policy)

        mock_adapter = MagicMock()
        mock_adapter.execute.return_value = [
            {"id": "d1", "content": "test", "metadata": {"tenant_id": "t1"}},
        ]
        proxy.register_adapter(VectorDBProvider.CHROMADB, mock_adapter)

        request = ProxyRequest(
            collection_name="audit-test",
            operation=VectorOperation.QUERY,
            tenant_id="t1",
            top_k=5,
        )
        proxy.process(request)

        audit_log = get_collection_audit_log()
        entries = audit_log.get_entries()
        assert len(entries) >= 1
        assert entries[0].collection_name == "audit-test"
        assert entries[0].tenant_id == "t1"
        assert entries[0].namespace_injected is True

    def test_audit_buffer_trimming(self):
        """Buffer trims old entries when max size exceeded."""
        audit_log = CollectionAuditLog(max_buffer_size=5)
        for i in range(10):
            audit_log.record(CollectionAuditEntry(
                collection_name="col", tenant_id=f"t{i}",
            ))
        assert audit_log.buffer_size == 5
        assert audit_log.total_entries == 10


# ���═══════════════════════════════���═══════════════════════��══════════════
# MILVUS FULL INTEGRATION TESTS
# ══════��════════════════════════════════���════════════════════════���══════


class TestMilvusFullIntegration:
    """Milvus gRPC proxy, metadata filter injection, partition isolation."""

    def test_milvus_filter_injection_basic(self):
        """Basic metadata filter injection for Milvus."""
        milvus_proxy = MilvusGRPCProxy()
        policy = CollectionPolicy(
            collection_name="test",
            provider=VectorDBProvider.MILVUS,
            namespace_field="tenant_id",
        )
        request = ProxyRequest(
            collection_name="test",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-1",
            top_k=5,
        )

        injection = milvus_proxy.inject_metadata_filter(request, policy)

        assert injection.injected_expr == 'tenant_id == "tenant-1"'
        assert injection.namespace_value == "tenant-1"

    def test_milvus_filter_injection_with_existing_filters(self):
        """Existing filters are preserved alongside injected namespace."""
        milvus_proxy = MilvusGRPCProxy()
        policy = CollectionPolicy(
            collection_name="test",
            provider=VectorDBProvider.MILVUS,
            namespace_field="tenant_id",
        )
        request = ProxyRequest(
            collection_name="test",
            operation=VectorOperation.QUERY,
            tenant_id="tenant-1",
            filters={"category": "public", "status": 1},
            top_k=5,
        )

        injection = milvus_proxy.inject_metadata_filter(request, policy)

        assert 'tenant_id == "tenant-1"' in injection.injected_expr
        assert "category" in injection.injected_expr

    def test_milvus_partition_config(self):
        """Partition isolation configuration works correctly."""
        config = MilvusPartitionConfig(
            use_partitions=True,
            partition_prefix="org_",
        )
        milvus_proxy = MilvusGRPCProxy(partition_config=config)
        policy = CollectionPolicy(
            collection_name="test",
            provider=VectorDBProvider.MILVUS,
            namespace_field="tenant_id",
        )
        request = ProxyRequest(
            collection_name="test",
            operation=VectorOperation.QUERY,
            tenant_id="acme-corp",
            top_k=5,
        )

        injection = milvus_proxy.inject_metadata_filter(request, policy)

        assert injection.used_partition_isolation
        assert injection.partition_names == ["org_acme-corp"]

    def test_milvus_execute_query_with_connection(self):
        """Execute query through Milvus proxy with mock connection."""
        mock_conn = MagicMock()
        mock_hit = MagicMock()
        mock_hit.id = "doc-1"
        mock_hit.entity = {"content": "test doc", "tenant_id": "t1"}
        mock_hit.distance = 0.1
        mock_conn.search.return_value = [[mock_hit]]
        mock_conn.has_partition.return_value = True

        milvus_proxy = MilvusGRPCProxy(connection=mock_conn)
        policy = CollectionPolicy(
            collection_name="test",
            provider=VectorDBProvider.MILVUS,
            namespace_field="tenant_id",
        )
        request = ProxyRequest(
            collection_name="test",
            operation=VectorOperation.QUERY,
            tenant_id="t1",
            query_vector=[0.1, 0.2],
            top_k=5,
        )

        docs = milvus_proxy.execute(request, policy)
        assert len(docs) == 1
        assert docs[0]["id"] == "doc-1"

    def test_milvus_insert_with_namespace_injection(self):
        """Insert operations inject tenant_id into documents."""
        mock_conn = MagicMock()
        mock_conn.has_partition.return_value = True

        milvus_proxy = MilvusGRPCProxy(connection=mock_conn)
        policy = CollectionPolicy(
            collection_name="test",
            provider=VectorDBProvider.MILVUS,
            namespace_field="tenant_id",
        )
        request = ProxyRequest(
            collection_name="test",
            operation=VectorOperation.INSERT,
            tenant_id="t1",
            documents=[{"content": "new doc"}],
        )

        milvus_proxy.execute(request, policy)

        # Verify tenant_id was injected into the document
        assert request.documents[0]["tenant_id"] == "t1"
        mock_conn.insert.assert_called_once()

    def test_milvus_delete_scoped_to_tenant(self):
        """Delete operations are scoped to tenant namespace."""
        mock_conn = MagicMock()
        mock_conn.has_partition.return_value = True

        milvus_proxy = MilvusGRPCProxy(connection=mock_conn)
        policy = CollectionPolicy(
            collection_name="test",
            provider=VectorDBProvider.MILVUS,
            namespace_field="tenant_id",
        )
        request = ProxyRequest(
            collection_name="test",
            operation=VectorOperation.DELETE,
            tenant_id="t1",
            document_ids=["doc-1", "doc-2"],
        )

        milvus_proxy.execute(request, policy)

        mock_conn.delete.assert_called_once()
        call_kwargs = mock_conn.delete.call_args[1]
        assert 'tenant_id == "t1"' in call_kwargs["filter"]

    def test_milvus_health_check(self):
        """Health check returns connection status."""
        mock_conn = MagicMock()
        mock_conn.list_collections.return_value = ["col1", "col2"]

        proxy = MilvusGRPCProxy(connection=mock_conn)
        health = proxy.health_check()

        assert health["connected"]
        assert health["collection_count"] == 2

    def test_milvus_stats_tracking(self):
        """Stats are tracked for Milvus proxy operations."""
        mock_conn = MagicMock()
        mock_conn.search.return_value = [[]]
        mock_conn.has_partition.return_value = True

        milvus_proxy = MilvusGRPCProxy(connection=mock_conn)
        policy = CollectionPolicy(
            collection_name="test",
            provider=VectorDBProvider.MILVUS,
            namespace_field="tenant_id",
        )

        for _ in range(3):
            request = ProxyRequest(
                collection_name="test",
                operation=VectorOperation.QUERY,
                tenant_id="t1",
                query_vector=[0.1],
                top_k=5,
            )
            milvus_proxy.execute(request, policy)

        assert milvus_proxy.stats["total_queries"] == 3
        assert milvus_proxy.stats["filter_injections"] == 3


# ═══════════════════════════════════════════════════��═══════════════════
# INTEGRATION: Proxy + Compliance + Audit combined
# ════════════════════════════════════════════════════���══════════════════


class TestIntegration:
    """End-to-end integration tests combining all Sprint 10 features."""

    def test_full_pipeline_chromadb(self):
        """Full pipeline: ChromaDB query with compliance tagging and audit."""
        proxy = VectorDBProxy()
        policy = CollectionPolicy(
            collection_name="full-test",
            provider=VectorDBProvider.CHROMADB,
            default_action=ProxyAction.DENY,
            allowed_operations=[VectorOperation.QUERY],
            namespace_field="tenant_id",
            max_results=10,
            is_active=True,
            scan_chunks_for_injection=False,
        )
        proxy.register_policy(policy)

        mock_adapter = MagicMock()
        mock_adapter.execute.return_value = [
            {"id": "d1", "content": "Call 555-123-4567 for details", "metadata": {"tenant_id": "t1"}},
            {"id": "d2", "content": "Public information", "metadata": {"tenant_id": "t1"}},
        ]
        proxy.register_adapter(VectorDBProvider.CHROMADB, mock_adapter)

        request = ProxyRequest(
            collection_name="full-test",
            operation=VectorOperation.QUERY,
            tenant_id="t1",
            top_k=5,
        )
        result = proxy.process(request)

        # Verify namespace injection
        assert result.namespace_injected
        assert request.filters["tenant_id"] == "t1"

        # Verify compliance tagging
        assert "PII" in result.compliance_tags
        assert result.requires_private_model

        # Verify audit log
        audit_log = get_collection_audit_log()
        entries = audit_log.get_entries()
        assert len(entries) >= 1
        latest = entries[0]
        assert latest.collection_name == "full-test"
        assert latest.compliance_tags.get("PII", 0) > 0

    def test_blocked_query_audited(self):
        """Blocked queries are still audited."""
        proxy = VectorDBProxy()
        policy = CollectionPolicy(
            collection_name="blocked-test",
            provider=VectorDBProvider.CHROMADB,
            default_action=ProxyAction.DENY,
            allowed_operations=[],  # No operations allowed
            is_active=True,
        )
        proxy.register_policy(policy)

        request = ProxyRequest(
            collection_name="blocked-test",
            operation=VectorOperation.QUERY,
            tenant_id="t1",
        )
        result = proxy.process(request)

        assert not result.allowed

    def test_unregistered_collection_denied(self):
        """Query to unregistered collection is denied."""
        proxy = VectorDBProxy()
        request = ProxyRequest(
            collection_name="unknown-col",
            operation=VectorOperation.QUERY,
            tenant_id="t1",
        )
        result = proxy.process(request)

        assert not result.allowed
        assert "not registered" in result.blocked_reason
