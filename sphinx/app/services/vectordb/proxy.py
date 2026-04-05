"""Vector DB Proxy Layer — intercepts vector DB queries from RAG pipelines.

Supports ChromaDB, Pinecone, and Milvus via transparent proxy adapters.
Enforces namespace isolation, collection allowlisting, operation policies, and max results caps.
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("sphinx.vectordb.proxy")


class VectorDBProvider(str, Enum):
    CHROMADB = "chromadb"
    PINECONE = "pinecone"
    MILVUS = "milvus"


class VectorOperation(str, Enum):
    QUERY = "query"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"


class ProxyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    MONITOR = "monitor"


@dataclass
class CollectionPolicy:
    """Policy for a governed vector collection."""
    collection_name: str
    provider: VectorDBProvider
    default_action: ProxyAction = ProxyAction.DENY
    allowed_operations: list[VectorOperation] = field(default_factory=list)
    sensitive_fields: list[str] = field(default_factory=list)
    namespace_field: str = "tenant_id"
    max_results: int = 10
    is_active: bool = True
    tenant_id: str = "*"


@dataclass
class ProxyRequest:
    """Incoming vector DB request to be intercepted."""
    collection_name: str
    operation: VectorOperation
    tenant_id: str
    query_vector: list[float] | None = None
    query_text: str | None = None
    filters: dict[str, Any] = field(default_factory=dict)
    top_k: int = 10
    documents: list[dict[str, Any]] | None = None
    document_ids: list[str] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProxyResult:
    """Result from the vector DB proxy enforcement."""
    allowed: bool = True
    action: ProxyAction = ProxyAction.ALLOW
    collection_name: str = ""
    operation: str = ""
    tenant_id: str = ""
    namespace_injected: bool = False
    results_capped: bool = False
    original_top_k: int = 0
    enforced_top_k: int = 0
    documents: list[dict[str, Any]] = field(default_factory=list)
    blocked_reason: str | None = None
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        d = {
            "allowed": self.allowed,
            "action": self.action.value if isinstance(self.action, ProxyAction) else self.action,
            "collection_name": self.collection_name,
            "operation": self.operation,
            "tenant_id": self.tenant_id,
            "namespace_injected": self.namespace_injected,
            "results_capped": self.results_capped,
            "original_top_k": self.original_top_k,
            "enforced_top_k": self.enforced_top_k,
            "document_count": len(self.documents),
            "latency_ms": round(self.latency_ms, 2),
        }
        if self.blocked_reason:
            d["blocked_reason"] = self.blocked_reason
        return d


class VectorDBProxy:
    """Main proxy layer that intercepts and enforces policies on vector DB operations.

    Enforcement order:
    1. Collection allowlist check
    2. Operation permission check
    3. Namespace isolation injection (for queries)
    4. Forward to adapter
    5. Max results cap on response
    """

    def __init__(self):
        self._policies: dict[str, CollectionPolicy] = {}
        self._adapters: dict[VectorDBProvider, "BaseVectorAdapter"] = {}
        self._stats = {"total_requests": 0, "blocked": 0, "allowed": 0, "monitored": 0}

    def register_policy(self, policy: CollectionPolicy) -> None:
        self._policies[policy.collection_name] = policy
        logger.info("Registered policy for collection %s", policy.collection_name)

    def remove_policy(self, collection_name: str) -> bool:
        if collection_name in self._policies:
            del self._policies[collection_name]
            return True
        return False

    def get_policy(self, collection_name: str) -> CollectionPolicy | None:
        return self._policies.get(collection_name)

    def list_policies(self) -> list[CollectionPolicy]:
        return list(self._policies.values())

    def register_adapter(self, provider: VectorDBProvider, adapter: "BaseVectorAdapter") -> None:
        self._adapters[provider] = adapter

    def get_stats(self) -> dict:
        return dict(self._stats)

    def process(self, request: ProxyRequest) -> ProxyResult:
        """Process a vector DB request through the proxy enforcement pipeline."""
        start = time.perf_counter()
        self._stats["total_requests"] += 1

        result = ProxyResult(
            collection_name=request.collection_name,
            operation=request.operation.value,
            tenant_id=request.tenant_id,
            original_top_k=request.top_k,
        )

        # Step 1: Collection allowlist check
        policy = self._policies.get(request.collection_name)
        if policy is None:
            self._stats["blocked"] += 1
            result.allowed = False
            result.action = ProxyAction.DENY
            result.blocked_reason = (
                f"Collection '{request.collection_name}' is not registered. "
                "All governed collections must have an explicit policy."
            )
            result.latency_ms = (time.perf_counter() - start) * 1000
            logger.warning(
                "Access denied: unlisted collection %s tenant=%s",
                request.collection_name, request.tenant_id,
            )
            return result

        if not policy.is_active:
            self._stats["blocked"] += 1
            result.allowed = False
            result.action = ProxyAction.DENY
            result.blocked_reason = f"Collection '{request.collection_name}' policy is inactive."
            result.latency_ms = (time.perf_counter() - start) * 1000
            return result

        # Step 2: Default action check
        if policy.default_action == ProxyAction.DENY:
            # Only allowed if operation is in the allowed list
            if request.operation not in policy.allowed_operations:
                self._stats["blocked"] += 1
                result.allowed = False
                result.action = ProxyAction.DENY
                result.blocked_reason = (
                    f"Operation '{request.operation.value}' not allowed on "
                    f"collection '{request.collection_name}'. "
                    f"Allowed: {[op.value for op in policy.allowed_operations]}"
                )
                result.latency_ms = (time.perf_counter() - start) * 1000
                logger.warning(
                    "Operation denied: %s on %s tenant=%s",
                    request.operation.value, request.collection_name, request.tenant_id,
                )
                return result
        elif policy.default_action == ProxyAction.MONITOR:
            result.action = ProxyAction.MONITOR

        # Step 3: Namespace isolation injection (for retrieval queries)
        if request.operation == VectorOperation.QUERY:
            request = self._inject_namespace(request, policy)
            result.namespace_injected = True

            # Enforce max results cap on the request
            max_allowed = min(policy.max_results, 100)
            max_allowed = max(max_allowed, 1)
            if request.top_k > max_allowed:
                request.top_k = max_allowed
                result.results_capped = True
            result.enforced_top_k = request.top_k

        # Step 4: Forward to adapter (if registered)
        adapter = self._adapters.get(policy.provider)
        if adapter is not None:
            try:
                docs = adapter.execute(request)
                # Step 5: Trim response if excess documents
                max_allowed = min(policy.max_results, 100)
                max_allowed = max(max_allowed, 1)
                if len(docs) > max_allowed:
                    docs = docs[:max_allowed]
                    result.results_capped = True
                result.documents = docs
            except Exception as e:
                logger.error("Adapter error for %s: %s", policy.provider.value, e)
                result.allowed = False
                result.action = ProxyAction.DENY
                result.blocked_reason = f"Adapter error: {str(e)}"
                self._stats["blocked"] += 1
                result.latency_ms = (time.perf_counter() - start) * 1000
                return result
        else:
            result.enforced_top_k = request.top_k

        if policy.default_action == ProxyAction.MONITOR:
            self._stats["monitored"] += 1
        else:
            self._stats["allowed"] += 1

        result.allowed = True
        result.latency_ms = (time.perf_counter() - start) * 1000
        return result

    def _inject_namespace(self, request: ProxyRequest, policy: CollectionPolicy) -> ProxyRequest:
        """Inject mandatory tenant namespace filter into the query.

        This is non-bypassable — even if the caller provides their own
        filter, the tenant namespace is forced as an additional constraint.
        """
        ns_field = policy.namespace_field
        tenant_id = request.tenant_id

        if not tenant_id:
            logger.warning(
                "Empty tenant_id for namespace injection on %s",
                request.collection_name,
            )

        # Force the namespace filter — overwrite any existing value
        request.filters[ns_field] = tenant_id

        logger.debug(
            "Namespace injected: %s=%s on collection %s",
            ns_field, tenant_id, request.collection_name,
        )
        return request


# Singleton
_proxy: VectorDBProxy | None = None


def get_vectordb_proxy() -> VectorDBProxy:
    global _proxy
    if _proxy is None:
        _proxy = VectorDBProxy()
    return _proxy


def reset_vectordb_proxy() -> None:
    global _proxy
    _proxy = None
