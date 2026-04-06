"""Milvus Full Integration — gRPC proxy support, metadata filter injection,
and partition-based namespace isolation.

Sprint 10: Vector DB Firewall Hardening & Observability.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from app.services.vectordb.proxy import (
    CollectionPolicy,
    ProxyRequest,
    VectorDBProvider,
    VectorOperation,
)

logger = logging.getLogger("sphinx.vectordb.milvus")


# ── Milvus Partition-Based Namespace Isolation ─────────────────────────


@dataclass
class MilvusPartitionConfig:
    """Configuration for partition-based namespace isolation in Milvus."""
    use_partitions: bool = True
    partition_prefix: str = "tenant_"
    auto_create_partitions: bool = True
    partition_key_field: str = "tenant_id"


@dataclass
class MilvusProxyConfig:
    """Configuration for the Milvus gRPC proxy."""
    host: str = "localhost"
    port: int = 19530
    grpc_port: int = 19530
    use_grpc: bool = True
    timeout_ms: int = 10000
    max_retry: int = 3
    secure: bool = False
    token: str = ""
    db_name: str = "default"


@dataclass
class MilvusFilterInjection:
    """Result of metadata filter injection for Milvus queries."""
    original_expr: str = ""
    injected_expr: str = ""
    partition_names: list[str] = field(default_factory=list)
    namespace_field: str = ""
    namespace_value: str = ""
    used_partition_isolation: bool = False

    def to_dict(self) -> dict:
        return {
            "original_expr": self.original_expr,
            "injected_expr": self.injected_expr,
            "partition_names": self.partition_names,
            "namespace_field": self.namespace_field,
            "namespace_value": self.namespace_value,
            "used_partition_isolation": self.used_partition_isolation,
        }


class MilvusGRPCProxy:
    """Full Milvus proxy with gRPC support, metadata filter injection,
    and partition-based namespace isolation.

    Features:
    - gRPC proxy support via pymilvus MilvusClient
    - Metadata filter injection (boolean expression rewriting)
    - Partition-based namespace isolation (partition per tenant)
    - Search parameter enforcement
    - Collection schema validation
    """

    def __init__(
        self,
        config: Optional[MilvusProxyConfig] = None,
        partition_config: Optional[MilvusPartitionConfig] = None,
        connection: Any = None,
    ):
        self._config = config or MilvusProxyConfig()
        self._partition_config = partition_config or MilvusPartitionConfig()
        self._connection = connection
        self._partition_cache: dict[str, set[str]] = {}
        self._stats = {
            "total_queries": 0,
            "filter_injections": 0,
            "partition_isolations": 0,
            "errors": 0,
        }

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    def set_connection(self, connection: Any) -> None:
        """Set or replace the Milvus connection."""
        self._connection = connection

    def inject_metadata_filter(
        self,
        request: ProxyRequest,
        policy: CollectionPolicy,
    ) -> MilvusFilterInjection:
        """Inject mandatory tenant namespace filter into Milvus boolean expression.

        Milvus uses boolean expressions for filtering. This method:
        1. Builds the tenant namespace expression
        2. Injects it as an AND clause (non-bypassable)
        3. Optionally restricts to tenant-specific partition

        Returns the injection result with original and injected expressions.
        """
        ns_field = policy.namespace_field
        tenant_id = request.tenant_id
        result = MilvusFilterInjection(
            namespace_field=ns_field,
            namespace_value=tenant_id,
        )

        # Build the tenant namespace expression
        tenant_expr = f'{ns_field} == "{tenant_id}"'

        # Get original expression from request filters
        original_expr = self._build_milvus_expr(request.filters)
        result.original_expr = original_expr

        # Inject the namespace filter — always AND with tenant expression
        if original_expr:
            # Remove any existing namespace filter to prevent bypass
            cleaned_expr = self._remove_field_from_expr(original_expr, ns_field)
            if cleaned_expr:
                result.injected_expr = f"({tenant_expr}) and ({cleaned_expr})"
            else:
                result.injected_expr = tenant_expr
        else:
            result.injected_expr = tenant_expr

        self._stats["filter_injections"] += 1

        # Partition-based isolation
        if self._partition_config.use_partitions and tenant_id:
            partition_name = f"{self._partition_config.partition_prefix}{tenant_id}"
            result.partition_names = [partition_name]
            result.used_partition_isolation = True
            self._stats["partition_isolations"] += 1

        return result

    def execute(self, request: ProxyRequest, policy: CollectionPolicy) -> list[dict[str, Any]]:
        """Execute a Milvus operation through the gRPC proxy with full enforcement.

        Enforcement pipeline:
        1. Inject metadata filter (for queries)
        2. Apply partition isolation (for queries)
        3. Forward to Milvus via gRPC
        4. Normalize results
        """
        if self._connection is None:
            logger.warning("Milvus connection not configured; returning empty results")
            return []

        self._stats["total_queries"] += 1

        try:
            if request.operation == VectorOperation.QUERY:
                return self._execute_query(request, policy)
            elif request.operation == VectorOperation.INSERT:
                return self._execute_insert(request, policy)
            elif request.operation == VectorOperation.DELETE:
                return self._execute_delete(request, policy)
            else:
                logger.warning("Unsupported operation: %s", request.operation)
                return []
        except Exception as e:
            self._stats["errors"] += 1
            logger.error("Milvus operation error: %s", e)
            raise

    def _execute_query(
        self, request: ProxyRequest, policy: CollectionPolicy
    ) -> list[dict[str, Any]]:
        """Execute a search query with metadata filter injection and partition isolation."""
        # Step 1: Inject metadata filter
        injection = self.inject_metadata_filter(request, policy)

        # Step 2: Build search parameters
        search_params = {
            "metric_type": request.metadata.get("metric_type", "L2"),
            "params": request.metadata.get("search_params", {"nprobe": 10}),
        }

        kwargs: dict[str, Any] = {
            "collection_name": request.collection_name,
            "data": [request.query_vector] if request.query_vector else [],
            "limit": request.top_k,
            "output_fields": request.metadata.get("output_fields", ["*"]),
            "search_params": search_params,
        }

        # Apply injected filter expression
        if injection.injected_expr:
            kwargs["filter"] = injection.injected_expr

        # Apply partition isolation
        if injection.used_partition_isolation and injection.partition_names:
            kwargs["partition_names"] = injection.partition_names

        # Auto-create partition if needed
        if (
            self._partition_config.auto_create_partitions
            and injection.used_partition_isolation
            and injection.partition_names
        ):
            self._ensure_partition_exists(
                request.collection_name, injection.partition_names[0]
            )

        logger.debug(
            "Milvus search: collection=%s filter=%s partitions=%s",
            request.collection_name,
            injection.injected_expr,
            injection.partition_names,
        )

        raw = self._connection.search(**kwargs)
        return self._normalize_results(raw)

    def _execute_insert(
        self, request: ProxyRequest, policy: CollectionPolicy
    ) -> list[dict[str, Any]]:
        """Execute an insert with tenant namespace enforcement."""
        if not request.documents:
            return []

        # Inject tenant_id into every document's metadata
        ns_field = policy.namespace_field
        tenant_id = request.tenant_id
        for doc in request.documents:
            doc[ns_field] = tenant_id

        kwargs: dict[str, Any] = {
            "collection_name": request.collection_name,
            "data": request.documents,
        }

        # Insert into tenant partition if partition isolation is enabled
        if self._partition_config.use_partitions and tenant_id:
            partition_name = f"{self._partition_config.partition_prefix}{tenant_id}"
            self._ensure_partition_exists(request.collection_name, partition_name)
            kwargs["partition_name"] = partition_name

        self._connection.insert(**kwargs)
        return []

    def _execute_delete(
        self, request: ProxyRequest, policy: CollectionPolicy
    ) -> list[dict[str, Any]]:
        """Execute a delete with tenant namespace enforcement."""
        # Build delete expression scoped to tenant
        ns_field = policy.namespace_field
        tenant_id = request.tenant_id
        tenant_expr = f'{ns_field} == "{tenant_id}"'

        if request.document_ids:
            ids_str = ", ".join(f'"{did}"' for did in request.document_ids)
            expr = f'({tenant_expr}) and (id in [{ids_str}])'
        else:
            expr = tenant_expr

        kwargs: dict[str, Any] = {
            "collection_name": request.collection_name,
            "filter": expr,
        }

        # Scope to tenant partition
        if self._partition_config.use_partitions and tenant_id:
            partition_name = f"{self._partition_config.partition_prefix}{tenant_id}"
            kwargs["partition_name"] = partition_name

        self._connection.delete(**kwargs)
        return []

    def _ensure_partition_exists(self, collection_name: str, partition_name: str) -> None:
        """Create a partition if it doesn't already exist (cached check)."""
        cache_key = f"{collection_name}:{partition_name}"
        if cache_key in self._partition_cache.get(collection_name, set()):
            return

        try:
            if hasattr(self._connection, "has_partition"):
                if not self._connection.has_partition(collection_name, partition_name):
                    self._connection.create_partition(collection_name, partition_name)
                    logger.info(
                        "Created Milvus partition: %s/%s",
                        collection_name, partition_name,
                    )
            # Cache the result
            if collection_name not in self._partition_cache:
                self._partition_cache[collection_name] = set()
            self._partition_cache[collection_name].add(cache_key)
        except Exception as e:
            logger.warning(
                "Failed to ensure partition %s/%s: %s",
                collection_name, partition_name, e,
            )

    def _build_milvus_expr(self, filters: dict) -> str:
        """Build Milvus boolean expression from flat filters."""
        parts = []
        for key, value in filters.items():
            if isinstance(value, str):
                parts.append(f'{key} == "{value}"')
            elif isinstance(value, bool):
                parts.append(f"{key} == {str(value).lower()}")
            elif isinstance(value, (int, float)):
                parts.append(f"{key} == {value}")
            elif isinstance(value, list):
                formatted = ", ".join(
                    f'"{v}"' if isinstance(v, str) else str(v) for v in value
                )
                parts.append(f"{key} in [{formatted}]")
        return " and ".join(parts) if parts else ""

    def _remove_field_from_expr(self, expr: str, field_name: str) -> str:
        """Remove references to a specific field from a boolean expression.

        Simple heuristic: split on ' and ' and remove parts containing the field.
        """
        parts = expr.split(" and ")
        cleaned = [p.strip() for p in parts if field_name not in p]
        return " and ".join(cleaned) if cleaned else ""

    def _normalize_results(self, raw: Any) -> list[dict[str, Any]]:
        """Normalize Milvus search results into standard document format."""
        docs = []
        if not raw:
            return docs

        hits = raw[0] if raw else []
        for hit in hits:
            entity = getattr(hit, "entity", {})
            doc = {
                "id": str(getattr(hit, "id", "")),
                "content": entity.get("content", "") if isinstance(entity, dict) else "",
                "metadata": dict(entity) if isinstance(entity, dict) else {},
                "score": getattr(hit, "distance", 0.0),
            }
            docs.append(doc)
        return docs

    def list_partitions(self, collection_name: str) -> list[str]:
        """List all partitions for a collection."""
        if self._connection is None:
            return []
        try:
            if hasattr(self._connection, "list_partitions"):
                return self._connection.list_partitions(collection_name)
        except Exception as e:
            logger.error("Failed to list partitions for %s: %s", collection_name, e)
        return []

    def health_check(self) -> dict[str, Any]:
        """Check Milvus connection health."""
        result = {
            "connected": False,
            "host": self._config.host,
            "port": self._config.port,
            "grpc": self._config.use_grpc,
        }
        if self._connection is None:
            return result
        try:
            if hasattr(self._connection, "list_collections"):
                collections = self._connection.list_collections()
                result["connected"] = True
                result["collection_count"] = len(collections)
        except Exception as e:
            result["error"] = str(e)
        return result


# ── Singleton ──────────────────────────────────────────────────────────

_milvus_proxy: Optional[MilvusGRPCProxy] = None


def get_milvus_proxy() -> MilvusGRPCProxy:
    global _milvus_proxy
    if _milvus_proxy is None:
        _milvus_proxy = MilvusGRPCProxy()
    return _milvus_proxy


def reset_milvus_proxy() -> None:
    global _milvus_proxy
    _milvus_proxy = None
