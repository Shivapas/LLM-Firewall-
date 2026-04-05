"""Namespace Isolation Injector — enforces tenant namespace on every retrieval query.

Non-bypassable: the authenticated tenant's namespace identifier is injected as a
mandatory filter on every query. Even if the caller provides conflicting filters,
the tenant namespace is always forced.
"""

import logging
from dataclasses import dataclass
from typing import Any

from app.services.vectordb.proxy import (
    CollectionPolicy,
    ProxyRequest,
    VectorDBProvider,
    VectorOperation,
)

logger = logging.getLogger("sphinx.vectordb.namespace")


@dataclass
class NamespaceInjectionResult:
    """Result of namespace injection on a query."""
    injected: bool = False
    namespace_field: str = ""
    namespace_value: str = ""
    original_filters: dict[str, Any] | None = None
    enforced_filters: dict[str, Any] | None = None

    def to_dict(self) -> dict:
        return {
            "injected": self.injected,
            "namespace_field": self.namespace_field,
            "namespace_value": self.namespace_value,
            "had_conflicting_filter": (
                self.original_filters is not None
                and self.namespace_field in (self.original_filters or {})
                and self.original_filters.get(self.namespace_field) != self.namespace_value
            ),
        }


class NamespaceIsolator:
    """Injects tenant namespace filter into every retrieval query.

    This operates as the core security boundary for multi-tenant RAG:
    - Every query MUST have the authenticated tenant's namespace
    - Existing filters on the namespace field are OVERWRITTEN (non-bypassable)
    - Supports ChromaDB where-filter, Pinecone metadata-filter, and Milvus expression
    """

    def inject(
        self,
        request: ProxyRequest,
        policy: CollectionPolicy,
    ) -> NamespaceInjectionResult:
        """Inject namespace filter into the request.

        Returns the injection result with details about what was changed.
        The request object is modified in-place.
        """
        if request.operation != VectorOperation.QUERY:
            return NamespaceInjectionResult(injected=False)

        ns_field = policy.namespace_field
        tenant_id = request.tenant_id
        original_filters = dict(request.filters) if request.filters else {}

        if not tenant_id:
            logger.error(
                "Cannot inject namespace: empty tenant_id for collection %s",
                request.collection_name,
            )
            return NamespaceInjectionResult(
                injected=False,
                namespace_field=ns_field,
                namespace_value="",
                original_filters=original_filters,
            )

        # Check for conflict (caller trying to set different namespace)
        if ns_field in request.filters and request.filters[ns_field] != tenant_id:
            logger.warning(
                "Namespace conflict detected: caller set %s=%s but authenticated tenant is %s. "
                "Overwriting with authenticated tenant namespace.",
                ns_field, request.filters[ns_field], tenant_id,
            )

        # Force inject — non-bypassable
        request.filters[ns_field] = tenant_id

        result = NamespaceInjectionResult(
            injected=True,
            namespace_field=ns_field,
            namespace_value=tenant_id,
            original_filters=original_filters,
            enforced_filters=dict(request.filters),
        )

        logger.info(
            "Namespace injected: %s=%s on %s (provider=%s)",
            ns_field, tenant_id, request.collection_name, policy.provider.value,
        )
        return result

    def validate_response_namespace(
        self,
        documents: list[dict],
        policy: CollectionPolicy,
        tenant_id: str,
    ) -> list[dict]:
        """Post-retrieval validation: strip any documents that leaked through
        without the correct namespace.

        This is a defense-in-depth measure — namespace injection should prevent
        cross-tenant docs, but this validates the response as well.
        """
        ns_field = policy.namespace_field
        valid_docs = []
        stripped = 0

        for doc in documents:
            metadata = doc.get("metadata", {})
            doc_tenant = metadata.get(ns_field, "")
            if doc_tenant == tenant_id or doc_tenant == "":
                valid_docs.append(doc)
            else:
                stripped += 1
                logger.warning(
                    "Post-retrieval namespace violation: doc %s has %s=%s but tenant is %s. Stripped.",
                    doc.get("id", "?"), ns_field, doc_tenant, tenant_id,
                )

        if stripped > 0:
            logger.error(
                "SECURITY: %d cross-tenant documents stripped from response "
                "for collection %s tenant=%s",
                stripped, policy.collection_name, tenant_id,
            )

        return valid_docs


# Singleton
_isolator: NamespaceIsolator | None = None


def get_namespace_isolator() -> NamespaceIsolator:
    global _isolator
    if _isolator is None:
        _isolator = NamespaceIsolator()
    return _isolator


def reset_namespace_isolator() -> None:
    global _isolator
    _isolator = None
