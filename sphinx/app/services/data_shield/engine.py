"""Data Shield Engine — orchestrates PII/PHI/credential scanning, redaction, and vault.

Supports running PII scan concurrently with the threat detection engine
via asyncio for combined latency < 30ms overhead.
"""

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

from app.services.data_shield.pii_recognizer import PIIRecognizer, PIIEntity, PIIType
from app.services.data_shield.phi_recognizer import PHIRecognizer
from app.services.data_shield.credential_scanner import CredentialScanner
from app.services.data_shield.redaction_engine import RedactionEngine, RedactionResult
from app.services.data_shield.vault import RedactionVault

logger = logging.getLogger("sphinx.data_shield.engine")

# Singleton engine instance
_engine: Optional["DataShieldEngine"] = None

# Thread pool for parallel scanning
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="data-shield")


@dataclass
class DataShieldResult:
    """Combined result from all Data Shield scanners."""
    entities: list[PIIEntity]
    redaction: RedactionResult | None
    scan_time_ms: float
    pii_count: int = 0
    phi_count: int = 0
    credential_count: int = 0

    def to_dict(self) -> dict:
        result = {
            "total_entities": len(self.entities),
            "pii_count": self.pii_count,
            "phi_count": self.phi_count,
            "credential_count": self.credential_count,
            "scan_time_ms": round(self.scan_time_ms, 2),
            "entity_types": list({e.entity_type.value for e in self.entities}),
        }
        if self.redaction:
            result["redaction_count"] = self.redaction.redaction_count
        return result


# PHI entity type values for classification
_PHI_TYPES = {"PATIENT_ID", "DIAGNOSIS_CODE", "MEDICATION", "PROVIDER_NAME", "MRN"}
# Credential entity type values
_CRED_TYPES = {
    "OPENAI_API_KEY", "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "GITHUB_TOKEN",
    "GITHUB_PAT", "SLACK_TOKEN", "STRIPE_KEY", "GOOGLE_API_KEY",
    "ANTHROPIC_API_KEY", "AZURE_KEY", "GENERIC_API_KEY", "CREDIT_CARD",
    "PRIVATE_KEY", "CONNECTION_STRING", "JWT_TOKEN", "BEARER_TOKEN",
}


class DataShieldEngine:
    """Main Data Shield engine — combines PII, PHI, and credential scanning with redaction."""

    def __init__(
        self,
        enable_vault: bool = True,
        vault_ttl: int = 300,
        custom_placeholders: dict[str, str] | None = None,
    ):
        self._pii = PIIRecognizer()
        self._phi = PHIRecognizer()
        self._cred = CredentialScanner()
        self._redactor = RedactionEngine(custom_placeholders=custom_placeholders)
        self._vault = RedactionVault(default_ttl=vault_ttl) if enable_vault else None

    @property
    def vault(self) -> RedactionVault | None:
        return self._vault

    def scan(self, text: str) -> list[PIIEntity]:
        """Scan text with all recognizers and return combined entity list."""
        entities: list[PIIEntity] = []
        entities.extend(self._pii.scan(text))
        entities.extend(self._phi.scan(text))
        entities.extend(self._cred.scan(text))
        # Deduplicate overlapping entities
        return self._deduplicate(entities)

    def scan_and_redact(
        self,
        text: str,
        use_vault: bool = False,
        tenant_id: str = "",
        session_id: str = "",
    ) -> DataShieldResult:
        """Scan text, detect entities, and redact them.

        If use_vault=True, uses reversible vault tokens instead of static placeholders.
        """
        start = time.perf_counter()

        entities = self.scan(text)

        if use_vault and self._vault and tenant_id and session_id:
            redacted_text = self._vault.redact_with_tokens(
                text, entities, tenant_id, session_id,
            )
            redaction = RedactionResult(
                original_text=text,
                redacted_text=redacted_text,
                entities_redacted=entities,
                redaction_count=len(entities),
            )
        else:
            redaction = self._redactor.redact(text, entities)

        scan_time_ms = (time.perf_counter() - start) * 1000

        pii_count, phi_count, cred_count = self._classify_counts(entities)

        return DataShieldResult(
            entities=entities,
            redaction=redaction,
            scan_time_ms=scan_time_ms,
            pii_count=pii_count,
            phi_count=phi_count,
            credential_count=cred_count,
        )

    def scan_request_body(
        self,
        body: bytes,
        use_vault: bool = False,
        tenant_id: str = "",
        session_id: str = "",
    ) -> tuple[bytes, DataShieldResult | None]:
        """Scan a JSON request body for PII/PHI/credentials and return redacted body.

        Returns (possibly_redacted_body, result_or_none).
        """
        if not body:
            return body, None

        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            return body, None

        text = self._extract_text(payload)
        if not text:
            return body, None

        result = self.scan_and_redact(text, use_vault, tenant_id, session_id)

        if result.redaction and result.redaction.redaction_count > 0:
            redacted_body = self._apply_redaction_to_body(
                payload, text, result.redaction.redacted_text,
            )
            return json.dumps(redacted_body).encode(), result

        return body, result

    async def scan_parallel(self, text: str) -> list[PIIEntity]:
        """Run all three scanners in parallel using asyncio + thread pool."""
        loop = asyncio.get_event_loop()

        pii_future = loop.run_in_executor(_executor, self._pii.scan, text)
        phi_future = loop.run_in_executor(_executor, self._phi.scan, text)
        cred_future = loop.run_in_executor(_executor, self._cred.scan, text)

        pii_entities, phi_entities, cred_entities = await asyncio.gather(
            pii_future, phi_future, cred_future,
        )

        entities = list(pii_entities) + list(phi_entities) + list(cred_entities)
        return self._deduplicate(entities)

    async def scan_and_redact_parallel(
        self,
        text: str,
        use_vault: bool = False,
        tenant_id: str = "",
        session_id: str = "",
    ) -> DataShieldResult:
        """Parallel version of scan_and_redact."""
        start = time.perf_counter()

        entities = await self.scan_parallel(text)

        if use_vault and self._vault and tenant_id and session_id:
            redacted_text = self._vault.redact_with_tokens(
                text, entities, tenant_id, session_id,
            )
            redaction = RedactionResult(
                original_text=text,
                redacted_text=redacted_text,
                entities_redacted=entities,
                redaction_count=len(entities),
            )
        else:
            redaction = self._redactor.redact(text, entities)

        scan_time_ms = (time.perf_counter() - start) * 1000

        pii_count, phi_count, cred_count = self._classify_counts(entities)

        return DataShieldResult(
            entities=entities,
            redaction=redaction,
            scan_time_ms=scan_time_ms,
            pii_count=pii_count,
            phi_count=phi_count,
            credential_count=cred_count,
        )

    def detokenize_response(
        self,
        response_text: str,
        tenant_id: str,
        session_id: str,
    ) -> str:
        """De-tokenize vault tokens in a response back to original values."""
        if not self._vault:
            return response_text
        return self._vault.detokenize(response_text, tenant_id, session_id)

    def _classify_counts(self, entities: list[PIIEntity]) -> tuple[int, int, int]:
        """Classify entities into PII, PHI, and credential counts."""
        pii = phi = cred = 0
        for e in entities:
            tv = e.entity_type.value if isinstance(e.entity_type, PIIType) else str(e.entity_type)
            if tv in _PHI_TYPES:
                phi += 1
            elif tv in _CRED_TYPES:
                cred += 1
            else:
                pii += 1
        return pii, phi, cred

    def _extract_text(self, payload: dict) -> str:
        """Extract prompt text from various LLM API request formats."""
        parts: list[str] = []

        if "system" in payload:
            system = payload["system"]
            if isinstance(system, str):
                parts.append(system)
            elif isinstance(system, list):
                for item in system:
                    if isinstance(item, dict) and "text" in item:
                        parts.append(item["text"])

        if "messages" in payload:
            for msg in payload["messages"]:
                content = msg.get("content", "")
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and "text" in item:
                            parts.append(item["text"])

        if "prompt" in payload:
            parts.append(str(payload["prompt"]))

        return "\n".join(parts)

    def _apply_redaction_to_body(
        self,
        payload: dict,
        original_text: str,
        redacted_text: str,
    ) -> dict:
        """Apply redacted text back into the request payload."""
        # Build a mapping of original -> redacted segments per message
        if "messages" in payload:
            for msg in payload["messages"]:
                content = msg.get("content", "")
                if isinstance(content, str) and content in original_text:
                    # Find the redacted version of this content
                    msg["content"] = self._redact_segment(content, original_text, redacted_text)
        if "prompt" in payload:
            prompt = str(payload["prompt"])
            if prompt in original_text:
                payload["prompt"] = self._redact_segment(prompt, original_text, redacted_text)
        if "system" in payload and isinstance(payload["system"], str):
            system = payload["system"]
            if system in original_text:
                payload["system"] = self._redact_segment(system, original_text, redacted_text)

        return payload

    def _redact_segment(self, segment: str, full_original: str, full_redacted: str) -> str:
        """Extract the redacted version of a specific segment from the full redacted text."""
        start_idx = full_original.find(segment)
        if start_idx == -1:
            return segment

        # Calculate the offset difference from redactions before this segment
        # Simple approach: re-scan and redact just this segment
        entities = self.scan(segment)
        if entities:
            result = self._redactor.redact(segment, entities)
            return result.redacted_text
        return segment

    def _deduplicate(self, entities: list[PIIEntity]) -> list[PIIEntity]:
        """Remove overlapping entities, keeping higher confidence ones."""
        if not entities:
            return entities
        entities.sort(key=lambda e: (e.start, -e.confidence))
        result: list[PIIEntity] = []
        for entity in entities:
            if result and entity.start < result[-1].end:
                if entity.confidence > result[-1].confidence:
                    result[-1] = entity
            else:
                result.append(entity)
        return result

    def get_stats(self) -> dict:
        """Return engine statistics."""
        return {
            "vault_enabled": self._vault is not None,
            "vault_size": self._vault.size if self._vault else 0,
        }


def get_data_shield_engine() -> DataShieldEngine:
    """Get or create the singleton Data Shield engine."""
    global _engine
    if _engine is None:
        _engine = DataShieldEngine()
    return _engine


def reset_data_shield_engine() -> None:
    """Reset the singleton engine (for testing)."""
    global _engine
    _engine = None
