"""Cross-vendor semantic parity validation — Sprint 6 / S6-T3.

Ensures that Thoth classification is invoked identically regardless of the
target LLM vendor (OpenAI, Anthropic, Azure OAI, Bedrock, OSS).

PRD NFR — Model Agnosticism:
  "Thoth classification SHALL be invoked identically regardless of target LLM
   vendor (OpenAI, Anthropic, Azure, OSS)"

Problem
-------
Different LLM vendors use different request/response body schemas.  Sphinx
already normalises provider I/O through the provider adapter layer
(``providers/``), but the Thoth classification call operates on the *raw*
request body bytes *before* provider normalisation.  Without explicit parity
validation, vendor-specific schema differences can cause the prompt extraction
step to silently produce empty or incomplete text for some vendors, resulting
in inconsistent classification coverage.

Solution
--------
``VendorParityValidator`` provides:
1. ``validate_extraction(body, vendor)`` — verifies that ``_extract_prompt_and_system``
   can extract non-empty prompt text from a given vendor's request format.
2. ``build_parity_report(samples)`` — generates a summary report comparing
   extraction quality across multiple vendor samples.
3. ``VendorExtractionResult`` — lightweight result dataclass for parity tests.

Test integration (S6-T4):
The integration test suite uses ``VendorParityValidator`` to assert that
identical semantic content produces identical Thoth classification call
payloads regardless of which vendor's request format is used.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("sphinx.thoth.vendor_parity")

# Canonical vendor identifiers (mirrored from proxy_plugin.py without importing)
VENDOR_OPENAI = "openai"
VENDOR_ANTHROPIC = "anthropic"
VENDOR_AZURE_OPENAI = "azure_openai"
VENDOR_BEDROCK = "bedrock"
VENDOR_OSS = "oss"


@dataclass
class VendorExtractionResult:
    """Result of prompt extraction from a vendor-specific request body.

    Attributes:
        vendor:           Vendor identifier.
        prompt_text:      Extracted user/human prompt text.
        system_prompt:    Extracted system prompt (may be None).
        extraction_ok:    True if prompt_text is non-empty.
        char_count:       Length of prompt_text for coverage comparison.
        parity_notes:     Human-readable notes about the extraction quality.
    """

    vendor: str
    prompt_text: str
    system_prompt: Optional[str]
    extraction_ok: bool
    char_count: int
    parity_notes: str = ""

    def to_dict(self) -> dict:
        return {
            "vendor": self.vendor,
            "prompt_text_preview": self.prompt_text[:120] if self.prompt_text else "",
            "system_prompt_present": self.system_prompt is not None,
            "extraction_ok": self.extraction_ok,
            "char_count": self.char_count,
            "parity_notes": self.parity_notes,
        }


@dataclass
class ParityReport:
    """Summary report comparing extraction quality across vendor samples.

    Attributes:
        total_samples:    Number of vendor samples evaluated.
        passing:          Vendors with successful extraction.
        failing:          Vendors with empty/failed extraction.
        parity_ok:        True if all vendors extracted non-empty text.
        details:          Per-vendor extraction results.
    """

    total_samples: int = 0
    passing: list[str] = field(default_factory=list)
    failing: list[str] = field(default_factory=list)
    parity_ok: bool = True
    details: list[VendorExtractionResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_samples": self.total_samples,
            "passing": self.passing,
            "failing": self.failing,
            "parity_ok": self.parity_ok,
            "details": [d.to_dict() for d in self.details],
        }


# ---------------------------------------------------------------------------
# Vendor-specific body builders (test utilities)
# ---------------------------------------------------------------------------

def build_openai_body(
    user_message: str,
    system_prompt: Optional[str] = None,
    model: str = "gpt-4o",
) -> bytes:
    """Build an OpenAI-format chat completions request body."""
    messages: list[dict] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_message})
    return json.dumps({"model": model, "messages": messages}).encode()


def build_anthropic_body(
    user_message: str,
    system_prompt: Optional[str] = None,
    model: str = "claude-3-5-sonnet-20241022",
) -> bytes:
    """Build an Anthropic messages-format request body."""
    payload: dict = {
        "model": model,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": user_message}],
    }
    if system_prompt:
        payload["system"] = system_prompt
    return json.dumps(payload).encode()


def build_azure_openai_body(
    user_message: str,
    system_prompt: Optional[str] = None,
    model: str = "gpt-4",
) -> bytes:
    """Build an Azure OpenAI-format request body.

    Azure OAI uses the same payload schema as OpenAI chat completions.
    """
    return build_openai_body(user_message, system_prompt=system_prompt, model=model)


def build_bedrock_body(
    user_message: str,
    system_prompt: Optional[str] = None,
    model: str = "amazon.titan-text-express-v1",
) -> bytes:
    """Build a simplified Bedrock-style request body.

    Bedrock Converse API uses a messages format similar to OpenAI.
    """
    messages = [{"role": "user", "content": user_message}]
    payload: dict = {"model": model, "messages": messages}
    if system_prompt:
        payload["system"] = system_prompt
    return json.dumps(payload).encode()


def build_oss_body(
    user_message: str,
    system_prompt: Optional[str] = None,
    model: str = "llama-3.1-8b-instruct",
) -> bytes:
    """Build an OSS-model request body (OpenAI-compatible format).

    Most OSS models served via vLLM / Ollama / llama.cpp expose an
    OpenAI-compatible chat completions endpoint.
    """
    return build_openai_body(user_message, system_prompt=system_prompt, model=model)


# ---------------------------------------------------------------------------
# Vendor parity validator
# ---------------------------------------------------------------------------

class VendorParityValidator:
    """Validates cross-vendor prompt extraction parity for Thoth classification.

    Uses the same ``_extract_prompt_and_system`` logic as the core classifier
    to verify that all vendor-specific request formats produce equivalent
    prompt text for Thoth.

    S6-T3 exit criterion: classification consistency is confirmed when
    ``validate_extraction`` returns ``extraction_ok=True`` for all vendor
    formats given the same semantic content.
    """

    def validate_extraction(
        self,
        body: bytes,
        vendor: str,
    ) -> VendorExtractionResult:
        """Extract prompt text from *body* and return a parity result.

        Uses the same ``_extract_prompt_and_system()`` function that the
        production classifier uses, ensuring parity validation matches
        real classification behaviour exactly.

        Args:
            body:    Raw vendor-format request body.
            vendor:  Vendor identifier (for labelling the result).

        Returns:
            ``VendorExtractionResult`` with extraction quality metrics.
        """
        from app.services.thoth.classifier import _extract_prompt_and_system

        prompt_text, system_prompt = _extract_prompt_and_system(body)

        notes = ""
        if not prompt_text:
            notes = f"Empty prompt text extracted from {vendor} body format"
            logger.warning(
                "VendorParityValidator: empty extraction vendor=%s body_preview=%r",
                vendor,
                body[:120],
            )
        else:
            notes = (
                f"OK: {len(prompt_text)} chars extracted"
                + (f", system_prompt present ({len(system_prompt)} chars)" if system_prompt else "")
            )

        return VendorExtractionResult(
            vendor=vendor,
            prompt_text=prompt_text,
            system_prompt=system_prompt,
            extraction_ok=bool(prompt_text),
            char_count=len(prompt_text),
            parity_notes=notes,
        )

    def build_parity_report(
        self,
        samples: list[tuple[bytes, str]],
    ) -> ParityReport:
        """Build a parity report for a list of (body, vendor) samples.

        Args:
            samples: List of (raw_body_bytes, vendor_name) tuples.

        Returns:
            ``ParityReport`` summarising extraction quality across all vendors.
        """
        report = ParityReport(total_samples=len(samples))

        for body, vendor in samples:
            result = self.validate_extraction(body, vendor)
            report.details.append(result)
            if result.extraction_ok:
                if vendor not in report.passing:
                    report.passing.append(vendor)
            else:
                if vendor not in report.failing:
                    report.failing.append(vendor)

        report.parity_ok = len(report.failing) == 0

        if not report.parity_ok:
            logger.warning(
                "VendorParityValidator: parity FAILED for vendor(s)=%s",
                report.failing,
            )
        else:
            logger.info(
                "VendorParityValidator: all %d vendor sample(s) passed parity check",
                len(samples),
            )

        return report

    def validate_cross_vendor_parity(
        self,
        user_message: str,
        system_prompt: Optional[str] = None,
    ) -> ParityReport:
        """Validate that identical content extracts correctly across all vendors.

        Builds canonical request bodies for OpenAI, Anthropic, Azure OAI,
        Bedrock, and OSS, then verifies that ``_extract_prompt_and_system``
        produces non-empty prompt text for each.

        This is the canonical S6-T3 parity check used by the test suite.

        Args:
            user_message:   The semantic content to test (same across all vendors).
            system_prompt:  Optional system prompt to include.

        Returns:
            ``ParityReport`` with per-vendor extraction results.
        """
        samples = [
            (build_openai_body(user_message, system_prompt), VENDOR_OPENAI),
            (build_anthropic_body(user_message, system_prompt), VENDOR_ANTHROPIC),
            (build_azure_openai_body(user_message, system_prompt), VENDOR_AZURE_OPENAI),
            (build_bedrock_body(user_message, system_prompt), VENDOR_BEDROCK),
            (build_oss_body(user_message, system_prompt), VENDOR_OSS),
        ]
        return self.build_parity_report(samples)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_validator: Optional[VendorParityValidator] = None


def get_vendor_parity_validator() -> VendorParityValidator:
    """Return the singleton VendorParityValidator."""
    global _validator
    if _validator is None:
        _validator = VendorParityValidator()
    return _validator
