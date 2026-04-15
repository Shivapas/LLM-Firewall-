"""SP-331: Canary injection into system prompt preamble.

Injects an invisible canary comment (``<!-- SPHINX-{token} -->``) into the
system prompt at Sphinx session initialisation.  The canary is prepended
to the system prompt so it appears as an HTML/XML comment that the LLM
should not reproduce in benign responses.

Security invariants:
  - System prompt delivered to LLM MUST contain canary comment
  - LLM response to benign queries MUST NOT reproduce the canary
  - Canary format uses non-obvious base62 encoding (no readable label)
"""

from __future__ import annotations

import logging
from typing import Optional

from app.services.canary.generator import (
    CanaryToken,
    CanaryTokenGenerator,
    get_canary_generator,
)

logger = logging.getLogger("sphinx.canary.injector")

# Canary comment template — non-obvious format per threat model
_CANARY_TEMPLATE = "<!-- SPHINX-{token} -->"


def format_canary_comment(token: str) -> str:
    """Format a canary token as an HTML comment for system prompt injection."""
    return _CANARY_TEMPLATE.format(token=token)


class CanaryInjector:
    """Injects canary tokens into system prompts at session initialisation.

    SP-331 acceptance criteria:
      - System prompt delivered to LLM contains canary comment
      - LLM response to benign queries does not reproduce canary
    """

    def __init__(
        self,
        generator: Optional[CanaryTokenGenerator] = None,
        enabled: bool = True,
    ) -> None:
        self._generator = generator
        self._enabled = enabled
        self._total_injections = 0

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    @property
    def total_injections(self) -> int:
        return self._total_injections

    def _get_generator(self) -> CanaryTokenGenerator:
        if self._generator is None:
            self._generator = get_canary_generator()
        return self._generator

    def inject(
        self,
        system_prompt: str,
        session_id: str,
        ttl_seconds: Optional[float] = None,
    ) -> tuple[str, CanaryToken]:
        """Inject a canary token into the system prompt.

        Generates a new canary token for the session and prepends the
        canary comment to the system prompt.

        Args:
            system_prompt: Original system prompt text.
            session_id: Unique session identifier.
            ttl_seconds: Optional TTL override for the canary token.

        Returns:
            Tuple of (modified_system_prompt, canary_token).
        """
        if not self._enabled:
            # When disabled, return unmodified prompt with a dummy token
            gen = self._get_generator()
            canary = gen.generate(session_id, ttl_seconds=ttl_seconds)
            return system_prompt, canary

        gen = self._get_generator()
        canary = gen.generate(session_id, ttl_seconds=ttl_seconds)
        canary_comment = format_canary_comment(canary.token)

        # Prepend canary comment to system prompt
        modified_prompt = f"{canary_comment}\n{system_prompt}"

        self._total_injections += 1
        logger.debug(
            "Canary injected into system prompt for session=%s",
            session_id,
        )
        return modified_prompt, canary

    def get_canary_for_session(self, session_id: str) -> Optional[CanaryToken]:
        """Retrieve the active canary token for a session."""
        gen = self._get_generator()
        return gen.get_token_for_session(session_id)

    def remove_session(self, session_id: str) -> bool:
        """Remove canary token when session ends."""
        gen = self._get_generator()
        return gen.expire_session(session_id)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_injector: Optional[CanaryInjector] = None


def get_canary_injector(
    generator: Optional[CanaryTokenGenerator] = None,
    enabled: bool = True,
) -> CanaryInjector:
    """Get or create the singleton canary injector."""
    global _injector
    if _injector is None:
        _injector = CanaryInjector(generator=generator, enabled=enabled)
    return _injector


def reset_canary_injector() -> None:
    """Reset the singleton (for testing)."""
    global _injector
    _injector = None
