"""Thoth-specific in-memory circuit breaker.

Sprint 2 / S2-T2: Sustained error rate threshold disables Thoth API calls
and activates structural-only enforcement mode (FR-CFG-03).

States
------
closed    Normal operation; Thoth calls are made as usual.
open      Error threshold exceeded; all Thoth calls are bypassed immediately,
          returning a ``circuit_open`` fallback context.
half_open Recovery probe; exactly one call is allowed through to test whether
          Thoth has recovered. Success → closed; failure → reopen.

Transitions
-----------
closed   → open       consecutive_failures >= error_threshold
open     → half_open  recovery_timeout_s elapsed since opening
half_open → closed    probe succeeds
half_open → open      probe fails

Design notes
------------
- Purely in-memory: no DB, Redis, or I/O dependency. The Thoth circuit breaker
  must not itself depend on external systems — that would create a dependency
  chain that defeats its purpose.
- Thread-safe via a reentrant lock; async-safe because all state updates are
  synchronous (no awaited I/O inside the lock).
- Singleton lifecycle managed by ``initialize_thoth_circuit_breaker()`` /
  ``get_thoth_circuit_breaker()``. Called from ``app/main.py`` lifespan.
"""

from __future__ import annotations

import logging
import threading
import time
from enum import Enum
from typing import Optional

logger = logging.getLogger("sphinx.thoth.circuit_breaker")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class ThothCircuitBreaker:
    """In-memory circuit breaker for the Thoth classification service.

    Args:
        error_threshold:     Consecutive failures before the circuit opens.
        recovery_timeout_s:  Seconds in OPEN state before transitioning to
                             HALF_OPEN for a recovery probe.
    """

    def __init__(
        self,
        error_threshold: int = 5,
        recovery_timeout_s: float = 30.0,
    ) -> None:
        self._error_threshold = error_threshold
        self._recovery_timeout_s = recovery_timeout_s
        self._state = CircuitState.CLOSED
        self._failure_count: int = 0
        self._success_count: int = 0
        self._opened_at: Optional[float] = None  # monotonic timestamp
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._maybe_transition_to_half_open()
            return self._state

    def is_available(self) -> bool:
        """Return True if a Thoth API call should be attempted.

        Returns False only when the circuit is OPEN (and the recovery
        window has not yet elapsed). During HALF_OPEN, returns True to
        allow the single probe request through.
        """
        with self._lock:
            self._maybe_transition_to_half_open()
            return self._state in (CircuitState.CLOSED, CircuitState.HALF_OPEN)

    def record_success(self) -> None:
        """Record a successful Thoth response.

        CLOSED:    Reset consecutive failure counter.
        HALF_OPEN: Probe succeeded → close the circuit.
        OPEN:      Should not occur; safe to ignore.
        """
        with self._lock:
            self._success_count += 1
            if self._state == CircuitState.HALF_OPEN:
                logger.info(
                    "ThothCircuitBreaker: probe succeeded — circuit CLOSED "
                    "(total_successes=%d)",
                    self._success_count,
                )
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._opened_at = None
            elif self._state == CircuitState.CLOSED:
                # Reset consecutive run on any success
                self._failure_count = 0

    def record_failure(self) -> None:
        """Record a Thoth error or timeout.

        CLOSED:    Increment failure counter; open circuit when threshold reached.
        HALF_OPEN: Probe failed → reopen circuit.
        OPEN:      Already open; no state change needed.
        """
        with self._lock:
            self._failure_count += 1

            if self._state == CircuitState.HALF_OPEN:
                logger.warning(
                    "ThothCircuitBreaker: probe FAILED — circuit RE-OPENED "
                    "(total_failures=%d)",
                    self._failure_count,
                )
                self._state = CircuitState.OPEN
                self._opened_at = time.monotonic()

            elif self._state == CircuitState.CLOSED:
                if self._failure_count >= self._error_threshold:
                    logger.warning(
                        "ThothCircuitBreaker: error threshold reached "
                        "(failures=%d >= threshold=%d) — circuit OPENED",
                        self._failure_count,
                        self._error_threshold,
                    )
                    self._state = CircuitState.OPEN
                    self._opened_at = time.monotonic()

    def get_status(self) -> dict:
        """Return an observability snapshot of current circuit breaker state."""
        with self._lock:
            self._maybe_transition_to_half_open()
            return {
                "state": self._state.value,
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "error_threshold": self._error_threshold,
                "recovery_timeout_s": self._recovery_timeout_s,
                "opened_at": self._opened_at,
            }

    def reset(self) -> None:
        """Force-close the circuit (admin override or test teardown)."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._opened_at = None
            logger.info("ThothCircuitBreaker: manually RESET to CLOSED")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _maybe_transition_to_half_open(self) -> None:
        """Check whether OPEN circuit should advance to HALF_OPEN.

        Called under the lock from every public method that inspects state.
        """
        if self._state == CircuitState.OPEN and self._opened_at is not None:
            elapsed = time.monotonic() - self._opened_at
            if elapsed >= self._recovery_timeout_s:
                logger.info(
                    "ThothCircuitBreaker: recovery window elapsed (%.1fs >= %.1fs) "
                    "— circuit HALF_OPEN (probe allowed)",
                    elapsed,
                    self._recovery_timeout_s,
                )
                self._state = CircuitState.HALF_OPEN
                self._opened_at = None  # Reset so re-open sets a fresh timestamp


# ---------------------------------------------------------------------------
# Singleton lifecycle
# ---------------------------------------------------------------------------

_thoth_cb: Optional[ThothCircuitBreaker] = None


def get_thoth_circuit_breaker() -> ThothCircuitBreaker:
    """Return the singleton ThothCircuitBreaker, creating with defaults if needed."""
    global _thoth_cb
    if _thoth_cb is None:
        _thoth_cb = ThothCircuitBreaker()
    return _thoth_cb


def initialize_thoth_circuit_breaker(
    error_threshold: int = 5,
    recovery_timeout_s: float = 30.0,
) -> ThothCircuitBreaker:
    """Create/replace the singleton with configuration from Settings.

    Called once during application lifespan startup when
    ``thoth_circuit_breaker_enabled=True``.
    """
    global _thoth_cb
    _thoth_cb = ThothCircuitBreaker(
        error_threshold=error_threshold,
        recovery_timeout_s=recovery_timeout_s,
    )
    logger.info(
        "ThothCircuitBreaker initialised: error_threshold=%d recovery_timeout_s=%.1f",
        error_threshold,
        recovery_timeout_s,
    )
    return _thoth_cb
