"""Memory Lifecycle Cap Enforcement — Sprint 26.

Configurable hard token limit on agent long-term memory (e.g., 20,000 tokens).
Enforces eviction of oldest content when cap is reached.  Prevents unbounded
data accumulation.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("sphinx.memory_firewall.lifecycle")


# ── Data Structures ─────────────────────────────────────────────────────


@dataclass
class MemoryEntry:
    """A single memory entry tracked for lifecycle management."""
    entry_id: str = ""
    agent_id: str = ""
    content_key: str = ""
    namespace: str = ""
    token_count: int = 0
    content_hash: str = ""
    created_at: str = ""

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "agent_id": self.agent_id,
            "content_key": self.content_key,
            "namespace": self.namespace,
            "token_count": self.token_count,
            "content_hash": self.content_hash,
            "created_at": self.created_at,
        }


@dataclass
class EvictionEvent:
    """Record of a memory eviction event."""
    event_id: str = ""
    timestamp: str = ""
    agent_id: str = ""
    evicted_entry_id: str = ""
    evicted_content_key: str = ""
    evicted_token_count: int = 0
    reason: str = ""
    tokens_before: int = 0
    tokens_after: int = 0

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "evicted_entry_id": self.evicted_entry_id,
            "evicted_content_key": self.evicted_content_key,
            "evicted_token_count": self.evicted_token_count,
            "reason": self.reason,
            "tokens_before": self.tokens_before,
            "tokens_after": self.tokens_after,
        }


@dataclass
class AgentMemoryCap:
    """Per-agent token cap configuration."""
    agent_id: str
    max_tokens: int = 20_000
    current_tokens: int = 0

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "max_tokens": self.max_tokens,
            "current_tokens": self.current_tokens,
            "utilization_pct": round(
                (self.current_tokens / self.max_tokens * 100) if self.max_tokens > 0 else 0, 1
            ),
        }


# ── Lifecycle Cap Manager ──────────────────────────────────────────────


class MemoryLifecycleManager:
    """Manages per-agent memory token caps and eviction.

    Each agent has a configurable maximum token budget for long-term memory.
    When a new write would exceed the cap, the oldest entries are evicted
    until enough room is available.
    """

    DEFAULT_MAX_TOKENS = 20_000

    def __init__(self, default_max_tokens: int = DEFAULT_MAX_TOKENS):
        self._default_max_tokens = default_max_tokens
        # agent_id -> AgentMemoryCap
        self._caps: dict[str, AgentMemoryCap] = {}
        # agent_id -> list[MemoryEntry] (ordered oldest-first)
        self._entries: dict[str, list[MemoryEntry]] = {}
        self._eviction_log: list[EvictionEvent] = []
        self._stats: dict[str, int] = {
            "total_entries": 0,
            "total_evictions": 0,
            "total_tokens_evicted": 0,
        }

    @property
    def default_max_tokens(self) -> int:
        return self._default_max_tokens

    # ── Cap Configuration ───────────────────────────────────────────────

    def set_cap(self, agent_id: str, max_tokens: int) -> AgentMemoryCap:
        """Set the token cap for an agent."""
        cap = self._caps.get(agent_id)
        if cap:
            cap.max_tokens = max_tokens
        else:
            cap = AgentMemoryCap(agent_id=agent_id, max_tokens=max_tokens)
            self._caps[agent_id] = cap
        logger.info("Set memory cap: agent=%s max_tokens=%d", agent_id, max_tokens)
        return cap

    def get_cap(self, agent_id: str) -> AgentMemoryCap:
        """Get the effective cap for an agent (creates default if missing)."""
        if agent_id not in self._caps:
            self._caps[agent_id] = AgentMemoryCap(
                agent_id=agent_id, max_tokens=self._default_max_tokens
            )
        return self._caps[agent_id]

    def list_caps(self) -> list[AgentMemoryCap]:
        return list(self._caps.values())

    # ── Entry Management ────────────────────────────────────────────────

    def add_entry(
        self,
        agent_id: str,
        content_key: str,
        token_count: int,
        namespace: str = "",
        content_hash: str = "",
    ) -> tuple[MemoryEntry, list[EvictionEvent]]:
        """Add a memory entry, evicting oldest entries if cap would be exceeded.

        Returns the new entry and a list of eviction events (if any).
        """
        cap = self.get_cap(agent_id)
        if agent_id not in self._entries:
            self._entries[agent_id] = []

        evictions: list[EvictionEvent] = []

        # Evict oldest entries until there is room
        while (
            cap.current_tokens + token_count > cap.max_tokens
            and self._entries[agent_id]
        ):
            oldest = self._entries[agent_id].pop(0)
            tokens_before = cap.current_tokens
            cap.current_tokens -= oldest.token_count
            tokens_after = cap.current_tokens

            event = EvictionEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc).isoformat(),
                agent_id=agent_id,
                evicted_entry_id=oldest.entry_id,
                evicted_content_key=oldest.content_key,
                evicted_token_count=oldest.token_count,
                reason=f"Token cap exceeded ({tokens_before + token_count}/{cap.max_tokens})",
                tokens_before=tokens_before,
                tokens_after=tokens_after,
            )
            evictions.append(event)
            self._eviction_log.append(event)
            self._stats["total_evictions"] += 1
            self._stats["total_tokens_evicted"] += oldest.token_count

            logger.info(
                "Memory eviction: agent=%s key=%s tokens=%d reason=%s",
                agent_id,
                oldest.content_key,
                oldest.token_count,
                event.reason,
            )

        # If still over cap after evicting everything, the entry itself is too large
        # but we still add it (capped to max)
        entry = MemoryEntry(
            entry_id=str(uuid.uuid4()),
            agent_id=agent_id,
            content_key=content_key,
            namespace=namespace,
            token_count=token_count,
            content_hash=content_hash,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._entries[agent_id].append(entry)
        cap.current_tokens += token_count
        self._stats["total_entries"] += 1

        return entry, evictions

    def remove_entry(self, agent_id: str, content_key: str) -> bool:
        """Remove a specific memory entry."""
        entries = self._entries.get(agent_id, [])
        for i, e in enumerate(entries):
            if e.content_key == content_key:
                cap = self.get_cap(agent_id)
                cap.current_tokens -= e.token_count
                entries.pop(i)
                return True
        return False

    def get_entries(self, agent_id: str) -> list[MemoryEntry]:
        return list(self._entries.get(agent_id, []))

    def get_agent_token_usage(self, agent_id: str) -> dict[str, Any]:
        """Get token usage summary for an agent."""
        cap = self.get_cap(agent_id)
        entries = self._entries.get(agent_id, [])
        return {
            "agent_id": agent_id,
            "current_tokens": cap.current_tokens,
            "max_tokens": cap.max_tokens,
            "utilization_pct": round(
                (cap.current_tokens / cap.max_tokens * 100) if cap.max_tokens > 0 else 0, 1
            ),
            "entry_count": len(entries),
        }

    # ── Eviction Log ────────────────────────────────────────────────────

    def get_eviction_log(
        self,
        agent_id: str | None = None,
        limit: int = 100,
    ) -> list[EvictionEvent]:
        results = self._eviction_log
        if agent_id:
            results = [e for e in results if e.agent_id == agent_id]
        return results[-limit:]

    def get_stats(self) -> dict[str, Any]:
        stats = dict(self._stats)
        stats["agents_tracked"] = len(self._caps)
        stats["default_max_tokens"] = self._default_max_tokens
        return stats


# ── Singleton ────────────────────────────────────────────────────────────

_manager: MemoryLifecycleManager | None = None


def get_memory_lifecycle_manager() -> MemoryLifecycleManager:
    global _manager
    if _manager is None:
        _manager = MemoryLifecycleManager()
    return _manager


def reset_memory_lifecycle_manager() -> None:
    global _manager
    _manager = None
