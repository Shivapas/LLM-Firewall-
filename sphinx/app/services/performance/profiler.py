"""Sprint 20 — Memory and CPU Profiling Utilities.

Provides middleware and service-level profiling to identify:
- Memory leaks under sustained load
- Inefficient regex compilation hotspots
- Cache eviction pressure
- Per-request CPU time breakdown

The profiling data is exposed via admin API endpoints and can be collected
during load tests.
"""

from __future__ import annotations

import gc
import logging
import os
import re
import time
import tracemalloc
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("sphinx.profiler")


# ── Memory Profiler ──────────────────────────────────────────────────────────


@dataclass
class MemorySnapshot:
    """Point-in-time memory usage snapshot."""

    timestamp: float = 0.0
    rss_mb: float = 0.0  # Resident Set Size
    tracemalloc_current_mb: float = 0.0
    tracemalloc_peak_mb: float = 0.0
    gc_generation_0: int = 0
    gc_generation_1: int = 0
    gc_generation_2: int = 0
    gc_objects: int = 0
    top_allocations: list[dict] = field(default_factory=list)


class MemoryProfiler:
    """Tracks memory usage over time and identifies leaks."""

    def __init__(self):
        self._snapshots: list[MemorySnapshot] = []
        self._tracing: bool = False
        self._max_snapshots: int = 1000

    def start_tracing(self) -> None:
        """Enable tracemalloc for detailed allocation tracking."""
        if not self._tracing:
            tracemalloc.start(25)  # 25 frames deep
            self._tracing = True
            logger.info("Memory tracing started")

    def stop_tracing(self) -> None:
        """Disable tracemalloc."""
        if self._tracing:
            tracemalloc.stop()
            self._tracing = False
            logger.info("Memory tracing stopped")

    def take_snapshot(self) -> MemorySnapshot:
        """Capture current memory state."""
        gc_stats = gc.get_stats()

        snap = MemorySnapshot(
            timestamp=time.time(),
            gc_generation_0=gc_stats[0]["collections"] if len(gc_stats) > 0 else 0,
            gc_generation_1=gc_stats[1]["collections"] if len(gc_stats) > 1 else 0,
            gc_generation_2=gc_stats[2]["collections"] if len(gc_stats) > 2 else 0,
            gc_objects=len(gc.get_objects()),
        )

        # RSS from /proc (Linux)
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        snap.rss_mb = int(line.split()[1]) / 1024.0
                        break
        except (FileNotFoundError, PermissionError):
            pass

        # tracemalloc stats
        if self._tracing:
            current, peak = tracemalloc.get_traced_memory()
            snap.tracemalloc_current_mb = current / (1024 * 1024)
            snap.tracemalloc_peak_mb = peak / (1024 * 1024)

            # Top 10 allocation sites
            tm_snap = tracemalloc.take_snapshot()
            top_stats = tm_snap.statistics("lineno")[:10]
            snap.top_allocations = [
                {
                    "file": str(stat.traceback),
                    "size_kb": stat.size / 1024,
                    "count": stat.count,
                }
                for stat in top_stats
            ]

        # Evict old snapshots
        self._snapshots.append(snap)
        if len(self._snapshots) > self._max_snapshots:
            self._snapshots = self._snapshots[-self._max_snapshots:]

        return snap

    def detect_leak(self, window: int = 10) -> Optional[dict]:
        """Heuristic leak detection: monotonically increasing RSS over last N snapshots."""
        if len(self._snapshots) < window:
            return None

        recent = self._snapshots[-window:]
        rss_values = [s.rss_mb for s in recent if s.rss_mb > 0]

        if len(rss_values) < window:
            return None

        # Check if RSS is monotonically increasing
        increasing = all(rss_values[i] <= rss_values[i + 1] for i in range(len(rss_values) - 1))
        growth_mb = rss_values[-1] - rss_values[0]

        if increasing and growth_mb > 10:  # >10 MB growth over window
            return {
                "detected": True,
                "growth_mb": round(growth_mb, 2),
                "window_snapshots": window,
                "start_rss_mb": round(rss_values[0], 2),
                "end_rss_mb": round(rss_values[-1], 2),
            }
        return {"detected": False, "growth_mb": round(growth_mb, 2)}

    def get_report(self) -> dict:
        """Return full profiling report."""
        latest = self._snapshots[-1] if self._snapshots else None
        leak_check = self.detect_leak()
        return {
            "tracing_active": self._tracing,
            "snapshot_count": len(self._snapshots),
            "latest": {
                "rss_mb": latest.rss_mb if latest else 0,
                "tracemalloc_current_mb": latest.tracemalloc_current_mb if latest else 0,
                "tracemalloc_peak_mb": latest.tracemalloc_peak_mb if latest else 0,
                "gc_objects": latest.gc_objects if latest else 0,
                "top_allocations": latest.top_allocations if latest else [],
            } if latest else None,
            "leak_detection": leak_check,
        }


# ── CPU / Request Profiler ───────────────────────────────────────────────────


@dataclass
class RequestProfile:
    """Timing breakdown for a single request."""

    request_id: str = ""
    total_ms: float = 0.0
    auth_ms: float = 0.0
    threat_detection_ms: float = 0.0
    pii_scan_ms: float = 0.0
    proxy_ms: float = 0.0
    output_scan_ms: float = 0.0


class CPUProfiler:
    """Collects per-request CPU time breakdown and identifies hotspots."""

    def __init__(self, max_profiles: int = 5000):
        self._profiles: list[RequestProfile] = []
        self._max_profiles = max_profiles
        self._enabled: bool = False

    @property
    def enabled(self) -> bool:
        return self._enabled

    def enable(self) -> None:
        self._enabled = True
        logger.info("CPU profiling enabled")

    def disable(self) -> None:
        self._enabled = False
        logger.info("CPU profiling disabled")

    def record(self, profile: RequestProfile) -> None:
        """Record a request profile."""
        if not self._enabled:
            return
        self._profiles.append(profile)
        if len(self._profiles) > self._max_profiles:
            self._profiles = self._profiles[-self._max_profiles:]

    def get_hotspot_report(self) -> dict:
        """Identify the slowest pipeline stages."""
        if not self._profiles:
            return {"profiles_collected": 0, "hotspots": []}

        stages = ["auth_ms", "threat_detection_ms", "pii_scan_ms", "proxy_ms", "output_scan_ms"]
        stage_totals: dict[str, list[float]] = {s: [] for s in stages}

        for p in self._profiles:
            for s in stages:
                val = getattr(p, s, 0.0)
                if val > 0:
                    stage_totals[s].append(val)

        hotspots = []
        for stage, values in stage_totals.items():
            if values:
                sorted_vals = sorted(values)
                p99_idx = int(len(sorted_vals) * 0.99)
                hotspots.append({
                    "stage": stage.replace("_ms", ""),
                    "mean_ms": round(sum(values) / len(values), 2),
                    "p99_ms": round(sorted_vals[min(p99_idx, len(sorted_vals) - 1)], 2),
                    "max_ms": round(max(values), 2),
                    "sample_count": len(values),
                })

        # Sort by p99 descending to surface worst stages first
        hotspots.sort(key=lambda h: h["p99_ms"], reverse=True)

        return {
            "profiles_collected": len(self._profiles),
            "hotspots": hotspots,
        }

    def clear(self) -> None:
        """Reset collected profiles."""
        self._profiles.clear()


# ── Regex Compilation Auditor ────────────────────────────────────────────────


class RegexAuditor:
    """Detects inefficient regex compilation patterns.

    Scans the threat pattern library for regex anti-patterns that cause
    catastrophic backtracking or unnecessary recompilation.
    """

    # Patterns that can cause catastrophic backtracking
    DANGEROUS_PATTERNS = [
        r"\(.*\+\)\+",     # Nested quantifiers: (a+)+
        r"\(.*\*\)\*",     # Nested quantifiers: (a*)*
        r"\(.*\+\)\*",     # Nested quantifiers: (a+)*
        r"\(.*\*\)\+",     # Nested quantifiers: (a*)+
    ]

    def __init__(self):
        self._compiled_checks = [re.compile(p) for p in self.DANGEROUS_PATTERNS]

    def audit_patterns(self, patterns: list[str]) -> dict:
        """Check a list of regex patterns for known anti-patterns."""
        findings = []
        compilation_times = []

        for pattern in patterns:
            # Time compilation
            start = time.perf_counter()
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                comp_time = (time.perf_counter() - start) * 1000
                compilation_times.append(comp_time)
            except re.error as e:
                findings.append({
                    "pattern": pattern[:100],
                    "issue": "compilation_error",
                    "detail": str(e),
                })
                continue

            # Check for catastrophic backtracking patterns
            for check in self._compiled_checks:
                if check.search(pattern):
                    findings.append({
                        "pattern": pattern[:100],
                        "issue": "catastrophic_backtracking_risk",
                        "detail": "Nested quantifiers detected",
                    })
                    break

            # Flag slow compilation (> 5ms)
            if comp_time > 5.0:
                findings.append({
                    "pattern": pattern[:100],
                    "issue": "slow_compilation",
                    "detail": f"Compilation took {comp_time:.1f}ms",
                })

        return {
            "total_patterns": len(patterns),
            "findings": findings,
            "finding_count": len(findings),
            "avg_compilation_ms": (
                round(sum(compilation_times) / len(compilation_times), 3)
                if compilation_times else 0
            ),
        }


# ── Cache Efficiency Monitor ─────────────────────────────────────────────────


@dataclass
class CacheStats:
    """Cache hit/miss statistics."""

    cache_name: str = ""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0
    max_size: int = 0
    hit_rate: float = 0.0


class CacheMonitor:
    """Monitors cache efficiency across policy, threat pattern, and PII caches."""

    def __init__(self):
        self._stats: dict[str, CacheStats] = {}

    def register_cache(self, name: str, max_size: int = 0) -> None:
        self._stats[name] = CacheStats(cache_name=name, max_size=max_size)

    def record_hit(self, name: str) -> None:
        if name in self._stats:
            self._stats[name].hits += 1
            self._update_rate(name)

    def record_miss(self, name: str) -> None:
        if name in self._stats:
            self._stats[name].misses += 1
            self._update_rate(name)

    def record_eviction(self, name: str) -> None:
        if name in self._stats:
            self._stats[name].evictions += 1

    def update_size(self, name: str, size: int) -> None:
        if name in self._stats:
            self._stats[name].size = size

    def _update_rate(self, name: str) -> None:
        s = self._stats[name]
        total = s.hits + s.misses
        s.hit_rate = round(s.hits / total * 100, 2) if total > 0 else 0.0

    def get_report(self) -> dict:
        return {
            "caches": {
                name: {
                    "hits": s.hits,
                    "misses": s.misses,
                    "evictions": s.evictions,
                    "size": s.size,
                    "max_size": s.max_size,
                    "hit_rate_pct": s.hit_rate,
                }
                for name, s in self._stats.items()
            }
        }


# ── Singleton Accessors ─────────────────────────────────────────────────────

_memory_profiler: Optional[MemoryProfiler] = None
_cpu_profiler: Optional[CPUProfiler] = None
_regex_auditor: Optional[RegexAuditor] = None
_cache_monitor: Optional[CacheMonitor] = None


def get_memory_profiler() -> MemoryProfiler:
    global _memory_profiler
    if _memory_profiler is None:
        _memory_profiler = MemoryProfiler()
    return _memory_profiler


def get_cpu_profiler() -> CPUProfiler:
    global _cpu_profiler
    if _cpu_profiler is None:
        _cpu_profiler = CPUProfiler()
    return _cpu_profiler


def get_regex_auditor() -> RegexAuditor:
    global _regex_auditor
    if _regex_auditor is None:
        _regex_auditor = RegexAuditor()
    return _regex_auditor


def get_cache_monitor() -> CacheMonitor:
    global _cache_monitor
    if _cache_monitor is None:
        _cache_monitor = CacheMonitor()
    return _cache_monitor
