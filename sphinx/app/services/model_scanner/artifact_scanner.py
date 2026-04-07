"""Model Artifact Scanner — Sprint 29.

Scan model files (GGUF, safetensors, PyTorch .pt/.bin) for:
- Deserialization attacks (malicious pickle payloads)
- Embedded backdoor triggers
- Suspicious opcode sequences in pickle streams

Designed to gate model deployment: only models that pass scanning
can be loaded by the gateway.
"""

from __future__ import annotations

import hashlib
import io
import logging
import pickle
import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, BinaryIO

logger = logging.getLogger("sphinx.model_scanner.artifact")


# ── Enums / Data Structures ──────────────────────────────────────────────


class ScanVerdict(str, Enum):
    SAFE = "safe"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    ERROR = "error"


class ModelFormat(str, Enum):
    PYTORCH = "pytorch"       # .pt / .bin
    SAFETENSORS = "safetensors"
    GGUF = "gguf"
    UNKNOWN = "unknown"


@dataclass
class ScanFinding:
    finding_id: str = ""
    severity: str = "high"          # critical, high, medium, low
    category: str = ""              # pickle_exploit, suspicious_opcode, backdoor_trigger, etc.
    description: str = ""
    offset: int = 0                 # byte offset in file
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "offset": self.offset,
            "details": self.details,
        }


@dataclass
class ScanResult:
    scan_id: str = ""
    filename: str = ""
    file_hash: str = ""
    file_size: int = 0
    model_format: str = ""
    verdict: str = "safe"
    findings: list[ScanFinding] = field(default_factory=list)
    scanned_at: str = ""
    scan_duration_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "filename": self.filename,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "model_format": self.model_format,
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
            "scanned_at": self.scanned_at,
            "scan_duration_ms": self.scan_duration_ms,
        }


# ── Dangerous Pickle Opcodes ────────────────────────────────────────────

# These opcodes are used in pickle-based exploits
DANGEROUS_PICKLE_OPCODES: dict[int, str] = {
    0x52: "REDUCE",        # obj.__reduce__() — primary exploit vector
    0x81: "NEWOBJ",        # cls.__new__(cls, *args) — object instantiation
    0x82: "NEWOBJ_EX",     # cls.__new__(cls, *args, **kwargs)
    0x83: "STACK_GLOBAL",  # push self.find_class(module, name)
    0x84: "INST",          # push instantiated class
    0x63: "GLOBAL",        # push module.name
    0x93: "STACK_GLOBAL",  # push self.find_class(module_name, qualname)
}

# Known malicious module+function patterns that indicate exploit payloads
MALICIOUS_IMPORTS: list[tuple[str, str]] = [
    ("os", "system"),
    ("os", "popen"),
    ("os", "exec"),
    ("os", "execve"),
    ("os", "execvp"),
    ("subprocess", "call"),
    ("subprocess", "check_output"),
    ("subprocess", "Popen"),
    ("subprocess", "run"),
    ("builtins", "exec"),
    ("builtins", "eval"),
    ("builtins", "__import__"),
    ("nt", "system"),
    ("posix", "system"),
    ("commands", "getoutput"),
    ("webbrowser", "open"),
    ("ctypes", "CDLL"),
    ("ctypes", "cdll"),
    ("socket", "socket"),
    ("http.client", "HTTPConnection"),
    ("urllib.request", "urlopen"),
    ("shutil", "rmtree"),
]

# Patterns indicating backdoor triggers in model weights
BACKDOOR_TRIGGER_PATTERNS: list[bytes] = [
    b"__reduce__",
    b"__reduce_ex__",
    b"exec(",
    b"eval(",
    b"os.system",
    b"subprocess",
    b"import os",
    b"import subprocess",
    b"__import__",
    b"\\x00BACKDOOR",
]


# ── Magic Bytes ──────────────────────────────────────────────────────────

SAFETENSORS_MAGIC = b"{"     # safetensors header starts with JSON
GGUF_MAGIC = b"GGUF"
PICKLE_MAGIC_V2 = b"\x80\x02"
PICKLE_MAGIC_V3 = b"\x80\x03"
PICKLE_MAGIC_V4 = b"\x80\x04"
PICKLE_MAGIC_V5 = b"\x80\x05"
ZIP_MAGIC = b"PK\x03\x04"   # PyTorch .pt files are ZIP archives


# ── Model Artifact Scanner ───────────────────────────────────────────────


class ModelArtifactScanner:
    """Scans model files for deserialization attacks and embedded threats.

    Supports PyTorch (.pt/.bin), safetensors, and GGUF formats.
    PyTorch files are the primary concern as they use pickle internally.
    """

    def __init__(self) -> None:
        self._scan_history: list[ScanResult] = []
        self._stats: dict[str, int] = {
            "total_scans": 0,
            "safe_models": 0,
            "malicious_models": 0,
            "suspicious_models": 0,
            "errors": 0,
        }

    def detect_format(self, data: bytes, filename: str = "") -> ModelFormat:
        """Detect model file format from magic bytes and extension."""
        ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""

        if ext == "safetensors" or (len(data) > 8 and data[:1] == SAFETENSORS_MAGIC):
            return ModelFormat.SAFETENSORS
        if ext == "gguf" or (len(data) >= 4 and data[:4] == GGUF_MAGIC):
            return ModelFormat.GGUF
        if ext in ("pt", "pth", "bin"):
            return ModelFormat.PYTORCH
        # Check for ZIP (PyTorch) or pickle magic
        if len(data) >= 4 and data[:4] == ZIP_MAGIC:
            return ModelFormat.PYTORCH
        if len(data) >= 2 and data[:2] in (PICKLE_MAGIC_V2, PICKLE_MAGIC_V3, PICKLE_MAGIC_V4, PICKLE_MAGIC_V5):
            return ModelFormat.PYTORCH
        return ModelFormat.UNKNOWN

    def scan(self, data: bytes, filename: str = "") -> ScanResult:
        """Scan a model file for security threats.

        Args:
            data: Raw bytes of the model file.
            filename: Original filename for format detection.

        Returns:
            ScanResult with verdict and any findings.
        """
        import time
        start = time.monotonic()

        scan_id = str(uuid.uuid4())
        file_hash = hashlib.sha256(data).hexdigest()
        model_format = self.detect_format(data, filename)

        self._stats["total_scans"] += 1
        findings: list[ScanFinding] = []

        try:
            if model_format == ModelFormat.PYTORCH:
                findings.extend(self._scan_pickle_payload(data))
                findings.extend(self._scan_backdoor_patterns(data))
            elif model_format == ModelFormat.SAFETENSORS:
                findings.extend(self._scan_safetensors(data))
            elif model_format == ModelFormat.GGUF:
                findings.extend(self._scan_gguf(data))
            else:
                # Scan raw bytes for any known patterns
                findings.extend(self._scan_backdoor_patterns(data))

        except Exception as e:
            logger.error("Error scanning model file %s: %s", filename, e)
            self._stats["errors"] += 1
            result = ScanResult(
                scan_id=scan_id,
                filename=filename,
                file_hash=file_hash,
                file_size=len(data),
                model_format=model_format.value,
                verdict=ScanVerdict.ERROR.value,
                findings=[ScanFinding(
                    finding_id=str(uuid.uuid4()),
                    severity="medium",
                    category="scan_error",
                    description=f"Error during scan: {e}",
                )],
                scanned_at=datetime.now(timezone.utc).isoformat(),
                scan_duration_ms=(time.monotonic() - start) * 1000,
            )
            self._scan_history.append(result)
            return result

        # Determine verdict
        if any(f.severity in ("critical", "high") for f in findings):
            verdict = ScanVerdict.MALICIOUS
            self._stats["malicious_models"] += 1
        elif findings:
            verdict = ScanVerdict.SUSPICIOUS
            self._stats["suspicious_models"] += 1
        else:
            verdict = ScanVerdict.SAFE
            self._stats["safe_models"] += 1

        elapsed = (time.monotonic() - start) * 1000
        result = ScanResult(
            scan_id=scan_id,
            filename=filename,
            file_hash=file_hash,
            file_size=len(data),
            model_format=model_format.value,
            verdict=verdict.value,
            findings=findings,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            scan_duration_ms=elapsed,
        )
        self._scan_history.append(result)

        logger.info(
            "Model scan complete: file=%s format=%s verdict=%s findings=%d duration=%.1fms",
            filename, model_format.value, verdict.value, len(findings), elapsed,
        )
        return result

    def _scan_pickle_payload(self, data: bytes) -> list[ScanFinding]:
        """Scan for dangerous pickle opcodes and malicious imports."""
        findings: list[ScanFinding] = []

        # Scan for dangerous opcode sequences
        for i, byte in enumerate(data):
            if byte in DANGEROUS_PICKLE_OPCODES:
                opcode_name = DANGEROUS_PICKLE_OPCODES[byte]
                # Only flag REDUCE and GLOBAL as high — they're the exploit vectors
                if opcode_name in ("REDUCE", "GLOBAL", "STACK_GLOBAL"):
                    # Check context around the opcode for malicious imports
                    context_start = max(0, i - 256)
                    context = data[context_start:i + 256]
                    for module, func in MALICIOUS_IMPORTS:
                        pattern = f"{module}\n{func}".encode()
                        alt_pattern = f"{module}.{func}".encode()
                        if pattern in context or alt_pattern in context:
                            findings.append(ScanFinding(
                                finding_id=str(uuid.uuid4()),
                                severity="critical",
                                category="pickle_exploit",
                                description=(
                                    f"Malicious pickle payload detected: {module}.{func}() "
                                    f"called via {opcode_name} opcode"
                                ),
                                offset=i,
                                details={
                                    "opcode": opcode_name,
                                    "module": module,
                                    "function": func,
                                },
                            ))

        # Scan for malicious import strings anywhere in the binary
        for module, func in MALICIOUS_IMPORTS:
            for pattern in [f"{module}\n{func}".encode(), f"c{module}\n{func}\n".encode()]:
                idx = data.find(pattern)
                if idx >= 0:
                    # Deduplicate — don't re-report if already found via opcode scan
                    already = any(
                        f.category == "pickle_exploit" and
                        f.details.get("module") == module and
                        f.details.get("function") == func
                        for f in findings
                    )
                    if not already:
                        findings.append(ScanFinding(
                            finding_id=str(uuid.uuid4()),
                            severity="critical",
                            category="pickle_exploit",
                            description=(
                                f"Pickle GLOBAL import of dangerous function: {module}.{func}"
                            ),
                            offset=idx,
                            details={"module": module, "function": func},
                        ))

        return findings

    def _scan_backdoor_patterns(self, data: bytes) -> list[ScanFinding]:
        """Scan for embedded backdoor trigger patterns in raw bytes."""
        findings: list[ScanFinding] = []
        for pattern in BACKDOOR_TRIGGER_PATTERNS:
            idx = data.find(pattern)
            if idx >= 0:
                # __reduce__ inside a pickle is expected; only flag it outside
                # the opcode context if it looks embedded in weight data
                if pattern in (b"__reduce__", b"__reduce_ex__"):
                    continue  # handled by pickle scanner
                findings.append(ScanFinding(
                    finding_id=str(uuid.uuid4()),
                    severity="high",
                    category="backdoor_trigger",
                    description=f"Suspicious pattern found in model data: {pattern.decode(errors='replace')}",
                    offset=idx,
                    details={"pattern": pattern.decode(errors="replace")},
                ))
        return findings

    def _scan_safetensors(self, data: bytes) -> list[ScanFinding]:
        """Scan safetensors files — these are inherently safer (no pickle).

        We still check for embedded executable content.
        """
        findings: list[ScanFinding] = []
        # safetensors format is JSON header + raw tensor data — no pickle
        # Check for any suspicious embedded content in the header
        try:
            # Header length is first 8 bytes (little-endian u64)
            if len(data) >= 8:
                header_len = struct.unpack("<Q", data[:8])[0]
                if header_len > len(data) - 8:
                    findings.append(ScanFinding(
                        finding_id=str(uuid.uuid4()),
                        severity="medium",
                        category="format_anomaly",
                        description="Safetensors header length exceeds file size",
                        details={"header_len": header_len, "file_size": len(data)},
                    ))
        except Exception:
            pass

        # Also scan raw bytes for any backdoor patterns
        for pattern in [b"exec(", b"eval(", b"os.system", b"subprocess"]:
            if pattern in data:
                findings.append(ScanFinding(
                    finding_id=str(uuid.uuid4()),
                    severity="high",
                    category="embedded_code",
                    description=f"Executable code pattern found in safetensors file: {pattern.decode()}",
                    offset=data.find(pattern),
                    details={"pattern": pattern.decode()},
                ))
        return findings

    def _scan_gguf(self, data: bytes) -> list[ScanFinding]:
        """Scan GGUF files for anomalies."""
        findings: list[ScanFinding] = []
        # GGUF is a binary format with metadata + quantized weights
        # Check magic
        if len(data) >= 4 and data[:4] != GGUF_MAGIC:
            findings.append(ScanFinding(
                finding_id=str(uuid.uuid4()),
                severity="medium",
                category="format_anomaly",
                description="GGUF magic bytes mismatch",
            ))
        # Scan for embedded executable patterns
        for pattern in [b"exec(", b"eval(", b"os.system", b"subprocess"]:
            if pattern in data:
                findings.append(ScanFinding(
                    finding_id=str(uuid.uuid4()),
                    severity="high",
                    category="embedded_code",
                    description=f"Executable code pattern in GGUF file: {pattern.decode()}",
                    offset=data.find(pattern),
                    details={"pattern": pattern.decode()},
                ))
        return findings

    # ── Query ────────────────────────────────────────────────────────────

    def get_scan_history(self, limit: int = 50) -> list[ScanResult]:
        return self._scan_history[-limit:]

    def get_stats(self) -> dict[str, int]:
        return dict(self._stats)


# ── Singleton ────────────────────────────────────────────────────────────

_scanner: ModelArtifactScanner | None = None


def get_model_artifact_scanner() -> ModelArtifactScanner:
    global _scanner
    if _scanner is None:
        _scanner = ModelArtifactScanner()
    return _scanner


def reset_model_artifact_scanner() -> None:
    global _scanner
    _scanner = None
