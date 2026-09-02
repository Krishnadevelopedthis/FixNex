"""Scanner adapter contract.

Every security tool FixNex integrates is wrapped in an adapter that returns
`NormalizedFinding` objects. Nothing downstream — correlation, scoring, risk,
remediation, reporting — knows which tool produced a finding, so a new scanner
can be added without touching the finding system.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

from app.models.enums import ScanProfile, Severity, TargetType

# --------------------------------------------------------------------------
# Severity normalisation
# --------------------------------------------------------------------------
# Different tools speak different dialects. Everything is mapped onto the
# platform's five canonical levels before it reaches the finding system.
_SEVERITY_ALIASES: dict[str, str] = {
    # canonical
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
    "information": Severity.INFORMATIONAL,
    "none": Severity.INFORMATIONAL,
    "unknown": Severity.INFORMATIONAL,
    # ZAP numeric risk codes
    "0": Severity.INFORMATIONAL,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
    # Nuclei / misc
    "warning": Severity.LOW,
    "error": Severity.MEDIUM,
    "severe": Severity.HIGH,
}


def normalize_severity(raw: str | int | float | None, default: str = Severity.INFORMATIONAL) -> str:
    """Map any scanner's severity vocabulary onto the canonical scale."""
    if raw is None:
        return default
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return severity_from_cvss(float(raw))
    key = str(raw).strip().lower()
    return _SEVERITY_ALIASES.get(key, default)


def severity_from_cvss(score: float | None) -> str:
    """CVSS v3.1 qualitative severity rating scale."""
    if score is None:
        return Severity.INFORMATIONAL
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFORMATIONAL


# --------------------------------------------------------------------------
# Normalised finding — the common format every adapter emits
# --------------------------------------------------------------------------
@dataclass
class NormalizedFinding:
    title: str
    description: str = ""
    severity: str = Severity.INFORMATIONAL
    target: str = ""
    endpoint: str | None = None
    source: str = "unknown"
    category: str | None = None
    parameter: str | None = None
    http_method: str | None = None
    cwe: str | None = None
    cve: list[str] = field(default_factory=list)
    cvss: float | None = None
    cvss_vector: str | None = None
    evidence: str | None = None
    request_snippet: str | None = None
    response_snippet: str | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    confidence: float = 0.5
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "target": self.target,
            "endpoint": self.endpoint,
            "source": self.source,
            "category": self.category,
            "parameter": self.parameter,
            "cwe": self.cwe,
            "cve": self.cve,
            "cvss": self.cvss,
            "cvss_vector": self.cvss_vector,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


@dataclass
class ScannerAvailability:
    available: bool
    detail: str
    version: str | None = None


@dataclass
class ScanContext:
    """Everything an adapter needs to scan one target."""

    target_value: str
    target_type: str = TargetType.WEB_APP
    profile: str = ScanProfile.STANDARD
    port: int | None = None
    base_path: str | None = None
    endpoints: list[dict] = field(default_factory=list)
    timeout: int = 900
    # Reports incremental progress back to the orchestrator (0-100 within this adapter).
    progress: Callable[[str, int], None] = lambda message, percent: None
    # Returns True when the operator has requested cancellation.
    is_cancelled: Callable[[], bool] = lambda: False

    # ------------------------------------------------------------ helpers
    @property
    def parsed(self):
        value = self.target_value
        if "://" not in value:
            value = f"https://{value}"
        return urlparse(value)

    @property
    def url(self) -> str:
        """Best-effort HTTP(S) URL for this target."""
        value = self.target_value
        if "://" not in value:
            scheme = "https" if (self.port in (None, 443)) else "http"
            value = f"{scheme}://{value}"
            if self.port and self.port not in (80, 443):
                value = f"{value}:{self.port}"
        if self.base_path:
            value = value.rstrip("/") + "/" + self.base_path.lstrip("/")
        return value

    @property
    def hostname(self) -> str:
        return self.parsed.hostname or self.target_value

    @property
    def effective_port(self) -> int:
        if self.port:
            return self.port
        if self.parsed.port:
            return self.parsed.port
        return 443 if self.parsed.scheme == "https" else 80

    @property
    def is_https(self) -> bool:
        return self.parsed.scheme == "https" or self.effective_port == 443

    def resolve_ip(self) -> str | None:
        try:
            return socket.gethostbyname(self.hostname)
        except OSError:
            return None


@dataclass
class ScanResult:
    """Execution metadata plus the normalised findings from one adapter."""

    scanner: str
    findings: list[NormalizedFinding] = field(default_factory=list)
    exit_code: int | None = None
    command_summary: str | None = None
    tool_version: str | None = None
    metrics: dict = field(default_factory=dict)
    error: str | None = None
    skipped_reason: str | None = None


class ScannerAdapter(ABC):
    """Base class for every integrated security tool."""

    name: str = "adapter"
    label: str = "Adapter"
    description: str = ""
    kind: str = "builtin"          # builtin | external
    requires: str | None = None    # human-readable dependency, e.g. "nmap binary"
    # Profiles this adapter participates in.
    profiles: tuple[str, ...] = (ScanProfile.STANDARD, ScanProfile.COMPREHENSIVE)
    target_types: tuple[str, ...] = (TargetType.WEB_APP, TargetType.REST_API, TargetType.HOST)
    # Rough share of overall scan time, used to weight progress reporting.
    weight: int = 1

    @abstractmethod
    def availability(self) -> ScannerAvailability:
        """Whether this scanner can run right now, and why not if it cannot."""

    def supports(self, target_type: str, profile: str) -> bool:
        return target_type in self.target_types and profile in self.profiles

    @abstractmethod
    def run(self, ctx: ScanContext) -> ScanResult:
        """Execute the scan and return normalised findings."""


# --------------------------------------------------------------------------
# Shared parsing helpers used by several adapters
# --------------------------------------------------------------------------
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CWE_PATTERN = re.compile(r"CWE-(\d{1,5})", re.IGNORECASE)


def extract_cves(*texts: str | None) -> list[str]:
    found: list[str] = []
    for text in texts:
        if not text:
            continue
        for match in CVE_PATTERN.findall(text):
            upper = match.upper()
            if upper not in found:
                found.append(upper)
    return found


def extract_cwe(*texts: str | None) -> str | None:
    for text in texts:
        if not text:
            continue
        match = CWE_PATTERN.search(text)
        if match:
            return f"CWE-{int(match.group(1))}"
    return None


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def truncate(text: str | None, limit: int = 4000) -> str | None:
    if text is None:
        return None
    text = str(text)
    return text if len(text) <= limit else text[: limit - 15] + "\n...[truncated]"
