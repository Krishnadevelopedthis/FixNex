"""Scanner registry and scan profile definitions.

Adding a new tool means writing one adapter and registering it here — the
finding pipeline downstream needs no changes.
"""
from __future__ import annotations

from app.models.enums import ScanProfile
from app.scanners.base import ScannerAdapter
from app.scanners.http_headers import HTTPHeadersAdapter
from app.scanners.nmap import NmapAdapter
from app.scanners.nuclei import NucleiAdapter
from app.scanners.port_scan import PortScanAdapter
from app.scanners.ssl_labs import SSLLabsAdapter
from app.scanners.tech_fingerprint import TechFingerprintAdapter
from app.scanners.tls import TLSAdapter
from app.scanners.whatweb import WhatWebAdapter
from app.scanners.zap import ZAPAdapter


class ScannerRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ScannerAdapter] = {}

    def register(self, adapter: ScannerAdapter) -> None:
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> ScannerAdapter | None:
        return self._adapters.get(name)

    def all(self) -> list[ScannerAdapter]:
        return list(self._adapters.values())

    def names(self) -> list[str]:
        return [str(n) for n in self._adapters]

    def for_profile(self, profile: str, target_type: str, only_available: bool = True) -> list[ScannerAdapter]:
        """Adapters that participate in a profile for a given target type."""
        selected = [a for a in self._adapters.values() if a.supports(target_type, profile)]
        if only_available:
            selected = [a for a in selected if a.availability().available]
        # Cheap, always-available checks run first so findings appear quickly.
        return sorted(selected, key=lambda a: (a.kind != "builtin", a.weight))

    def availability_report(self) -> list[dict]:
        report = []
        for adapter in sorted(self._adapters.values(), key=lambda a: (a.kind != "builtin", a.name)):
            availability = adapter.availability()
            report.append(
                {
                    "name": str(adapter.name),
                    "label": adapter.label,
                    "description": adapter.description,
                    "kind": adapter.kind,
                    "available": availability.available,
                    "availability_detail": availability.detail,
                    "version": availability.version,
                    "requires": adapter.requires,
                }
            )
        return report


scanner_registry = ScannerRegistry()
for _adapter in (
    HTTPHeadersAdapter(),
    TLSAdapter(),
    TechFingerprintAdapter(),
    PortScanAdapter(),
    NmapAdapter(),
    NucleiAdapter(),
    ZAPAdapter(),
    WhatWebAdapter(),
    SSLLabsAdapter(),
):
    scanner_registry.register(_adapter)


PROFILE_DEFINITIONS = [
    {
        "name": str(ScanProfile.LIGHT),
        "label": "Light",
        "description": (
            "Non-invasive reconnaissance: technology fingerprinting, HTTP security "
            "headers, cookie attributes and TLS configuration. Safe for production."
        ),
        "invasive": False,
        "estimated_duration": "under a minute",
    },
    {
        "name": str(ScanProfile.STANDARD),
        "label": "Standard",
        "description": (
            "Light checks plus port and service discovery (Nmap), template-based "
            "vulnerability detection (Nuclei) and OWASP ZAP passive scanning."
        ),
        "invasive": False,
        "estimated_duration": "2 to 10 minutes",
    },
    {
        "name": str(ScanProfile.COMPREHENSIVE),
        "label": "Comprehensive",
        "description": (
            "Standard checks plus ZAP active scanning, a broader Nuclei template set, "
            "a wider port range and SSL Labs grading. Never runs destructive, "
            "denial-of-service or brute-force templates."
        ),
        "invasive": True,
        "estimated_duration": "10 to 30 minutes",
    },
]


def profile_info(target_type: str = "WEB_APP") -> list[dict]:
    result = []
    for definition in PROFILE_DEFINITIONS:
        adapters = scanner_registry.for_profile(definition["name"], target_type, only_available=False)
        result.append({**definition, "scanners": [str(a.name) for a in adapters]})
    return result
