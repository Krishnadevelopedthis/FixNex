"""Qualys SSL Labs adapter (optional).

Only runs on the Comprehensive profile against publicly resolvable hosts. When
the API is unreachable — or the target is internal — the scan is skipped and
the built-in TLS adapter remains the source of TLS findings.
"""
from __future__ import annotations

import ipaddress
import socket
import time

import httpx

from app.core.config import settings
from app.models.enums import ScannerName, ScanProfile, Severity, TargetType
from app.scanners.base import (
    NormalizedFinding,
    ScanContext,
    ScannerAdapter,
    ScannerAvailability,
    ScanResult,
)

_GRADE_SEVERITY = {
    "A+": Severity.INFORMATIONAL,
    "A": Severity.INFORMATIONAL,
    "A-": Severity.INFORMATIONAL,
    "B": Severity.LOW,
    "C": Severity.MEDIUM,
    "D": Severity.MEDIUM,
    "E": Severity.HIGH,
    "F": Severity.HIGH,
    "T": Severity.HIGH,
    "M": Severity.MEDIUM,
}


class SSLLabsAdapter(ScannerAdapter):
    name = ScannerName.SSL_LABS
    label = "Qualys SSL Labs"
    description = (
        "Third-party TLS configuration grading. Requires the target to be publicly "
        "reachable; FixNex falls back to its built-in TLS adapter otherwise."
    )
    kind = "external"
    requires = "outbound internet access to api.ssllabs.com and a public target"
    profiles = (ScanProfile.COMPREHENSIVE,)
    target_types = (TargetType.WEB_APP, TargetType.REST_API)
    weight = 3

    def availability(self) -> ScannerAvailability:
        if settings.OFFLINE_MODE:
            return ScannerAvailability(False, "OFFLINE_MODE is enabled; external APIs are not called.")
        try:
            response = httpx.get(f"{settings.SSL_LABS_API_BASE}/info", timeout=8)
            response.raise_for_status()
            data = response.json()
            return ScannerAvailability(
                True, "SSL Labs API reachable.", str(data.get("engineVersion", ""))[:40] or None
            )
        except Exception as exc:
            return ScannerAvailability(
                False,
                f"SSL Labs API is not reachable ({type(exc).__name__}). The built-in TLS "
                "adapter still assesses certificates and protocols.",
            )

    @staticmethod
    def _is_public(host: str) -> bool:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
            return ip.is_global
        except (OSError, ValueError):
            return False

    def run(self, ctx: ScanContext) -> ScanResult:
        result = ScanResult(scanner=self.name, command_summary=f"SSL Labs analysis of {ctx.hostname}")
        availability = self.availability()
        if not availability.available:
            result.skipped_reason = availability.detail
            return result
        if not self._is_public(ctx.hostname):
            result.skipped_reason = (
                f"{ctx.hostname} does not resolve to a public address; SSL Labs can only "
                "assess internet-facing hosts."
            )
            return result

        params = {"host": ctx.hostname, "all": "done", "fromCache": "on", "maxAge": "24"}
        deadline = time.monotonic() + min(ctx.timeout, 300)
        payload: dict = {}
        ctx.progress(f"Requesting SSL Labs analysis for {ctx.hostname}", 15)

        try:
            while time.monotonic() < deadline and not ctx.is_cancelled():
                response = httpx.get(f"{settings.SSL_LABS_API_BASE}/analyze", params=params, timeout=30)
                response.raise_for_status()
                payload = response.json()
                status = payload.get("status")
                if status == "READY":
                    break
                if status == "ERROR":
                    result.error = payload.get("statusMessage", "SSL Labs reported an error.")
                    return result
                ctx.progress(f"SSL Labs analysis in progress ({status})", 40)
                time.sleep(10)
        except Exception as exc:
            result.error = f"SSL Labs request failed: {type(exc).__name__}: {exc}"[:400]
            return result

        if payload.get("status") != "READY":
            result.skipped_reason = "The SSL Labs analysis did not complete within the scan timeout."
            return result

        result.exit_code = 0
        findings: list[NormalizedFinding] = []
        for endpoint in payload.get("endpoints", []):
            grade = endpoint.get("grade")
            if not grade:
                continue
            severity = _GRADE_SEVERITY.get(grade, Severity.LOW)
            findings.append(
                NormalizedFinding(
                    title=f"SSL Labs TLS grade {grade} for {ctx.hostname}",
                    description=(
                        f"Qualys SSL Labs graded the TLS configuration of "
                        f"{endpoint.get('ipAddress', ctx.hostname)} as **{grade}**. "
                        + (
                            "This reflects a weak or outdated TLS configuration."
                            if severity != Severity.INFORMATIONAL
                            else "This reflects a strong TLS configuration."
                        )
                    ),
                    severity=severity,
                    target=ctx.target_value,
                    endpoint=endpoint.get("ipAddress", ctx.hostname),
                    source=self.name,
                    category="Cryptographic Failure",
                    cwe="CWE-326" if severity != Severity.INFORMATIONAL else None,
                    evidence=f"Grade: {grade}\nStatus: {endpoint.get('statusMessage')}",
                    remediation=(
                        "Follow the SSL Labs report recommendations: disable legacy protocols, "
                        "prefer AEAD cipher suites and enable HSTS."
                    ),
                    references=[f"https://www.ssllabs.com/ssltest/analyze.html?d={ctx.hostname}"],
                    confidence=0.95,
                    raw={"grade": grade, "hasWarnings": endpoint.get("hasWarnings")},
                )
            )
        result.findings = findings
        result.metrics = {"endpoints": len(payload.get("endpoints", []))}
        return result
