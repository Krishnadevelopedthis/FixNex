"""Built-in TLS / certificate assessment.

Uses only the Python standard library, so TLS posture is always assessed even
when the SSL Labs API is unreachable or no API key is configured.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from app.models.enums import ScannerName, ScanProfile, Severity, TargetType
from app.scanners.base import (
    NormalizedFinding,
    ScanContext,
    ScannerAdapter,
    ScannerAvailability,
    ScanResult,
)

# Protocols that should no longer be accepted.
_LEGACY_PROTOCOLS = {
    "SSLv3": (Severity.HIGH, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"),
    "TLSv1": (Severity.MEDIUM, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "TLSv1.1": (Severity.MEDIUM, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"),
}

_WEAK_CIPHER_TOKENS = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon")


class TLSAdapter(ScannerAdapter):
    name = ScannerName.TLS
    label = "TLS / Certificate Analysis"
    description = (
        "Validates the certificate chain, expiry, hostname match, negotiated protocol "
        "and cipher suite. Built into FixNex — always available, non-invasive."
    )
    kind = "builtin"
    profiles = (ScanProfile.LIGHT, ScanProfile.STANDARD, ScanProfile.COMPREHENSIVE)
    target_types = (TargetType.WEB_APP, TargetType.REST_API, TargetType.HOST)
    weight = 1

    def availability(self) -> ScannerAvailability:
        return ScannerAvailability(True, "Built-in adapter (Python standard library).")

    def run(self, ctx: ScanContext) -> ScanResult:
        host, port = ctx.hostname, ctx.effective_port
        result = ScanResult(scanner=self.name, command_summary=f"TLS handshake with {host}:{port}")

        if not ctx.is_https and port not in (443, 8443):
            result.skipped_reason = "Target is not served over TLS."
            result.exit_code = 0
            result.findings = [
                NormalizedFinding(
                    title="Service does not use TLS encryption",
                    description=(
                        f"The target {host}:{port} is reachable over plaintext HTTP. All traffic, "
                        "including credentials and session tokens, can be read and modified by "
                        "anyone on the network path."
                    ),
                    severity=Severity.HIGH,
                    target=ctx.target_value,
                    endpoint=f"{host}:{port}",
                    source=self.name,
                    category="Cryptographic Failure",
                    cwe="CWE-319",
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    evidence=f"No TLS listener detected on {host}:{port}.",
                    remediation="Serve the application over HTTPS and redirect all HTTP traffic to it.",
                    confidence=0.8,
                )
            ]
            return result

        ctx.progress(f"Performing TLS handshake with {host}:{port}", 20)
        findings: list[NormalizedFinding] = []

        # A permissive context is required to *observe* a broken chain rather
        # than merely failing; certificate problems are then reported as findings.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    der = tls_sock.getpeercert(binary_form=True)
                    protocol = tls_sock.version()
                    cipher = tls_sock.cipher()
        except Exception as exc:
            result.error = f"TLS handshake failed: {type(exc).__name__}: {exc}"[:400]
            result.exit_code = 1
            return result

        result.exit_code = 0
        result.metrics = {
            "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
            "cipher_bits": cipher[2] if cipher else None,
            "certificate_bytes": len(der) if der else 0,
        }

        ctx.progress("Validating certificate", 55)
        findings.extend(self._check_certificate(ctx, cert, host))
        ctx.progress("Evaluating protocol and cipher strength", 80)
        findings.extend(self._check_protocol(ctx, protocol, cipher, host, port))

        result.findings = findings
        return result

    # ---------------------------------------------------------------- helpers
    def _check_certificate(self, ctx: ScanContext, cert: dict | None, host: str) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        if not cert:
            # verify_mode=CERT_NONE yields an empty dict for self-signed chains.
            return [
                NormalizedFinding(
                    title="TLS certificate could not be validated",
                    description=(
                        "The server presented a certificate that could not be validated against "
                        "a trusted certificate authority. This is typical of a self-signed or "
                        "incorrectly chained certificate and prevents clients from "
                        "distinguishing the real server from an impostor."
                    ),
                    severity=Severity.MEDIUM,
                    target=ctx.target_value,
                    endpoint=host,
                    source=self.name,
                    category="Cryptographic Failure",
                    cwe="CWE-295",
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    evidence="The peer certificate could not be verified against the system trust store.",
                    remediation="Install a certificate issued by a publicly trusted CA and serve the full chain.",
                    confidence=0.75,
                )
            ]

        not_after = cert.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left < 0:
                    findings.append(
                        NormalizedFinding(
                            title="TLS certificate has expired",
                            description=(
                                f"The certificate for {host} expired on {expiry:%Y-%m-%d} "
                                f"({abs(days_left)} days ago). Browsers will present a full-page "
                                "interstitial warning and users are trained to click through it."
                            ),
                            severity=Severity.HIGH,
                            target=ctx.target_value,
                            endpoint=host,
                            source=self.name,
                            category="Cryptographic Failure",
                            cwe="CWE-298",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
                            evidence=f"notAfter = {not_after}",
                            remediation="Renew the certificate and automate renewal (for example with ACME).",
                            confidence=0.99,
                        )
                    )
                elif days_left < 30:
                    findings.append(
                        NormalizedFinding(
                            title=f"TLS certificate expires in {days_left} days",
                            description=(
                                f"The certificate for {host} expires on {expiry:%Y-%m-%d}. "
                                "Expiry causes a hard outage for every client."
                            ),
                            severity=Severity.LOW,
                            target=ctx.target_value,
                            endpoint=host,
                            source=self.name,
                            category="Cryptographic Failure",
                            cwe="CWE-298",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L",
                            evidence=f"notAfter = {not_after} ({days_left} days remaining)",
                            remediation="Renew the certificate and enable automated renewal.",
                            confidence=0.99,
                        )
                    )
            except ValueError:
                pass

        # Hostname / SAN match
        names: list[str] = []
        for entry in cert.get("subjectAltName", ()):  # (('DNS', 'example.com'), ...)
            if entry[0] in ("DNS", "IP Address"):
                names.append(entry[1])
        if names and not self._hostname_matches(host, names):
            findings.append(
                NormalizedFinding(
                    title="TLS certificate does not match the requested hostname",
                    description=(
                        f"The certificate presented for {host} is issued for "
                        f"{', '.join(names[:5])}. Clients cannot confirm they are talking to "
                        "the intended server."
                    ),
                    severity=Severity.MEDIUM,
                    target=ctx.target_value,
                    endpoint=host,
                    source=self.name,
                    category="Cryptographic Failure",
                    cwe="CWE-297",
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    evidence=f"Requested host: {host}\nCertificate names: {', '.join(names)}",
                    remediation="Issue a certificate covering the hostname actually served.",
                    confidence=0.9,
                )
            )
        return findings

    @staticmethod
    def _hostname_matches(host: str, names: list[str]) -> bool:
        host = host.lower()
        for name in names:
            name = name.lower()
            if name == host:
                return True
            if name.startswith("*.") and host.count(".") >= name.count(".") - 1:
                if host.endswith(name[1:]):
                    return True
        return False

    def _check_protocol(self, ctx: ScanContext, protocol, cipher, host, port) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        if protocol in _LEGACY_PROTOCOLS:
            severity, vector = _LEGACY_PROTOCOLS[protocol]
            findings.append(
                NormalizedFinding(
                    title=f"Deprecated TLS protocol in use ({protocol})",
                    description=(
                        f"The server negotiated {protocol}, which is deprecated and no longer "
                        "considered secure. Modern browsers refuse it and it is vulnerable to "
                        "known downgrade and padding-oracle attacks."
                    ),
                    severity=severity,
                    target=ctx.target_value,
                    endpoint=f"{host}:{port}",
                    source=self.name,
                    category="Cryptographic Failure",
                    cwe="CWE-327",
                    cvss_vector=vector,
                    evidence=f"Negotiated protocol: {protocol}",
                    remediation="Disable TLS 1.1 and below; require TLS 1.2 with TLS 1.3 preferred.",
                    confidence=0.97,
                )
            )
        if cipher:
            cipher_name, _, bits = cipher
            if any(token.lower() in cipher_name.lower() for token in _WEAK_CIPHER_TOKENS):
                findings.append(
                    NormalizedFinding(
                        title=f"Weak TLS cipher suite negotiated ({cipher_name})",
                        description=(
                            f"The server negotiated {cipher_name}, which relies on a cryptographic "
                            "primitive that is no longer considered safe."
                        ),
                        severity=Severity.MEDIUM,
                        target=ctx.target_value,
                        endpoint=f"{host}:{port}",
                        source=self.name,
                        category="Cryptographic Failure",
                        cwe="CWE-327",
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        evidence=f"Negotiated cipher: {cipher_name} ({bits} bits)",
                        remediation="Restrict the cipher list to modern AEAD suites (AES-GCM, ChaCha20-Poly1305).",
                        confidence=0.9,
                    )
                )
            elif bits and bits < 128:
                findings.append(
                    NormalizedFinding(
                        title=f"TLS cipher provides insufficient key strength ({bits} bits)",
                        description=f"The negotiated cipher {cipher_name} provides only {bits} bits of strength.",
                        severity=Severity.MEDIUM,
                        target=ctx.target_value,
                        endpoint=f"{host}:{port}",
                        source=self.name,
                        category="Cryptographic Failure",
                        cwe="CWE-326",
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        evidence=f"{cipher_name} ({bits} bits)",
                        remediation="Require cipher suites offering at least 128-bit strength.",
                        confidence=0.9,
                    )
                )
        return findings
