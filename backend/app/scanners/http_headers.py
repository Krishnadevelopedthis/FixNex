"""Built-in HTTP security header / cookie / CORS analyser.

Implemented in pure Python so that the LIGHT profile produces genuine results
on any installation, with no external tooling required.
"""
from __future__ import annotations

import re

import httpx

from app.core.config import settings
from app.models.enums import ScannerName, ScanProfile, Severity, TargetType
from app.scanners.base import (
    NormalizedFinding,
    ScanContext,
    ScannerAdapter,
    ScannerAvailability,
    ScanResult,
    truncate,
)

# Each check: header -> (title, severity, cwe, cvss vector, description, remediation)
_HEADER_CHECKS = {
    "content-security-policy": (
        "Missing Content-Security-Policy header",
        Severity.MEDIUM,
        "CWE-693",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "The application does not send a Content-Security-Policy header. CSP is the "
        "primary defence-in-depth control against cross-site scripting and content "
        "injection, restricting which script, style and frame sources a browser will load.",
        "Define a Content-Security-Policy that whitelists only the origins the application "
        "genuinely needs, starting from `default-src 'self'` and removing 'unsafe-inline'.",
    ),
    "strict-transport-security": (
        "Missing HTTP Strict-Transport-Security (HSTS) header",
        Severity.MEDIUM,
        "CWE-319",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "The server does not instruct browsers to use HTTPS exclusively. Without HSTS a "
        "user's first request, or any manually typed http:// URL, can be intercepted and "
        "downgraded by a network attacker.",
        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` over HTTPS.",
    ),
    "x-frame-options": (
        "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
        Severity.MEDIUM,
        "CWE-1021",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "The response permits the page to be embedded in a frame on another origin, "
        "allowing an attacker to overlay it and trick users into performing unintended "
        "actions (clickjacking).",
        "Send `X-Frame-Options: DENY` (or `SAMEORIGIN`) and a CSP `frame-ancestors` directive.",
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options header",
        Severity.LOW,
        "CWE-693",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "Without `nosniff`, browsers may MIME-sniff a response and interpret it as a type "
        "other than the one declared, which can turn an uploaded file into executable script.",
        "Send `X-Content-Type-Options: nosniff` on every response.",
    ),
    "referrer-policy": (
        "Missing Referrer-Policy header",
        Severity.LOW,
        "CWE-200",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "Without an explicit Referrer-Policy the full URL — potentially including session "
        "identifiers or other sensitive path/query data — may be sent to third-party sites.",
        "Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
    ),
}

_DISCLOSURE_HEADERS = {
    "server": "web server software and version",
    "x-powered-by": "application framework and version",
    "x-aspnet-version": "ASP.NET framework version",
    "x-generator": "content management system and version",
}

_VERSION_RE = re.compile(r"\d+\.\d+")


class HTTPHeadersAdapter(ScannerAdapter):
    name = ScannerName.HTTP_HEADERS
    label = "HTTP Security Headers"
    description = (
        "Analyses HTTP response headers, cookie attributes and CORS configuration. "
        "Built into FixNex — always available, non-invasive."
    )
    kind = "builtin"
    profiles = (ScanProfile.LIGHT, ScanProfile.STANDARD, ScanProfile.COMPREHENSIVE)
    target_types = (TargetType.WEB_APP, TargetType.REST_API)
    weight = 1

    def availability(self) -> ScannerAvailability:
        return ScannerAvailability(True, "Built-in adapter (no external dependency).")

    def run(self, ctx: ScanContext) -> ScanResult:
        result = ScanResult(scanner=self.name, command_summary=f"HTTP GET {ctx.url}")
        ctx.progress("Requesting target and reading response headers", 10)

        try:
            # Certificate problems are reported by the TLS adapter; this adapter
            # must still be able to inspect headers on a host with a bad cert.
            with httpx.Client(
                timeout=settings.HTTP_SCAN_TIMEOUT_SECONDS,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": "FixNex/1.0 (authorised security assessment)"},
            ) as client:
                response = client.get(ctx.url)
        except Exception as exc:
            result.error = f"Could not reach the target over HTTP: {type(exc).__name__}: {exc}"[:400]
            result.exit_code = 1
            return result

        headers = {k.lower(): v for k, v in response.headers.items()}
        result.exit_code = 0
        result.metrics = {
            "status_code": response.status_code,
            "final_url": str(response.url),
            "header_count": len(headers),
            "response_bytes": len(response.content),
        }
        findings: list[NormalizedFinding] = []
        ctx.progress("Evaluating security headers", 45)

        csp = headers.get("content-security-policy", "")
        for header, (title, severity, cwe, vector, description, remediation) in _HEADER_CHECKS.items():
            present = header in headers
            # A CSP frame-ancestors directive is an acceptable substitute for X-Frame-Options.
            if header == "x-frame-options" and "frame-ancestors" in csp.lower():
                present = True
            # HSTS is only meaningful over HTTPS.
            if header == "strict-transport-security" and not str(response.url).startswith("https"):
                continue
            if present:
                continue
            findings.append(
                NormalizedFinding(
                    title=title,
                    description=description,
                    severity=severity,
                    target=ctx.target_value,
                    endpoint=str(response.url),
                    source=self.name,
                    category="Security Misconfiguration",
                    cwe=cwe,
                    cvss_vector=vector,
                    evidence=f"Response from {response.url} (HTTP {response.status_code}) "
                    f"did not include the `{header}` header.",
                    remediation=remediation,
                    confidence=0.95,
                    references=["https://owasp.org/www-project-secure-headers/"],
                    raw={"missing_header": header, "status_code": response.status_code},
                )
            )

        ctx.progress("Checking information disclosure headers", 65)
        for header, what in _DISCLOSURE_HEADERS.items():
            value = headers.get(header)
            if not value:
                continue
            # Only flag when a version number is actually leaked.
            if header == "server" and not _VERSION_RE.search(value):
                continue
            findings.append(
                NormalizedFinding(
                    title=f"Information disclosure via `{header}` response header",
                    description=(
                        f"The server discloses its {what} in the `{header}` response header. "
                        "This lets an attacker map the technology stack to publicly known "
                        "vulnerabilities without any active probing."
                    ),
                    severity=Severity.LOW,
                    target=ctx.target_value,
                    endpoint=str(response.url),
                    source=self.name,
                    category="Information Disclosure",
                    cwe="CWE-200",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    evidence=f"{header}: {value}",
                    remediation=f"Suppress or genericise the `{header}` header at the web server or proxy.",
                    confidence=0.9,
                    raw={"header": header, "value": value},
                )
            )

        ctx.progress("Inspecting cookie attributes", 80)
        findings.extend(self._check_cookies(ctx, response))

        ctx.progress("Inspecting CORS configuration", 92)
        findings.extend(self._check_cors(ctx, headers, response))

        result.findings = findings
        return result

    # ------------------------------------------------------------------ cookies
    def _check_cookies(self, ctx: ScanContext, response) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        raw_cookies = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
        for cookie in raw_cookies:
            name = cookie.split("=", 1)[0].strip()
            lowered = cookie.lower()
            issues: list[tuple[str, str, str, str, str]] = []
            if "secure" not in lowered:
                issues.append((
                    "Secure", "CWE-614", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "the cookie may be transmitted over an unencrypted connection",
                    "Add the `Secure` attribute so the cookie is only sent over HTTPS.",
                ))
            if "httponly" not in lowered:
                issues.append((
                    "HttpOnly", "CWE-1004", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    "client-side JavaScript can read the cookie, so any XSS becomes session theft",
                    "Add the `HttpOnly` attribute to keep the cookie out of reach of scripts.",
                ))
            if "samesite" not in lowered:
                issues.append((
                    "SameSite", "CWE-1275", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    "the cookie is sent on cross-site requests, enabling cross-site request forgery",
                    "Add `SameSite=Lax` (or `Strict`) to the cookie.",
                ))
            for attribute, cwe, vector, consequence, remediation in issues:
                findings.append(
                    NormalizedFinding(
                        title=f"Cookie `{name}` set without the {attribute} attribute",
                        description=(
                            f"The cookie `{name}` is issued without the `{attribute}` attribute, "
                            f"which means {consequence}."
                        ),
                        severity=Severity.MEDIUM if attribute != "SameSite" else Severity.LOW,
                        target=ctx.target_value,
                        endpoint=str(response.url),
                        source=self.name,
                        category="Session Management",
                        parameter=name,
                        cwe=cwe,
                        cvss_vector=vector,
                        evidence=truncate(f"Set-Cookie: {cookie}", 500),
                        remediation=remediation,
                        confidence=0.92,
                        raw={"cookie": name, "attribute": attribute},
                    )
                )
        return findings

    # --------------------------------------------------------------------- CORS
    def _check_cors(self, ctx: ScanContext, headers: dict, response) -> list[NormalizedFinding]:
        origin = headers.get("access-control-allow-origin")
        credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
        if not origin:
            return []
        if origin == "*" and credentials:
            severity, cvss = Severity.HIGH, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
            detail = (
                "The application returns `Access-Control-Allow-Origin: *` together with "
                "`Access-Control-Allow-Credentials: true`. Browsers reject this combination, "
                "but it indicates a permissive CORS policy that frequently accompanies "
                "origin-reflection bugs allowing any site to read authenticated responses."
            )
        elif origin == "*":
            severity, cvss = Severity.LOW, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
            detail = (
                "The application allows any origin to read its responses via "
                "`Access-Control-Allow-Origin: *`. This is acceptable for genuinely public "
                "data, but exposes any non-public response served on this endpoint."
            )
        else:
            return []
        return [
            NormalizedFinding(
                title="Permissive Cross-Origin Resource Sharing (CORS) policy",
                description=detail,
                severity=severity,
                target=ctx.target_value,
                endpoint=str(response.url),
                source=self.name,
                category="Security Misconfiguration",
                cwe="CWE-942",
                cvss_vector=cvss,
                evidence=f"Access-Control-Allow-Origin: {origin}\n"
                f"Access-Control-Allow-Credentials: {credentials}",
                remediation=(
                    "Replace the wildcard with an explicit allow-list of trusted origins and "
                    "never combine a reflected origin with credentialed requests."
                ),
                confidence=0.88,
                raw={"allow_origin": origin, "allow_credentials": credentials},
            )
        ]
