"""Built-in technology fingerprinting.

Serves as the always-available fallback for WhatWeb: detects web server,
framework, CMS and front-end libraries from response headers, cookies and
markup. Results also populate the target's technology inventory.
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

# name -> (where, regex, category)  where in {"header", "body", "cookie"}
_SIGNATURES: list[tuple[str, str, str, str]] = [
    ("nginx", "header:server", r"nginx(?:/([\d.]+))?", "Web Server"),
    ("Apache HTTP Server", "header:server", r"apache(?:/([\d.]+))?", "Web Server"),
    ("Microsoft IIS", "header:server", r"microsoft-iis(?:/([\d.]+))?", "Web Server"),
    ("LiteSpeed", "header:server", r"litespeed", "Web Server"),
    ("Caddy", "header:server", r"caddy", "Web Server"),
    ("Cloudflare", "header:server", r"cloudflare", "CDN"),
    ("Express", "header:x-powered-by", r"express", "Framework"),
    ("PHP", "header:x-powered-by", r"php(?:/([\d.]+))?", "Language"),
    ("ASP.NET", "header:x-powered-by", r"asp\.net", "Framework"),
    ("Next.js", "header:x-powered-by", r"next\.js", "Framework"),
    ("Django", "cookie", r"csrftoken", "Framework"),
    ("Flask / Werkzeug", "header:server", r"werkzeug(?:/([\d.]+))?", "Framework"),
    ("Ruby on Rails", "cookie", r"_session_id|_rails", "Framework"),
    ("Java / Servlet container", "cookie", r"jsessionid", "Framework"),
    ("PHP session", "cookie", r"phpsessid", "Language"),
    ("Laravel", "cookie", r"laravel_session", "Framework"),
    ("WordPress", "body", r"wp-content|wp-includes", "CMS"),
    ("Drupal", "body", r"drupal\.settings|sites/all/", "CMS"),
    ("Joomla", "body", r"/media/jui/|joomla", "CMS"),
    ("React", "body", r"__REACT_DEVTOOLS|data-reactroot|react(?:-dom)?[.-][\d.]*min\.js", "Frontend"),
    ("Vue.js", "body", r"__VUE__|vue(?:\.runtime)?[.-][\d.]*min\.js", "Frontend"),
    ("Angular", "body", r"ng-version|angular[.-][\d.]*min\.js", "Frontend"),
    ("jQuery", "body", r"jquery[.-]([\d.]+)(?:\.min)?\.js", "Frontend"),
    ("Bootstrap", "body", r"bootstrap[.-]([\d.]+)?(?:\.min)?\.css", "Frontend"),
    ("FastAPI / Starlette", "header:server", r"uvicorn", "Framework"),
    ("Vite", "body", r"/@vite/client|type=\"module\".*?/assets/", "Build Tool"),
]

_GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


class TechFingerprintAdapter(ScannerAdapter):
    name = ScannerName.TECH_FINGERPRINT
    label = "Technology Fingerprinting"
    description = (
        "Identifies web server, framework, CMS and front-end libraries from headers, "
        "cookies and markup. Built into FixNex — always available, non-invasive."
    )
    kind = "builtin"
    profiles = (ScanProfile.LIGHT, ScanProfile.STANDARD, ScanProfile.COMPREHENSIVE)
    target_types = (TargetType.WEB_APP, TargetType.REST_API)
    weight = 1

    def availability(self) -> ScannerAvailability:
        return ScannerAvailability(True, "Built-in adapter (no external dependency).")

    def run(self, ctx: ScanContext) -> ScanResult:
        result = ScanResult(scanner=self.name, command_summary=f"Fingerprint {ctx.url}")
        ctx.progress("Fetching target for fingerprinting", 20)
        try:
            with httpx.Client(
                timeout=settings.HTTP_SCAN_TIMEOUT_SECONDS,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": "FixNex/1.0 (authorised security assessment)"},
            ) as client:
                response = client.get(ctx.url)
        except Exception as exc:
            result.error = f"Could not reach the target: {type(exc).__name__}: {exc}"[:400]
            result.exit_code = 1
            return result

        result.exit_code = 0
        headers = {k.lower(): v for k, v in response.headers.items()}
        body = response.text[:400_000]
        cookies = " ".join(response.headers.get_list("set-cookie")) if hasattr(response.headers, "get_list") else ""

        ctx.progress("Matching technology signatures", 60)
        detected: list[dict] = []
        for tech_name, where, pattern, category in _SIGNATURES:
            if where.startswith("header:"):
                haystack = headers.get(where.split(":", 1)[1], "")
            elif where == "cookie":
                haystack = cookies
            else:
                haystack = body
            if not haystack:
                continue
            match = re.search(pattern, haystack, re.I)
            if match:
                version = next((g for g in match.groups() if g), None) if match.groups() else None
                detected.append({"name": tech_name, "category": category, "version": version})

        generator = _GENERATOR_RE.search(body)
        if generator:
            detected.append({"name": generator.group(1).strip()[:80], "category": "Generator", "version": None})

        # De-duplicate, preferring entries that carry a version.
        unique: dict[str, dict] = {}
        for item in detected:
            existing = unique.get(item["name"])
            if existing is None or (item["version"] and not existing["version"]):
                unique[item["name"]] = item
        technologies = list(unique.values())

        title_match = _TITLE_RE.search(body)
        result.metrics = {
            "technologies": technologies,
            "status_code": response.status_code,
            "page_title": (title_match.group(1).strip()[:120] if title_match else None),
        }

        ctx.progress("Recording technology inventory", 90)
        findings: list[NormalizedFinding] = []
        if technologies:
            summary = ", ".join(
                f"{t['name']}{' ' + t['version'] if t['version'] else ''}" for t in technologies
            )
            findings.append(
                NormalizedFinding(
                    title="Technology stack fingerprinted",
                    description=(
                        "The following technologies were identified from publicly visible "
                        f"response data: {summary}. This is recorded for asset inventory and "
                        "to guide targeted vulnerability checks; it is not a vulnerability in "
                        "itself."
                    ),
                    severity=Severity.INFORMATIONAL,
                    target=ctx.target_value,
                    endpoint=str(response.url),
                    source=self.name,
                    category="Reconnaissance",
                    cwe="CWE-200",
                    evidence=truncate(summary, 1500),
                    remediation=(
                        "Where practical, suppress version banners so that the exact software "
                        "version is not disclosed to unauthenticated visitors."
                    ),
                    confidence=0.85,
                    raw={"technologies": technologies},
                )
            )

        # A disclosed version number is directly actionable for an attacker.
        versioned = [t for t in technologies if t["version"]]
        if versioned:
            listed = ", ".join(f"{t['name']} {t['version']}" for t in versioned)
            findings.append(
                NormalizedFinding(
                    title="Software version numbers disclosed",
                    description=(
                        f"Exact version numbers were recovered for: {listed}. An attacker can "
                        "match these against public vulnerability databases to select working "
                        "exploits without touching the application."
                    ),
                    severity=Severity.LOW,
                    target=ctx.target_value,
                    endpoint=str(response.url),
                    source=self.name,
                    category="Information Disclosure",
                    cwe="CWE-200",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    evidence=listed,
                    remediation="Remove or genericise version banners in headers, markup and asset paths.",
                    confidence=0.8,
                    raw={"versioned": versioned},
                )
            )

        result.findings = findings
        return result
