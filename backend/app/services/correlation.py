"""Finding correlation and deduplication.

Several scanners routinely report the same underlying issue. Rather than
showing the analyst three copies, FixNex derives a stable correlation key
for each normalised finding and merges matches into a single finding that
carries one source record per contributing scanner.

    ZAP ──────┐
    Nuclei ───┤
    Nmap ─────┼──▶ normalise ──▶ correlate ──▶ deduplicate ──▶ Finding
    WhatWeb ──┘
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

from app.scanners.base import NormalizedFinding
from app.services import cwe as cwe_service

# Noise removed before comparing titles across tools.
_TITLE_NOISE = re.compile(
    r"\b(detected|found|discovered|possible|potential|issue|vulnerability|"
    r"misconfiguration|check|test|scanner|by\s+\w+)\b",
    re.IGNORECASE,
)
_VERSION_NOISE = re.compile(r"\b\d+(\.\d+)+\b")
_NON_WORD = re.compile(r"[^a-z0-9]+")


def normalize_title(title: str) -> str:
    """Reduce a scanner's title to a comparable canonical token."""
    text = (title or "").lower()
    text = _VERSION_NOISE.sub(" ", text)
    text = _TITLE_NOISE.sub(" ", text)
    text = _NON_WORD.sub(" ", text)
    tokens = sorted({t for t in text.split() if len(t) > 2})
    return " ".join(tokens)


def normalize_endpoint(endpoint: str | None) -> str:
    """Path-level identity: scheme, port, query string and fragment are ignored."""
    if not endpoint:
        return ""
    value = endpoint if "://" in endpoint else f"//{endpoint}"
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "/").rstrip("/") or "/"
    return f"{host}{path}"


def vulnerability_identity(finding: NormalizedFinding) -> str:
    """The strongest available identity signal for *what* the issue is.

    A shared CVE is the strongest signal, then a shared CWE, then the
    normalised title.
    """
    if finding.cve:
        return f"cve:{sorted(c.upper() for c in finding.cve)[0]}"
    cwe_id = cwe_service.normalize_cwe_id(finding.cwe) or cwe_service.infer_from_text(
        finding.title, finding.description
    )
    if cwe_id:
        return f"cwe:{cwe_id}"
    return f"title:{normalize_title(finding.title)}"


def correlation_key(finding: NormalizedFinding) -> str:
    """Stable key identifying one real-world issue, independent of scanner."""
    parts = [
        (finding.target or "").lower(),
        normalize_endpoint(finding.endpoint),
        vulnerability_identity(finding),
        (finding.parameter or "").lower(),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:40]


def deduplicate(findings: list[NormalizedFinding]) -> list[tuple[str, list[NormalizedFinding]]]:
    """Group normalised findings from one scan run by correlation key.

    Returns `(key, [findings])` groups in first-seen order; the caller decides
    how to merge each group into a persisted finding.
    """
    groups: dict[str, list[NormalizedFinding]] = {}
    order: list[str] = []
    for finding in findings:
        key = correlation_key(finding)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(finding)
    return [(key, groups[key]) for key in order]


def merge_group(group: list[NormalizedFinding]) -> NormalizedFinding:
    """Collapse correlated findings into the single richest representation.

    The highest severity wins, the most confident source wins, and text fields
    are filled from whichever scanner supplied the most detail.
    """
    from app.models.enums import SEVERITY_ORDER

    primary = max(
        group,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.confidence, len(f.description or "")),
    )
    merged = NormalizedFinding(
        title=primary.title,
        description=primary.description,
        severity=primary.severity,
        target=primary.target,
        endpoint=primary.endpoint,
        source=primary.source,
        category=primary.category,
        parameter=primary.parameter,
        http_method=primary.http_method,
        cwe=primary.cwe,
        cvss=primary.cvss,
        cvss_vector=primary.cvss_vector,
        evidence=primary.evidence,
        request_snippet=primary.request_snippet,
        response_snippet=primary.response_snippet,
        remediation=primary.remediation,
        confidence=primary.confidence,
        raw=dict(primary.raw),
    )

    for finding in group:
        for cve in finding.cve:
            if cve.upper() not in merged.cve:
                merged.cve.append(cve.upper())
        for reference in finding.references:
            if reference not in merged.references:
                merged.references.append(reference)
        merged.cwe = merged.cwe or finding.cwe
        merged.cvss = merged.cvss if merged.cvss is not None else finding.cvss
        merged.cvss_vector = merged.cvss_vector or finding.cvss_vector
        merged.description = merged.description or finding.description
        merged.remediation = merged.remediation or finding.remediation
        merged.evidence = merged.evidence or finding.evidence
        merged.request_snippet = merged.request_snippet or finding.request_snippet
        merged.response_snippet = merged.response_snippet or finding.response_snippet
        merged.parameter = merged.parameter or finding.parameter

    # Independent confirmation by several tools raises confidence, capped at 0.99.
    distinct_sources = {f.source for f in group}
    if len(distinct_sources) > 1:
        merged.confidence = min(0.99, merged.confidence + 0.05 * (len(distinct_sources) - 1))

    merged.references = merged.references[:10]
    return merged
