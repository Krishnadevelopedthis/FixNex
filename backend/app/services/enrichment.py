"""CVE enrichment via the NVD API, with database-backed caching.

The platform never keeps its own CVE database: identifiers found by scanners
are looked up on demand and cached. If NVD is unreachable or no API key is
configured, enrichment degrades to a link-only record and the finding still
carries its CVE identifier.
"""
from __future__ import annotations

import logging
import re
from datetime import timedelta

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.base import utcnow
from app.models.enums import EnrichmentSource
from app.models.system import EnrichmentCache
from app.scanners.base import severity_from_cvss

logger = logging.getLogger("prcampus.enrichment")

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def _cache_get(db: Session, source: str, key: str) -> dict | None:
    entry = (
        db.query(EnrichmentCache)
        .filter(EnrichmentCache.source == source, EnrichmentCache.cache_key == key)
        .first()
    )
    if entry is None:
        return None
    if entry.expires_at and entry.expires_at < utcnow():
        return None
    return entry.payload


def _cache_put(db: Session, source: str, key: str, payload: dict) -> None:
    entry = (
        db.query(EnrichmentCache)
        .filter(EnrichmentCache.source == source, EnrichmentCache.cache_key == key)
        .first()
    )
    now = utcnow()
    expires = now + timedelta(hours=settings.ENRICHMENT_CACHE_TTL_HOURS)
    if entry:
        entry.payload = payload
        entry.fetched_at = now
        entry.expires_at = expires
    else:
        db.add(
            EnrichmentCache(
                source=source, cache_key=key, payload=payload, fetched_at=now, expires_at=expires
            )
        )


def _fallback(cve_id: str, reason: str) -> dict:
    return {
        "cve_id": cve_id,
        "description": None,
        "cvss_score": None,
        "cvss_vector": None,
        "severity": None,
        "published": None,
        "source": "NVD",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "enriched": False,
        "detail": reason,
    }


def lookup_cve(db: Session, cve_id: str) -> dict:
    """Return normalised NVD data for one CVE identifier."""
    cve_id = cve_id.strip().upper()
    if not CVE_RE.match(cve_id):
        return _fallback(cve_id, "Not a well-formed CVE identifier.")

    cached = _cache_get(db, EnrichmentSource.NVD, cve_id)
    if cached is not None:
        return cached

    if settings.OFFLINE_MODE:
        return _fallback(cve_id, "Offline mode is enabled; NVD was not queried.")

    headers = {"User-Agent": "FixNex/1.0"}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    try:
        response = httpx.get(
            settings.NVD_API_BASE,
            params={"cveId": cve_id},
            headers=headers,
            timeout=settings.NVD_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        logger.info("NVD lookup for %s failed: %s", cve_id, exc)
        return _fallback(cve_id, f"NVD was unreachable ({type(exc).__name__}).")

    vulnerabilities = data.get("vulnerabilities") or []
    if not vulnerabilities:
        payload = _fallback(cve_id, "No record for this identifier was returned by NVD.")
        _cache_put(db, EnrichmentSource.NVD, cve_id, payload)
        return payload

    cve = vulnerabilities[0].get("cve", {})
    description = next(
        (d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), None
    )

    score = vector = severity = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        cvss_data = entries[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        vector = cvss_data.get("vectorString")
        severity = cvss_data.get("baseSeverity") or (
            severity_from_cvss(float(score)) if score is not None else None
        )
        break

    weaknesses = [
        d.get("value")
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if str(d.get("value", "")).startswith("CWE-")
    ]

    payload = {
        "cve_id": cve_id,
        "description": (description or "")[:4000] or None,
        "cvss_score": float(score) if score is not None else None,
        "cvss_vector": vector,
        "severity": (severity or "").upper() or None,
        "published": cve.get("published"),
        "cwes": weaknesses[:5],
        "source": "NVD",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "enriched": True,
    }
    _cache_put(db, EnrichmentSource.NVD, cve_id, payload)
    return payload


def enrich_cves(db: Session, cve_ids: list[str], limit: int = 5) -> list[dict]:
    """Look up several CVEs, capped so a single finding cannot stall a scan."""
    results: list[dict] = []
    for cve_id in list(dict.fromkeys(cve_ids))[:limit]:
        try:
            results.append(lookup_cve(db, cve_id))
        except Exception:  # pragma: no cover - enrichment is best-effort
            logger.exception("Unexpected error enriching %s", cve_id)
            results.append(_fallback(cve_id, "An unexpected error occurred during enrichment."))
    return results
