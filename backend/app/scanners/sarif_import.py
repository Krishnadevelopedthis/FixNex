"""SARIF 2.1.0 import.

SARIF is the OASIS interchange format that most SAST, IaC, container and secret
scanners can emit — Semgrep, Trivy, Gitleaks, Snyk, Checkov, CodeQL, SonarQube
and many others. Parsing it here means FixNex ingests any of those tools
without writing a dedicated adapter for each: the file is converted into the
same `NormalizedFinding` list every adapter produces, then handed to the
existing ingest pipeline (normalise → correlate → score → risk → persist).

Unlike the live adapters this is not a `ScannerAdapter` — nothing is executed.
It converts results a tool produced elsewhere, and the resulting findings are
attributed to `imported:<tool>` so their provenance stays explicit.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from app.core.exceptions import ValidationError
from app.models.enums import Severity
from app.scanners.base import (
    NormalizedFinding,
    extract_cves,
    normalize_severity,
    severity_from_cvss,
    truncate,
)

logger = logging.getLogger("prcampus.sarif")

MAX_SARIF_BYTES = 20 * 1024 * 1024
MAX_RESULTS = 5000

# SARIF's `level` vocabulary is small and its own; mapping it explicitly is more
# faithful than relying on the generic alias table, which reads "error" as a
# mid-severity word rather than a SARIF failure level.
SARIF_LEVEL_SEVERITY: dict[str, str] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFORMATIONAL,
}

# Tools commonly tag rules with CWE identifiers in these shapes:
#   "CWE-89"  |  "external/cwe/cwe-089"  |  "cwe:89"
_CWE_TAG = re.compile(r"cwe[-/:]?0*(\d{1,5})", re.IGNORECASE)


def _text(node: Any) -> str | None:
    """SARIF multiformatMessageString → plain text."""
    if node is None:
        return None
    if isinstance(node, str):
        return node or None
    if isinstance(node, dict):
        return node.get("text") or node.get("markdown") or None
    return None


def _cwe_from(*sources: Any) -> str | None:
    for source in sources:
        if not source:
            continue
        haystack = source if isinstance(source, str) else json.dumps(source)
        match = _CWE_TAG.search(haystack)
        if match:
            return f"CWE-{int(match.group(1))}"
    return None


def _rule_index(run: dict) -> dict[str, dict]:
    """Rule metadata by ruleId, across the driver and any extensions."""
    rules: dict[str, dict] = {}
    tool = run.get("tool") or {}
    components = [tool.get("driver") or {}, *(tool.get("extensions") or [])]
    for component in components:
        for rule in component.get("rules") or []:
            rule_id = rule.get("id")
            if rule_id:
                rules[str(rule_id)] = rule
    return rules


def _resolve_rule(result: dict, run: dict, rules: dict[str, dict]) -> dict:
    """Find a result's rule via ruleId, then fall back to ruleIndex."""
    rule_id = result.get("ruleId")
    if rule_id and str(rule_id) in rules:
        return rules[str(rule_id)]
    index = result.get("ruleIndex")
    if isinstance(index, int) and index >= 0:
        driver_rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        if index < len(driver_rules):
            return driver_rules[index]
    return {}


def _severity_for(result: dict, rule: dict) -> str:
    """Resolve severity, preferring a numeric score over the coarse level.

    `security-severity` is the convention GitHub code scanning and most SARIF
    producers use to carry a CVSS-style 0-10 number; it is far more precise
    than SARIF's four levels, so it wins when present.
    """
    for holder in (result.get("properties") or {}, rule.get("properties") or {}):
        raw = holder.get("security-severity") or holder.get("security_severity")
        if raw is not None:
            try:
                return severity_from_cvss(float(raw))
            except (TypeError, ValueError):
                pass

    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    if level:
        key = str(level).lower()
        if key in SARIF_LEVEL_SEVERITY:
            return SARIF_LEVEL_SEVERITY[key]
        # Anything outside the SARIF vocabulary still goes through the shared
        # alias table so unusual producers degrade sensibly.
        return normalize_severity(level)
    return Severity.INFORMATIONAL


def _cvss_from(result: dict, rule: dict) -> float | None:
    for holder in (result.get("properties") or {}, rule.get("properties") or {}):
        raw = holder.get("security-severity") or holder.get("security_severity")
        if raw is not None:
            try:
                score = float(raw)
            except (TypeError, ValueError):
                continue
            if 0.0 <= score <= 10.0:
                return round(score, 1)
    return None


def _location(result: dict) -> tuple[str | None, str | None]:
    """Return (endpoint, code snippet) from the first physical/logical location."""
    for location in result.get("locations") or []:
        physical = location.get("physicalLocation") or {}
        artifact = physical.get("artifactLocation") or {}
        uri = artifact.get("uri")
        if uri:
            region = physical.get("region") or {}
            line = region.get("startLine")
            endpoint = f"{uri}:{line}" if line else uri
            snippet = _text((region.get("snippet") or {}))
            return endpoint[:600], truncate(snippet, 2000)
        logical = location.get("logicalLocations") or []
        if logical:
            name = logical[0].get("fullyQualifiedName") or logical[0].get("name")
            if name:
                return str(name)[:600], None
    return None, None


def _is_suppressed(result: dict) -> bool:
    """SARIF suppressions mean the producing tool already dismissed the result."""
    for suppression in result.get("suppressions") or []:
        if str(suppression.get("status", "accepted")).lower() in ("accepted", ""):
            return True
    return False


def tool_name_from(document: dict) -> str | None:
    """Best-effort tool name straight out of the document."""
    for run in document.get("runs") or []:
        driver = ((run.get("tool") or {}).get("driver") or {})
        name = driver.get("name")
        if name:
            return str(name)
    return None


def parse_sarif_bytes(raw: bytes, tool_name: str, target_value: str = "") -> tuple[list[NormalizedFinding], dict]:
    """Parse raw SARIF bytes. Returns (findings, metrics)."""
    if len(raw) > MAX_SARIF_BYTES:
        raise ValidationError(
            f"The SARIF file is larger than the {MAX_SARIF_BYTES // (1024 * 1024)} MB limit."
        )
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise ValidationError("The SARIF file must be UTF-8 encoded.") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"The file is not valid JSON: {exc}") from exc
    return parse_sarif(document, tool_name, target_value)


def parse_sarif(document: dict, tool_name: str, target_value: str = "") -> tuple[list[NormalizedFinding], dict]:
    """Convert a SARIF 2.1.0 document into normalised findings."""
    if not isinstance(document, dict):
        raise ValidationError("The SARIF document must be a JSON object.")

    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValidationError(
            "The SARIF document contains no runs. Check that this is a SARIF report "
            "and not another JSON format."
        )

    version = str(document.get("version") or "")
    if version and not version.startswith("2."):
        logger.info("SARIF version %s is outside 2.x; parsing on a best-effort basis.", version)

    source = f"imported:{tool_name}"
    findings: list[NormalizedFinding] = []
    suppressed = 0
    truncated = False

    for run in runs:
        if not isinstance(run, dict):
            continue
        rules = _rule_index(run)
        driver = ((run.get("tool") or {}).get("driver") or {})
        driver_name = driver.get("name") or tool_name

        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            if len(findings) >= MAX_RESULTS:
                truncated = True
                break
            if _is_suppressed(result):
                suppressed += 1
                continue

            rule = _resolve_rule(result, run, rules)
            rule_id = str(result.get("ruleId") or rule.get("id") or "")

            message = _text(result.get("message")) or ""
            rule_short = _text(rule.get("shortDescription"))
            rule_full = _text(rule.get("fullDescription"))

            # Prefer a human rule name for the title, then the message, then the id.
            title = (
                rule.get("name")
                or rule_short
                or (message.split("\n")[0] if message else None)
                or rule_id
                or "Imported finding"
            )

            description = message or rule_full or rule_short or ""
            if rule_full and message and rule_full not in message:
                description = f"{message}\n\n{rule_full}"

            tags = (rule.get("properties") or {}).get("tags") or []
            cwe = _cwe_from(rule_id, tags, rule.get("properties"), result.get("properties"),
                            rule_short, rule_full, message)

            endpoint, snippet = _location(result)
            help_text = _text(rule.get("help"))
            help_uri = rule.get("helpUri")

            references = [str(help_uri)] if help_uri else []
            for tag in tags:
                if isinstance(tag, str) and tag.startswith("http"):
                    references.append(tag)

            severity = _severity_for(result, rule)

            findings.append(
                NormalizedFinding(
                    title=str(title)[:300],
                    description=truncate(description, 6000) or "",
                    severity=severity,
                    target=target_value,
                    endpoint=endpoint,
                    source=source,
                    # The rule id is the most useful grouping label these tools give us.
                    category=(rule_id or driver_name or "Imported")[:120],
                    cwe=cwe,
                    cve=extract_cves(rule_id, message, rule_full, json.dumps(tags) if tags else None),
                    cvss=_cvss_from(result, rule),
                    evidence=snippet or truncate(message, 2000),
                    remediation=help_text,
                    references=references[:8],
                    # Imported results are third-party assertions that still need an
                    # analyst's verification, so confidence stays deliberately moderate.
                    confidence=0.7,
                    raw={
                        "rule_id": rule_id,
                        "tool": driver_name,
                        "level": result.get("level"),
                        "sarif_version": version or "unknown",
                        "fingerprints": result.get("partialFingerprints") or {},
                    },
                )
            )
        if truncated:
            break

    metrics = {
        "tool": tool_name,
        "sarif_version": version or "unknown",
        "runs": len(runs),
        "results_imported": len(findings),
        "results_suppressed": suppressed,
        "truncated": truncated,
    }
    return findings, metrics
