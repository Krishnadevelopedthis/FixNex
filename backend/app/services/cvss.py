"""CVSS v3.1 scoring.

Backed by the `cvss` library's reference implementation — FixNex never
invents its own base-score arithmetic. Where a scanner supplies no vector, a
representative vector for the reported severity is used and clearly recorded.
"""
from __future__ import annotations

import logging

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

from app.models.enums import Severity
from app.scanners.base import severity_from_cvss

logger = logging.getLogger("prcampus.cvss")

# Representative vectors used only when a scanner reports a severity but no
# vector. Flagged via `estimated=True` so the UI can show it as an estimate.
_SEVERITY_TEMPLATE_VECTORS: dict[str, str] = {
    Severity.CRITICAL: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    Severity.HIGH: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    Severity.MEDIUM: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    Severity.LOW: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    Severity.INFORMATIONAL: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
}


class CVSSResult:
    __slots__ = ("score", "vector", "severity", "version", "estimated", "metrics")

    def __init__(self, score, vector, severity, version, estimated=False, metrics=None):
        self.score = score
        self.vector = vector
        self.severity = severity
        self.version = version
        self.estimated = estimated
        self.metrics = metrics or {}

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "vector": self.vector,
            "severity": self.severity,
            "version": self.version,
            "estimated": self.estimated,
            "metrics": self.metrics,
        }


def parse_vector(vector: str) -> CVSSResult | None:
    """Parse and score a CVSS v2 / v3.x / v4.0 vector string."""
    if not vector or not vector.strip():
        return None
    vector = vector.strip()
    try:
        if vector.startswith("CVSS:4"):
            parsed = CVSS4(vector)
            score = float(parsed.base_score)
            version = "4.0"
        elif vector.startswith("CVSS:3"):
            parsed = CVSS3(vector)
            score = float(parsed.base_score)
            version = "3.1" if vector.startswith("CVSS:3.1") else "3.0"
        else:
            parsed = CVSS2(vector)
            score = float(parsed.base_score)
            version = "2.0"
    except (CVSSError, Exception) as exc:  # noqa: BLE001 - any malformed vector
        logger.debug("Could not parse CVSS vector %r: %s", vector, exc)
        return None

    return CVSSResult(
        score=round(score, 1),
        vector=vector,
        severity=severity_from_cvss(score),
        version=version,
        estimated=False,
        metrics=_describe(vector),
    )


def score_finding(
    vector: str | None, reported_score: float | None, reported_severity: str | None
) -> CVSSResult:
    """Resolve the best available CVSS score for a normalised finding.

    Precedence: an explicit vector, then a scanner-reported numeric score, then
    a representative vector derived from the reported severity.
    """
    parsed = parse_vector(vector) if vector else None
    if parsed:
        return parsed

    if reported_score is not None:
        try:
            score = round(float(reported_score), 1)
        except (TypeError, ValueError):
            score = None
        if score is not None and 0.0 <= score <= 10.0:
            return CVSSResult(
                score=score,
                vector=None,
                severity=severity_from_cvss(score),
                version="3.1",
                estimated=False,
            )

    severity = reported_severity if reported_severity in _SEVERITY_TEMPLATE_VECTORS else Severity.INFORMATIONAL
    template = _SEVERITY_TEMPLATE_VECTORS[severity]
    parsed_template = parse_vector(template)
    return CVSSResult(
        score=parsed_template.score if parsed_template else 0.0,
        vector=template,
        severity=severity,
        version="3.1",
        estimated=True,
        metrics=_describe(template),
    )


_METRIC_LABELS = {
    "AV": ("Attack Vector", {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
    "AC": ("Attack Complexity", {"L": "Low", "H": "High"}),
    "PR": ("Privileges Required", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("User Interaction", {"N": "None", "R": "Required"}),
    "S": ("Scope", {"U": "Unchanged", "C": "Changed"}),
    "C": ("Confidentiality", {"H": "High", "L": "Low", "N": "None"}),
    "I": ("Integrity", {"H": "High", "L": "Low", "N": "None"}),
    "A": ("Availability", {"H": "High", "L": "Low", "N": "None"}),
}


def _describe(vector: str) -> dict:
    """Human-readable breakdown of a CVSS vector for the finding detail page."""
    described: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        if key in _METRIC_LABELS:
            label, values = _METRIC_LABELS[key]
            described[label] = values.get(value, value)
    return described


def validate_vector(vector: str) -> bool:
    return parse_vector(vector) is not None
