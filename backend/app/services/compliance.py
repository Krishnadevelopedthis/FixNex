"""Compliance mapping and readiness rollup.

Findings are engineering artefacts; audits are asked in the language of control
frameworks. This maps the weaknesses FixNex actually produces onto OWASP Top
10 categories and the NIST SP 800-53 Rev. 5 and ISO/IEC 27001:2022 controls
those weaknesses bear on, then reports readiness per control.

Scope is deliberate: the table covers the CWEs already in `services/cwe.py`
rather than attempting all 900+ MITRE entries. A mapping nobody maintains is
worse than a small one that is honest about its edges — `coverage` reports how
many findings the table actually recognised.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models.enums import SEVERITY_ORDER, FindingStatus, Severity, VerificationStatus
from app.models.finding import Finding
from app.services import cwe as cwe_service


@dataclass(frozen=True)
class ControlRef:
    id: str
    title: str


# --------------------------------------------------------------------------
# Framework control catalogues (only the controls this mapping references)
# --------------------------------------------------------------------------
NIST_CONTROLS: dict[str, str] = {
    "AC-3": "Access Enforcement",
    "AC-6": "Least Privilege",
    "AU-2": "Event Logging",
    "AU-6": "Audit Record Review, Analysis and Reporting",
    "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality",
    "IA-2": "Identification and Authentication (Organizational Users)",
    "IA-5": "Authenticator Management",
    "RA-5": "Vulnerability Monitoring and Scanning",
    "SA-11": "Developer Testing and Evaluation",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-13": "Cryptographic Protection",
    "SC-23": "Session Authenticity",
    "SC-28": "Protection of Information at Rest",
    "SI-2": "Flaw Remediation",
    "SI-10": "Information Input Validation",
    "SI-11": "Error Handling",
}

ISO_CONTROLS: dict[str, str] = {
    "A.5.15": "Access control",
    "A.5.17": "Authentication information",
    "A.5.18": "Access rights",
    "A.8.2": "Privileged access rights",
    "A.8.5": "Secure authentication",
    "A.8.8": "Management of technical vulnerabilities",
    "A.8.9": "Configuration management",
    "A.8.12": "Data leakage prevention",
    "A.8.15": "Logging",
    "A.8.24": "Use of cryptography",
    "A.8.25": "Secure development life cycle",
    "A.8.26": "Application security requirements",
    "A.8.28": "Secure coding",
}

# OWASP Top 10:2021 categories used by the mapping.
OWASP_CATEGORIES: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}


@dataclass(frozen=True)
class Mapping:
    owasp: str
    nist: tuple[str, ...]
    iso: tuple[str, ...]


# CWE -> OWASP category -> framework controls.
CWE_MAPPING: dict[str, Mapping] = {
    # --- Injection -------------------------------------------------------
    "CWE-89": Mapping("A03", ("SI-10", "SA-11"), ("A.8.28", "A.8.26")),
    "CWE-79": Mapping("A03", ("SI-10", "SA-11"), ("A.8.28", "A.8.26")),
    "CWE-78": Mapping("A03", ("SI-10", "CM-7"), ("A.8.28",)),
    "CWE-94": Mapping("A03", ("SI-10", "SA-11"), ("A.8.28",)),
    "CWE-98": Mapping("A03", ("SI-10", "CM-7"), ("A.8.28",)),
    "CWE-90": Mapping("A03", ("SI-10",), ("A.8.28",)),
    "CWE-611": Mapping("A05", ("SI-10", "CM-6"), ("A.8.28", "A.8.9")),
    "CWE-22": Mapping("A01", ("AC-3", "SI-10"), ("A.5.15", "A.8.28")),
    "CWE-20": Mapping("A03", ("SI-10",), ("A.8.28",)),
    "CWE-915": Mapping("A03", ("SI-10",), ("A.8.28",)),
    # --- Broken access control -------------------------------------------
    "CWE-284": Mapping("A01", ("AC-3", "AC-6"), ("A.5.15", "A.5.18")),
    "CWE-285": Mapping("A01", ("AC-3",), ("A.5.15",)),
    "CWE-639": Mapping("A01", ("AC-3",), ("A.5.15",)),
    "CWE-862": Mapping("A01", ("AC-3", "AC-6"), ("A.5.15", "A.5.18")),
    "CWE-863": Mapping("A01", ("AC-3",), ("A.5.15",)),
    "CWE-269": Mapping("A01", ("AC-6",), ("A.8.2",)),
    "CWE-732": Mapping("A01", ("AC-3", "AC-6"), ("A.5.15", "A.8.2")),
    "CWE-601": Mapping("A01", ("SI-10",), ("A.8.28",)),
    # --- Cryptographic failures ------------------------------------------
    "CWE-319": Mapping("A02", ("SC-8", "SC-13"), ("A.8.24",)),
    "CWE-311": Mapping("A02", ("SC-8", "SC-28"), ("A.8.24",)),
    "CWE-326": Mapping("A02", ("SC-13",), ("A.8.24",)),
    "CWE-327": Mapping("A02", ("SC-13",), ("A.8.24",)),
    "CWE-295": Mapping("A02", ("SC-8", "SC-13"), ("A.8.24",)),
    "CWE-297": Mapping("A02", ("SC-8",), ("A.8.24",)),
    "CWE-298": Mapping("A02", ("SC-8",), ("A.8.24",)),
    "CWE-256": Mapping("A02", ("IA-5", "SC-28"), ("A.5.17", "A.8.24")),
    "CWE-522": Mapping("A02", ("IA-5",), ("A.5.17",)),
    # --- Authentication ---------------------------------------------------
    "CWE-287": Mapping("A07", ("IA-2",), ("A.8.5",)),
    "CWE-306": Mapping("A07", ("IA-2", "AC-3"), ("A.8.5", "A.5.15")),
    "CWE-521": Mapping("A07", ("IA-5",), ("A.5.17", "A.8.5")),
    "CWE-798": Mapping("A07", ("IA-5",), ("A.5.17",)),
    "CWE-384": Mapping("A07", ("SC-23",), ("A.8.5",)),
    "CWE-613": Mapping("A07", ("SC-23", "IA-2"), ("A.8.5",)),
    # --- Session management ----------------------------------------------
    "CWE-614": Mapping("A05", ("SC-8", "SC-23"), ("A.8.24", "A.8.9")),
    "CWE-1004": Mapping("A05", ("SC-23",), ("A.8.9",)),
    "CWE-1275": Mapping("A05", ("SC-23",), ("A.8.9",)),
    "CWE-352": Mapping("A01", ("SC-23", "AC-3"), ("A.5.15",)),
    "CWE-565": Mapping("A05", ("SC-23",), ("A.8.9",)),
    # --- Misconfiguration -------------------------------------------------
    "CWE-693": Mapping("A05", ("CM-6",), ("A.8.9",)),
    "CWE-1021": Mapping("A05", ("CM-6",), ("A.8.9",)),
    "CWE-942": Mapping("A05", ("CM-6", "AC-3"), ("A.8.9", "A.5.15")),
    "CWE-548": Mapping("A05", ("CM-6", "CM-7"), ("A.8.9", "A.8.12")),
    "CWE-668": Mapping("A05", ("CM-7", "AC-3"), ("A.8.9", "A.5.15")),
    # --- Information disclosure -------------------------------------------
    "CWE-200": Mapping("A05", ("CM-6", "SC-28"), ("A.8.12",)),
    "CWE-209": Mapping("A05", ("SI-11", "CM-6"), ("A.8.12",)),
    "CWE-359": Mapping("A02", ("SC-28",), ("A.8.12",)),
    # --- Components and integrity ------------------------------------------
    "CWE-502": Mapping("A08", ("SI-2", "SI-10"), ("A.8.8", "A.8.28")),
    "CWE-829": Mapping("A08", ("SI-2", "CM-7"), ("A.8.8",)),
    "CWE-434": Mapping("A04", ("SI-10", "CM-7"), ("A.8.26",)),
    "CWE-190": Mapping("A04", ("SI-10",), ("A.8.28",)),
    "CWE-119": Mapping("A06", ("SI-2",), ("A.8.8",)),
    # --- SSRF, availability, logging ---------------------------------------
    "CWE-918": Mapping("A10", ("SC-8", "AC-3"), ("A.8.26",)),
    "CWE-400": Mapping("A04", ("SC-8",), ("A.8.26",)),
    "CWE-778": Mapping("A09", ("AU-2", "AU-6"), ("A.8.15",)),
}

FRAMEWORKS = {
    "NIST_800_53": {"label": "NIST SP 800-53 Rev. 5", "controls": NIST_CONTROLS},
    "ISO_27001": {"label": "ISO/IEC 27001:2022 Annex A", "controls": ISO_CONTROLS},
}

# Findings that no longer count against a control.
_RESOLVED = (FindingStatus.CLOSED,)


def map_cwe(cwe_id: str | None) -> Mapping | None:
    normalized = cwe_service.normalize_cwe_id(cwe_id)
    return CWE_MAPPING.get(normalized) if normalized else None


def _readiness(open_count: int, resolved_count: int, worst_open: str | None) -> float:
    """Percentage readiness for one control.

    Fully ready with nothing open. Otherwise the score falls with the number of
    open findings, weighted by the worst severity among them — a control with
    one critical gap must not look healthier than one with three low ones.
    """
    if open_count == 0:
        return 100.0
    weight = {
        Severity.CRITICAL: 45.0,
        Severity.HIGH: 30.0,
        Severity.MEDIUM: 18.0,
        Severity.LOW: 10.0,
        Severity.INFORMATIONAL: 4.0,
    }.get(worst_open or Severity.MEDIUM, 18.0)

    # The first open finding costs the full weight; further ones add less, so a
    # long tail of the same severity cannot drive a control below zero.
    penalty = weight + (open_count - 1) * (weight * 0.35)
    total = open_count + resolved_count
    if total:
        # Credit for what has actually been fixed against this control.
        penalty *= 1 - 0.4 * (resolved_count / total)
    return round(max(0.0, 100.0 - min(penalty, 100.0)), 1)


def build_compliance(db: Session, assessment_id: int) -> dict:
    """Per-framework control coverage and readiness for one assessment."""
    findings = (
        db.query(Finding)
        .filter(
            Finding.assessment_id == assessment_id,
            Finding.verification_status != VerificationStatus.FALSE_POSITIVE,
            Finding.is_suppressed.is_(False),
        )
        .all()
    )

    # control id -> {"open": [...], "resolved": [...]} per framework
    buckets: dict[str, dict[str, dict[str, list[Finding]]]] = {
        key: {} for key in FRAMEWORKS
    }
    owasp_buckets: dict[str, dict[str, list[Finding]]] = {}
    mapped = 0
    unmapped_cwes: set[str] = set()

    for finding in findings:
        mapping = map_cwe(finding.cwe_id)
        if mapping is None:
            if finding.cwe_id:
                unmapped_cwes.add(finding.cwe_id)
            continue
        mapped += 1
        state = "resolved" if finding.status in _RESOLVED else "open"

        owasp = owasp_buckets.setdefault(mapping.owasp, {"open": [], "resolved": []})
        owasp[state].append(finding)

        for framework, control_ids in (("NIST_800_53", mapping.nist), ("ISO_27001", mapping.iso)):
            for control_id in control_ids:
                bucket = buckets[framework].setdefault(control_id, {"open": [], "resolved": []})
                bucket[state].append(finding)

    def worst(items: list[Finding]) -> str | None:
        return max((f.severity for f in items), key=lambda s: SEVERITY_ORDER.get(s, 0), default=None)

    frameworks_out = []
    for key, meta in FRAMEWORKS.items():
        controls = []
        for control_id, bucket in sorted(buckets[key].items()):
            open_items, resolved_items = bucket["open"], bucket["resolved"]
            controls.append({
                "id": control_id,
                "title": meta["controls"].get(control_id, control_id),
                "open_findings": len(open_items),
                "resolved_findings": len(resolved_items),
                "worst_open_severity": worst(open_items),
                "readiness": _readiness(len(open_items), len(resolved_items), worst(open_items)),
                "finding_ids": [f.id for f in open_items][:20],
            })
        controls.sort(key=lambda c: (c["readiness"], -c["open_findings"]))
        # Overall readiness is the mean across controls the assessment touched;
        # a control with no evidence either way is not scored at all.
        readiness = round(sum(c["readiness"] for c in controls) / len(controls), 1) if controls else None
        frameworks_out.append({
            "key": key,
            "label": meta["label"],
            "controls_affected": len(controls),
            "controls_at_risk": sum(1 for c in controls if c["open_findings"] > 0),
            "readiness": readiness,
            "controls": controls,
        })

    owasp_out = [
        {
            "id": category,
            "title": OWASP_CATEGORIES.get(category, category),
            "open_findings": len(bucket["open"]),
            "resolved_findings": len(bucket["resolved"]),
            "worst_open_severity": worst(bucket["open"]),
        }
        for category, bucket in sorted(owasp_buckets.items())
    ]

    return {
        "assessment_id": assessment_id,
        "frameworks": frameworks_out,
        "owasp_top_10": owasp_out,
        "coverage": {
            "findings_considered": len(findings),
            "findings_mapped": mapped,
            "findings_unmapped": len(findings) - mapped,
            "mapping_rate": round(100.0 * mapped / len(findings), 1) if findings else 0.0,
            "unmapped_cwes": sorted(unmapped_cwes)[:20],
            "catalogue_size": len(CWE_MAPPING),
        },
        "disclaimer": (
            "Control mappings are indicative, not an audit. They show which controls the "
            "findings in this assessment bear on; they do not assess controls no finding "
            "touched, and they are not a certification of compliance."
        ),
    }
