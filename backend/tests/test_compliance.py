"""Compliance mapping table and readiness rollup."""
from __future__ import annotations

import pytest

from app.core.permissions import Role
from app.models.enums import FindingStatus, Severity, VerificationStatus
from app.models.finding import Finding
from app.services.compliance import (
    CWE_MAPPING,
    ISO_CONTROLS,
    NIST_CONTROLS,
    OWASP_CATEGORIES,
    _readiness,
    build_compliance,
    map_cwe,
)
from app.services.cwe import CWE_CATALOGUE


# ------------------------------------------------------------ mapping table
def test_every_catalogued_cwe_is_mapped():
    """The mapping must cover the weaknesses the platform actually produces."""
    missing = sorted(set(CWE_CATALOGUE) - set(CWE_MAPPING))
    assert not missing, f"unmapped CWEs from the catalogue: {missing}"


def test_no_mapping_references_an_unknown_control():
    for cwe_id, mapping in CWE_MAPPING.items():
        for control in mapping.nist:
            assert control in NIST_CONTROLS, f"{cwe_id} -> unknown NIST control {control}"
        for control in mapping.iso:
            assert control in ISO_CONTROLS, f"{cwe_id} -> unknown ISO control {control}"


def test_no_mapping_references_an_unknown_owasp_category():
    for cwe_id, mapping in CWE_MAPPING.items():
        assert mapping.owasp in OWASP_CATEGORIES, f"{cwe_id} -> {mapping.owasp}"


def test_every_mapping_has_at_least_one_control_per_framework():
    for cwe_id, mapping in CWE_MAPPING.items():
        assert mapping.nist, cwe_id
        assert mapping.iso, cwe_id


@pytest.mark.parametrize(
    "cwe,owasp",
    [
        ("CWE-89", "A03"),    # SQL injection  -> Injection
        ("CWE-79", "A03"),    # XSS            -> Injection
        ("CWE-319", "A02"),   # cleartext      -> Cryptographic Failures
        ("CWE-287", "A07"),   # auth           -> Identification and Authentication
        ("CWE-639", "A01"),   # IDOR           -> Broken Access Control
        ("CWE-918", "A10"),   # SSRF           -> SSRF
        ("CWE-502", "A08"),   # deserialisation-> Integrity Failures
    ],
)
def test_well_known_cwes_land_in_the_right_owasp_category(cwe, owasp):
    assert map_cwe(cwe).owasp == owasp


def test_map_cwe_normalises_input():
    assert map_cwe("89") is map_cwe("CWE-89")
    assert map_cwe("cwe-89") is map_cwe("CWE-89")


def test_map_cwe_returns_none_for_unknown_or_missing():
    assert map_cwe(None) is None
    assert map_cwe("CWE-999999") is None
    assert map_cwe("not-a-cwe") is None


# --------------------------------------------------------------- readiness
def test_control_with_no_open_findings_is_fully_ready():
    assert _readiness(0, 0, None) == 100.0
    assert _readiness(0, 5, None) == 100.0


def test_readiness_falls_as_open_findings_accumulate():
    one = _readiness(1, 0, Severity.MEDIUM)
    two = _readiness(2, 0, Severity.MEDIUM)
    three = _readiness(3, 0, Severity.MEDIUM)
    assert 100.0 > one > two > three >= 0.0


def test_severity_weighting_beats_raw_count():
    """One critical gap must not look healthier than a few low ones."""
    critical = _readiness(1, 0, Severity.CRITICAL)
    lows = _readiness(3, 0, Severity.LOW)
    assert critical < lows


def test_resolved_findings_improve_readiness():
    without = _readiness(2, 0, Severity.HIGH)
    with_fixes = _readiness(2, 6, Severity.HIGH)
    assert with_fixes > without


def test_readiness_is_clamped_to_zero():
    assert _readiness(50, 0, Severity.CRITICAL) == 0.0


def test_readiness_never_exceeds_one_hundred():
    for open_count in range(0, 5):
        for resolved in range(0, 5):
            for severity in (Severity.CRITICAL, Severity.LOW, Severity.INFORMATIONAL):
                assert 0.0 <= _readiness(open_count, resolved, severity) <= 100.0


# ------------------------------------------------------------------ rollup
def _add(db, assessment, target, cwe, severity=Severity.HIGH, status=FindingStatus.CONFIRMED, **kw):
    from app.services.references import assign_reference

    finding = Finding(
        assessment_id=assessment.id, target_id=target.id, primary_source="test",
        title=f"Finding for {cwe}", cwe_id=cwe, severity=severity, status=status,
        verification_status=kw.pop("verification_status", VerificationStatus.CONFIRMED), **kw,
    )
    db.add(finding)
    assign_reference(db, finding)
    db.commit()
    return finding


def test_rollup_maps_a_finding_onto_both_frameworks(db, assessment, target):
    _add(db, assessment, target, "CWE-89", Severity.CRITICAL)
    result = build_compliance(db, assessment.id)

    assert result["coverage"]["findings_mapped"] == 1
    assert result["coverage"]["mapping_rate"] == 100.0

    by_key = {f["key"]: f for f in result["frameworks"]}
    nist_controls = {c["id"] for c in by_key["NIST_800_53"]["controls"]}
    iso_controls = {c["id"] for c in by_key["ISO_27001"]["controls"]}
    assert "SI-10" in nist_controls
    assert "A.8.28" in iso_controls


def test_closed_findings_do_not_count_against_a_control(db, assessment, target):
    _add(db, assessment, target, "CWE-89", Severity.CRITICAL, status=FindingStatus.CLOSED)
    result = build_compliance(db, assessment.id)
    nist = next(f for f in result["frameworks"] if f["key"] == "NIST_800_53")
    si10 = next(c for c in nist["controls"] if c["id"] == "SI-10")
    assert si10["open_findings"] == 0
    assert si10["resolved_findings"] == 1
    assert si10["readiness"] == 100.0


def test_false_positives_are_excluded_entirely(db, assessment, target):
    _add(
        db, assessment, target, "CWE-89", Severity.CRITICAL,
        status=FindingStatus.FALSE_POSITIVE, verification_status=VerificationStatus.FALSE_POSITIVE,
    )
    result = build_compliance(db, assessment.id)
    assert result["coverage"]["findings_considered"] == 0
    assert result["frameworks"][0]["controls_affected"] == 0


def test_suppressed_findings_are_excluded(db, assessment, target):
    _add(db, assessment, target, "CWE-89", Severity.CRITICAL, is_suppressed=True)
    assert build_compliance(db, assessment.id)["coverage"]["findings_considered"] == 0


def test_unmapped_cwes_are_reported_not_hidden(db, assessment, target):
    _add(db, assessment, target, "CWE-99999", Severity.HIGH)
    coverage = build_compliance(db, assessment.id)["coverage"]
    assert coverage["findings_unmapped"] == 1
    assert coverage["mapping_rate"] == 0.0
    assert "CWE-99999" in coverage["unmapped_cwes"]


def test_controls_are_ordered_worst_first(db, assessment, target):
    _add(db, assessment, target, "CWE-89", Severity.CRITICAL)   # SI-10, SA-11
    _add(db, assessment, target, "CWE-200", Severity.LOW)       # CM-6, SC-28
    nist = next(f for f in build_compliance(db, assessment.id)["frameworks"] if f["key"] == "NIST_800_53")
    readiness = [c["readiness"] for c in nist["controls"]]
    assert readiness == sorted(readiness)


def test_owasp_rollup_groups_by_category(db, assessment, target):
    _add(db, assessment, target, "CWE-89", Severity.CRITICAL)
    _add(db, assessment, target, "CWE-79", Severity.HIGH)
    owasp = {o["id"]: o for o in build_compliance(db, assessment.id)["owasp_top_10"]}
    assert owasp["A03"]["open_findings"] == 2
    assert owasp["A03"]["worst_open_severity"] == Severity.CRITICAL


def test_empty_assessment_reports_no_readiness(db, assessment):
    result = build_compliance(db, assessment.id)
    assert result["coverage"]["findings_considered"] == 0
    for framework in result["frameworks"]:
        # No evidence either way, so nothing is scored rather than scoring 100%.
        assert framework["readiness"] is None


# -------------------------------------------------------------------- route
def test_route_returns_frameworks_and_disclaimer(client, auth, assessment, target, db):
    _add(db, assessment, target, "CWE-89", Severity.CRITICAL)
    response = client.get(f"/api/assessments/{assessment.id}/compliance", headers=auth(Role.SECURITY_LEAD))
    assert response.status_code == 200
    body = response.json()
    assert {f["key"] for f in body["frameworks"]} == {"NIST_800_53", "ISO_27001"}
    assert "not an audit" in body["disclaimer"]


def test_route_is_readable_by_a_viewer(client, auth, assessment):
    assert client.get(
        f"/api/assessments/{assessment.id}/compliance", headers=auth(Role.VIEWER)
    ).status_code == 200


def test_route_404s_for_a_missing_assessment(client, auth):
    assert client.get("/api/assessments/999999/compliance", headers=auth(Role.ADMIN)).status_code == 404
