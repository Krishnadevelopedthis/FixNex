"""CVSS scoring, CWE classification, contextual risk and correlation."""
from __future__ import annotations

import pytest

from app.models.enums import Criticality, DataSensitivity, Exposure, Severity
from app.scanners.base import NormalizedFinding, normalize_severity, severity_from_cvss
from app.services import correlation, cwe as cwe_service, risk as risk_engine
from app.services.cvss import parse_vector, score_finding


# --------------------------------------------------------------------- CVSS
@pytest.mark.parametrize(
    "vector,expected_score,expected_severity",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, Severity.CRITICAL),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, Severity.MEDIUM),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, Severity.MEDIUM),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, Severity.INFORMATIONAL),
    ],
)
def test_cvss_matches_the_reference_implementation(vector, expected_score, expected_severity):
    result = parse_vector(vector)
    assert result is not None
    assert result.score == expected_score
    assert result.severity == expected_severity
    assert result.version == "3.1"


def test_invalid_cvss_vector_returns_none():
    assert parse_vector("not-a-vector") is None
    assert parse_vector("") is None


def test_missing_vector_falls_back_to_a_flagged_estimate():
    result = score_finding(None, None, Severity.HIGH)
    assert result.estimated is True
    assert result.severity == Severity.HIGH
    assert result.vector is not None


def test_a_scanner_supplied_score_is_preserved():
    result = score_finding(None, 7.2, Severity.MEDIUM)
    assert result.score == 7.2
    assert result.estimated is False


@pytest.mark.parametrize(
    "score,expected",
    [(9.9, Severity.CRITICAL), (7.0, Severity.HIGH), (4.0, Severity.MEDIUM),
     (0.1, Severity.LOW), (0.0, Severity.INFORMATIONAL)],
)
def test_cvss_severity_bands(score, expected):
    assert severity_from_cvss(score) == expected


# ------------------------------------------------------- severity normalisation
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("critical", Severity.CRITICAL), ("High", Severity.HIGH),
        ("moderate", Severity.MEDIUM), ("info", Severity.INFORMATIONAL),
        ("3", Severity.HIGH), ("0", Severity.INFORMATIONAL),   # ZAP risk codes
        ("warning", Severity.LOW), (None, Severity.INFORMATIONAL),
        ("something-unknown", Severity.INFORMATIONAL),
    ],
)
def test_scanner_severity_dialects_are_normalised(raw, expected):
    assert normalize_severity(raw) == expected


# ----------------------------------------------------------------------- CWE
def test_known_cwe_lookup():
    entry = cwe_service.lookup("CWE-89")
    assert entry["name"] == "SQL Injection"
    assert entry["known"] is True
    assert entry["url"].endswith("/89.html")


def test_unknown_cwe_is_still_linked():
    entry = cwe_service.lookup("CWE-99999")
    assert entry["known"] is False
    assert "99999" in entry["url"]


@pytest.mark.parametrize("value,expected", [("89", "CWE-89"), ("CWE-79", "CWE-79"), ("cwe-352", "CWE-352"), ("nonsense", None)])
def test_cwe_id_normalisation(value, expected):
    assert cwe_service.normalize_cwe_id(value) == expected


@pytest.mark.parametrize(
    "text,expected",
    [
        ("SQL Injection in login", "CWE-89"),
        ("Reflected Cross-Site Scripting", "CWE-79"),
        ("Missing Strict-Transport-Security header", "CWE-319"),
        ("Directory listing enabled", "CWE-548"),
    ],
)
def test_cwe_inferred_from_title_when_scanner_supplies_none(text, expected):
    assert cwe_service.infer_from_text(text) == expected


# ------------------------------------------------------------ contextual risk
def test_context_raises_risk_without_saturating():
    result = risk_engine.calculate(
        cvss_score=6.1, severity=Severity.MEDIUM,
        asset_criticality=Criticality.HIGH, data_sensitivity=DataSensitivity.HIGH,
        exposure=Exposure.INTERNET_FACING, confidence=0.9,
    )
    assert 6.1 < result["risk_score"] < 10.0
    assert result["explanation"]


def test_context_lowers_risk_for_an_isolated_low_value_asset():
    result = risk_engine.calculate(
        cvss_score=9.8, severity=Severity.CRITICAL,
        asset_criticality=Criticality.LOW, data_sensitivity=DataSensitivity.NONE,
        exposure=Exposure.ISOLATED, confidence=0.9,
    )
    assert result["risk_score"] < 9.8


def test_risk_never_exceeds_ten_or_drops_below_zero():
    high = risk_engine.calculate(
        cvss_score=10.0, severity=Severity.CRITICAL, asset_criticality=Criticality.CRITICAL,
        data_sensitivity=DataSensitivity.HIGH, exposure=Exposure.INTERNET_FACING,
        exploit_available=True, verification_status="CONFIRMED",
    )
    assert 0.0 <= high["risk_score"] <= 10.0


def test_false_positive_risk_is_zero():
    result = risk_engine.calculate(
        cvss_score=9.8, severity=Severity.CRITICAL, verification_status="FALSE_POSITIVE"
    )
    assert result["risk_score"] == 0.0


def test_risk_is_labelled_as_platform_specific():
    result = risk_engine.calculate(cvss_score=5.0, severity=Severity.MEDIUM)
    assert "not an official CVSS" in result["disclaimer"]


def test_risk_ordering_follows_cvss_ordering():
    ctx = dict(asset_criticality=Criticality.HIGH, data_sensitivity=DataSensitivity.HIGH,
               exposure=Exposure.INTERNET_FACING, confidence=0.9)
    scores = [risk_engine.calculate(cvss_score=c, severity=Severity.MEDIUM, **ctx)["risk_score"]
              for c in (2.0, 4.8, 6.1, 8.2, 9.8)]
    assert scores == sorted(scores), scores


# ------------------------------------------------------------- correlation
def _f(title, source, **kw):
    return NormalizedFinding(title=title, source=source, target="app.local", **kw)


def test_same_issue_from_different_scanners_shares_a_correlation_key():
    a = _f("SQL Injection", "zap", endpoint="https://app.local/search?q=1", cwe="CWE-89", parameter="q")
    b = _f("Possible SQL injection detected", "nuclei", endpoint="https://app.local/search", cwe="CWE-89", parameter="q")
    assert correlation.correlation_key(a) == correlation.correlation_key(b)


def test_different_issues_do_not_correlate():
    a = _f("SQL Injection", "zap", endpoint="https://app.local/a", cwe="CWE-89")
    b = _f("Missing HSTS header", "http_headers", endpoint="https://app.local/a", cwe="CWE-319")
    assert correlation.correlation_key(a) != correlation.correlation_key(b)


def test_same_weakness_on_different_endpoints_stays_separate():
    a = _f("SQL Injection", "zap", endpoint="https://app.local/a", cwe="CWE-89")
    b = _f("SQL Injection", "zap", endpoint="https://app.local/b", cwe="CWE-89")
    assert correlation.correlation_key(a) != correlation.correlation_key(b)


def test_a_shared_cve_correlates_across_differing_titles():
    a = _f("Apache RCE", "nuclei", endpoint="https://app.local/", cve=["CVE-2021-41773"])
    b = _f("Path traversal in httpd", "zap", endpoint="https://app.local/", cve=["CVE-2021-41773"])
    assert correlation.correlation_key(a) == correlation.correlation_key(b)


def test_merge_keeps_highest_severity_and_raises_confidence():
    group = [
        _f("SQL Injection", "zap", cwe="CWE-89", severity=Severity.HIGH, confidence=0.7),
        _f("SQL injection", "nuclei", cwe="CWE-89", severity=Severity.CRITICAL, confidence=0.85, cvss=9.8),
    ]
    merged = correlation.merge_group(group)
    assert merged.severity == Severity.CRITICAL
    assert merged.cvss == 9.8
    # Independent confirmation by a second tool increases confidence.
    assert merged.confidence > 0.85


def test_deduplicate_groups_by_issue():
    findings = [
        _f("SQL Injection", "zap", endpoint="https://app.local/s", cwe="CWE-89", parameter="q"),
        _f("SQL injection found", "nuclei", endpoint="https://app.local/s", cwe="CWE-89", parameter="q"),
        _f("Missing CSP", "http_headers", endpoint="https://app.local/", cwe="CWE-693"),
    ]
    groups = correlation.deduplicate(findings)
    assert len(groups) == 2
    assert sorted(len(g[1]) for g in groups) == [1, 2]
