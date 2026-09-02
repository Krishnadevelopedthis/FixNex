"""Attack-path chain rules and graph construction."""
from __future__ import annotations

import pytest

from app.core.permissions import Role
from app.models.enums import FindingStatus, Severity, VerificationStatus
from app.models.finding import Finding
from app.services.attack_paths import CHAIN_RULES, Match, build_attack_paths


def make(title="Some finding", cwe=None, category=None, severity=Severity.MEDIUM, description=""):
    """A detached Finding, enough for the matcher — no database needed."""
    return Finding(
        title=title, cwe_id=cwe, category=category, severity=severity, description=description
    )


def rule(rule_id):
    return next(r for r in CHAIN_RULES if r.id == rule_id)


# ------------------------------------------------------------------ matching
def test_match_on_cwe():
    m = Match(cwes=frozenset({"CWE-79"}))
    assert m.matches(make(cwe="CWE-79"))
    assert not m.matches(make(cwe="CWE-89"))


def test_match_on_category():
    m = Match(categories=frozenset({"Injection"}))
    assert m.matches(make(category="Injection"))
    assert not m.matches(make(category="Cryptography"))


def test_match_on_title_keyword():
    m = Match(keywords=("admin",))
    assert m.matches(make(title="Exposed admin console"))
    assert not m.matches(make(title="Missing security header"))


def test_keywords_are_matched_against_the_title_not_the_description():
    """Regression: a description that merely mentions XSS is not an XSS finding.

    The Missing-CSP finding's description explains that CSP defends against
    cross-site scripting. Matching descriptions made it match the XSS rule and
    produced a fabricated attack path.
    """
    m = Match(cwes=frozenset({"CWE-79"}), keywords=("cross-site scripting", "xss"))
    csp = make(
        title="Missing Content-Security-Policy header",
        cwe="CWE-693",
        description="CSP is the primary defence against cross-site scripting.",
    )
    assert not m.matches(csp)
    assert m.matches(make(title="Reflected cross-site scripting in search", cwe="CWE-79"))


def test_require_keyword_makes_the_keyword_mandatory():
    """Without this, 'exposed admin surface' matches any information disclosure."""
    loose = Match(categories=frozenset({"Information Disclosure"}), keywords=("admin",))
    strict = Match(
        categories=frozenset({"Information Disclosure"}), keywords=("admin",), require_keyword=True
    )
    banner = make(title="Server banner disclosed", category="Information Disclosure")
    assert loose.matches(banner)
    assert not strict.matches(banner)
    assert strict.matches(make(title="Exposed admin panel", category="Information Disclosure"))


def test_require_keyword_still_enforces_the_class_constraint():
    m = Match(cwes=frozenset({"CWE-200"}), keywords=("version",), require_keyword=True)
    assert m.matches(make(title="Software version disclosed", cwe="CWE-200"))
    # Right words, wrong weakness class.
    assert not m.matches(make(title="Software version disclosed", cwe="CWE-89"))


# --------------------------------------------------------------- chain rules
def test_xss_plus_httponly_chain_matches():
    r = rule("xss-weak-cookie")
    assert r.prerequisite.matches(make(title="Reflected XSS in search", cwe="CWE-79"))
    assert r.enabler.matches(make(title="Cookie without HttpOnly", cwe="CWE-1004"))
    assert r.outcome_severity == Severity.HIGH


def test_injection_credential_rule_excludes_xss():
    """XSS is injection, but it does not reach the credential store."""
    r = rule("injection-credential-storage")
    assert r.prerequisite.matches(make(title="SQL injection", cwe="CWE-89"))
    assert not r.prerequisite.matches(make(title="Reflected XSS", cwe="CWE-79", category="Injection"))


def test_outdated_component_rule_excludes_plain_injection():
    r = rule("disclosure-outdated-component")
    assert r.enabler.matches(make(title="log4j remote code execution", cwe="CWE-502"))
    assert not r.enabler.matches(make(title="SQL injection", cwe="CWE-89", category="Injection"))


def test_every_rule_escalates_above_a_medium_pair():
    """A chain must be worth surfacing — otherwise it is just two findings."""
    from app.models.enums import SEVERITY_ORDER

    for r in CHAIN_RULES:
        assert SEVERITY_ORDER[r.outcome_severity] >= SEVERITY_ORDER[Severity.HIGH], r.id


def test_every_rule_explains_itself():
    for r in CHAIN_RULES:
        assert r.rationale and len(r.rationale) > 60, r.id
        assert r.outcome and r.name, r.id


def test_rule_ids_are_unique():
    ids = [r.id for r in CHAIN_RULES]
    assert len(ids) == len(set(ids))


# ------------------------------------------------------------------- graph
def _add(db, assessment, target, **kw):
    from app.services.references import assign_reference

    finding = Finding(
        assessment_id=assessment.id,
        target_id=target.id,
        primary_source="test",
        status=kw.pop("status", FindingStatus.CONFIRMED),
        verification_status=kw.pop("verification_status", VerificationStatus.CONFIRMED),
        **kw,
    )
    db.add(finding)
    assign_reference(db, finding)
    db.commit()
    return finding


def test_graph_links_two_findings_to_one_outcome(db, assessment, target):
    _add(db, assessment, target, title="Reflected XSS in search", cwe_id="CWE-79", severity=Severity.HIGH)
    _add(db, assessment, target, title="Cookie without HttpOnly", cwe_id="CWE-1004", severity=Severity.MEDIUM)

    graph = build_attack_paths(db, assessment.id)
    assert graph["summary"]["paths"] == 1
    path = graph["paths"][0]
    assert path["rule_id"] == "xss-weak-cookie"
    assert path["outcome_severity"] == Severity.HIGH

    outcomes = [n for n in graph["nodes"] if n["kind"] == "outcome"]
    findings = [n for n in graph["nodes"] if n["kind"] == "finding"]
    assert len(outcomes) == 1 and len(findings) == 2
    # Both findings point at the shared outcome.
    assert len(graph["edges"]) == 2
    assert {e["role"] for e in graph["edges"]} == {"prerequisite", "enabler"}


def test_a_lone_finding_forms_no_path(db, assessment, target):
    _add(db, assessment, target, title="Reflected XSS in search", cwe_id="CWE-79", severity=Severity.HIGH)
    assert build_attack_paths(db, assessment.id)["summary"]["paths"] == 0


def test_closed_and_false_positive_findings_are_not_footholds(db, assessment, target):
    _add(db, assessment, target, title="Reflected XSS in search", cwe_id="CWE-79", severity=Severity.HIGH)
    _add(
        db, assessment, target, title="Cookie without HttpOnly", cwe_id="CWE-1004",
        severity=Severity.MEDIUM, status=FindingStatus.CLOSED,
    )
    assert build_attack_paths(db, assessment.id)["summary"]["paths"] == 0

    _add(
        db, assessment, target, title="Another cookie without HttpOnly", cwe_id="CWE-1004",
        severity=Severity.MEDIUM, status=FindingStatus.FALSE_POSITIVE,
        verification_status=VerificationStatus.FALSE_POSITIVE,
    )
    assert build_attack_paths(db, assessment.id)["summary"]["paths"] == 0


def test_suppressed_findings_are_excluded(db, assessment, target):
    _add(db, assessment, target, title="Reflected XSS in search", cwe_id="CWE-79", severity=Severity.HIGH)
    _add(
        db, assessment, target, title="Cookie without HttpOnly", cwe_id="CWE-1004",
        severity=Severity.MEDIUM, is_suppressed=True,
    )
    assert build_attack_paths(db, assessment.id)["summary"]["paths"] == 0


def test_chains_do_not_span_different_targets(db, assessment, target, users):
    """A weakness on one system cannot chain into a finding on another."""
    from app.models.enums import TargetStatus
    from app.models.target import Target
    from app.services.references import assign_reference

    other = Target(
        assessment_id=assessment.id, name="Other system",
        value="https://other.in-scope.example.com", target_type="WEB_APP",
        status=TargetStatus.AUTHORIZED, authorization_confirmed=True,
    )
    db.add(other)
    assign_reference(db, other)
    db.commit()

    _add(db, assessment, target, title="Reflected XSS in search", cwe_id="CWE-79", severity=Severity.HIGH)
    _add(db, assessment, other, title="Cookie without HttpOnly", cwe_id="CWE-1004", severity=Severity.MEDIUM)
    assert build_attack_paths(db, assessment.id)["summary"]["paths"] == 0


def test_chain_spans_endpoints_within_one_target(db, assessment, target):
    """XSS on /search can steal a cookie issued at /login."""
    _add(
        db, assessment, target, title="Reflected XSS in search", cwe_id="CWE-79",
        severity=Severity.HIGH, endpoint="https://app.in-scope.example.com/search",
    )
    _add(
        db, assessment, target, title="Cookie without HttpOnly", cwe_id="CWE-1004",
        severity=Severity.MEDIUM, endpoint="https://app.in-scope.example.com/login",
    )
    graph = build_attack_paths(db, assessment.id)
    assert graph["summary"]["paths"] == 1
    assert graph["paths"][0]["same_surface"] is False


def test_escalation_flag_marks_chains_worse_than_their_parts(db, assessment, target):
    _add(db, assessment, target, title="Unsafe innerHTML assignment", cwe_id="CWE-79", severity=Severity.MEDIUM)
    _add(db, assessment, target, title="Cookie without HttpOnly", cwe_id="CWE-1004", severity=Severity.MEDIUM)
    path = build_attack_paths(db, assessment.id)["paths"][0]
    # Two MEDIUMs implying a HIGH outcome is exactly the point of the feature.
    assert path["escalates"] is True


# -------------------------------------------------------------------- route
def test_route_returns_graph_and_disclaimer(client, auth, assessment, target, db):
    _add(db, assessment, target, title="Reflected XSS in search", cwe_id="CWE-79", severity=Severity.HIGH)
    _add(db, assessment, target, title="Cookie without HttpOnly", cwe_id="CWE-1004", severity=Severity.MEDIUM)

    response = client.get(f"/api/assessments/{assessment.id}/attack-paths", headers=auth(Role.SECURITY_LEAD))
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["paths"] == 1
    assert body["nodes"] and body["edges"]
    assert "not proof" in body["disclaimer"]


def test_route_is_readable_by_any_role_with_finding_view(client, auth, assessment):
    for role in (Role.VIEWER, Role.ANALYST, Role.SECURITY_ENGINEER, Role.ADMIN):
        response = client.get(f"/api/assessments/{assessment.id}/attack-paths", headers=auth(role))
        assert response.status_code == 200, role


def test_route_404s_for_a_missing_assessment(client, auth):
    assert client.get("/api/assessments/999999/attack-paths", headers=auth(Role.ADMIN)).status_code == 404
