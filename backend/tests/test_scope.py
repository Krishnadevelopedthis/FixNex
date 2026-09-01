"""Authorised scope enforcement — the platform's core safety control."""
from __future__ import annotations

import pytest

from app.core.permissions import Role
from app.models.enums import ScopeRuleType
from app.models.target import ScopeRule
from app.services import scope


def rule(rule_type, value, is_exclusion=False):
    return ScopeRule(rule_type=rule_type, value=value, is_exclusion=is_exclusion)


@pytest.mark.parametrize(
    "rule_type,rule_value,candidate,expected",
    [
        (ScopeRuleType.DOMAIN, "college.edu", "https://college.edu/login", True),
        (ScopeRuleType.DOMAIN, "college.edu", "https://sub.college.edu", False),
        (ScopeRuleType.WILDCARD_DOMAIN, "*.college.edu", "https://portal.college.edu", True),
        (ScopeRuleType.WILDCARD_DOMAIN, "*.college.edu", "https://college.edu", True),
        (ScopeRuleType.WILDCARD_DOMAIN, "*.college.edu", "https://notcollege.edu", False),
        (ScopeRuleType.WILDCARD_DOMAIN, "*.college.edu", "https://college.edu.evil.com", False),
        (ScopeRuleType.IP, "10.0.0.5", "10.0.0.5", True),
        (ScopeRuleType.IP, "10.0.0.5", "10.0.0.6", False),
        (ScopeRuleType.CIDR, "10.0.0.0/24", "10.0.0.99", True),
        (ScopeRuleType.CIDR, "10.0.0.0/24", "10.0.1.1", False),
        (ScopeRuleType.URL, "https://app.local/api", "https://app.local/api/users", True),
        (ScopeRuleType.URL, "https://app.local/api", "https://app.local/admin", False),
    ],
)
def test_scope_rule_matching(rule_type, rule_value, candidate, expected):
    assert scope._matches(rule(rule_type, rule_value), candidate) is expected


def test_a_hostname_never_matches_a_cidr_rule():
    """DNS could change between the check and the scan, so only literals match."""
    assert scope._matches(rule(ScopeRuleType.CIDR, "10.0.0.0/8"), "evil.example.com") is False


def test_empty_scope_denies_everything(db, assessment):
    db.query(ScopeRule).filter(ScopeRule.assessment_id == assessment.id).delete()
    db.commit()
    decision = scope.check(db, assessment, "https://app.in-scope.example.com")
    assert decision.in_scope is False
    assert "No authorised scope" in decision.reason


def test_exclusions_take_priority_over_inclusions(db, assessment, users):
    db.add(
        ScopeRule(
            assessment_id=assessment.id,
            rule_type=ScopeRuleType.DOMAIN,
            value="payments.in-scope.example.com",
            is_exclusion=True,
        )
    )
    db.commit()
    allowed = scope.check(db, assessment, "https://app.in-scope.example.com")
    excluded = scope.check(db, assessment, "https://payments.in-scope.example.com")
    assert allowed.in_scope is True
    assert excluded.in_scope is False
    assert "exclusion" in excluded.reason.lower()


@pytest.mark.parametrize(
    "malicious",
    ["app.local; rm -rf /", "app.local && curl evil.com", "app.local|nc evil 1", "app.local`id`"],
)
def test_command_injection_characters_are_rejected(malicious):
    from app.core.exceptions import ValidationError

    with pytest.raises(ValidationError):
        scope.validate_target_value(malicious)


# ------------------------------------------------------------------ API level
def test_out_of_scope_target_is_rejected_by_the_api(client, auth, assessment):
    response = client.post(
        f"/api/assessments/{assessment.id}/targets",
        headers=auth(Role.SECURITY_LEAD),
        json={
            "name": "Someone else's server",
            "target_type": "WEB_APP",
            "value": "https://not-authorised.example.org",
            "authorization_confirmed": True,
        },
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "scope_violation"


def test_target_without_authorization_confirmation_is_rejected(client, auth, assessment):
    response = client.post(
        f"/api/assessments/{assessment.id}/targets",
        headers=auth(Role.SECURITY_LEAD),
        json={
            "name": "In scope but unconfirmed",
            "target_type": "WEB_APP",
            "value": "https://app.in-scope.example.com",
            "authorization_confirmed": False,
        },
    )
    assert response.status_code == 403
    assert "authoriz" in response.json()["error"]["message"].lower()


def test_in_scope_and_authorized_target_is_accepted(client, auth, assessment):
    response = client.post(
        f"/api/assessments/{assessment.id}/targets",
        headers=auth(Role.SECURITY_LEAD),
        json={
            "name": "Authorised target",
            "target_type": "WEB_APP",
            "value": "https://portal.in-scope.example.com",
            "authorization_confirmed": True,
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "AUTHORIZED"


def test_blocked_scope_violation_is_written_to_the_audit_log(client, auth, assessment):
    client.post(
        f"/api/assessments/{assessment.id}/targets",
        headers=auth(Role.SECURITY_LEAD),
        json={
            "name": "Out of scope",
            "target_type": "WEB_APP",
            "value": "https://evil.example.org",
            "authorization_confirmed": True,
        },
    )
    logs = client.get(
        "/api/audit-logs", headers=auth(Role.ADMIN), params={"page_size": 100}
    ).json()
    assert any(e["action"] == "scope.violation_blocked" for e in logs["items"])
