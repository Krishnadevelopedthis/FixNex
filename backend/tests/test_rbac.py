"""Role-based access control."""
from __future__ import annotations

import pytest

from app.core.permissions import (
    Permission,
    ROLE_PERMISSIONS,
    Role,
    permissions_for_role,
    role_has_permission,
)


def test_admin_holds_every_permission():
    assert ROLE_PERMISSIONS[Role.ADMIN] == frozenset(p.value for p in Permission)


def test_viewer_is_read_only():
    for permission in permissions_for_role(Role.VIEWER):
        assert permission.split(":")[1] in {"view", "view_all", "download"}, permission


def test_developer_cannot_score_or_verify_findings():
    assert not role_has_permission(Role.DEVELOPER, Permission.FINDING_SCORE)
    assert not role_has_permission(Role.DEVELOPER, Permission.FINDING_VERIFY)
    assert not role_has_permission(Role.DEVELOPER, Permission.EVIDENCE_DELETE)
    assert not role_has_permission(Role.DEVELOPER, Permission.FINDING_VIEW_ALL)
    # ...but can do their actual job
    assert role_has_permission(Role.DEVELOPER, Permission.REMEDIATION_UPDATE)
    assert role_has_permission(Role.DEVELOPER, Permission.RETEST_REQUEST)


def test_only_admin_can_administer_users():
    for role in Role:
        if role is Role.ADMIN:
            continue
        assert not role_has_permission(role, Permission.USER_CREATE)
        assert not role_has_permission(role, Permission.USER_DELETE)
        assert not role_has_permission(role, Permission.ROLE_MANAGE)


def test_no_role_can_delete_audit_logs():
    """There is deliberately no audit-delete permission at all."""
    assert not any(p.value.startswith("audit:delete") for p in Permission)


@pytest.mark.parametrize(
    "role,expected",
    [
        (Role.VIEWER, 403),
        (Role.DEVELOPER, 403),
        (Role.ANALYST, 403),
        (Role.SECURITY_ENGINEER, 403),
        (Role.SECURITY_LEAD, 201),
        (Role.ADMIN, 201),
    ],
)
def test_only_leads_and_admins_may_create_an_assessment(client, auth, role, expected):
    response = client.post(
        "/api/assessments", headers=auth(role), json={"name": "RBAC probe assessment"}
    )
    assert response.status_code == expected, response.text


@pytest.mark.parametrize("role", [Role.VIEWER, Role.DEVELOPER, Role.ANALYST])
def test_unprivileged_roles_cannot_start_a_scan(client, auth, role, assessment, target):
    response = client.post(
        "/api/scans",
        headers=auth(role),
        json={
            "assessment_id": assessment.id,
            "target_id": target.id,
            "profile": "LIGHT",
            "authorization_confirmed": True,
        },
    )
    assert response.status_code == 403


def test_viewer_cannot_modify_a_finding(client, auth, finding):
    assert client.patch(
        f"/api/findings/{finding.id}", headers=auth(Role.VIEWER), json={"title": "changed"}
    ).status_code == 403
    assert client.post(
        f"/api/findings/{finding.id}/verify", headers=auth(Role.VIEWER), json={"confirmed": True}
    ).status_code == 403


def test_developer_cannot_change_cvss(client, auth, finding):
    response = client.post(
        f"/api/findings/{finding.id}/score",
        headers=auth(Role.DEVELOPER),
        json={"cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", "severity": "LOW"},
    )
    assert response.status_code == 403


def test_admin_can_manage_users_but_engineer_cannot(client, auth):
    payload = {
        "email": "new.person@test.example.com",
        "full_name": "New Person",
        "password": "AnotherPass123",
        "role": "VIEWER",
    }
    assert client.post("/api/users", headers=auth(Role.SECURITY_ENGINEER), json=payload).status_code == 403
    assert client.post("/api/users", headers=auth(Role.ADMIN), json=payload).status_code == 201
