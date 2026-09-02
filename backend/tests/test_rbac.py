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


# --------------------------------------------------------- user administration
def test_deactivated_users_are_hidden_from_pickers_by_default(client, auth, users):
    """Assignment pickers should not offer accounts that can no longer sign in."""
    target = users[Role.ANALYST]
    client.patch(f"/api/users/{target.id}", headers=auth(Role.ADMIN), json={"is_active": False})

    listed = client.get("/api/users", headers=auth(Role.ADMIN)).json()
    assert target.id not in [u["id"] for u in listed]


def test_deactivated_users_are_still_reachable_for_administration(client, auth, users):
    """Regression: deactivating a user made them vanish with no way back.

    The admin screen listed users with the active-only default, so clicking
    deactivate removed the row and left no control to reactivate it - the
    account was stranded.
    """
    target = users[Role.ANALYST]
    client.patch(f"/api/users/{target.id}", headers=auth(Role.ADMIN), json={"is_active": False})

    listed = client.get(
        "/api/users", headers=auth(Role.ADMIN), params={"active_only": False}
    ).json()
    row = next((u for u in listed if u["id"] == target.id), None)
    assert row is not None, "administration must be able to see a deactivated account"
    assert row["is_active"] is False


def test_a_deactivated_user_can_be_reactivated(client, auth, users):
    target = users[Role.ANALYST]
    client.patch(f"/api/users/{target.id}", headers=auth(Role.ADMIN), json={"is_active": False})

    response = client.patch(
        f"/api/users/{target.id}", headers=auth(Role.ADMIN), json={"is_active": True}
    )
    assert response.status_code == 200

    listed = client.get("/api/users", headers=auth(Role.ADMIN)).json()
    assert target.id in [u["id"] for u in listed]


def test_a_deactivated_user_cannot_sign_in(client, auth, users):
    from tests.conftest import TEST_PASSWORD

    target = users[Role.ANALYST]
    client.patch(f"/api/users/{target.id}", headers=auth(Role.ADMIN), json={"is_active": False})

    response = client.post(
        "/api/auth/login", json={"email": target.email, "password": TEST_PASSWORD}
    )
    assert response.status_code == 401
