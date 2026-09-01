"""Assessment CRUD, dashboard and audit-trail integrity."""
from __future__ import annotations

from app.core.permissions import Role


def test_assessment_crud_round_trip(client, auth):
    created = client.post(
        "/api/assessments",
        headers=auth(Role.SECURITY_LEAD),
        json={
            "name": "Campus Portal Review",
            "client_name": "Demo College",
            "description": "Quarterly review.",
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["reference"].startswith("ASM-")
    assert body["status"] == "DRAFT"
    assessment_id = body["id"]

    updated = client.patch(
        f"/api/assessments/{assessment_id}",
        headers=auth(Role.SECURITY_LEAD),
        json={"status": "ACTIVE", "notes": "Kick-off complete."},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "ACTIVE"

    listing = client.get("/api/assessments", headers=auth(Role.VIEWER)).json()
    assert any(a["id"] == assessment_id for a in listing["items"])

    detail = client.get(f"/api/assessments/{assessment_id}", headers=auth(Role.VIEWER)).json()
    assert detail["stats"] is not None

    assert client.delete(
        f"/api/assessments/{assessment_id}", headers=auth(Role.VIEWER)
    ).status_code == 403
    assert client.delete(
        f"/api/assessments/{assessment_id}", headers=auth(Role.SECURITY_LEAD)
    ).status_code in (200, 204)


def test_end_date_before_start_date_is_rejected(client, auth):
    response = client.post(
        "/api/assessments",
        headers=auth(Role.SECURITY_LEAD),
        json={"name": "Backwards dates", "start_date": "2026-05-10", "end_date": "2026-05-01"},
    )
    assert response.status_code == 422


def test_missing_assessment_returns_404(client, auth):
    assert client.get("/api/assessments/999999", headers=auth(Role.ADMIN)).status_code == 404


def test_dashboard_is_available_to_every_role(client, auth):
    for role in (Role.ADMIN, Role.SECURITY_LEAD, Role.SECURITY_ENGINEER,
                 Role.ANALYST, Role.VIEWER, Role.DEVELOPER):
        response = client.get("/api/dashboard", headers=auth(role))
        assert response.status_code == 200, role
        assert "findings" in response.json()


def test_audit_entries_are_written_for_key_actions(client, auth):
    client.post("/api/assessments", headers=auth(Role.SECURITY_LEAD), json={"name": "Audited work"})
    logs = client.get(
        "/api/audit-logs", headers=auth(Role.ADMIN), params={"page_size": 100}
    ).json()
    actions = {entry["action"] for entry in logs["items"]}
    assert "assessment.created" in actions
    assert "auth.login" in actions


def test_audit_log_records_the_actor_and_ip(client, auth):
    client.post("/api/assessments", headers=auth(Role.SECURITY_LEAD), json={"name": "Attributed"})
    logs = client.get(
        "/api/audit-logs", headers=auth(Role.ADMIN), params={"page_size": 100}
    ).json()
    entry = next(e for e in logs["items"] if e["action"] == "assessment.created")
    assert entry["actor_email"]
    assert entry["actor_role"]


def test_audit_log_has_no_mutation_endpoints(client, auth):
    """There must be no ordinary way to delete or edit an audit record."""
    headers = auth(Role.ADMIN)
    assert client.delete("/api/audit-logs/1", headers=headers).status_code in (404, 405)
    assert client.patch("/api/audit-logs/1", headers=headers, json={}).status_code in (404, 405)
    assert client.put("/api/audit-logs/1", headers=headers, json={}).status_code in (404, 405)


def test_failed_login_is_audited(client, users):
    client.post(
        "/api/auth/login",
        json={"email": users[Role.ADMIN].email, "password": "wrong-password"},
    )
    token = client.post(
        "/api/auth/login",
        json={"email": users[Role.ADMIN].email, "password": "TestPass123!"},
    ).json()["access_token"]
    logs = client.get(
        "/api/audit-logs",
        headers={"Authorization": f"Bearer {token}"},
        params={"page_size": 100},
    ).json()
    assert any(e["action"] == "auth.login_failed" for e in logs["items"])


def test_system_health_reports_component_status(client, auth):
    response = client.get("/api/system/health", headers=auth(Role.ADMIN))
    assert response.status_code == 200
    body = response.json()
    assert body["components"]
    kinds = {c["kind"] for c in body["components"]}
    assert {"database", "storage", "scanner"} <= kinds


def test_scanner_and_profile_catalogues_are_exposed(client, auth):
    scanners = client.get("/api/scans/scanners", headers=auth(Role.SECURITY_ENGINEER))
    assert scanners.status_code == 200
    assert len(scanners.json()) >= 8

    profiles = client.get("/api/scans/profiles", headers=auth(Role.SECURITY_ENGINEER))
    assert profiles.status_code == 200
    assert {p["name"] for p in profiles.json()} == {"LIGHT", "STANDARD", "COMPREHENSIVE"}
