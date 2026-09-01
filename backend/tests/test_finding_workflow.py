"""Finding lifecycle, verification and false-positive handling."""
from __future__ import annotations

import pytest

from app.core.exceptions import WorkflowError
from app.core.permissions import Role
from app.models.enums import FindingStatus, VerificationStatus
from app.services import workflow


def test_confirming_a_finding_sets_status_and_attribution(client, auth, finding):
    response = client.post(
        f"/api/findings/{finding.id}/verify",
        headers=auth(Role.SECURITY_ENGINEER),
        json={"confirmed": True, "note": "Reproduced manually."},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == FindingStatus.CONFIRMED
    assert body["verification_status"] == VerificationStatus.CONFIRMED
    assert body["verified_by"]["role"] == Role.SECURITY_ENGINEER
    assert body["verified_at"]


def test_false_positive_requires_a_written_reason(client, auth, finding):
    response = client.post(
        f"/api/findings/{finding.id}/verify",
        headers=auth(Role.SECURITY_ENGINEER),
        json={"confirmed": False},
    )
    assert response.status_code == 422
    assert "reason is required" in response.json()["error"]["message"].lower()


def test_false_positive_is_retained_not_deleted(client, auth, finding):
    reason = "Input is HTML-encoded before rendering; verified with five payloads."
    response = client.post(
        f"/api/findings/{finding.id}/verify",
        headers=auth(Role.SECURITY_ENGINEER),
        json={"confirmed": False, "reason": reason},
    )
    assert response.status_code == 200
    assert response.json()["status"] == FindingStatus.FALSE_POSITIVE

    # Still retrievable, with the justification preserved for audit.
    detail = client.get(
        f"/api/findings/{finding.id}", headers=auth(Role.SECURITY_ENGINEER)
    ).json()
    assert detail["false_positive_reason"] == reason
    assert detail["risk"]["risk_score"] == 0.0


def test_false_positive_still_appears_in_listings_for_audit(client, auth, finding):
    client.post(
        f"/api/findings/{finding.id}/verify",
        headers=auth(Role.SECURITY_ENGINEER),
        json={"confirmed": False, "reason": "Safely encoded."},
    )
    listing = client.get(
        "/api/findings",
        headers=auth(Role.SECURITY_ENGINEER),
        params={"include_false_positive": True, "page_size": 100},
    ).json()
    assert any(item["id"] == finding.id for item in listing["items"])


def test_an_unconfirmed_finding_cannot_be_assigned(db, users, finding):
    from app.core.exceptions import WorkflowError as WE

    with pytest.raises(WE):
        workflow.assign(
            db,
            users[Role.SECURITY_LEAD],
            finding,
            assigned_to=users[Role.DEVELOPER],
        )


def test_illegal_transition_is_refused(db, users, finding):
    """CLOSED is not reachable directly from DISCOVERED."""
    finding.status = FindingStatus.DISCOVERED
    with pytest.raises(WorkflowError):
        workflow._assert_transition(finding, FindingStatus.CLOSED)


def test_full_lifecycle_discovered_to_closed(client, auth, db, users, finding):
    headers_eng = auth(Role.SECURITY_ENGINEER)
    headers_lead = auth(Role.SECURITY_LEAD)
    headers_dev = auth(Role.DEVELOPER)

    assert client.post(
        f"/api/findings/{finding.id}/verify", headers=headers_eng,
        json={"confirmed": True},
    ).json()["status"] == FindingStatus.CONFIRMED

    assert client.post(
        f"/api/findings/{finding.id}/triage", headers=headers_lead,
        json={"priority": "P1"},
    ).json()["status"] == FindingStatus.TRIAGED

    assigned = client.post(
        f"/api/findings/{finding.id}/assign", headers=headers_lead,
        json={"assigned_to_id": users[Role.DEVELOPER].id, "priority": "P1"},
    ).json()
    assert assigned["status"] == FindingStatus.REMEDIATION
    assert assigned["sla"]["due_at"] is not None

    assert client.post(
        f"/api/findings/{finding.id}/ready-for-retest", headers=headers_dev,
        json={"fix_summary": "Switched to prepared statements."},
    ).status_code == 200

    retest = client.post(
        f"/api/findings/{finding.id}/retest", headers=headers_eng,
        json={"result": "PASS", "summary": "No longer exploitable."},
    )
    assert retest.status_code == 201, retest.text

    detail = client.get(f"/api/findings/{finding.id}", headers=headers_eng).json()
    assert detail["status"] == FindingStatus.CLOSED
    assert detail["closed_at"] is not None
    events = [h["event_type"] for h in detail["history"]]
    for expected in ("VERIFIED", "TRIAGED", "ASSIGNED", "RETEST_PERFORMED", "CLOSED"):
        assert expected in events, events


def test_failed_retest_reopens_remediation(client, auth, users, finding):
    headers_eng = auth(Role.SECURITY_ENGINEER)
    headers_lead = auth(Role.SECURITY_LEAD)
    headers_dev = auth(Role.DEVELOPER)

    client.post(f"/api/findings/{finding.id}/verify", headers=headers_eng, json={"confirmed": True})
    client.post(
        f"/api/findings/{finding.id}/assign", headers=headers_lead,
        json={"assigned_to_id": users[Role.DEVELOPER].id},
    )
    client.post(
        f"/api/findings/{finding.id}/ready-for-retest", headers=headers_dev, json={}
    )
    response = client.post(
        f"/api/findings/{finding.id}/retest", headers=headers_eng,
        json={"result": "FAIL", "summary": "Payload still executes."},
    )
    assert response.status_code == 201

    detail = client.get(f"/api/findings/{finding.id}", headers=headers_eng).json()
    assert detail["status"] == FindingStatus.REMEDIATION
    assert detail["remediation"]["status"] == "REOPENED"
    assert detail["remediation"]["reopened_count"] == 1


def test_developer_cannot_mark_their_own_work_resolved(client, auth, users, finding):
    client.post(
        f"/api/findings/{finding.id}/verify", headers=auth(Role.SECURITY_ENGINEER),
        json={"confirmed": True},
    )
    client.post(
        f"/api/findings/{finding.id}/assign", headers=auth(Role.SECURITY_LEAD),
        json={"assigned_to_id": users[Role.DEVELOPER].id},
    )
    response = client.patch(
        f"/api/findings/{finding.id}/remediation",
        headers=auth(Role.DEVELOPER),
        json={"status": "RESOLVED"},
    )
    assert response.status_code == 403


def test_developer_only_sees_findings_assigned_to_them(client, auth, users, finding, db):
    unassigned = client.get("/api/findings", headers=auth(Role.DEVELOPER)).json()
    assert unassigned["total"] == 0

    client.post(
        f"/api/findings/{finding.id}/verify", headers=auth(Role.SECURITY_ENGINEER),
        json={"confirmed": True},
    )
    client.post(
        f"/api/findings/{finding.id}/assign", headers=auth(Role.SECURITY_LEAD),
        json={"assigned_to_id": users[Role.DEVELOPER].id},
    )
    assigned = client.get("/api/findings", headers=auth(Role.DEVELOPER)).json()
    assert assigned["total"] == 1
    assert assigned["items"][0]["id"] == finding.id
