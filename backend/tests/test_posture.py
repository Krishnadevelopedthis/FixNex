"""Security posture score and the asset x severity heatmap."""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.core.permissions import Role
from app.db.base import utcnow
from app.models.enums import FindingStatus, Severity, VerificationStatus
from app.models.finding import Finding
from app.services.stats import (
    AGEING_DAYS,
    POSTURE_WEIGHTS,
    asset_severity_heatmap,
    posture_score,
)


def _add(db, assessment, target, severity=Severity.MEDIUM, status=FindingStatus.CONFIRMED, **kw):
    from app.services.references import assign_reference

    finding = Finding(
        assessment_id=assessment.id, target_id=target.id, primary_source="test",
        title=kw.pop("title", f"{severity} finding"), severity=severity, status=status,
        verification_status=kw.pop("verification_status", VerificationStatus.CONFIRMED),
        first_seen_at=kw.pop("first_seen_at", utcnow()), **kw,
    )
    db.add(finding)
    assign_reference(db, finding)
    db.commit()
    return finding


# ------------------------------------------------------------------- score
def test_clean_assessment_scores_one_hundred(db, assessment):
    result = posture_score(db, assessment.id)
    assert result["score"] == 100.0
    assert result["grade"] == "A"
    assert all(f["penalty"] == 0.0 for f in result["factors"])


def test_open_criticals_deduct_the_most(db, assessment, target):
    _add(db, assessment, target, Severity.CRITICAL)
    result = posture_score(db, assessment.id)
    critical = next(f for f in result["factors"] if f["key"] == "open_critical")
    assert critical["count"] == 1
    assert critical["penalty"] > 0
    assert result["score"] < 100.0


def test_each_factor_is_capped_at_its_weight(db, assessment, target):
    """No single factor may sink the score on its own."""
    for _ in range(40):
        _add(db, assessment, target, Severity.CRITICAL)
    result = posture_score(db, assessment.id)
    critical = next(f for f in result["factors"] if f["key"] == "open_critical")
    assert critical["penalty"] == POSTURE_WEIGHTS["open_critical"]
    # Criticals alone cannot take the score below 100 - that weight.
    assert result["score"] >= 100.0 - sum(POSTURE_WEIGHTS.values())


def test_score_is_clamped_between_zero_and_one_hundred(db, assessment, target):
    for _ in range(40):
        _add(db, assessment, target, Severity.CRITICAL,
             status=FindingStatus.DISCOVERED, verification_status=VerificationStatus.UNVERIFIED,
             sla_due_at=utcnow() - timedelta(days=5),
             first_seen_at=utcnow() - timedelta(days=AGEING_DAYS + 10))
    result = posture_score(db, assessment.id)
    assert 0.0 <= result["score"] <= 100.0


def test_sla_breaches_are_counted(db, assessment, target):
    _add(db, assessment, target, Severity.MEDIUM, sla_due_at=utcnow() - timedelta(days=2))
    _add(db, assessment, target, Severity.MEDIUM, sla_due_at=utcnow() + timedelta(days=2))
    breaches = next(
        f for f in posture_score(db, assessment.id)["factors"] if f["key"] == "sla_breaches"
    )
    assert breaches["count"] == 1


def test_ageing_findings_are_counted(db, assessment, target):
    _add(db, assessment, target, first_seen_at=utcnow() - timedelta(days=AGEING_DAYS + 1))
    _add(db, assessment, target, first_seen_at=utcnow())
    ageing = next(
        f for f in posture_score(db, assessment.id)["factors"] if f["key"] == "ageing_findings"
    )
    assert ageing["count"] == 1


def test_unverified_backlog_is_counted(db, assessment, target):
    _add(db, assessment, target, status=FindingStatus.DISCOVERED,
         verification_status=VerificationStatus.UNVERIFIED)
    _add(db, assessment, target, status=FindingStatus.NEEDS_VERIFICATION,
         verification_status=VerificationStatus.UNVERIFIED)
    _add(db, assessment, target, status=FindingStatus.CONFIRMED)
    backlog = next(
        f for f in posture_score(db, assessment.id)["factors"] if f["key"] == "unverified_backlog"
    )
    assert backlog["count"] == 2


def test_closed_findings_do_not_count_against_posture(db, assessment, target):
    _add(db, assessment, target, Severity.CRITICAL, status=FindingStatus.CLOSED)
    result = posture_score(db, assessment.id)
    assert result["score"] == 100.0
    assert result["totals"]["closed"] == 1
    assert result["totals"]["resolution_rate"] == 100.0


def test_false_positives_are_excluded(db, assessment, target):
    _add(db, assessment, target, Severity.CRITICAL, status=FindingStatus.FALSE_POSITIVE,
         verification_status=VerificationStatus.FALSE_POSITIVE)
    assert posture_score(db, assessment.id)["score"] == 100.0


def test_suppressed_findings_are_excluded(db, assessment, target):
    _add(db, assessment, target, Severity.CRITICAL, is_suppressed=True)
    assert posture_score(db, assessment.id)["score"] == 100.0


def test_score_is_monotonic_in_open_criticals(db, assessment, target):
    scores = []
    for _ in range(4):
        _add(db, assessment, target, Severity.CRITICAL)
        scores.append(posture_score(db, assessment.id)["score"])
    assert scores == sorted(scores, reverse=True), scores


GRADE_BANDS = [(85.0, "A"), (70.0, "B"), (55.0, "C"), (35.0, "D"), (0.0, "F")]


def _expected_grade(score: float) -> str:
    return next(grade for threshold, grade in GRADE_BANDS if score >= threshold)


@pytest.mark.parametrize("critical_count", [0, 1, 3, 5, 12])
def test_grade_always_matches_its_own_score_band(db, assessment, target, critical_count):
    """Assert the grade is consistent with the score rather than hardcoding
    counts, so tuning the weights cannot silently desynchronise the two."""
    for _ in range(critical_count):
        _add(db, assessment, target, Severity.CRITICAL)
    result = posture_score(db, assessment.id)
    assert result["grade"] == _expected_grade(result["score"])


def test_worsening_findings_move_the_grade_down(db, assessment, target):
    grades = []
    for _ in range(4):
        for _ in range(3):
            _add(db, assessment, target, Severity.CRITICAL, status=FindingStatus.DISCOVERED,
                 verification_status=VerificationStatus.UNVERIFIED,
                 sla_due_at=utcnow() - timedelta(days=1))
        grades.append(posture_score(db, assessment.id)["grade"])
    # Grades never improve as more unresolved criticals pile up.
    assert grades == sorted(grades)


def test_score_always_ships_its_workings(db, assessment, target):
    """An unexplained score is not actionable, so the breakdown is mandatory."""
    _add(db, assessment, target, Severity.CRITICAL)
    result = posture_score(db, assessment.id)
    assert set(POSTURE_WEIGHTS) == {f["key"] for f in result["factors"]}
    for factor in result["factors"]:
        assert factor["label"] and factor["explanation"]
        assert 0.0 <= factor["penalty"] <= factor["max_penalty"]
    assert "not an industry standard" in result["methodology"]
    # Deductions must actually reconcile with the headline number.
    assert result["score"] == pytest.approx(
        max(0.0, 100.0 - sum(f["penalty"] for f in result["factors"])), abs=0.05
    )


def test_factors_are_ordered_by_impact(db, assessment, target):
    _add(db, assessment, target, Severity.CRITICAL)
    _add(db, assessment, target, Severity.HIGH)
    penalties = [f["penalty"] for f in posture_score(db, assessment.id)["factors"]]
    assert penalties == sorted(penalties, reverse=True)


# ----------------------------------------------------------------- heatmap
def test_heatmap_counts_open_findings_per_severity(db, assessment, target):
    _add(db, assessment, target, Severity.CRITICAL)
    _add(db, assessment, target, Severity.CRITICAL)
    _add(db, assessment, target, Severity.LOW)
    heatmap = asset_severity_heatmap(db, assessment.id)
    assert len(heatmap["assets"]) == 1
    counts = heatmap["assets"][0]["counts"]
    assert counts["CRITICAL"] == 2 and counts["LOW"] == 1
    assert heatmap["assets"][0]["total"] == 3
    assert heatmap["max_count"] == 2


def test_heatmap_keys_are_plain_strings(db, assessment, target):
    """The payload has to serialise as JSON, so no enum keys."""
    _add(db, assessment, target, Severity.HIGH)
    heatmap = asset_severity_heatmap(db, assessment.id)
    for key in heatmap["assets"][0]["counts"]:
        assert isinstance(key, str)
    assert all(isinstance(s, str) for s in heatmap["severities"])


def test_heatmap_merges_targets_sharing_one_asset(db, assessment, target, users):
    """Two targets on the same system are one row, not two identical ones."""
    from app.models.asset import Asset
    from app.models.enums import TargetStatus
    from app.models.target import Target
    from app.services.references import assign_reference

    asset = Asset(name="Shared platform", criticality=Severity.HIGH)
    db.add(asset)
    assign_reference(db, asset)
    second = Target(
        assessment_id=assessment.id, name="API tier", value="https://api.in-scope.example.com",
        target_type="WEB_APP", status=TargetStatus.AUTHORIZED, authorization_confirmed=True,
        asset_id=asset.id,
    )
    db.add(second)
    assign_reference(db, second)
    target.asset_id = asset.id
    db.commit()

    _add(db, assessment, target, Severity.HIGH)
    _add(db, assessment, second, Severity.CRITICAL)

    heatmap = asset_severity_heatmap(db, assessment.id)
    assert len(heatmap["assets"]) == 1
    row = heatmap["assets"][0]
    assert row["name"] == "Shared platform"
    assert row["targets"] == 2
    assert row["counts"]["HIGH"] == 1 and row["counts"]["CRITICAL"] == 1


def test_heatmap_orders_by_worst_severity_first(db, assessment, target, users):
    from app.models.enums import TargetStatus
    from app.models.target import Target
    from app.services.references import assign_reference

    quiet = Target(
        assessment_id=assessment.id, name="Quiet system", value="https://quiet.in-scope.example.com",
        target_type="WEB_APP", status=TargetStatus.AUTHORIZED, authorization_confirmed=True,
    )
    db.add(quiet)
    assign_reference(db, quiet)
    db.commit()

    for _ in range(5):
        _add(db, assessment, quiet, Severity.LOW)
    _add(db, assessment, target, Severity.CRITICAL)

    heatmap = asset_severity_heatmap(db, assessment.id)
    # One critical outranks five lows.
    assert heatmap["assets"][0]["counts"]["CRITICAL"] == 1


def test_heatmap_excludes_closed_and_false_positive(db, assessment, target):
    _add(db, assessment, target, Severity.CRITICAL, status=FindingStatus.CLOSED)
    _add(db, assessment, target, Severity.HIGH, status=FindingStatus.FALSE_POSITIVE,
         verification_status=VerificationStatus.FALSE_POSITIVE)
    assert asset_severity_heatmap(db, assessment.id)["assets"] == []


# ------------------------------------------------------------------ routes
def test_dashboard_carries_posture_and_heatmap(client, auth):
    body = client.get("/api/dashboard", headers=auth(Role.SECURITY_LEAD)).json()
    assert body["posture"] is not None
    assert body["asset_heatmap"] is not None
    assert 0.0 <= body["posture"]["score"] <= 100.0


def test_assessment_posture_route(client, auth, assessment, target, db):
    _add(db, assessment, target, Severity.CRITICAL)
    response = client.get(f"/api/assessments/{assessment.id}/posture", headers=auth(Role.VIEWER))
    assert response.status_code == 200
    assert response.json()["factors"]


def test_assessment_heatmap_route(client, auth, assessment, target, db):
    _add(db, assessment, target, Severity.HIGH)
    response = client.get(f"/api/assessments/{assessment.id}/heatmap", headers=auth(Role.VIEWER))
    assert response.status_code == 200
    assert response.json()["assets"][0]["counts"]["HIGH"] == 1
