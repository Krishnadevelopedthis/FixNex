"""Assessment, scope and team management."""
from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.models.assessment import Assessment, AssessmentMember
from app.models.enums import AssessmentStatus
from app.models.target import ScopeRule
from app.models.user import User
from app.schemas.assessments import (
    AssessmentListItem,
    AssessmentRead,
    AssessmentSummaryStats,
    MemberRead,
    ScopeRuleRead,
    SeverityBreakdown,
)
from app.services import audit, scope as scope_service, stats
from app.services.audit import AuditAction
from app.services.references import assign_reference


def _user_brief(user):
    from app.services.findings import user_brief

    return user_brief(user)


def stats_schema(db: Session, assessment: Assessment) -> AssessmentSummaryStats:
    raw = stats.assessment_stats(db, assessment)
    return AssessmentSummaryStats(
        **{**raw, "severity": SeverityBreakdown(**raw["severity"])}
    )


def to_read(db: Session, assessment: Assessment, with_stats: bool = True) -> AssessmentRead:
    return AssessmentRead(
        id=assessment.id,
        reference=assessment.reference,
        name=assessment.name,
        description=assessment.description,
        client_name=assessment.client_name,
        start_date=assessment.start_date,
        end_date=assessment.end_date,
        status=assessment.status,
        methodology=assessment.methodology,
        notes=assessment.notes,
        engagement_type=assessment.engagement_type,
        tags=assessment.tags or [],
        is_demo=assessment.is_demo,
        created_at=assessment.created_at,
        updated_at=assessment.updated_at,
        created_by=_user_brief(assessment.created_by),
        members=[
            MemberRead(
                id=m.id,
                user_id=m.user_id,
                role_in_assessment=m.role_in_assessment,
                user=_user_brief(m.user),
            )
            for m in assessment.members
        ],
        stats=stats_schema(db, assessment) if with_stats else None,
    )


def to_list_item(db: Session, assessment: Assessment) -> AssessmentListItem:
    return AssessmentListItem(
        id=assessment.id,
        reference=assessment.reference,
        name=assessment.name,
        client_name=assessment.client_name,
        status=assessment.status,
        start_date=assessment.start_date,
        end_date=assessment.end_date,
        is_demo=assessment.is_demo,
        created_at=assessment.created_at,
        stats=stats_schema(db, assessment),
    )


def scope_rule_read(rule: ScopeRule) -> ScopeRuleRead:
    return ScopeRuleRead(
        id=rule.id,
        assessment_id=rule.assessment_id,
        rule_type=rule.rule_type,
        value=rule.value,
        is_exclusion=rule.is_exclusion,
        note=rule.note,
        created_at=rule.created_at,
        created_by=_user_brief(rule.created_by),
    )


def create(db: Session, user: User, payload, request: Request | None = None) -> Assessment:
    if payload.start_date and payload.end_date and payload.end_date < payload.start_date:
        raise ValidationError("The end date cannot fall before the start date.")

    assessment = Assessment(
        name=payload.name,
        description=payload.description,
        client_name=payload.client_name,
        start_date=payload.start_date,
        end_date=payload.end_date,
        methodology=payload.methodology
        or (
            "OWASP Web Security Testing Guide (WSTG) informed methodology: reconnaissance, "
            "automated scanning, manual verification, evidence collection, risk analysis, "
            "remediation tracking and retesting."
        ),
        notes=payload.notes,
        engagement_type=payload.engagement_type,
        tags=payload.tags,
        status=AssessmentStatus.DRAFT,
        created_by_id=user.id,
    )
    db.add(assessment)
    assign_reference(db, assessment)

    member_ids = set(payload.member_ids) | {user.id}
    for member_id in member_ids:
        member_user = db.get(User, member_id)
        if member_user is None:
            continue
        db.add(
            AssessmentMember(
                assessment_id=assessment.id,
                user_id=member_id,
                role_in_assessment=("Owner" if member_id == user.id else None),
            )
        )

    audit.record(
        db,
        action=AuditAction.ASSESSMENT_CREATED,
        user=user,
        resource_type="Assessment",
        resource_id=assessment.id,
        assessment_id=assessment.id,
        description=f"Assessment {assessment.reference} '{assessment.name}' created.",
        new_value={"name": assessment.name, "client": assessment.client_name},
        request=request,
    )
    db.commit()
    db.refresh(assessment)
    return assessment


def update(db: Session, user: User, assessment: Assessment, payload, request: Request | None = None) -> Assessment:
    old = {"status": assessment.status, "name": assessment.name}
    data = payload.model_dump(exclude_unset=True)
    for field, value in data.items():
        setattr(assessment, field, value)

    if assessment.start_date and assessment.end_date and assessment.end_date < assessment.start_date:
        raise ValidationError("The end date cannot fall before the start date.")

    action = (
        AuditAction.ASSESSMENT_STATUS_CHANGED
        if "status" in data and data["status"] != old["status"]
        else AuditAction.ASSESSMENT_UPDATED
    )
    audit.record(
        db,
        action=action,
        user=user,
        resource_type="Assessment",
        resource_id=assessment.id,
        assessment_id=assessment.id,
        description=f"Assessment {assessment.reference} updated.",
        old_value=old,
        new_value={"status": assessment.status, "name": assessment.name},
        request=request,
    )
    db.commit()
    db.refresh(assessment)
    return assessment


def delete(db: Session, user: User, assessment: Assessment, request: Request | None = None) -> None:
    if assessment.is_demo:
        raise ConflictError(
            "Seeded demo assessments cannot be deleted. Reset the demo data instead."
        )
    audit.record(
        db,
        action=AuditAction.ASSESSMENT_DELETED,
        user=user,
        resource_type="Assessment",
        resource_id=assessment.id,
        assessment_id=assessment.id,
        description=f"Assessment {assessment.reference} '{assessment.name}' deleted.",
        old_value={"name": assessment.name, "reference": assessment.reference},
        request=request,
    )
    db.delete(assessment)
    db.commit()


def set_team(db: Session, user: User, assessment: Assessment, members, request: Request | None = None) -> Assessment:
    existing = {m.user_id: m for m in assessment.members}
    wanted = {m.user_id: m.role_in_assessment for m in members}

    for user_id in list(existing):
        if user_id not in wanted:
            db.delete(existing[user_id])
    for user_id, role_in_assessment in wanted.items():
        if db.get(User, user_id) is None:
            raise ValidationError(f"User {user_id} was not found.")
        if user_id in existing:
            existing[user_id].role_in_assessment = role_in_assessment
        else:
            db.add(
                AssessmentMember(
                    assessment_id=assessment.id,
                    user_id=user_id,
                    role_in_assessment=role_in_assessment,
                )
            )

    audit.record(
        db,
        action=AuditAction.TEAM_UPDATED,
        user=user,
        resource_type="Assessment",
        resource_id=assessment.id,
        assessment_id=assessment.id,
        description=f"Assessment team updated ({len(wanted)} members).",
        old_value={"members": sorted(existing)},
        new_value={"members": sorted(wanted)},
        request=request,
    )
    db.commit()
    db.refresh(assessment)
    return assessment


def add_scope_rule(db: Session, user: User, assessment: Assessment, payload, request: Request | None = None) -> ScopeRule:
    value = scope_service.validate_target_value(payload.value, payload.rule_type)
    duplicate = (
        db.query(ScopeRule)
        .filter(
            ScopeRule.assessment_id == assessment.id,
            ScopeRule.rule_type == payload.rule_type,
            ScopeRule.value == value,
            ScopeRule.is_exclusion == payload.is_exclusion,
        )
        .first()
    )
    if duplicate:
        raise ConflictError("That scope rule already exists on this assessment.")

    rule = ScopeRule(
        assessment_id=assessment.id,
        rule_type=payload.rule_type,
        value=value,
        is_exclusion=payload.is_exclusion,
        note=payload.note,
        created_by_id=user.id,
    )
    db.add(rule)
    audit.record(
        db,
        action=AuditAction.SCOPE_RULE_CREATED,
        user=user,
        resource_type="ScopeRule",
        resource_id=None,
        assessment_id=assessment.id,
        description=(
            f"{'Exclusion' if payload.is_exclusion else 'Authorised'} scope rule added: "
            f"{payload.rule_type} = {value}"
        ),
        new_value={"rule_type": payload.rule_type, "value": value, "is_exclusion": payload.is_exclusion},
        request=request,
    )
    db.commit()
    db.refresh(rule)
    return rule


def delete_scope_rule(db: Session, user: User, assessment: Assessment, rule_id: int, request: Request | None = None) -> None:
    rule = db.get(ScopeRule, rule_id)
    if rule is None or rule.assessment_id != assessment.id:
        raise NotFoundError("That scope rule was not found on this assessment.")
    audit.record(
        db,
        action=AuditAction.SCOPE_RULE_DELETED,
        user=user,
        resource_type="ScopeRule",
        resource_id=rule.id,
        assessment_id=assessment.id,
        description=f"Scope rule removed: {rule.rule_type} = {rule.value}",
        old_value={"rule_type": rule.rule_type, "value": rule.value},
        request=request,
    )
    db.delete(rule)
    db.commit()
