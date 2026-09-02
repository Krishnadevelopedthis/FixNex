from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status

from app.api.deps import (
    CurrentUser,
    DbSession,
    Pagination,
    require_assessment_access,
    require_permission,
)
from app.core.permissions import Permission
from app.models.assessment import Assessment
from app.models.enums import AssessmentStatus
from app.models.target import ScopeRule
from app.schemas.dashboard import AssetHeatmap, PostureScore
from app.schemas.assessments import (
    AttackPathResponse,
    ComplianceResponse,
    AssessmentCreate,
    AssessmentListItem,
    AssessmentRead,
    AssessmentUpdate,
    ScopeCheckRequest,
    ScopeCheckResponse,
    ScopeRuleCreate,
    ScopeRuleRead,
    TeamUpdate,
)
from app.schemas.common import MessageResponse, Page
from app.schemas.targets import TargetCreate, TargetRead
from app.services import attack_paths as attack_path_service
from app.services import stats as stats_service
from app.services import compliance as compliance_service
from app.services import assessments as service
from app.services import scope as scope_service
from app.services import targets as target_service

router = APIRouter(prefix="/assessments", tags=["Assessments"])


@router.post(
    "",
    response_model=AssessmentRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.ASSESSMENT_CREATE))],
    summary="Create an assessment",
)
def create_assessment(
    payload: AssessmentCreate, request: Request, db: DbSession, user: CurrentUser
) -> AssessmentRead:
    assessment = service.create(db, user, payload, request)
    return service.to_read(db, assessment)


@router.get(
    "",
    response_model=Page[AssessmentListItem],
    dependencies=[Depends(require_permission(Permission.ASSESSMENT_VIEW))],
    summary="List assessments",
)
def list_assessments(
    db: DbSession,
    user: CurrentUser,
    pagination: Pagination,
    status_filter: Annotated[list[AssessmentStatus] | None, Query(alias="status")] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    include_demo: bool = True,
) -> Page[AssessmentListItem]:
    query = db.query(Assessment)
    if status_filter:
        query = query.filter(Assessment.status.in_([s.value for s in status_filter]))
    if search:
        term = f"%{search.strip()}%"
        query = query.filter(
            Assessment.name.ilike(term)
            | Assessment.client_name.ilike(term)
            | Assessment.reference.ilike(term)
        )
    if not include_demo:
        query = query.filter(Assessment.is_demo.is_(False))

    total = query.count()
    rows = (
        query.order_by(Assessment.created_at.desc())
        .offset(pagination.offset)
        .limit(pagination.page_size)
        .all()
    )
    visible = [a for a in rows if require_visible(db, user, a)]
    return Page.build(
        [service.to_list_item(db, a) for a in visible], total, pagination.page, pagination.page_size
    )


def require_visible(db, user, assessment) -> bool:
    from app.api.deps import user_can_access_assessment

    return user_can_access_assessment(db, user, assessment)


@router.get(
    "/{assessment_id}",
    response_model=AssessmentRead,
    dependencies=[Depends(require_permission(Permission.ASSESSMENT_VIEW))],
    summary="Assessment detail",
)
def get_assessment(assessment_id: int, db: DbSession, user: CurrentUser) -> AssessmentRead:
    assessment = require_assessment_access(db, user, assessment_id)
    return service.to_read(db, assessment)


@router.patch(
    "/{assessment_id}",
    response_model=AssessmentRead,
    dependencies=[Depends(require_permission(Permission.ASSESSMENT_UPDATE))],
    summary="Update an assessment",
)
def update_assessment(
    assessment_id: int, payload: AssessmentUpdate, request: Request, db: DbSession, user: CurrentUser
) -> AssessmentRead:
    assessment = require_assessment_access(db, user, assessment_id)
    assessment = service.update(db, user, assessment, payload, request)
    return service.to_read(db, assessment)


@router.delete(
    "/{assessment_id}",
    response_model=MessageResponse,
    dependencies=[Depends(require_permission(Permission.ASSESSMENT_DELETE))],
    summary="Delete an assessment",
)
def delete_assessment(
    assessment_id: int, request: Request, db: DbSession, user: CurrentUser
) -> MessageResponse:
    assessment = require_assessment_access(db, user, assessment_id)
    reference = assessment.reference
    service.delete(db, user, assessment, request)
    return MessageResponse(message=f"Assessment {reference} was deleted.")


@router.put(
    "/{assessment_id}/team",
    response_model=AssessmentRead,
    dependencies=[Depends(require_permission(Permission.ASSESSMENT_MANAGE_TEAM))],
    summary="Set the assessment team",
)
def set_team(
    assessment_id: int, payload: TeamUpdate, request: Request, db: DbSession, user: CurrentUser
) -> AssessmentRead:
    assessment = require_assessment_access(db, user, assessment_id)
    assessment = service.set_team(db, user, assessment, payload.members, request)
    return service.to_read(db, assessment)


# --------------------------------------------------------------------- scope
@router.get(
    "/{assessment_id}/scope",
    response_model=list[ScopeRuleRead],
    dependencies=[Depends(require_permission(Permission.ASSESSMENT_VIEW))],
    summary="List authorised scope rules",
)
def list_scope(assessment_id: int, db: DbSession, user: CurrentUser) -> list[ScopeRuleRead]:
    require_assessment_access(db, user, assessment_id)
    rules = (
        db.query(ScopeRule)
        .filter(ScopeRule.assessment_id == assessment_id)
        .order_by(ScopeRule.is_exclusion, ScopeRule.id)
        .all()
    )
    return [service.scope_rule_read(r) for r in rules]


@router.post(
    "/{assessment_id}/scope",
    response_model=ScopeRuleRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.SCOPE_MANAGE))],
    summary="Authorise a domain, URL, IP or CIDR range",
)
def add_scope_rule(
    assessment_id: int, payload: ScopeRuleCreate, request: Request, db: DbSession, user: CurrentUser
) -> ScopeRuleRead:
    assessment = require_assessment_access(db, user, assessment_id)
    rule = service.add_scope_rule(db, user, assessment, payload, request)
    return service.scope_rule_read(rule)


@router.delete(
    "/{assessment_id}/scope/{rule_id}",
    response_model=MessageResponse,
    dependencies=[Depends(require_permission(Permission.SCOPE_MANAGE))],
    summary="Remove a scope rule",
)
def delete_scope_rule(
    assessment_id: int, rule_id: int, request: Request, db: DbSession, user: CurrentUser
) -> MessageResponse:
    assessment = require_assessment_access(db, user, assessment_id)
    service.delete_scope_rule(db, user, assessment, rule_id, request)
    return MessageResponse(message="Scope rule removed.")


@router.post(
    "/{assessment_id}/scope/check",
    response_model=ScopeCheckResponse,
    dependencies=[Depends(require_permission(Permission.ASSESSMENT_VIEW))],
    summary="Check whether a value is inside the authorised scope",
)
def check_scope(
    assessment_id: int, payload: ScopeCheckRequest, db: DbSession, user: CurrentUser
) -> ScopeCheckResponse:
    assessment = require_assessment_access(db, user, assessment_id)
    decision = scope_service.check(db, assessment, payload.value)
    return ScopeCheckResponse(
        value=payload.value,
        in_scope=decision.in_scope,
        matched_rule=service.scope_rule_read(decision.matched_rule) if decision.matched_rule else None,
        reason=decision.reason,
    )


# ------------------------------------------------------------------- targets
@router.get(
    "/{assessment_id}/targets",
    response_model=list[TargetRead],
    dependencies=[Depends(require_permission(Permission.TARGET_VIEW))],
    summary="List the assessment's targets",
)
def list_targets(assessment_id: int, db: DbSession, user: CurrentUser) -> list[TargetRead]:
    assessment = require_assessment_access(db, user, assessment_id)
    return [target_service.to_read(db, t) for t in assessment.targets]


@router.post(
    "/{assessment_id}/targets",
    response_model=TargetRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.TARGET_CREATE))],
    summary="Add an authorised target",
)
def add_target(
    assessment_id: int, payload: TargetCreate, request: Request, db: DbSession, user: CurrentUser
) -> TargetRead:
    assessment = require_assessment_access(db, user, assessment_id)
    target = target_service.create_target(db, user, assessment, payload, request)
    return target_service.to_read(db, target)


@router.get(
    "/{assessment_id}/attack-paths",
    response_model=AttackPathResponse,
    dependencies=[Depends(require_permission(Permission.FINDING_VIEW))],
    summary="Potential attack chains among this assessment's findings",
)
def attack_paths(assessment_id: int, db: DbSession, user: CurrentUser) -> AttackPathResponse:
    """Chains where one finding makes another materially more dangerous.

    Only live findings are considered — a closed, suppressed or false-positive
    finding is not a foothold.
    """
    require_assessment_access(db, user, assessment_id)
    return AttackPathResponse(**attack_path_service.build_attack_paths(db, assessment_id))


@router.get(
    "/{assessment_id}/compliance",
    response_model=ComplianceResponse,
    dependencies=[Depends(require_permission(Permission.FINDING_VIEW))],
    summary="Control-framework readiness derived from this assessment's findings",
)
def compliance(assessment_id: int, db: DbSession, user: CurrentUser) -> ComplianceResponse:
    """Map findings onto OWASP Top 10, NIST SP 800-53 and ISO/IEC 27001 controls.

    Readiness reflects only the controls that findings in this assessment touch;
    controls with no evidence either way are not scored.
    """
    require_assessment_access(db, user, assessment_id)
    return ComplianceResponse(**compliance_service.build_compliance(db, assessment_id))


@router.get(
    "/{assessment_id}/posture",
    response_model=PostureScore,
    dependencies=[Depends(require_permission(Permission.DASHBOARD_VIEW))],
    summary="Explainable security posture score for one assessment",
)
def assessment_posture(assessment_id: int, db: DbSession, user: CurrentUser) -> PostureScore:
    """A 0-100 score returned with every deduction that produced it."""
    require_assessment_access(db, user, assessment_id)
    return PostureScore(**stats_service.posture_score(db, assessment_id))


@router.get(
    "/{assessment_id}/heatmap",
    response_model=AssetHeatmap,
    dependencies=[Depends(require_permission(Permission.DASHBOARD_VIEW))],
    summary="Open findings per asset per severity",
)
def assessment_heatmap(assessment_id: int, db: DbSession, user: CurrentUser) -> AssetHeatmap:
    require_assessment_access(db, user, assessment_id)
    return AssetHeatmap(**stats_service.asset_severity_heatmap(db, assessment_id))
