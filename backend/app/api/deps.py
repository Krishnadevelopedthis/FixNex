"""Reusable FastAPI dependencies: authentication, RBAC and pagination.

Routes never inspect `user.role` directly — they declare the permission they
need and this module resolves it against the central permission matrix.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Annotated

from fastapi import Depends, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.exceptions import AuthenticationError, NotFoundError, PermissionDeniedError
from app.core.permissions import Permission, Role
from app.db.session import get_db
from app.models.assessment import Assessment, AssessmentMember
from app.models.user import User
from app.schemas.common import PaginationParams
from app.security.tokens import decode_token

MAX_PAGE = 1_000_000

bearer_scheme = HTTPBearer(auto_error=False, description="JWT access token")

DbSession = Annotated[Session, Depends(get_db)]


def get_current_user(
    db: DbSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
) -> User:
    if credentials is None or not credentials.credentials:
        raise AuthenticationError("Authentication credentials were not provided.")

    payload = decode_token(credentials.credentials, expected_type="access")
    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthenticationError("Malformed authentication token.") from exc

    user = db.get(User, user_id)
    if user is None:
        raise AuthenticationError("The account for this token no longer exists.")
    if not user.is_active:
        raise AuthenticationError("This account has been deactivated.")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_permission(*permissions: Permission | str) -> Callable[..., User]:
    """Dependency factory: require every listed permission.

        @router.post("/", dependencies=[Depends(require_permission(Permission.SCAN_CREATE))])
    """
    required = [str(p) for p in permissions]

    def _dependency(user: CurrentUser) -> User:
        missing = [p for p in required if not user.has_permission(p)]
        if missing:
            raise PermissionDeniedError(
                "Your role ("
                f"{user.role}) does not grant the required permission: {', '.join(missing)}."
            )
        return user

    return _dependency


def require_any_permission(*permissions: Permission | str) -> Callable[..., User]:
    options = [str(p) for p in permissions]

    def _dependency(user: CurrentUser) -> User:
        if not any(user.has_permission(p) for p in options):
            raise PermissionDeniedError(
                f"Your role ({user.role}) does not grant any of: {', '.join(options)}."
            )
        return user

    return _dependency


def get_pagination(
    # `page` is bounded as well as `page_size`: the SQL OFFSET is
    # (page - 1) * page_size, and an unbounded page overflows a bigint, which
    # surfaced as a 500 rather than a validation error.
    page: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 25,
) -> PaginationParams:
    return PaginationParams(page=page, page_size=page_size)


Pagination = Annotated[PaginationParams, Depends(get_pagination)]


def get_assessment_or_404(db: Session, assessment_id: int) -> Assessment:
    assessment = db.get(Assessment, assessment_id)
    if assessment is None:
        raise NotFoundError(f"Assessment {assessment_id} was not found.")
    return assessment


def user_can_access_assessment(db: Session, user: User, assessment: Assessment) -> bool:
    """Admins, leads, engineers, analysts and auditors see all assessments.

    Developers only see assessments they are a member of or hold a finding in.
    """
    if user.role != Role.DEVELOPER:
        return True
    if assessment.created_by_id == user.id:
        return True
    member = (
        db.query(AssessmentMember)
        .filter(
            AssessmentMember.assessment_id == assessment.id,
            AssessmentMember.user_id == user.id,
        )
        .first()
    )
    if member:
        return True
    from app.models.finding import Finding  # local import avoids a cycle

    assigned = (
        db.query(Finding.id)
        .filter(Finding.assessment_id == assessment.id, Finding.assigned_to_id == user.id)
        .first()
    )
    return assigned is not None


def require_assessment_access(db: Session, user: User, assessment_id: int) -> Assessment:
    assessment = get_assessment_or_404(db, assessment_id)
    if not user_can_access_assessment(db, user, assessment):
        raise PermissionDeniedError("You do not have access to this assessment.")
    return assessment


def get_request_context(request: Request) -> Request:
    return request
