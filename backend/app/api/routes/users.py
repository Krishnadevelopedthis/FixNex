from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status

from app.api.deps import CurrentUser, DbSession, require_any_permission, require_permission
from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.core.permissions import ROLE_LABELS, Permission, permission_matrix
from app.models.user import User
from app.schemas.common import MessageResponse
from app.schemas.users import RoleInfo, UserCreate, UserRead, UserUpdate
from app.security.passwords import hash_password, validate_password_strength
from app.services import audit, auth as auth_service
from app.services.audit import AuditAction

router = APIRouter(tags=["Users & Roles"])


def _read(user: User) -> UserRead:
    return UserRead(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        role_label=ROLE_LABELS.get(user.role, user.role),
        job_title=user.job_title,
        is_active=user.is_active,
        is_demo=user.is_demo,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
    )


@router.get(
    "/users",
    response_model=list[UserRead],
    dependencies=[Depends(require_any_permission(Permission.USER_VIEW, Permission.FINDING_ASSIGN))],
    summary="List users (used for assignment pickers)",
)
def list_users(
    db: DbSession,
    user: CurrentUser,
    role: Annotated[str | None, Query(max_length=40)] = None,
    active_only: bool = True,
) -> list[UserRead]:
    query = db.query(User)
    if role:
        query = query.filter(User.role == role)
    if active_only:
        query = query.filter(User.is_active.is_(True))
    return [_read(u) for u in query.order_by(User.full_name).all()]


@router.post(
    "/users",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.USER_CREATE))],
    summary="Create a user",
)
def create_user(
    payload: UserCreate, request: Request, db: DbSession, user: CurrentUser
) -> UserRead:
    created = auth_service.create_user(
        db,
        email=payload.email,
        full_name=payload.full_name,
        password=payload.password,
        role=payload.role,
        job_title=payload.job_title,
    )
    audit.record(
        db,
        action=AuditAction.USER_CREATED,
        user=user,
        resource_type="User",
        resource_id=created.id,
        description=f"User {created.email} created with role {created.role}.",
        new_value={"email": created.email, "role": created.role},
        request=request,
    )
    db.commit()
    db.refresh(created)
    return _read(created)


@router.get(
    "/users/{user_id}",
    response_model=UserRead,
    dependencies=[Depends(require_permission(Permission.USER_VIEW))],
    summary="User detail",
)
def get_user(user_id: int, db: DbSession, user: CurrentUser) -> UserRead:
    target = db.get(User, user_id)
    if target is None:
        raise NotFoundError(f"User {user_id} was not found.")
    return _read(target)


@router.patch(
    "/users/{user_id}",
    response_model=UserRead,
    dependencies=[Depends(require_permission(Permission.USER_UPDATE))],
    summary="Update a user, their role or their password",
)
def update_user(
    user_id: int, payload: UserUpdate, request: Request, db: DbSession, user: CurrentUser
) -> UserRead:
    target = db.get(User, user_id)
    if target is None:
        raise NotFoundError(f"User {user_id} was not found.")

    old = {"role": target.role, "is_active": target.is_active}
    data = payload.model_dump(exclude_unset=True)

    if "role" in data and data["role"] != target.role:
        # Refuse to remove the last remaining active administrator.
        if target.role == "ADMIN":
            remaining = (
                db.query(User)
                .filter(User.role == "ADMIN", User.is_active.is_(True), User.id != target.id)
                .count()
            )
            if remaining == 0:
                raise ConflictError("The last active administrator's role cannot be changed.")

    if "is_active" in data and data["is_active"] is False and target.id == user.id:
        raise ValidationError("You cannot deactivate your own account.")

    password = data.pop("password", None)
    if password:
        validate_password_strength(password)
        target.hashed_password = hash_password(password)

    for field, value in data.items():
        setattr(target, field, value)

    audit.record(
        db,
        action=AuditAction.ROLE_CHANGED if old["role"] != target.role else AuditAction.USER_UPDATED,
        user=user,
        resource_type="User",
        resource_id=target.id,
        description=f"User {target.email} updated.",
        old_value=old,
        new_value={"role": target.role, "is_active": target.is_active},
        request=request,
    )
    db.commit()
    db.refresh(target)
    return _read(target)


@router.delete(
    "/users/{user_id}",
    response_model=MessageResponse,
    dependencies=[Depends(require_permission(Permission.USER_DELETE))],
    summary="Deactivate a user (accounts are never hard-deleted)",
)
def deactivate_user(
    user_id: int, request: Request, db: DbSession, user: CurrentUser
) -> MessageResponse:
    target = db.get(User, user_id)
    if target is None:
        raise NotFoundError(f"User {user_id} was not found.")
    if target.id == user.id:
        raise ValidationError("You cannot deactivate your own account.")

    # Deactivating rather than deleting keeps every audit reference intact.
    target.is_active = False
    audit.record(
        db,
        action=AuditAction.USER_DELETED,
        user=user,
        resource_type="User",
        resource_id=target.id,
        description=f"User {target.email} deactivated.",
        old_value={"is_active": True},
        new_value={"is_active": False},
        request=request,
    )
    db.commit()
    return MessageResponse(
        message=f"{target.email} has been deactivated.",
        detail="Accounts are deactivated rather than deleted so audit references remain valid.",
    )


@router.get(
    "/roles",
    response_model=list[RoleInfo],
    summary="Role definitions and the permissions each one grants",
)
def list_roles(user: CurrentUser) -> list[RoleInfo]:
    return [RoleInfo(**row) for row in permission_matrix()]
