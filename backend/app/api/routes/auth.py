from __future__ import annotations

from fastapi import APIRouter, Request, status

from app.api.deps import CurrentUser, DbSession
from app.core.exceptions import AuthenticationError
from app.models.user import User
from app.schemas.auth import (
    ChangePasswordRequest,
    CurrentUser as CurrentUserSchema,
    LoginRequest,
    RefreshRequest,
    TokenResponse,
)
from app.schemas.common import MessageResponse
from app.security.tokens import decode_token
from app.services import audit, auth as auth_service
from app.services.audit import AuditAction

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse, summary="Sign in and receive a JWT")
def login(payload: LoginRequest, request: Request, db: DbSession) -> TokenResponse:
    user = auth_service.authenticate(db, payload.email, payload.password, request)
    return TokenResponse(**auth_service.issue_tokens(user))


@router.post("/refresh", response_model=TokenResponse, summary="Exchange a refresh token")
def refresh(payload: RefreshRequest, db: DbSession) -> TokenResponse:
    claims = decode_token(payload.refresh_token, expected_type="refresh")
    user = db.get(User, int(claims["sub"]))
    if user is None or not user.is_active:
        raise AuthenticationError("This account is no longer active.")
    return TokenResponse(**auth_service.issue_tokens(user))


@router.post("/logout", response_model=MessageResponse, summary="Sign out")
def logout(request: Request, db: DbSession, user: CurrentUser) -> MessageResponse:
    audit.record(
        db,
        action=AuditAction.LOGOUT,
        user=user,
        resource_type="User",
        resource_id=user.id,
        description=f"{user.full_name} signed out.",
        request=request,
    )
    db.commit()
    return MessageResponse(message="Signed out successfully.")


@router.get("/me", response_model=CurrentUserSchema, summary="Current user and permissions")
def me(user: CurrentUser) -> CurrentUserSchema:
    return auth_service.build_current_user(user)


@router.post("/change-password", response_model=MessageResponse, status_code=status.HTTP_200_OK)
def change_password(
    payload: ChangePasswordRequest, request: Request, db: DbSession, user: CurrentUser
) -> MessageResponse:
    auth_service.change_password(db, user, payload.current_password, payload.new_password, request)
    return MessageResponse(message="Password updated successfully.")
