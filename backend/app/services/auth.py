"""Authentication service."""
from __future__ import annotations

from fastapi import Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.exceptions import AuthenticationError, ConflictError, ValidationError
from app.core.permissions import ROLE_LABELS, Role
from app.db.base import utcnow
from app.models.user import User
from app.schemas.auth import CurrentUser
from app.security.passwords import (
    hash_password,
    needs_rehash,
    validate_password_strength,
    verify_password,
)
from app.security.rate_limit import login_rate_limiter
from app.security.tokens import (
    access_token_expiry_seconds,
    create_access_token,
    create_refresh_token,
)
from app.services import audit
from app.services.audit import AuditAction


def _rate_limit_key(email: str, request: Request | None) -> str:
    return f"{email.lower()}|{audit.client_ip(request) or 'unknown'}"


def authenticate(db: Session, email: str, password: str, request: Request | None = None) -> User:
    """Verify credentials, throttling repeated failures per email + IP."""
    login_rate_limiter.check(_rate_limit_key(email, request))

    user = db.query(User).filter(func.lower(User.email) == email.lower()).first()

    # Always run a verification so that a missing account and a wrong password
    # take a comparable amount of time.
    if user is None:
        hash_password("timing-equalisation-placeholder")
        audit.record(
            db,
            action=AuditAction.LOGIN_FAILED,
            actor_email=email,
            description="Login failed: unknown account.",
            request=request,
        )
        db.commit()
        raise AuthenticationError("Incorrect email or password.")

    if not verify_password(password, user.hashed_password):
        audit.record(
            db,
            action=AuditAction.LOGIN_FAILED,
            user=user,
            description="Login failed: incorrect password.",
            request=request,
        )
        db.commit()
        raise AuthenticationError("Incorrect email or password.")

    if not user.is_active:
        audit.record(
            db,
            action=AuditAction.LOGIN_FAILED,
            user=user,
            description="Login failed: account deactivated.",
            request=request,
        )
        db.commit()
        raise AuthenticationError("This account has been deactivated.")

    # Transparently upgrade the stored hash if the Argon2 parameters changed.
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(password)

    user.last_login_at = utcnow()
    login_rate_limiter.reset(_rate_limit_key(email, request))
    audit.record(
        db,
        action=AuditAction.LOGIN,
        user=user,
        resource_type="User",
        resource_id=user.id,
        description=f"{user.full_name} signed in.",
        request=request,
    )
    db.commit()
    return user


def build_current_user(user: User) -> CurrentUser:
    return CurrentUser(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        role_label=ROLE_LABELS.get(user.role, user.role),
        job_title=user.job_title,
        is_active=user.is_active,
        is_demo=user.is_demo,
        last_login_at=user.last_login_at,
        permissions=sorted(user.permissions),
    )


def issue_tokens(user: User) -> dict:
    return {
        "access_token": create_access_token(user.id, user.role),
        "refresh_token": create_refresh_token(user.id),
        "token_type": "bearer",
        "expires_in": access_token_expiry_seconds(),
        "user": build_current_user(user),
    }


def change_password(
    db: Session, user: User, current_password: str, new_password: str, request: Request | None = None
) -> None:
    if not verify_password(current_password, user.hashed_password):
        raise AuthenticationError("Your current password is incorrect.")
    if current_password == new_password:
        raise ValidationError("The new password must differ from the current one.")
    validate_password_strength(new_password)
    user.hashed_password = hash_password(new_password)
    audit.record(
        db,
        action=AuditAction.PASSWORD_CHANGED,
        user=user,
        resource_type="User",
        resource_id=user.id,
        description="Password changed.",
        request=request,
    )
    db.commit()


def create_user(
    db: Session,
    *,
    email: str,
    full_name: str,
    password: str,
    role: str = Role.VIEWER,
    job_title: str | None = None,
    is_demo: bool = False,
    validate_strength: bool = True,
) -> User:
    existing = db.query(User).filter(func.lower(User.email) == email.lower()).first()
    if existing:
        raise ConflictError(f"A user with the email {email} already exists.")
    if validate_strength:
        validate_password_strength(password)
    user = User(
        email=email.lower(),
        full_name=full_name,
        hashed_password=hash_password(password),
        role=role,
        job_title=job_title,
        is_demo=is_demo,
        is_active=True,
    )
    db.add(user)
    db.flush()
    return user
