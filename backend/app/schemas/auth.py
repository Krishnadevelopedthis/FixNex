from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.schemas.common import ORMModel


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: "CurrentUser"


class RefreshRequest(BaseModel):
    refresh_token: str


class CurrentUser(ORMModel):
    id: int
    email: str
    full_name: str
    role: str
    role_label: str
    job_title: str | None = None
    is_active: bool
    is_demo: bool = False
    last_login_at: datetime | None = None
    permissions: list[str]


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=1, max_length=200)


TokenResponse.model_rebuild()
