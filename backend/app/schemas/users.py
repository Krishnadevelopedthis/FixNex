from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.core.permissions import Role
from app.schemas.common import ORMModel


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=150)
    password: str = Field(min_length=1, max_length=200)
    role: Role = Role.VIEWER
    job_title: str | None = Field(None, max_length=120)


class UserUpdate(BaseModel):
    full_name: str | None = Field(None, min_length=2, max_length=150)
    role: Role | None = None
    job_title: str | None = Field(None, max_length=120)
    is_active: bool | None = None
    password: str | None = Field(None, min_length=1, max_length=200)


class UserRead(ORMModel):
    id: int
    email: str
    full_name: str
    role: str
    role_label: str | None = None
    job_title: str | None = None
    is_active: bool
    is_demo: bool
    last_login_at: datetime | None = None
    created_at: datetime


class RoleInfo(BaseModel):
    role: str
    label: str
    description: str
    permissions: list[str]
