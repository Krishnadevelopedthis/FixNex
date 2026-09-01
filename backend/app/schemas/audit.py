from __future__ import annotations

from datetime import datetime

from app.schemas.common import ORMModel, UserBrief


class AuditLogRead(ORMModel):
    id: int
    action: str
    actor_email: str | None = None
    actor_role: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    assessment_id: int | None = None
    description: str | None = None
    old_value: dict | None = None
    new_value: dict | None = None
    ip_address: str | None = None
    created_at: datetime
    user: UserBrief | None = None
