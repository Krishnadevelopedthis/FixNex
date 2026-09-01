"""Per-finding timeline entries (distinct from the global audit log)."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.finding import Finding, FindingHistory
from app.models.user import User


def record(
    db: Session,
    finding: Finding,
    *,
    event_type: str,
    user: User | None = None,
    actor_name: str | None = None,
    from_status: str | None = None,
    to_status: str | None = None,
    note: str | None = None,
    metadata: dict | None = None,
) -> FindingHistory:
    entry = FindingHistory(
        finding_id=finding.id,
        user_id=user.id if user else None,
        actor_name=(user.full_name if user else actor_name),
        event_type=event_type,
        from_status=from_status,
        to_status=to_status,
        note=note,
        event_metadata=metadata or {},
        created_at=utcnow(),
    )
    db.add(entry)
    return entry
