"""SLA engine: per-severity remediation deadlines and status."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.base import utcnow
from app.models.enums import SLAStatus, Severity
from app.models.system import SystemSetting

SLA_SETTING_KEY = "sla_hours"

DEFAULT_SLA_HOURS: dict[str, int] = {
    Severity.CRITICAL: settings.SLA_HOURS_CRITICAL,
    Severity.HIGH: settings.SLA_HOURS_HIGH,
    Severity.MEDIUM: settings.SLA_HOURS_MEDIUM,
    Severity.LOW: settings.SLA_HOURS_LOW,
    Severity.INFORMATIONAL: settings.SLA_HOURS_INFORMATIONAL,
}


def get_sla_hours(db: Session | None = None) -> dict[str, int]:
    """Configured SLA windows, falling back to the environment defaults."""
    hours = dict(DEFAULT_SLA_HOURS)
    if db is not None:
        setting = db.query(SystemSetting).filter(SystemSetting.key == SLA_SETTING_KEY).first()
        if setting and isinstance(setting.value, dict):
            for severity, value in setting.value.items():
                if severity in hours and isinstance(value, int) and value > 0:
                    hours[severity] = value
    return hours


def set_sla_hours(db: Session, values: dict[str, int], user_id: int | None = None) -> dict[str, int]:
    setting = db.query(SystemSetting).filter(SystemSetting.key == SLA_SETTING_KEY).first()
    if setting is None:
        setting = SystemSetting(
            key=SLA_SETTING_KEY,
            description="Remediation SLA window, in hours, per severity level.",
        )
        db.add(setting)
    setting.value = values
    setting.updated_by_id = user_id
    return values


def due_at(severity: str, start: datetime | None = None, db: Session | None = None,
           override_hours: int | None = None) -> datetime:
    hours = override_hours or get_sla_hours(db).get(severity, settings.SLA_HOURS_MEDIUM)
    return (start or utcnow()) + timedelta(hours=hours)


def _as_utc(value: datetime | None) -> datetime | None:
    """Coerce a datetime to timezone-aware UTC.

    Some database backends (SQLite, and any column written before the
    timezone-aware default) return naive datetimes. Treat those as UTC rather
    than raising when they are compared against an aware "now".
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def evaluate(deadline: datetime | None, *, resolved_at: datetime | None = None,
             is_closed: bool = False) -> dict:
    """Compute the SLA status shown as the traffic-light indicator in the UI."""
    deadline = _as_utc(deadline)
    resolved_at = _as_utc(resolved_at)
    if deadline is None:
        return {"due_at": None, "status": SLAStatus.NOT_APPLICABLE, "hours_remaining": None, "breached": False}

    if is_closed or resolved_at is not None:
        finished = resolved_at or utcnow()
        breached = finished > deadline
        return {
            "due_at": deadline,
            "status": SLAStatus.BREACHED if breached else SLAStatus.MET,
            "hours_remaining": round((deadline - finished).total_seconds() / 3600, 1),
            "breached": breached,
        }

    now = utcnow()
    remaining = (deadline - now).total_seconds() / 3600
    if remaining < 0:
        status = SLAStatus.OVERDUE
    else:
        total_window = max((deadline - now).total_seconds(), 1)
        # "Due soon" once the remaining window falls under 25% of a typical window.
        status = SLAStatus.DUE_SOON if remaining <= 24 or total_window <= 0 else SLAStatus.ON_TRACK
    return {
        "due_at": deadline,
        "status": status,
        "hours_remaining": round(remaining, 1),
        "breached": remaining < 0,
    }
