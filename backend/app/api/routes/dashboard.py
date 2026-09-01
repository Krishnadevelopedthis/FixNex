from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import CurrentUser, DbSession, require_permission
from app.core.config import settings
from app.core.permissions import Permission
from app.schemas.dashboard import DashboardResponse
from app.services import stats

router = APIRouter(tags=["Dashboard"])


@router.get(
    "/dashboard",
    response_model=DashboardResponse,
    dependencies=[Depends(require_permission(Permission.DASHBOARD_VIEW))],
    summary="Aggregated security posture for the dashboard",
)
def get_dashboard(db: DbSession, user: CurrentUser) -> DashboardResponse:
    return stats.build_dashboard(db, demo_mode=settings.DEMO_MODE)
