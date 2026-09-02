from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.api.deps import CurrentUser, DbSession, require_permission
from app.core.config import settings
from app.core.permissions import Permission
from app.db.session import check_database
from app.scanners.registry import scanner_registry
from app.schemas.common import MessageResponse
from app.schemas.system import ComponentHealth, SLASettings, SystemHealthResponse
from app.services import ai_triage as ai_triage_service
from app.services import audit, sla as sla_service
from app.services.audit import AuditAction
from app.storage import get_storage

router = APIRouter(prefix="/system", tags=["System"])


def _celery_workers() -> int:
    """How many Celery workers are consuming the queue.

    Returns -1 when it cannot be determined, so an inconclusive probe is not
    mistaken for "no workers".
    """
    try:
        from app.workers.celery_app import celery_app

        replies = celery_app.control.ping(timeout=1.5) or []
        return len(replies)
    except Exception:
        return -1


@router.get(
    "/health",
    response_model=SystemHealthResponse,
    dependencies=[Depends(require_permission(Permission.SYSTEM_VIEW))],
    summary="Infrastructure and scanner availability",
)
def system_health(db: DbSession, user: CurrentUser) -> SystemHealthResponse:
    components: list[ComponentHealth] = []

    db_ok, db_detail = check_database()
    components.append(
        ComponentHealth(
            name="postgresql", label="PostgreSQL", kind="database",
            available=db_ok, detail=db_detail, required=True,
        )
    )

    storage = get_storage()
    storage_ok, storage_detail = storage.health()
    components.append(
        ComponentHealth(
            name=storage.name,
            label="MinIO" if storage.name == "minio" else "Local file storage",
            kind="storage", available=storage_ok, detail=storage_detail, required=True,
        )
    )

    from app.workers.runner import get_task_runner

    runner = get_task_runner()
    runner_ok, runner_detail = runner.health()
    components.append(
        ComponentHealth(
            name=runner.name,
            label="Celery worker" if runner.name == "celery" else "In-process task runner",
            kind="worker", available=runner_ok, detail=runner_detail, required=True,
        )
    )

    # Redis is this platform's Celery broker - it is not used as a cache. A
    # reachable broker with no worker consuming it is worse than no broker at
    # all: the runner switches to Celery and every scan queues for ever, so the
    # worker is checked too and reported as the actual problem.
    if settings.REDIS_URL:
        try:
            import redis

            redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=2).ping()
            redis_ok, redis_detail = True, f"Broker reachable at {settings.REDIS_URL}"
        except Exception as exc:
            redis_ok, redis_detail = False, f"{type(exc).__name__}: {exc}"[:160]
    else:
        redis_ok, redis_detail = False, (
            "REDIS_URL is not configured, so scans run on the in-process thread "
            "runner. That is a supported configuration, not a fault."
        )

    if redis_ok:
        workers = _celery_workers()
        if workers == 0:
            redis_ok = False
            redis_detail = (
                f"The broker at {settings.REDIS_URL} is reachable but no Celery worker is "
                "consuming it. Start a worker (celery -A app.workers.celery_app.celery_app "
                "worker) or set TASK_RUNNER=thread, otherwise queued scans will never run."
            )
        elif workers > 0:
            redis_detail = f"{redis_detail}; {workers} worker(s) consuming the queue"

    components.append(
        ComponentHealth(
            name="redis", label="Redis (Celery broker)", kind="queue",
            available=redis_ok, detail=redis_detail, required=False,
        )
    )

    # AI triage is optional in exactly the same way a scanner binary is.
    ai_ok, ai_detail = ai_triage_service.availability()
    components.append(
        ComponentHealth(
            name="ai_triage", label="AI Triage Assistant", kind="enrichment",
            available=ai_ok, detail=ai_detail, required=False,
            version=settings.AI_TRIAGE_MODEL if ai_ok else None,
        )
    )

    for adapter in scanner_registry.availability_report():
        components.append(
            ComponentHealth(
                name=adapter["name"],
                label=adapter["label"],
                kind="scanner",
                available=adapter["available"],
                detail=adapter["availability_detail"],
                version=adapter["version"],
                required=adapter["kind"] == "builtin",
            )
        )

    degraded = [c.name for c in components if not c.available]
    healthy = all(c.available for c in components if c.required)

    return SystemHealthResponse(
        healthy=healthy,
        degraded_components=degraded,
        components=components,
        task_runner=runner.name,
        storage_backend=storage.name,
        offline_mode=settings.OFFLINE_MODE,
        demo_mode=settings.DEMO_MODE,
        version=settings.VERSION,
    )


@router.get(
    "/settings/sla",
    response_model=SLASettings,
    dependencies=[Depends(require_permission(Permission.SYSTEM_VIEW))],
    summary="Configured SLA windows, in hours, per severity",
)
def get_sla_settings(db: DbSession, user: CurrentUser) -> SLASettings:
    return SLASettings(**sla_service.get_sla_hours(db))


@router.put(
    "/settings/sla",
    response_model=SLASettings,
    dependencies=[Depends(require_permission(Permission.SETTINGS_MANAGE))],
    summary="Update the remediation SLA windows",
)
def update_sla_settings(
    payload: SLASettings, request: Request, db: DbSession, user: CurrentUser
) -> SLASettings:
    old = sla_service.get_sla_hours(db)
    values = payload.model_dump()
    sla_service.set_sla_hours(db, values, user.id)
    audit.record(
        db,
        action=AuditAction.SETTINGS_UPDATED,
        user=user,
        resource_type="SystemSetting",
        resource_id=sla_service.SLA_SETTING_KEY,
        description="Remediation SLA windows updated.",
        old_value=old,
        new_value=values,
        request=request,
    )
    db.commit()
    return SLASettings(**values)


@router.post(
    "/demo/seed",
    response_model=MessageResponse,
    dependencies=[Depends(require_permission(Permission.SETTINGS_MANAGE))],
    summary="Seed (or re-seed) the labelled demonstration dataset",
)
def seed_demo(request: Request, db: DbSession, user: CurrentUser) -> MessageResponse:
    from app.seed.demo import seed_demo_data

    summary = seed_demo_data(db, reset=True)
    audit.record(
        db,
        action=AuditAction.DEMO_DATA_SEEDED,
        user=user,
        resource_type="System",
        description=f"Demonstration data seeded: {summary}",
        new_value=summary,
        request=request,
    )
    db.commit()
    return MessageResponse(
        message="Demonstration data seeded.",
        detail=(
            "All seeded records are flagged as DEMO DATA and are visually labelled "
            "throughout the interface and in generated reports."
        ),
    )
