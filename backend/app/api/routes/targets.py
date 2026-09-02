from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status

from app.api.deps import CurrentUser, DbSession, Pagination, require_assessment_access, require_permission
from app.core.exceptions import NotFoundError
from app.core.permissions import Permission
from app.models.asset import Asset
from app.models.target import Target
from app.schemas.assets import AssetCreate, AssetRead, AssetUpdate
from app.schemas.common import MessageResponse, Page
from app.schemas.targets import (
    OpenAPIImportRequest,
    OpenAPIImportResult,
    TargetEndpointRead,
    TargetRead,
    TargetUpdate,
)
from app.services import targets as service

router = APIRouter(tags=["Targets & Assets"])


def _get_target(db, user, target_id: int) -> Target:
    target = db.get(Target, target_id)
    if target is None:
        raise NotFoundError(f"Target {target_id} was not found.")
    require_assessment_access(db, user, target.assessment_id)
    return target


# --------------------------------------------------------------------- targets
@router.get(
    "/targets",
    response_model=Page[TargetRead],
    dependencies=[Depends(require_permission(Permission.TARGET_VIEW))],
    summary="List targets across assessments",
)
def list_targets(
    db: DbSession,
    user: CurrentUser,
    pagination: Pagination,
    assessment_id: Annotated[int | None, Query()] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
) -> Page[TargetRead]:
    """Paginated, like every other collection endpoint on this API."""
    query = db.query(Target)
    if assessment_id:
        require_assessment_access(db, user, assessment_id)
        query = query.filter(Target.assessment_id == assessment_id)
    if search:
        term = f"%{search.strip()}%"
        query = query.filter(Target.name.ilike(term) | Target.value.ilike(term))

    total = query.count()
    rows = (
        query.order_by(Target.id.desc())
        .offset(pagination.offset)
        .limit(pagination.page_size)
        .all()
    )
    return Page.build(
        [service.to_read(db, t) for t in rows], total, pagination.page, pagination.page_size
    )


@router.get(
    "/targets/{target_id}",
    response_model=TargetRead,
    dependencies=[Depends(require_permission(Permission.TARGET_VIEW))],
    summary="Target detail",
)
def get_target(target_id: int, db: DbSession, user: CurrentUser) -> TargetRead:
    return service.to_read(db, _get_target(db, user, target_id))


@router.patch(
    "/targets/{target_id}",
    response_model=TargetRead,
    dependencies=[Depends(require_permission(Permission.TARGET_UPDATE))],
    summary="Update a target",
)
def update_target(
    target_id: int, payload: TargetUpdate, request: Request, db: DbSession, user: CurrentUser
) -> TargetRead:
    target = _get_target(db, user, target_id)
    return service.to_read(db, service.update_target(db, user, target, payload, request))


@router.delete(
    "/targets/{target_id}",
    response_model=MessageResponse,
    dependencies=[Depends(require_permission(Permission.TARGET_DELETE))],
    summary="Remove a target",
)
def delete_target(
    target_id: int, request: Request, db: DbSession, user: CurrentUser
) -> MessageResponse:
    target = _get_target(db, user, target_id)
    reference = target.reference
    service.delete_target(db, user, target, request)
    return MessageResponse(message=f"Target {reference} removed.")


@router.get(
    "/targets/{target_id}/endpoints",
    response_model=list[TargetEndpointRead],
    dependencies=[Depends(require_permission(Permission.TARGET_VIEW))],
    summary="List a REST API target's endpoints",
)
def list_endpoints(target_id: int, db: DbSession, user: CurrentUser) -> list[TargetEndpointRead]:
    target = _get_target(db, user, target_id)
    return [
        TargetEndpointRead(
            id=e.id, method=e.method, path=e.path, summary=e.summary,
            source=e.source, auth_required=e.auth_required,
        )
        for e in target.endpoints
    ]


@router.post(
    "/targets/{target_id}/import-openapi",
    response_model=OpenAPIImportResult,
    dependencies=[Depends(require_permission(Permission.TARGET_UPDATE))],
    summary="Import API endpoints from an OpenAPI/Swagger specification",
)
def import_openapi(
    target_id: int, payload: OpenAPIImportRequest, request: Request, db: DbSession, user: CurrentUser
) -> OpenAPIImportResult:
    target = _get_target(db, user, target_id)
    return OpenAPIImportResult(**service.import_openapi(db, user, target, payload, request))


# ---------------------------------------------------------------------- assets
@router.get(
    "/assets",
    response_model=Page[AssetRead],
    dependencies=[Depends(require_permission(Permission.ASSET_VIEW))],
    summary="Asset inventory",
)
def list_assets(db: DbSession, user: CurrentUser, pagination: Pagination) -> Page[AssetRead]:
    """Paginated, like every other collection endpoint on this API."""
    query = db.query(Asset)
    total = query.count()
    rows = (
        query.order_by(Asset.id).offset(pagination.offset).limit(pagination.page_size).all()
    )
    return Page.build(
        [service.asset_read(db, a) for a in rows], total, pagination.page, pagination.page_size
    )


@router.post(
    "/assets",
    response_model=AssetRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.ASSET_CREATE))],
    summary="Register a business asset",
)
def create_asset(
    payload: AssetCreate, request: Request, db: DbSession, user: CurrentUser
) -> AssetRead:
    return service.asset_read(db, service.create_asset(db, user, payload, request))


@router.get(
    "/assets/{asset_id}",
    response_model=AssetRead,
    dependencies=[Depends(require_permission(Permission.ASSET_VIEW))],
    summary="Asset detail",
)
def get_asset(asset_id: int, db: DbSession, user: CurrentUser) -> AssetRead:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError(f"Asset {asset_id} was not found.")
    return service.asset_read(db, asset)


@router.patch(
    "/assets/{asset_id}",
    response_model=AssetRead,
    dependencies=[Depends(require_permission(Permission.ASSET_UPDATE))],
    summary="Update an asset's context (drives contextual risk)",
)
def update_asset(
    asset_id: int, payload: AssetUpdate, request: Request, db: DbSession, user: CurrentUser
) -> AssetRead:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError(f"Asset {asset_id} was not found.")
    return service.asset_read(db, service.update_asset(db, user, asset, payload, request))
