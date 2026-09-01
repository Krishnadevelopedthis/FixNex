"""Target and asset management, including OpenAPI endpoint import."""
from __future__ import annotations

import httpx
from fastapi import Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError, ScopeViolationError, ValidationError
from app.db.base import utcnow
from app.models.assessment import Assessment
from app.models.asset import Asset
from app.models.enums import FindingStatus, TargetStatus, TargetType
from app.models.finding import Finding
from app.models.scan import ScanJob
from app.models.target import Target, TargetEndpoint
from app.models.user import User
from app.schemas.assets import AssetRead
from app.schemas.targets import AUTHORIZATION_STATEMENT, TargetEndpointRead, TargetRead
from app.services import audit, scope as scope_service
from app.services.audit import AuditAction
from app.services.references import assign_reference

_HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def _user_brief(user):
    from app.services.findings import user_brief

    return user_brief(user)


# ---------------------------------------------------------------- serialisation
def to_read(db: Session, target: Target) -> TargetRead:
    last_scan = (
        db.query(func.max(ScanJob.created_at)).filter(ScanJob.target_id == target.id).scalar()
    )
    return TargetRead(
        id=target.id,
        reference=target.reference,
        assessment_id=target.assessment_id,
        asset_id=target.asset_id,
        asset_name=target.asset.name if target.asset else None,
        name=target.name,
        target_type=target.target_type,
        value=target.value,
        hostname=target.hostname,
        port=target.port,
        base_path=target.base_path,
        description=target.description,
        status=target.status,
        authorization_confirmed=target.authorization_confirmed,
        authorization_statement=target.authorization_statement,
        authorized_at=target.authorized_at,
        authorized_by=_user_brief(target.authorized_by),
        technologies=target.technologies or [],
        is_demo=target.is_demo,
        created_at=target.created_at,
        endpoint_count=len(target.endpoints),
        findings_count=db.query(Finding).filter(Finding.target_id == target.id).count(),
        last_scan_at=last_scan,
    )


def asset_read(db: Session, asset: Asset) -> AssetRead:
    open_findings = (
        db.query(Finding)
        .join(Target, Finding.target_id == Target.id)
        .filter(
            Target.asset_id == asset.id,
            Finding.status.notin_([FindingStatus.CLOSED, FindingStatus.FALSE_POSITIVE]),
        )
    )
    from app.models.enums import SEVERITY_ORDER

    severities = [f.severity for f in open_findings.all()]
    highest = max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0)) if severities else None

    return AssetRead(
        id=asset.id,
        reference=asset.reference,
        name=asset.name,
        description=asset.description,
        asset_type=asset.asset_type,
        owner=asset.owner,
        business_unit=asset.business_unit,
        primary_url=asset.primary_url,
        criticality=asset.criticality,
        data_sensitivity=asset.data_sensitivity,
        exposure=asset.exposure,
        technologies=asset.technologies or [],
        tags=asset.tags or [],
        is_demo=asset.is_demo,
        created_at=asset.created_at,
        open_findings=len(severities),
        highest_severity=highest,
    )


# --------------------------------------------------------------------- assets
def create_asset(db: Session, user: User, payload, request: Request | None = None) -> Asset:
    asset = Asset(**payload.model_dump())
    db.add(asset)
    assign_reference(db, asset)
    audit.record(
        db,
        action=AuditAction.ASSET_CREATED,
        user=user,
        resource_type="Asset",
        resource_id=asset.id,
        description=f"Asset {asset.reference} '{asset.name}' created ({asset.criticality} criticality).",
        new_value={"name": asset.name, "criticality": asset.criticality},
        request=request,
    )
    db.commit()
    db.refresh(asset)
    return asset


def update_asset(db: Session, user: User, asset: Asset, payload, request: Request | None = None) -> Asset:
    old = {"criticality": asset.criticality, "exposure": asset.exposure}
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(asset, field, value)
    audit.record(
        db,
        action=AuditAction.ASSET_UPDATED,
        user=user,
        resource_type="Asset",
        resource_id=asset.id,
        description=f"Asset {asset.reference} updated.",
        old_value=old,
        new_value={"criticality": asset.criticality, "exposure": asset.exposure},
        request=request,
    )
    db.commit()
    db.refresh(asset)
    return asset


# -------------------------------------------------------------------- targets
def create_target(
    db: Session, user: User, assessment: Assessment, payload, request: Request | None = None
) -> Target:
    """Add a target, enforcing scope membership and explicit authorisation."""
    value = scope_service.validate_target_value(payload.value)

    if not payload.authorization_confirmed:
        raise ScopeViolationError(
            "You must confirm the authorisation statement before a target can be added: "
            f'"{AUTHORIZATION_STATEMENT}"'
        )

    decision = scope_service.check(db, assessment, value)
    if not decision.in_scope:
        audit.record(
            db,
            action=AuditAction.SCOPE_VIOLATION_BLOCKED,
            user=user,
            resource_type="Target",
            assessment_id=assessment.id,
            description=f"Attempt to add out-of-scope target {value} was blocked: {decision.reason}",
            request=request,
        )
        db.commit()
        raise ScopeViolationError(decision.reason)

    duplicate = (
        db.query(Target)
        .filter(Target.assessment_id == assessment.id, Target.value == value)
        .first()
    )
    if duplicate:
        raise ConflictError(f"{value} is already a target of this assessment.")

    if payload.asset_id is not None and db.get(Asset, payload.asset_id) is None:
        raise ValidationError(f"Asset {payload.asset_id} was not found.")

    now = utcnow()
    target = Target(
        assessment_id=assessment.id,
        asset_id=payload.asset_id,
        name=payload.name,
        target_type=payload.target_type,
        value=value,
        hostname=scope_service.parse_host(value),
        port=payload.port,
        base_path=payload.base_path,
        description=payload.description,
        status=TargetStatus.AUTHORIZED,
        authorization_confirmed=True,
        authorization_statement=AUTHORIZATION_STATEMENT,
        authorized_by_id=user.id,
        authorized_at=now,
        is_demo=assessment.is_demo,
    )
    db.add(target)
    assign_reference(db, target)

    audit.record(
        db,
        action=AuditAction.TARGET_CREATED,
        user=user,
        resource_type="Target",
        resource_id=target.id,
        assessment_id=assessment.id,
        description=(
            f"Target {target.reference} '{value}' added and authorised by {user.full_name}. "
            f"{decision.reason}"
        ),
        new_value={
            "value": value,
            "target_type": payload.target_type,
            "authorization_statement": AUTHORIZATION_STATEMENT,
            "scope_rule": decision.matched_rule.value if decision.matched_rule else None,
        },
        request=request,
    )
    db.commit()
    db.refresh(target)
    return target


def update_target(db: Session, user: User, target: Target, payload, request: Request | None = None) -> Target:
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(target, field, value)
    audit.record(
        db,
        action=AuditAction.TARGET_UPDATED,
        user=user,
        resource_type="Target",
        resource_id=target.id,
        assessment_id=target.assessment_id,
        description=f"Target {target.reference} updated.",
        request=request,
    )
    db.commit()
    db.refresh(target)
    return target


def delete_target(db: Session, user: User, target: Target, request: Request | None = None) -> None:
    audit.record(
        db,
        action=AuditAction.TARGET_DELETED,
        user=user,
        resource_type="Target",
        resource_id=target.id,
        assessment_id=target.assessment_id,
        description=f"Target {target.reference} '{target.value}' removed.",
        old_value={"value": target.value},
        request=request,
    )
    db.delete(target)
    db.commit()


# ------------------------------------------------------------ OpenAPI import
def import_openapi(
    db: Session, user: User, target: Target, payload, request: Request | None = None
) -> dict:
    """Import API operations from an OpenAPI / Swagger document.

    Every imported path is re-checked against the assessment's scope.
    """
    if target.target_type != TargetType.REST_API:
        raise ValidationError(
            "OpenAPI import is only available for targets of type REST_API."
        )

    spec = payload.spec
    if spec is None:
        if not payload.spec_url:
            raise ValidationError("Provide either an OpenAPI document or a URL to fetch it from.")
        decision = scope_service.check(db, target.assessment, payload.spec_url)
        if not decision.in_scope:
            raise ScopeViolationError(
                f"The specification URL is outside the authorised scope: {decision.reason}"
            )
        try:
            response = httpx.get(payload.spec_url, timeout=20, follow_redirects=True, verify=False)
            response.raise_for_status()
            spec = response.json()
        except Exception as exc:
            raise ValidationError(
                f"Could not fetch the OpenAPI document: {type(exc).__name__}: {exc}"
            ) from exc

    if not isinstance(spec, dict) or "paths" not in spec:
        raise ValidationError("The document does not look like an OpenAPI specification (no 'paths').")

    if payload.replace_existing:
        for endpoint in list(target.endpoints):
            db.delete(endpoint)
        db.flush()

    info = spec.get("info", {}) if isinstance(spec.get("info"), dict) else {}
    security_schemes = bool((spec.get("components", {}) or {}).get("securitySchemes"))

    imported = skipped = 0
    for path, operations in (spec.get("paths") or {}).items():
        if not isinstance(operations, dict):
            skipped += 1
            continue
        for method, operation in operations.items():
            if method.lower() not in _HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                skipped += 1
                continue
            parameters = [
                {
                    "name": p.get("name"),
                    "in": p.get("in"),
                    "required": bool(p.get("required")),
                }
                for p in (operation.get("parameters") or [])
                if isinstance(p, dict)
            ]
            db.add(
                TargetEndpoint(
                    target_id=target.id,
                    method=method.upper()[:10],
                    path=str(path)[:500],
                    summary=(operation.get("summary") or operation.get("operationId") or None),
                    source="OPENAPI",
                    auth_required=bool(operation.get("security")) or security_schemes,
                    parameters=parameters,
                )
            )
            imported += 1

    audit.record(
        db,
        action=AuditAction.TARGET_UPDATED,
        user=user,
        resource_type="Target",
        resource_id=target.id,
        assessment_id=target.assessment_id,
        description=(
            f"{imported} API endpoints imported into target {target.reference} from an "
            f"OpenAPI specification ({info.get('title', 'untitled')})."
        ),
        new_value={"imported": imported, "skipped": skipped},
        request=request,
    )
    db.commit()
    db.refresh(target)

    return {
        "imported": imported,
        "skipped": skipped,
        "title": info.get("title"),
        "version": info.get("version"),
        "endpoints": [
            TargetEndpointRead(
                id=e.id,
                method=e.method,
                path=e.path,
                summary=e.summary,
                source=e.source,
                auth_required=e.auth_required,
            )
            for e in target.endpoints
        ],
    }


def get_target_in_assessment(db: Session, assessment_id: int, target_id: int) -> Target:
    target = db.get(Target, target_id)
    if target is None or target.assessment_id != assessment_id:
        raise NotFoundError("The target was not found in this assessment.")
    return target
