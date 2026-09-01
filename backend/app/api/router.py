"""Aggregate API router."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import (
    assessments,
    audit,
    auth,
    dashboard,
    evidence,
    findings,
    remediation,
    reports,
    scans,
    system,
    targets,
    users,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(assessments.router)
api_router.include_router(targets.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(evidence.router)
api_router.include_router(remediation.router)
api_router.include_router(reports.router)
api_router.include_router(audit.router)
api_router.include_router(users.router)
api_router.include_router(system.router)
