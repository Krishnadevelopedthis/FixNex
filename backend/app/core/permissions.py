"""Centralised permission catalogue and role -> permission mapping.

Role checks are never scattered through the codebase: routes depend on a
permission, and this module is the single place that decides which role holds
which permission.
"""
from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "ADMIN"
    SECURITY_LEAD = "SECURITY_LEAD"
    SECURITY_ENGINEER = "SECURITY_ENGINEER"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"
    DEVELOPER = "DEVELOPER"


ROLE_LABELS: dict[str, str] = {
    Role.ADMIN: "Administrator",
    Role.SECURITY_LEAD: "Security Lead",
    Role.SECURITY_ENGINEER: "Security Engineer",
    Role.ANALYST: "Tester / Analyst",
    Role.VIEWER: "Viewer / Auditor",
    Role.DEVELOPER: "Developer / Remediation",
}

ROLE_DESCRIPTIONS: dict[str, str] = {
    Role.ADMIN: "Full platform access including user, role and system administration.",
    Role.SECURITY_LEAD: "Owns assessments: scope, team, finding approval, remediation and reporting.",
    Role.SECURITY_ENGINEER: "Runs scans and reconnaissance, verifies findings, scores risk and retests.",
    Role.ANALYST: "Performs manual testing, raises findings, uploads evidence and comments.",
    Role.VIEWER: "Read-only access to assessments, findings, evidence, reports and audit data.",
    Role.DEVELOPER: "Works assigned findings: updates remediation status and requests retests.",
}


class Permission(StrEnum):
    """Every action the platform can authorise."""

    # dashboard
    DASHBOARD_VIEW = "dashboard:view"

    # assessments
    ASSESSMENT_CREATE = "assessment:create"
    ASSESSMENT_VIEW = "assessment:view"
    ASSESSMENT_UPDATE = "assessment:update"
    ASSESSMENT_DELETE = "assessment:delete"
    ASSESSMENT_MANAGE_TEAM = "assessment:manage_team"

    # scope & assets & targets
    SCOPE_MANAGE = "scope:manage"
    ASSET_CREATE = "asset:create"
    ASSET_VIEW = "asset:view"
    ASSET_UPDATE = "asset:update"
    TARGET_CREATE = "target:create"
    TARGET_VIEW = "target:view"
    TARGET_UPDATE = "target:update"
    TARGET_DELETE = "target:delete"

    # scans
    SCAN_CREATE = "scan:create"
    SCAN_VIEW = "scan:view"
    SCAN_CANCEL = "scan:cancel"

    # findings
    FINDING_CREATE = "finding:create"
    FINDING_VIEW = "finding:view"          # at least own assigned findings
    FINDING_VIEW_ALL = "finding:view_all"  # every finding in scope of access
    FINDING_UPDATE = "finding:update"
    FINDING_VERIFY = "finding:verify"      # confirm / mark false positive
    FINDING_SCORE = "finding:score"        # change CVSS / contextual risk
    FINDING_TRIAGE = "finding:triage"
    FINDING_ASSIGN = "finding:assign"
    FINDING_COMMENT = "finding:comment"
    FINDING_SUPPRESS = "finding:suppress"

    # evidence
    EVIDENCE_UPLOAD = "evidence:upload"
    EVIDENCE_VIEW = "evidence:view"
    EVIDENCE_DELETE = "evidence:delete"

    # remediation & retest
    REMEDIATION_CREATE = "remediation:create"
    REMEDIATION_UPDATE = "remediation:update"
    REMEDIATION_VIEW = "remediation:view"
    RETEST_CREATE = "retest:create"
    RETEST_APPROVE = "retest:approve"
    RETEST_REQUEST = "retest:request"  # developer marks work ready for retest

    # reporting
    REPORT_CREATE = "report:create"
    REPORT_VIEW = "report:view"
    REPORT_DOWNLOAD = "report:download"

    # audit & system
    AUDIT_VIEW = "audit:view"
    SYSTEM_VIEW = "system:view"
    SETTINGS_MANAGE = "settings:manage"

    # user administration
    USER_CREATE = "user:create"
    USER_VIEW = "user:view"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    ROLE_MANAGE = "role:manage"


P = Permission

_VIEWER_PERMISSIONS: frozenset[str] = frozenset({
    P.DASHBOARD_VIEW, P.ASSESSMENT_VIEW, P.ASSET_VIEW, P.TARGET_VIEW, P.SCAN_VIEW,
    P.FINDING_VIEW, P.FINDING_VIEW_ALL, P.EVIDENCE_VIEW, P.REMEDIATION_VIEW,
    P.REPORT_VIEW, P.REPORT_DOWNLOAD, P.AUDIT_VIEW, P.SYSTEM_VIEW,
})

_DEVELOPER_PERMISSIONS: frozenset[str] = frozenset({
    P.DASHBOARD_VIEW,
    P.ASSESSMENT_VIEW,
    P.TARGET_VIEW,
    # Deliberately *not* FINDING_VIEW_ALL: developers only see assigned findings.
    P.FINDING_VIEW,
    P.FINDING_COMMENT,
    P.EVIDENCE_VIEW,
    P.REMEDIATION_VIEW, P.REMEDIATION_UPDATE,
    P.RETEST_REQUEST,
})

_ANALYST_PERMISSIONS: frozenset[str] = _VIEWER_PERMISSIONS | frozenset({
    P.FINDING_CREATE, P.FINDING_UPDATE, P.FINDING_COMMENT,
    P.EVIDENCE_UPLOAD,
    P.SCAN_VIEW,
})

_SECURITY_ENGINEER_PERMISSIONS: frozenset[str] = _ANALYST_PERMISSIONS | frozenset({
    P.SCAN_CREATE, P.SCAN_CANCEL,
    P.TARGET_CREATE, P.TARGET_UPDATE,
    P.FINDING_VERIFY, P.FINDING_SCORE, P.FINDING_TRIAGE, P.FINDING_SUPPRESS,
    P.RETEST_CREATE,
    P.REMEDIATION_CREATE, P.REMEDIATION_UPDATE,
    P.REPORT_CREATE,
})

_SECURITY_LEAD_PERMISSIONS: frozenset[str] = _SECURITY_ENGINEER_PERMISSIONS | frozenset({
    P.ASSESSMENT_CREATE, P.ASSESSMENT_UPDATE, P.ASSESSMENT_DELETE, P.ASSESSMENT_MANAGE_TEAM,
    P.SCOPE_MANAGE,
    P.ASSET_CREATE, P.ASSET_UPDATE,
    P.TARGET_DELETE,
    P.FINDING_ASSIGN,
    P.EVIDENCE_DELETE,
    P.RETEST_APPROVE,
    P.USER_VIEW,
})

_ALL_PERMISSIONS: frozenset[str] = frozenset(p.value for p in Permission)

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    Role.ADMIN: _ALL_PERMISSIONS,
    Role.SECURITY_LEAD: _SECURITY_LEAD_PERMISSIONS,
    Role.SECURITY_ENGINEER: _SECURITY_ENGINEER_PERMISSIONS,
    Role.ANALYST: _ANALYST_PERMISSIONS,
    Role.VIEWER: _VIEWER_PERMISSIONS,
    Role.DEVELOPER: _DEVELOPER_PERMISSIONS,
}


def permissions_for_role(role: str) -> frozenset[str]:
    return ROLE_PERMISSIONS.get(role, frozenset())


def role_has_permission(role: str, permission: str) -> bool:
    return permission in permissions_for_role(role)


def permission_matrix() -> list[dict]:
    """Rendered by the admin 'Roles & Permissions' screen."""
    return [
        {
            "role": role.value,
            "label": ROLE_LABELS[role],
            "description": ROLE_DESCRIPTIONS[role],
            "permissions": sorted(ROLE_PERMISSIONS[role]),
        }
        for role in Role
    ]
