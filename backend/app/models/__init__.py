"""Model package — importing this registers every table on the shared metadata."""
from app.db.base import Base
from app.models.assessment import Assessment, AssessmentMember
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.evidence import Evidence
from app.models.finding import Finding, FindingComment, FindingHistory, FindingSource
from app.models.remediation import Remediation, Retest
from app.models.report import Report
from app.models.scan import ScanJob, ScannerRun
from app.models.system import EnrichmentCache, SystemSetting
from app.models.target import ScopeRule, Target, TargetEndpoint
from app.models.user import User

__all__ = [
    "Base", "User", "Asset", "Assessment", "AssessmentMember", "ScopeRule", "Target",
    "TargetEndpoint", "ScanJob", "ScannerRun", "Finding", "FindingSource", "FindingHistory",
    "FindingComment", "Evidence", "Remediation", "Retest", "Report", "AuditLog",
    "EnrichmentCache", "SystemSetting",
]
