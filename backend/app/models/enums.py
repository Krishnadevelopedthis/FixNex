"""Shared vocabulary for the assessment lifecycle."""
from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


SEVERITY_ORDER: dict[str, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 1,
}


class AssessmentStatus(StrEnum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"


class TargetType(StrEnum):
    WEB_APP = "WEB_APP"
    REST_API = "REST_API"
    HOST = "HOST"


class TargetStatus(StrEnum):
    PENDING_AUTHORIZATION = "PENDING_AUTHORIZATION"
    AUTHORIZED = "AUTHORIZED"
    DISABLED = "DISABLED"


class ScopeRuleType(StrEnum):
    DOMAIN = "DOMAIN"
    WILDCARD_DOMAIN = "WILDCARD_DOMAIN"
    URL = "URL"
    IP = "IP"
    CIDR = "CIDR"
    API_ENDPOINT = "API_ENDPOINT"


class ScanProfile(StrEnum):
    LIGHT = "LIGHT"
    STANDARD = "STANDARD"
    COMPREHENSIVE = "COMPREHENSIVE"
    # Results produced by a tool elsewhere and uploaded (e.g. SARIF from CI).
    IMPORTED = "IMPORTED"


class ScanStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScannerRunStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    UNAVAILABLE = "UNAVAILABLE"


class ScannerName(StrEnum):
    """Adapters registered with the scanner registry."""

    # Built-in adapters implemented in pure Python (always available).
    HTTP_HEADERS = "http_headers"
    TLS = "tls"
    TECH_FINGERPRINT = "tech_fingerprint"
    PORT_SCAN = "port_scan"
    # External tool adapters (used when the binary/service is installed).
    NMAP = "nmap"
    NUCLEI = "nuclei"
    ZAP = "zap"
    WHATWEB = "whatweb"
    SSL_LABS = "ssl_labs"
    # Non-scanner origins
    MANUAL = "manual"


class FindingStatus(StrEnum):
    DISCOVERED = "DISCOVERED"
    NEEDS_VERIFICATION = "NEEDS_VERIFICATION"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    TRIAGED = "TRIAGED"
    REMEDIATION = "REMEDIATION"
    RETEST = "RETEST"
    CLOSED = "CLOSED"


class VerificationStatus(StrEnum):
    UNVERIFIED = "UNVERIFIED"
    IN_REVIEW = "IN_REVIEW"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class RemediationStatus(StrEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    READY_FOR_RETEST = "READY_FOR_RETEST"
    RETESTING = "RETESTING"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"


class RetestResult(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"


class Priority(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class SLAStatus(StrEnum):
    ON_TRACK = "ON_TRACK"
    DUE_SOON = "DUE_SOON"
    OVERDUE = "OVERDUE"
    MET = "MET"
    BREACHED = "BREACHED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Criticality(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DataSensitivity(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class Exposure(StrEnum):
    INTERNET_FACING = "INTERNET_FACING"
    INTERNAL = "INTERNAL"
    ISOLATED = "ISOLATED"


class DataOrigin(StrEnum):
    """Provenance of a finding.

    The platform never presents fabricated data as a real scanner result:
    anything that did not come from an executed scanner is labelled here and
    surfaced in the UI and in reports.
    """

    REAL_SCAN = "REAL_SCAN"      # produced by a scanner FixNex itself executed
    IMPORTED = "IMPORTED"        # produced by a tool elsewhere, uploaded as SARIF
    MANUAL = "MANUAL"            # raised by an analyst during manual testing
    SEEDED_DEMO = "SEEDED_DEMO"  # demo seed data, always labelled as such


class ReportFormat(StrEnum):
    PDF = "PDF"
    CSV = "CSV"
    JSON = "JSON"
    XLSX = "XLSX"
    HTML = "HTML"


class ReportStatus(StrEnum):
    PENDING = "PENDING"
    GENERATING = "GENERATING"
    READY = "READY"
    FAILED = "FAILED"


class AssetType(StrEnum):
    WEB_APPLICATION = "WEB_APPLICATION"
    REST_API = "REST_API"
    SERVER = "SERVER"
    NETWORK_DEVICE = "NETWORK_DEVICE"
    DATABASE = "DATABASE"
    OTHER = "OTHER"


class EnrichmentSource(StrEnum):
    NVD = "NVD"
    CWE = "CWE"
    SSL_LABS = "SSL_LABS"


class HistoryEventType(StrEnum):
    CREATED = "CREATED"
    STATUS_CHANGED = "STATUS_CHANGED"
    VERIFIED = "VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SCORED = "SCORED"
    TRIAGED = "TRIAGED"
    ASSIGNED = "ASSIGNED"
    EVIDENCE_ADDED = "EVIDENCE_ADDED"
    COMMENT = "COMMENT"
    REMEDIATION_UPDATED = "REMEDIATION_UPDATED"
    RETEST_PERFORMED = "RETEST_PERFORMED"
    REOPENED = "REOPENED"
    CLOSED = "CLOSED"
    ENRICHED = "ENRICHED"
    CORRELATED = "CORRELATED"
