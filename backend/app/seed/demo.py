"""Labelled demonstration dataset.

Everything created here is marked `is_demo=True` and carries the
`SEEDED_DEMO` data origin, so the UI and generated reports always distinguish
seeded demonstration content from findings produced by a scanner that actually
ran. Findings are moved through the workflow using the real service functions,
so their history and audit trail are genuine rather than fabricated rows.
"""
from __future__ import annotations

import logging
from datetime import date, timedelta
from io import BytesIO

from sqlalchemy import func
from sqlalchemy.orm import Session
from starlette.datastructures import Headers, UploadFile

from app.core.permissions import Role
from app.db.base import utcnow
from app.db.session import session_scope
from app.models.assessment import Assessment, AssessmentMember
from app.models.asset import Asset
from app.models.enums import (
    AssessmentStatus,
    AssetType,
    Criticality,
    DataOrigin,
    DataSensitivity,
    Exposure,
    FindingStatus,
    Priority,
    RetestResult,
    ScannerName,
    ScopeRuleType,
    Severity,
    TargetStatus,
    TargetType,
    VerificationStatus,
)
from app.models.finding import Finding, FindingSource
from app.models.target import ScopeRule, Target
from app.models.user import User
from app.services import audit, cwe as cwe_service, evidence as evidence_service
from app.services import history, remediation as remediation_service, risk as risk_engine
from app.services import sla as sla_service, workflow
from app.services.audit import AuditAction
from app.services.auth import create_user
from app.services.cvss import score_finding
from app.services.references import assign_reference

logger = logging.getLogger("prcampus.seed")

DEMO_PASSWORD = "DemoPass123!"

DEMO_USERS = [
    ("admin@fixnex.io", "Aarav Sharma", Role.ADMIN, "Platform Administrator"),
    ("lead@fixnex.io", "Priya Nair", Role.SECURITY_LEAD, "Security Lead"),
    ("engineer@fixnex.io", "Rohan Mehta", Role.SECURITY_ENGINEER, "Security Engineer"),
    ("analyst@fixnex.io", "Sara Iyer", Role.ANALYST, "Security Analyst"),
    ("developer@fixnex.io", "Vikram Rao", Role.DEVELOPER, "Application Developer"),
    ("auditor@fixnex.io", "Meera Joshi", Role.VIEWER, "Compliance Auditor"),
]

# A deliberately non-routable domain: the demo dataset never points at a real
# third-party system, and nothing here is scanned automatically.
DEMO_DOMAIN = "demo.example.local"


def _get_or_create_users(db: Session) -> dict[str, User]:
    users: dict[str, User] = {}
    for email, full_name, role, title in DEMO_USERS:
        existing = db.query(User).filter(func.lower(User.email) == email).first()
        if existing is None:
            existing = create_user(
                db,
                email=email,
                full_name=full_name,
                password=DEMO_PASSWORD,
                role=role,
                job_title=title,
                is_demo=True,
                validate_strength=False,
            )
        users[role] = existing
    db.flush()
    return users


def _make_finding(
    db: Session,
    assessment: Assessment,
    target: Target,
    *,
    title: str,
    description: str,
    severity: str,
    source: str,
    cvss_vector: str | None = None,
    cwe_id: str | None = None,
    cve_ids: list[str] | None = None,
    endpoint: str | None = None,
    parameter: str | None = None,
    http_method: str | None = None,
    category: str | None = None,
    evidence_text: str | None = None,
    request_snippet: str | None = None,
    response_snippet: str | None = None,
    remediation_recommendation: str | None = None,
    references: list[str] | None = None,
    confidence: float = 0.9,
    extra_sources: list[str] | None = None,
) -> Finding:
    """Create one seeded finding, scored with the same services a real scan uses."""
    cvss = score_finding(cvss_vector, None, severity)
    cwe_entry = cwe_service.lookup(cwe_id)
    context = risk_engine.context_from_target(target)
    risk = risk_engine.calculate(
        cvss_score=cvss.score,
        severity=severity,
        confidence=confidence,
        cvss_metrics=cvss.metrics,
        **context,
    )
    now = utcnow()
    all_sources = [source, *(extra_sources or [])]

    finding = Finding(
        assessment_id=assessment.id,
        target_id=target.id,
        title=title,
        description=description,
        category=category or (cwe_entry["category"] if cwe_entry else None),
        endpoint=endpoint,
        parameter=parameter,
        http_method=http_method,
        technical_details=evidence_text,
        request_snippet=request_snippet,
        response_snippet=response_snippet,
        remediation_recommendation=remediation_recommendation,
        references=references or [],
        primary_source=str(source),
        # Clearly labelled: this did not come from a scanner that actually ran.
        data_origin=DataOrigin.SEEDED_DEMO,
        is_demo=True,
        correlation_key=None,
        source_count=len(set(all_sources)),
        duplicate_hits=len(all_sources) - 1,
        confidence=confidence,
        severity=severity,
        cvss_score=cvss.score,
        cvss_vector=cvss.vector,
        cvss_version=cvss.version,
        cwe_id=cwe_id,
        cwe_name=cwe_entry["name"] if cwe_entry else None,
        cve_ids=cve_ids or [],
        cve_details=[],
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        impact=risk["impact"],
        likelihood=risk["likelihood"],
        risk_factors={**risk["factors"], "explanation": risk["explanation"]},
        status=FindingStatus.DISCOVERED,
        verification_status=VerificationStatus.UNVERIFIED,
        sla_due_at=sla_service.due_at(severity, now, db),
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add(finding)
    assign_reference(db, finding)

    for scanner in set(all_sources):
        db.add(
            FindingSource(
                finding=finding,
                scanner=str(scanner),
                raw_title=title,
                raw_severity=severity,
                confidence=confidence,
                raw_data={"demo": True},
            )
        )

    history.record(
        db,
        finding,
        event_type="CREATED",
        actor_name="Demo dataset",
        to_status=FindingStatus.DISCOVERED,
        note=(
            f"Seeded demonstration finding attributed to {', '.join(sorted(set(all_sources)))}. "
            "This is DEMO DATA, not the output of an executed scan."
        ),
        metadata={"demo": True, "sources": sorted(set(all_sources))},
    )
    if len(set(all_sources)) > 1:
        history.record(
            db,
            finding,
            event_type="CORRELATED",
            actor_name="Correlation engine",
            note=(
                f"{len(all_sources)} scanner reports were correlated into this single finding."
            ),
            metadata={"demo": True},
        )
    db.flush()
    return finding


def _reset_demo_data(db: Session) -> None:
    """Remove previously seeded demo content, leaving real data untouched."""
    demo_assessments = db.query(Assessment).filter(Assessment.is_demo.is_(True)).all()
    for assessment in demo_assessments:
        db.delete(assessment)  # cascades to targets, scans, findings, reports
    db.query(Asset).filter(Asset.is_demo.is_(True)).delete(synchronize_session=False)
    db.flush()


def seed_demo_data(db: Session, reset: bool = True) -> dict:
    """Create the labelled demonstration dataset. Returns a summary."""
    if reset:
        _reset_demo_data(db)

    users = _get_or_create_users(db)
    lead = users[Role.SECURITY_LEAD]
    engineer = users[Role.SECURITY_ENGINEER]
    analyst = users[Role.ANALYST]
    developer = users[Role.DEVELOPER]

    # ------------------------------------------------------------- asset
    asset = Asset(
        name="College Student Portal",
        description=(
            "Public student portal providing admissions, results, fee payment and "
            "personal record management for approximately 12,000 students."
        ),
        asset_type=AssetType.WEB_APPLICATION,
        owner="IT Department",
        business_unit="Academic Systems",
        primary_url=f"https://{DEMO_DOMAIN}",
        criticality=Criticality.HIGH,
        data_sensitivity=DataSensitivity.HIGH,
        exposure=Exposure.INTERNET_FACING,
        technologies=[
            {"name": "nginx", "version": "1.18.0", "category": "Web Server"},
            {"name": "PHP", "version": "7.4", "category": "Language"},
            {"name": "MySQL", "version": None, "category": "Database"},
            {"name": "jQuery", "version": "1.12.4", "category": "Frontend"},
        ],
        tags=["demo", "student-data", "internet-facing"],
        is_demo=True,
    )
    db.add(asset)
    assign_reference(db, asset)

    # -------------------------------------------------------- assessment
    today = date.today()
    assessment = Assessment(
        name="College Portal Security Assessment",
        description=(
            "Full-scope web application security assessment of the college student portal, "
            "covering authentication, session management, injection, access control, "
            "transport security and information disclosure."
        ),
        client_name="Demo College of Engineering",
        start_date=today - timedelta(days=6),
        end_date=today + timedelta(days=8),
        status=AssessmentStatus.ACTIVE,
        methodology=(
            "OWASP Web Security Testing Guide (WSTG) informed methodology:\n"
            "1. Reconnaissance and technology fingerprinting\n"
            "2. Automated scanning (Nmap, Nuclei, OWASP ZAP, built-in adapters)\n"
            "3. Manual verification of every automated finding\n"
            "4. Evidence collection with SHA-256 chain of custody\n"
            "5. CVSS v3.1 scoring, CWE/CVE classification and contextual risk analysis\n"
            "6. Triage, remediation assignment and SLA tracking\n"
            "7. Retesting and closure"
        ),
        notes="DEMO DATA — seeded for demonstration purposes.",
        engagement_type="Grey-box web application assessment",
        tags=["demo", "web", "owasp"],
        is_demo=True,
        created_by_id=lead.id,
    )
    db.add(assessment)
    assign_reference(db, assessment)

    for member, role_label in (
        (lead, "Assessment Lead"),
        (engineer, "Security Engineer"),
        (analyst, "Tester"),
        (developer, "Remediation Owner"),
    ):
        db.add(
            AssessmentMember(
                assessment_id=assessment.id, user_id=member.id, role_in_assessment=role_label
            )
        )

    # ------------------------------------------------------------- scope
    for rule_type, value, note in (
        (ScopeRuleType.WILDCARD_DOMAIN, f"*.{DEMO_DOMAIN}", "All portal subdomains are in scope."),
        (ScopeRuleType.DOMAIN, DEMO_DOMAIN, "Primary portal hostname."),
        (ScopeRuleType.API_ENDPOINT, f"https://api.{DEMO_DOMAIN}/v1", "Student records REST API."),
    ):
        db.add(
            ScopeRule(
                assessment_id=assessment.id,
                rule_type=rule_type,
                value=value,
                is_exclusion=False,
                note=note,
                created_by_id=lead.id,
            )
        )
    # An explicit carve-out demonstrates that exclusions take priority.
    db.add(
        ScopeRule(
            assessment_id=assessment.id,
            rule_type=ScopeRuleType.DOMAIN,
            value=f"payments.{DEMO_DOMAIN}",
            is_exclusion=True,
            note="Third-party payment gateway — explicitly OUT of scope, do not test.",
            created_by_id=lead.id,
        )
    )
    db.flush()

    # ----------------------------------------------------------- targets
    now = utcnow()
    web_target = Target(
        assessment_id=assessment.id,
        asset_id=asset.id,
        name="Student Portal (web)",
        target_type=TargetType.WEB_APP,
        value=f"https://{DEMO_DOMAIN}",
        hostname=DEMO_DOMAIN,
        description="Primary student-facing web application.",
        status=TargetStatus.AUTHORIZED,
        authorization_confirmed=True,
        authorization_statement=(
            "I confirm that I am authorized to perform security testing against this target."
        ),
        authorized_by_id=lead.id,
        authorized_at=now,
        technologies=asset.technologies,
        is_demo=True,
    )
    api_target = Target(
        assessment_id=assessment.id,
        asset_id=asset.id,
        name="Student Records API",
        target_type=TargetType.REST_API,
        value=f"https://api.{DEMO_DOMAIN}/v1",
        hostname=f"api.{DEMO_DOMAIN}",
        base_path="/v1",
        description="REST API backing the student portal.",
        status=TargetStatus.AUTHORIZED,
        authorization_confirmed=True,
        authorization_statement=(
            "I confirm that I am authorized to perform security testing against this target."
        ),
        authorized_by_id=lead.id,
        authorized_at=now,
        is_demo=True,
    )
    # References are assigned one target at a time: each call flushes, and a
    # pending sibling row would otherwise be inserted with a null reference.
    db.add(web_target)
    assign_reference(db, web_target)
    db.add(api_target)
    assign_reference(db, api_target)
    db.flush()

    # ---------------------------------------------------------- findings
    sqli = _make_finding(
        db, assessment, web_target,
        title="SQL injection in student results lookup",
        description=(
            "The `roll_no` parameter of the results lookup endpoint is concatenated directly "
            "into a SQL query. A single quote produces a database error, and a boolean-based "
            "payload reliably alters the result set, confirming that attacker-controlled input "
            "reaches the SQL interpreter. This permits extraction of arbitrary data from the "
            "student records database, including credentials and personal information."
        ),
        severity=Severity.CRITICAL,
        source=ScannerName.NUCLEI,
        extra_sources=[str(ScannerName.ZAP)],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_id="CWE-89",
        endpoint=f"https://{DEMO_DOMAIN}/results.php",
        parameter="roll_no",
        http_method="GET",
        category="Injection",
        evidence_text=(
            "Payload:  roll_no=21CS001' OR '1'='1\n"
            "Response: returned 12,431 rows instead of 1 (HTTP 200)\n"
            "Payload:  roll_no=21CS001'\n"
            "Response: 'You have an error in your SQL syntax' (HTTP 500)"
        ),
        request_snippet=(
            "GET /results.php?roll_no=21CS001%27%20OR%20%271%27%3D%271 HTTP/1.1\n"
            f"Host: {DEMO_DOMAIN}\n"
            "User-Agent: FixNex/1.0"
        ),
        response_snippet=(
            "HTTP/1.1 500 Internal Server Error\n"
            "Content-Type: text/html\n\n"
            "Warning: mysqli_fetch_assoc(): You have an error in your SQL syntax; check the "
            "manual that corresponds to your MySQL server version..."
        ),
        remediation_recommendation=(
            "Replace string concatenation with parameterised queries (prepared statements) "
            "throughout the results module. Apply an allow-list validation on `roll_no` and "
            "ensure the database account used by the application holds only SELECT privileges "
            "on the tables it genuinely needs."
        ),
        references=[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        confidence=0.95,
    )

    xss = _make_finding(
        db, assessment, web_target,
        title="Reflected cross-site scripting in the search field",
        description=(
            "The `q` parameter of the course search page is reflected into the HTML response "
            "without output encoding. An attacker can craft a link that executes arbitrary "
            "JavaScript in the victim's browser session, enabling session token theft and "
            "actions performed as the victim."
        ),
        severity=Severity.HIGH,
        source=ScannerName.ZAP,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
        cwe_id="CWE-79",
        endpoint=f"https://{DEMO_DOMAIN}/search",
        parameter="q",
        http_method="GET",
        category="Injection",
        evidence_text=(
            "Payload:  q=<script>alert(document.domain)</script>\n"
            "Reflected unencoded inside the results heading element."
        ),
        response_snippet=(
            "<h2>Results for <script>alert(document.domain)</script></h2>"
        ),
        remediation_recommendation=(
            "Contextually output-encode all user input before rendering it into HTML. Adopt a "
            "templating engine with automatic escaping and deploy a Content-Security-Policy "
            "that disallows inline script execution."
        ),
        references=["https://owasp.org/www-community/attacks/xss/"],
        confidence=0.9,
    )

    headers = _make_finding(
        db, assessment, web_target,
        title="Missing Content-Security-Policy header",
        description=(
            "The application does not send a Content-Security-Policy header. CSP is the "
            "primary defence-in-depth control against cross-site scripting and content "
            "injection, restricting which script, style and frame sources a browser will load."
        ),
        severity=Severity.MEDIUM,
        source=ScannerName.HTTP_HEADERS,
        extra_sources=[str(ScannerName.ZAP)],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        cwe_id="CWE-693",
        endpoint=f"https://{DEMO_DOMAIN}/",
        category="Security Misconfiguration",
        evidence_text="Response headers contained no `Content-Security-Policy` entry.",
        remediation_recommendation=(
            "Define a Content-Security-Policy starting from `default-src 'self'` and remove "
            "any reliance on inline scripts."
        ),
        references=["https://owasp.org/www-project-secure-headers/"],
        confidence=0.95,
    )

    tls = _make_finding(
        db, assessment, web_target,
        title="Weak TLS configuration: TLS 1.0 and 1.1 accepted",
        description=(
            "The server still negotiates TLS 1.0 and TLS 1.1. Both are deprecated, are "
            "rejected by current browsers and remain vulnerable to known downgrade and "
            "padding-oracle attacks."
        ),
        severity=Severity.MEDIUM,
        source=ScannerName.TLS,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        cwe_id="CWE-327",
        endpoint=f"{DEMO_DOMAIN}:443",
        category="Cryptographic Failure",
        evidence_text="Negotiated protocol: TLSv1\nAccepted cipher: AES128-SHA",
        remediation_recommendation=(
            "Disable TLS 1.1 and below at the web server or load balancer, require TLS 1.2 "
            "with TLS 1.3 preferred, and restrict the cipher list to modern AEAD suites."
        ),
        confidence=0.97,
    )

    disclosure = _make_finding(
        db, assessment, web_target,
        title="Information disclosure via `Server` response header",
        description=(
            "The server discloses its web server software and version in the `Server` "
            "response header, letting an attacker map the technology stack to publicly "
            "known vulnerabilities without any active probing."
        ),
        severity=Severity.LOW,
        source=ScannerName.HTTP_HEADERS,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cwe_id="CWE-200",
        endpoint=f"https://{DEMO_DOMAIN}/",
        category="Information Disclosure",
        evidence_text="Server: nginx/1.18.0",
        remediation_recommendation="Set `server_tokens off;` in the nginx configuration.",
        confidence=0.9,
    )

    idor = _make_finding(
        db, assessment, api_target,
        title="Insecure direct object reference on the student records endpoint",
        description=(
            "The `/v1/students/{id}` endpoint returns any student's full record to any "
            "authenticated user. Incrementing the identifier exposes the personal details, "
            "contact information and academic history of other students."
        ),
        severity=Severity.HIGH,
        source=ScannerName.MANUAL,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        cwe_id="CWE-639",
        endpoint=f"https://api.{DEMO_DOMAIN}/v1/students/1042",
        parameter="id",
        http_method="GET",
        category="Access Control",
        evidence_text=(
            "Authenticated as student 21CS001 (id 1041).\n"
            "GET /v1/students/1042 returned the complete record for a different student."
        ),
        remediation_recommendation=(
            "Enforce an ownership check on every record access: the authenticated subject must "
            "match the requested resource, or hold an explicit staff role."
        ),
        confidence=0.98,
    )

    false_positive = _make_finding(
        db, assessment, web_target,
        title="Possible cross-site scripting in the feedback form",
        description=(
            "An automated check flagged the `comment` parameter of the feedback form as "
            "potentially reflecting unencoded input."
        ),
        severity=Severity.HIGH,
        source=ScannerName.ZAP,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        cwe_id="CWE-79",
        endpoint=f"https://{DEMO_DOMAIN}/feedback",
        parameter="comment",
        http_method="POST",
        category="Injection",
        evidence_text="Scanner reported the payload appearing in the response body.",
        remediation_recommendation="No action required — see the false-positive justification.",
        confidence=0.45,
    )

    needs_verification = _make_finding(
        db, assessment, web_target,
        title="Session cookie issued without the HttpOnly attribute",
        description=(
            "The `PHPSESSID` cookie is issued without the `HttpOnly` attribute, so client-side "
            "JavaScript can read it. Combined with any cross-site scripting flaw this turns "
            "into full session theft."
        ),
        severity=Severity.MEDIUM,
        source=ScannerName.HTTP_HEADERS,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        cwe_id="CWE-1004",
        endpoint=f"https://{DEMO_DOMAIN}/login",
        parameter="PHPSESSID",
        category="Session Management",
        evidence_text="Set-Cookie: PHPSESSID=8f2c...; path=/",
        remediation_recommendation="Add the `HttpOnly`, `Secure` and `SameSite=Lax` attributes.",
        confidence=0.92,
    )

    open_port = _make_finding(
        db, assessment, web_target,
        title="Open port 3306/tcp (MySQL) reachable from the internet",
        description=(
            "The MySQL database port is reachable from outside the college network. Database "
            "services should never be directly exposed: they are routinely targeted for "
            "brute-force and known-exploit attacks."
        ),
        severity=Severity.HIGH,
        source=ScannerName.NMAP,
        extra_sources=[str(ScannerName.PORT_SCAN)],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe_id="CWE-668",
        endpoint=f"{DEMO_DOMAIN}:3306",
        category="Network Exposure",
        evidence_text="3306/tcp open  mysql  MySQL 5.7.38",
        remediation_recommendation=(
            "Restrict port 3306 with a firewall rule so that only the application servers can "
            "reach it."
        ),
        confidence=0.95,
    )
    db.commit()

    # --------------------------------------------------- drive the workflow
    # Each of these calls is the same code path the UI uses, so the resulting
    # history and audit entries are real.

    # 1. Closed: confirmed -> triaged -> assigned -> fixed -> retest PASS
    workflow.verify(db, engineer, tls, confirmed=True,
                    note="Reproduced with openssl s_client; TLS 1.0 handshake succeeded.")
    workflow.triage(db, lead, tls, priority=Priority.P3, note="Scheduled with the infrastructure team.")
    workflow.assign(db, lead, tls, assigned_to=developer,
                    recommendation="Disable TLS 1.0/1.1 at the load balancer.",
                    note="Please coordinate with the network team.")
    remediation_service.mark_ready_for_retest(
        db, developer, tls,
        fix_summary="Updated the nginx TLS configuration to require TLS 1.2 minimum and "
                    "restricted ciphers to modern AEAD suites.",
    )
    remediation_service.perform_retest(
        db, engineer, tls, result=RetestResult.PASS,
        summary="TLS 1.0 and 1.1 handshakes are now rejected. Only TLS 1.2 and 1.3 negotiate.",
        method="openssl s_client -tls1 / -tls1_1 / -tls1_2 against the host",
    )

    # 2. In remediation, assigned to the developer
    workflow.verify(db, engineer, sqli, confirmed=True,
                    note="Manually reproduced: boolean-based and error-based payloads both confirmed.")
    workflow.triage(db, lead, sqli, priority=Priority.P1, note="Highest priority — student PII at risk.")
    workflow.assign(db, lead, sqli, assigned_to=developer, priority=Priority.P1, sla_hours=24,
                    recommendation="Convert the results module to prepared statements.")
    remediation_service.update(
        db, developer, sqli,
        _RemediationPayload(status="IN_PROGRESS",
                            developer_notes="Refactoring the results query to use PDO prepared statements."),
    )

    # 3. Confirmed, awaiting triage
    workflow.verify(db, analyst, xss, confirmed=True,
                    note="Payload executes in Chrome 120; confirmed with a proof-of-concept link.")

    # 4. False positive, retained for audit with a written justification
    workflow.verify(
        db, engineer, false_positive, confirmed=False,
        reason=(
            "The feedback form output is HTML-encoded by the templating engine before "
            "rendering. The scanner matched on the reflected payload appearing inside a "
            "JSON debug field that is never rendered as HTML. Manually verified with "
            "multiple payloads — no script execution is possible."
        ),
        note="Verified manually by the security engineer.",
    )

    # 5. Needs verification
    needs_verification.status = FindingStatus.NEEDS_VERIFICATION
    needs_verification.verification_status = VerificationStatus.IN_REVIEW
    history.record(
        db, needs_verification, event_type="STATUS_CHANGED", user=engineer,
        from_status=FindingStatus.DISCOVERED, to_status=FindingStatus.NEEDS_VERIFICATION,
        note="Queued for manual verification.",
    )

    # 6. Assigned and overdue, to demonstrate SLA breach reporting
    workflow.verify(db, engineer, idor, confirmed=True, note="Reproduced against two accounts.")
    workflow.triage(db, lead, idor, priority=Priority.P2)
    workflow.assign(db, lead, idor, assigned_to=developer, priority=Priority.P2)
    if idor.remediation:
        overdue_at = utcnow() - timedelta(days=2)
        idor.remediation.sla_due_at = overdue_at
        idor.sla_due_at = overdue_at

    # 7. open_port confirmed but not yet assigned; headers/disclosure left as DISCOVERED
    workflow.verify(db, engineer, open_port, confirmed=True,
                    note="Confirmed with an external TCP connect from outside the campus network.")
    db.commit()

    # ---------------------------------------------------------- evidence
    _attach_demo_evidence(db, sqli, engineer)
    _attach_demo_evidence(db, xss, analyst, kind="xss")
    db.commit()

    audit.record(
        db,
        action=AuditAction.DEMO_DATA_SEEDED,
        user=users[Role.ADMIN],
        resource_type="Assessment",
        resource_id=assessment.id,
        assessment_id=assessment.id,
        description="Labelled demonstration dataset seeded.",
    )
    db.commit()

    finding_count = (
        db.query(func.count(Finding.id)).filter(Finding.assessment_id == assessment.id).scalar()
    )
    summary = {
        "assessment": assessment.reference,
        "assessment_name": assessment.name,
        "targets": 2,
        "findings": int(finding_count or 0),
        "users": len(DEMO_USERS),
        "demo_password": DEMO_PASSWORD,
    }
    logger.info("Demo dataset seeded: %s", summary)
    return summary


class _RemediationPayload:
    """Minimal stand-in for the RemediationUpdate schema used by the seed."""

    def __init__(self, status=None, developer_notes=None, fix_summary=None, priority=None,
                 assigned_to_id=None, sla_hours=None):
        self.status = status
        self.developer_notes = developer_notes
        self.fix_summary = fix_summary
        self.priority = priority
        self.assigned_to_id = assigned_to_id
        self.sla_hours = sla_hours


_PNG_1X1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000d49444154789c6360000002000100ffff03000006"
    "0005570b8e0000000049454e44ae426082"
)


def _upload_file(filename: str, content: bytes, content_type: str) -> UploadFile:
    """Wrap raw bytes in an UploadFile so the seed uses the real upload path."""
    return UploadFile(
        file=BytesIO(content),
        filename=filename,
        headers=Headers({"content-type": content_type}),
    )


def _attach_demo_evidence(db: Session, finding: Finding, user: User, kind: str = "sqli") -> None:
    """Attach a small, clearly-labelled evidence artefact via the real service."""
    text = (
        f"FixNex DEMO EVIDENCE — {finding.reference}\n"
        f"{'=' * 60}\n"
        f"Finding : {finding.title}\n"
        f"Target  : {finding.endpoint}\n"
        f"Captured: {utcnow().isoformat()}\n\n"
        f"{finding.technical_details or ''}\n\n"
        "NOTE: This artefact is part of the seeded demonstration dataset.\n"
    ).encode()

    try:
        evidence_service.upload(
            db,
            user,
            finding,
            _upload_file(f"{finding.reference.lower()}-proof.txt", text, "text/plain"),
            description=(
                "Request/response capture demonstrating the issue (DEMO DATA)."
                if kind == "sqli"
                else "Proof-of-concept capture for the reflected payload (DEMO DATA)."
            ),
        )
        evidence_service.upload(
            db,
            user,
            finding,
            _upload_file(f"{finding.reference.lower()}-screenshot.png", _PNG_1X1, "image/png"),
            description="Screenshot placeholder for annotation (DEMO DATA).",
        )
    except Exception:  # pragma: no cover - evidence is a nice-to-have for the seed
        logger.exception("Could not attach demo evidence to %s", finding.reference)


def seed_if_empty() -> dict | None:
    """Seed on startup when the database has no assessments yet."""
    with session_scope() as db:
        if db.query(func.count(Assessment.id)).scalar():
            logger.info("Database already contains assessments; skipping demo seeding.")
            return None
        return seed_demo_data(db, reset=False)
