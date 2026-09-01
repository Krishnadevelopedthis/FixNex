"""Shared pytest fixtures.

Tests run against a throwaway SQLite database so the suite needs no external
services. The environment is configured before any application module is
imported, because settings are read at import time.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="prcampus-tests-"))

os.environ.update(
    ENVIRONMENT="test",
    DEBUG="false",
    DATABASE_URL=f"sqlite:///{_TMP / 'test.db'}",
    JWT_SECRET="test-secret-key-that-is-long-enough-for-testing-only",
    TASK_RUNNER="thread",
    STORAGE_BACKEND="local",
    LOCAL_STORAGE_PATH=str(_TMP / "storage"),
    OFFLINE_MODE="true",           # never call NVD / SSL Labs from tests
    DEMO_MODE="false",
    SEED_ON_STARTUP="false",
    AUTH_RATE_LIMIT_ATTEMPTS="1000",
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.core.permissions import Role  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app as fastapi_app  # noqa: E402
from app.models.assessment import Assessment  # noqa: E402
from app.models.target import ScopeRule, Target  # noqa: E402
from app.models.enums import ScopeRuleType, TargetStatus, TargetType  # noqa: E402
from app.services.auth import create_user  # noqa: E402
from app.services.references import assign_reference  # noqa: E402
import app.models  # noqa: E402,F401

TEST_PASSWORD = "TestPass123!"

engine = create_engine(
    os.environ["DATABASE_URL"],
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)


@pytest.fixture(scope="session", autouse=True)
def _schema():
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture
def db():
    """A session bound to the test database, rolled back after each test."""
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSession(bind=connection)
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def client(db):
    """API client whose requests share the test's database session."""
    def _get_db():
        # Each real request gets a fresh session; the tests share one, so expire
        # cached state first to avoid serving stale relationship collections.
        db.expire_all()
        try:
            yield db
        finally:
            pass

    fastapi_app.dependency_overrides[get_db] = _get_db
    with TestClient(fastapi_app) as test_client:
        yield test_client
    fastapi_app.dependency_overrides.clear()


# --------------------------------------------------------------------- users
@pytest.fixture
def users(db):
    """One active user per role."""
    created = {}
    for role in Role:
        created[role] = create_user(
            db,
            email=f"{role.value.lower()}@test.example.com",
            full_name=f"{role.value.title()} User",
            password=TEST_PASSWORD,
            role=role,
            validate_strength=False,
        )
    db.commit()
    return created


@pytest.fixture
def auth(client, users):
    """Returns a callable: auth(Role.ADMIN) -> {'Authorization': 'Bearer ...'}."""
    cache: dict[str, dict] = {}

    def _headers(role: Role) -> dict:
        if role not in cache:
            response = client.post(
                "/api/auth/login",
                json={"email": users[role].email, "password": TEST_PASSWORD},
            )
            assert response.status_code == 200, response.text
            cache[role] = {"Authorization": f"Bearer {response.json()['access_token']}"}
        return cache[role]

    return _headers


# ---------------------------------------------------------------- assessment
@pytest.fixture
def assessment(db, users):
    item = Assessment(
        name="Test Assessment",
        client_name="Test Client",
        status="ACTIVE",
        created_by_id=users[Role.SECURITY_LEAD].id,
    )
    db.add(item)
    assign_reference(db, item)
    db.add(
        ScopeRule(
            assessment_id=item.id,
            rule_type=ScopeRuleType.WILDCARD_DOMAIN,
            value="*.in-scope.example.com",
            created_by_id=users[Role.SECURITY_LEAD].id,
        )
    )
    db.commit()
    return item


@pytest.fixture
def target(db, assessment, users):
    item = Target(
        assessment_id=assessment.id,
        name="Test Target",
        target_type=TargetType.WEB_APP,
        value="https://app.in-scope.example.com",
        hostname="app.in-scope.example.com",
        status=TargetStatus.AUTHORIZED,
        authorization_confirmed=True,
        authorized_by_id=users[Role.SECURITY_LEAD].id,
    )
    db.add(item)
    assign_reference(db, item)
    db.commit()
    return item


@pytest.fixture
def finding(db, assessment, target):
    """A discovered finding ready to be driven through the workflow."""
    from app.models.enums import DataOrigin, FindingStatus, Severity, VerificationStatus
    from app.models.finding import Finding

    item = Finding(
        assessment_id=assessment.id,
        target_id=target.id,
        title="SQL injection in login form",
        description="Test finding.",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_version="3.1",
        cwe_id="CWE-89",
        primary_source="nuclei",
        data_origin=DataOrigin.REAL_SCAN,
        status=FindingStatus.DISCOVERED,
        verification_status=VerificationStatus.UNVERIFIED,
        confidence=0.9,
        risk_score=9.8,
        risk_level=Severity.CRITICAL,
    )
    db.add(item)
    assign_reference(db, item)
    db.commit()
    return item
