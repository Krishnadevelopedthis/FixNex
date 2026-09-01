"""Authentication and token handling."""
from __future__ import annotations

from app.core.permissions import Role
from app.security.passwords import hash_password, validate_password_strength, verify_password
from tests.conftest import TEST_PASSWORD

import pytest

from app.core.exceptions import ValidationError


def test_login_returns_token_and_permissions(client, users):
    response = client.post(
        "/api/auth/login",
        json={"email": users[Role.ADMIN].email, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"] and body["refresh_token"]
    assert body["user"]["role"] == Role.ADMIN
    assert "assessment:create" in body["user"]["permissions"]


def test_login_with_wrong_password_is_rejected(client, users):
    response = client.post(
        "/api/auth/login",
        json={"email": users[Role.ADMIN].email, "password": "not-the-password"},
    )
    assert response.status_code == 401
    # The message must not reveal whether the account exists.
    assert "Incorrect email or password" in response.json()["error"]["message"]


def test_login_with_unknown_account_is_rejected_identically(client, users):
    response = client.post(
        "/api/auth/login",
        json={"email": "nobody@test.example.com", "password": TEST_PASSWORD},
    )
    assert response.status_code == 401
    assert "Incorrect email or password" in response.json()["error"]["message"]


def test_protected_endpoint_requires_a_token(client):
    assert client.get("/api/assessments").status_code == 401


def test_malformed_token_is_rejected(client):
    response = client.get("/api/assessments", headers={"Authorization": "Bearer not-a-jwt"})
    assert response.status_code == 401


def test_me_returns_the_current_user(client, auth, users):
    response = client.get("/api/auth/me", headers=auth(Role.SECURITY_ENGINEER))
    assert response.status_code == 200
    assert response.json()["email"] == users[Role.SECURITY_ENGINEER].email


def test_refresh_token_issues_a_new_access_token(client, users):
    tokens = client.post(
        "/api/auth/login",
        json={"email": users[Role.VIEWER].email, "password": TEST_PASSWORD},
    ).json()
    response = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert response.status_code == 200
    assert response.json()["access_token"]


def test_an_access_token_cannot_be_used_as_a_refresh_token(client, users):
    tokens = client.post(
        "/api/auth/login",
        json={"email": users[Role.VIEWER].email, "password": TEST_PASSWORD},
    ).json()
    response = client.post("/api/auth/refresh", json={"refresh_token": tokens["access_token"]})
    assert response.status_code == 401


def test_passwords_are_hashed_with_argon2id():
    digest = hash_password("SomePassword123")
    assert digest.startswith("$argon2id$")
    assert "SomePassword123" not in digest
    assert verify_password("SomePassword123", digest)
    assert not verify_password("wrong", digest)


def test_the_same_password_produces_different_hashes():
    assert hash_password("Repeated123") != hash_password("Repeated123")


@pytest.mark.parametrize("weak", ["short1A", "alllowercase123", "ALLUPPERCASE123", "NoDigitsHere"])
def test_weak_passwords_are_rejected(weak):
    with pytest.raises(ValidationError):
        validate_password_strength(weak)


def test_change_password_requires_the_current_password(client, auth):
    response = client.post(
        "/api/auth/change-password",
        headers=auth(Role.ANALYST),
        json={"current_password": "wrong-password", "new_password": "BrandNewPass123"},
    )
    assert response.status_code == 401
