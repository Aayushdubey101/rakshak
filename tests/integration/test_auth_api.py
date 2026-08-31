"""End to end: POST /api/v1/auth/{register,login,forgot-password,reset-password}
-- real end-user accounts, distinct from the service-key `/api/v1/auth/token`
exchange `test_async_investigation_api.py` already covers.
"""

import pytest
from fastapi.testclient import TestClient

from apps.api import main

EMAIL = "scam.reporter@example.com"
PASSWORD = "correct horse battery staple"


@pytest.fixture
def client():
    return TestClient(main.app)


def test_register_then_use_the_session_token(client):
    response = client.post("/api/v1/auth/register", json={"email": EMAIL, "password": PASSWORD})

    assert response.status_code == 200
    body = response.json()
    assert body["token"].startswith("tok.")
    assert body["user"]["email"] == EMAIL

    # The issued token is a real, usable credential against a protected route.
    listing = client.get("/api/v1/investigations", headers={"Authorization": f"Bearer {body['token']}"})
    assert listing.status_code == 200


def test_registering_the_same_email_twice_is_rejected(client):
    client.post("/api/v1/auth/register", json={"email": EMAIL, "password": PASSWORD})
    response = client.post("/api/v1/auth/register", json={"email": EMAIL, "password": PASSWORD})

    assert response.status_code == 409


def test_login_with_correct_credentials_succeeds(client):
    client.post("/api/v1/auth/register", json={"email": EMAIL, "password": PASSWORD})

    response = client.post("/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})

    assert response.status_code == 200
    assert response.json()["token"].startswith("tok.")


def test_login_with_wrong_password_is_rejected(client):
    client.post("/api/v1/auth/register", json={"email": EMAIL, "password": PASSWORD})

    response = client.post("/api/v1/auth/login", json={"email": EMAIL, "password": "wrong password"})

    assert response.status_code == 401


def test_login_with_unknown_email_is_rejected(client):
    response = client.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": PASSWORD})

    assert response.status_code == 401


def test_forgot_password_for_unknown_email_still_returns_ok(client):
    """Account-enumeration guard: the response must not reveal whether the
    email exists."""
    response = client.post("/api/v1/auth/forgot-password", json={"email": "nobody@example.com"})

    assert response.status_code == 200
    assert "dev_reset_token" not in response.json()


def test_forgot_password_then_reset_lets_the_new_password_log_in(client):
    client.post("/api/v1/auth/register", json={"email": EMAIL, "password": PASSWORD})

    forgot = client.post("/api/v1/auth/forgot-password", json={"email": EMAIL})
    reset_token = forgot.json()["dev_reset_token"]  # dev-mode only: ENVIRONMENT != "production" in tests

    reset = client.post("/api/v1/auth/reset-password", json={"token": reset_token, "new_password": "a whole new password"})
    assert reset.status_code == 200

    old_login = client.post("/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert old_login.status_code == 401

    new_login = client.post("/api/v1/auth/login", json={"email": EMAIL, "password": "a whole new password"})
    assert new_login.status_code == 200


def test_reset_password_rejects_a_session_token_used_as_a_reset_token(client):
    """A logged-in session token must not double as a password-reset
    credential -- they carry different scopes on purpose."""
    session = client.post("/api/v1/auth/register", json={"email": EMAIL, "password": PASSWORD}).json()

    response = client.post(
        "/api/v1/auth/reset-password", json={"token": session["token"], "new_password": "irrelevant"}
    )

    assert response.status_code == 400
