"""Real scoped auth, end to end against the live API (task.md phase 14)."""

import pytest
from fastapi.testclient import TestClient

from apps.api import main
from packages.shared.db.repositories import get_api_key_repository
from packages.shared.security.api_keys import SCOPE_ANALYZE, SCOPE_READ_INVESTIGATIONS

LEGACY_KEY = "test_secret_key"
SCAM_TEXT = "Your SBI account is blocked. Send Rs 5000 to scammer@okaxis immediately to unblock."


@pytest.fixture
def client():
    return TestClient(main.app)


def _investigate(client, headers):
    return client.post(
        "/api/v1/investigations",
        json={"platform": "web", "content_type": "text", "text": SCAM_TEXT},
        headers=headers,
    )


def test_missing_credential_is_rejected(client):
    assert _investigate(client, {}).status_code == 401


def test_unknown_credential_is_rejected(client):
    assert _investigate(client, {"x-api-key": "not-a-real-key"}).status_code == 401


def test_legacy_shared_secret_still_works(client):
    assert _investigate(client, {"x-api-key": LEGACY_KEY}).status_code == 200


async def test_a_real_scoped_key_with_the_right_scope_works(client):
    _, plaintext = await get_api_key_repository().create(
        principal="telegram-bot", scopes=frozenset({SCOPE_ANALYZE})
    )
    assert _investigate(client, {"x-api-key": plaintext}).status_code == 200


async def test_a_real_key_missing_the_scope_is_forbidden(client):
    _, plaintext = await get_api_key_repository().create(
        principal="read-only", scopes=frozenset({SCOPE_READ_INVESTIGATIONS})
    )
    assert _investigate(client, {"x-api-key": plaintext}).status_code == 403


async def test_a_revoked_key_is_rejected(client):
    key_id, plaintext = await get_api_key_repository().create(
        principal="bot", scopes=frozenset({SCOPE_ANALYZE})
    )
    await get_api_key_repository().revoke(key_id)
    assert _investigate(client, {"x-api-key": plaintext}).status_code == 401


async def test_bearer_header_with_the_raw_api_key_also_works(client):
    _, plaintext = await get_api_key_repository().create(
        principal="bot", scopes=frozenset({SCOPE_ANALYZE})
    )
    assert _investigate(client, {"Authorization": f"Bearer {plaintext}"}).status_code == 200


def test_token_exchange_requires_a_valid_key(client):
    response = client.post("/api/v1/auth/token", headers={"x-api-key": "nope"})
    assert response.status_code == 401


def test_token_exchange_then_use_the_token(client):
    token_response = client.post("/api/v1/auth/token", headers={"x-api-key": LEGACY_KEY})
    assert token_response.status_code == 200
    body = token_response.json()
    assert body["token"].startswith("tok.")
    assert body["expires_at"] > 0

    response = _investigate(client, {"Authorization": f"Bearer {body['token']}"})
    assert response.status_code == 200
