"""End to end: POST /api/v1/investigations/async + GET /api/v1/investigations/{id}
-- task.md phase 13's polling contract.

REDIS_URL is unset in the test environment (tests/conftest.py), so the async
endpoint exercises its documented dev-convenience fallback: run inline,
return `status: complete` immediately. That fallback is real production
behavior, not a test-only shortcut -- any deployment without Redis configured
takes the same path.
"""

import pytest
from fastapi.testclient import TestClient

from apps.api import main
from packages.shared.db.repositories import get_investigation_repository

SCAM_TEXT = "Your SBI account is blocked. Send Rs 5000 to scammer@okaxis immediately to unblock."
AUTH_HEADERS = {"x-api-key": "test_secret_key"}


@pytest.fixture
def client():
    return TestClient(main.app)


def test_async_investigation_completes_inline_without_redis(client):
    response = client.post(
        "/api/v1/investigations/async",
        json={"platform": "web", "content_type": "text", "text": SCAM_TEXT},
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "complete"
    assert body["investigation_id"]


def test_polling_a_completed_investigation_returns_its_report(client):
    create = client.post(
        "/api/v1/investigations/async",
        json={"platform": "web", "content_type": "text", "text": SCAM_TEXT},
        headers=AUTH_HEADERS,
    )
    investigation_id = create.json()["investigation_id"]

    response = client.get(f"/api/v1/investigations/{investigation_id}", headers=AUTH_HEADERS)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "complete"
    assert body["report"]["verdict"] == "scam"


async def test_polling_a_queued_but_unfinished_investigation_returns_pending(client):
    await get_investigation_repository().create_pending("inv_pending_1", platform="web", content_type="text")

    response = client.get("/api/v1/investigations/inv_pending_1", headers=AUTH_HEADERS)

    assert response.status_code == 200
    assert response.json() == {"investigation_id": "inv_pending_1", "status": "pending"}


def test_polling_an_unknown_investigation_is_404(client):
    response = client.get("/api/v1/investigations/does-not-exist", headers=AUTH_HEADERS)

    assert response.status_code == 404
