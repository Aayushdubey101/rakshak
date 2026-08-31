"""Liveness/readiness (task.md phase 15). Health routes are exempt from
API-key auth (packages/apps/api/middleware/auth.py doesn't gate `/health/*`,
only `/api/*`), so these hit the client with no credential."""

from fastapi.testclient import TestClient

from apps.api import main


def client() -> TestClient:
    return TestClient(main.app)


def test_liveness_is_always_ok():
    response = client().get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_reports_every_dependency():
    response = client().get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in {"ready", "degraded"}
    assert set(body["checks"]) == {"database", "redis", "object_storage", "llm_providers"}
    # No REDIS_URL configured in the test environment -- disabled, not an error.
    assert body["checks"]["redis"] == "disabled"
    # In-memory sqlite (tests/integration/conftest.py) is always reachable.
    assert body["checks"]["database"] == "ok"


def test_readiness_is_ready_when_database_and_storage_are_ok():
    body = client().get("/health/ready").json()
    assert body["status"] == "ready"
