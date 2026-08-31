"""Unit coverage for `apps/api/middleware/security_headers.py` (task.md phase 14)."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.middleware.security_headers import SecurityHeadersMiddleware


def _client() -> TestClient:
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/ping")
    def ping():
        return {"ok": True}

    @app.get("/page")
    def page():
        from fastapi.responses import HTMLResponse
        return HTMLResponse("<html></html>")

    return TestClient(app)


def test_baseline_headers_always_present():
    response = _client().get("/ping")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_hsts_absent_on_plain_http():
    response = _client().get("/ping")
    assert "Strict-Transport-Security" not in response.headers


def test_hsts_present_when_forwarded_from_a_tls_terminating_edge():
    response = _client().get("/ping", headers={"X-Forwarded-Proto": "https"})
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"


def test_csp_present_on_html_responses_only():
    html_response = _client().get("/page")
    assert "default-src 'self'" in html_response.headers["Content-Security-Policy"]

    json_response = _client().get("/ping")
    assert "Content-Security-Policy" not in json_response.headers
