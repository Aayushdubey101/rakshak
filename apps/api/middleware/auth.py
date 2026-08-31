"""Authentication (task.md phase 14): resolves the caller's principal and
attaches it to `request.state.principal`. Authorization -- whether that
principal may do a specific thing -- is `apps.api.dependencies.require_scope()`,
a separate question checked per-route, not here.

Every `/api/*` route requires a credential now, not just `/api/honeypot/*` --
`/api/v1/investigations` had no real check before this (its
`Depends(verify_api_key)` was a no-op kept only to show a field in Swagger
UI), a genuine gap this phase closes, not a hypothetical one.
"""

from __future__ import annotations

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from packages.shared.config.settings import get_settings
from packages.shared.security.api_keys import ApiKeyPrincipal, SCOPE_ADMIN
from packages.shared.security.tokens import TOKEN_PREFIX, verify_token

_EXEMPT_PATHS = frozenset({
    "/", "/docs", "/openapi.json", "/redoc",
    "/api/v1/auth/register", "/api/v1/auth/login",
    "/api/v1/auth/forgot-password", "/api/v1/auth/reset-password",
})
_EXEMPT_PREFIXES = ("/api/honeypot/health", "/static")


def _unauthorized() -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"error": "Unauthorized", "message": "Invalid or missing x-api-key header"},
    )


def _extract_credential(request: Request) -> str | None:
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        return auth_header[len("bearer "):].strip()
    return request.headers.get("x-api-key")


async def resolve_principal(credential: str | None) -> ApiKeyPrincipal | None:
    """DB-backed scoped keys first; the legacy shared secret (granted the
    admin scope, matching its historical full-access behavior) is the
    dev-convenience fallback -- same DISABLED-not-a-stub shape as every other
    optional-infra seam in this codebase. An operator who has provisioned
    real keys via `scripts/manage_api_keys.py` never falls through to it."""
    if not credential:
        return None

    if credential.startswith(TOKEN_PREFIX):
        return verify_token(credential, secret=get_settings().API_SECRET_KEY)

    from packages.shared.db.repositories import get_api_key_repository

    principal = await get_api_key_repository().verify(credential)
    if principal is not None:
        return principal

    settings = get_settings()
    if settings.API_SECRET_KEY and credential == settings.API_SECRET_KEY:
        return ApiKeyPrincipal(principal="legacy-shared-secret", scopes=frozenset({SCOPE_ADMIN}))
    return None


class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in _EXEMPT_PATHS or path.startswith(_EXEMPT_PREFIXES) or not path.startswith("/api"):
            return await call_next(request)

        principal = await resolve_principal(_extract_credential(request))
        if principal is None:
            return _unauthorized()

        request.state.principal = principal
        return await call_next(request)
