"""Route-level authorization. `apps.api.middleware.auth.APIKeyMiddleware`
answers "who is this caller" and sets `request.state.principal`; this answers
"may this principal do this specific thing" -- a FastAPI dependency per route,
because different endpoints need different scopes and a single middleware
can't express that.
"""

from __future__ import annotations

from fastapi import HTTPException, Request

from packages.shared.security.api_keys import ApiKeyPrincipal


def get_principal(request: Request) -> ApiKeyPrincipal:
    principal = getattr(request.state, "principal", None)
    if principal is None:
        # The auth middleware runs first for every /api/* route and always
        # rejects before this dependency executes -- reaching here with no
        # principal means the middleware was bypassed (e.g. a route added
        # outside /api/*), which is a wiring bug, not a client error.
        raise HTTPException(status_code=401, detail="Unauthenticated")
    return principal


def require_scope(scope: str):
    def _check(request: Request) -> ApiKeyPrincipal:
        principal = get_principal(request)
        if not principal.has_scope(scope):
            raise HTTPException(status_code=403, detail=f"missing required scope: {scope}")
        return principal

    return _check
