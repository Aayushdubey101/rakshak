"""End-user account auth: register/login/forgot-password/reset-password.

Distinct from `POST /api/v1/auth/token` (`investigations.py`) which exchanges
an existing *service* API key for a short-lived token -- these endpoints are
how a person with no credential yet gets one. All four are unauthenticated on
purpose (`apps/api/middleware/auth.py`'s `_EXEMPT_PATHS`) and reuse the same
signed-token scheme (`packages/shared/security/tokens.py`) the service-key
flow already uses: a logged-in user is just an `ApiKeyPrincipal` whose
`principal` is `user:<id>` and whose scopes never include `admin` or
`research:honeypot` -- keeping honeypot isolation (rule #8) intact for free.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from packages.shared.config.settings import get_settings
from packages.shared.db.repositories import get_user_repository
from packages.shared.security.api_keys import (
    ApiKeyPrincipal,
    SCOPE_ANALYZE,
    SCOPE_READ_INVESTIGATIONS,
    SCOPE_READ_THREAT_INTEL,
)
from packages.shared.security.passwords import hash_password, verify_password
from packages.shared.security.tokens import issue_token, verify_token

logger = logging.getLogger("uvicorn")

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

SESSION_TTL_SECONDS = 60 * 60 * 24  # 24h -- a person's session, not a machine call
RESET_TTL_SECONDS = 15 * 60
RESET_SCOPE = "password_reset"
MIN_PASSWORD_LENGTH = 8
_USER_SCOPES = frozenset({SCOPE_ANALYZE, SCOPE_READ_INVESTIGATIONS, SCOPE_READ_THREAT_INTEL})


def _validate_email(value: str) -> str:
    # A basic sanity check, not RFC 5322 validation -- avoids adding the
    # `email-validator` dependency Pydantic's `EmailStr` would require.
    if "@" not in value or value.startswith("@") or value.endswith("@"):
        raise ValueError("not a valid email address")
    return value


class RegisterRequest(BaseModel):
    email: str
    password: str

    _validate = field_validator("email")(_validate_email)


class LoginRequest(BaseModel):
    email: str
    password: str

    _validate = field_validator("email")(_validate_email)


class ForgotPasswordRequest(BaseModel):
    email: str

    _validate = field_validator("email")(_validate_email)


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class SessionResponse(BaseModel):
    token: str
    expires_at: int
    user: dict


def _issue_session(user_id: str, email: str | None) -> SessionResponse:
    principal = ApiKeyPrincipal(principal=f"user:{user_id}", scopes=_USER_SCOPES)
    token, expires_at = issue_token(principal, secret=get_settings().API_SECRET_KEY, ttl_seconds=SESSION_TTL_SECONDS)
    return SessionResponse(token=token, expires_at=expires_at, user={"id": user_id, "email": email})


@router.post("/register", response_model=SessionResponse)
async def register(req: RegisterRequest):
    if len(req.password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters")

    repo = get_user_repository()
    existing = await repo.get_by_email(req.email)
    if existing is not None and existing.password_hash:
        raise HTTPException(status_code=409, detail="An account with this email already exists")

    password_hash = hash_password(req.password)
    if existing is not None:
        await repo.set_password(existing.id, password_hash)
        user_id = existing.id
    else:
        user = await repo.create(email=req.email, password_hash=password_hash)
        user_id = user.id
    return _issue_session(user_id, req.email)


@router.post("/login", response_model=SessionResponse)
async def login(req: LoginRequest):
    repo = get_user_repository()
    user = await repo.get_by_email(req.email)
    if user is None or not user.password_hash or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return _issue_session(user.id, user.email)


@router.post("/forgot-password")
async def forgot_password(req: ForgotPasswordRequest):
    """Always returns 200 regardless of whether the email exists -- an
    account-enumeration guard, same reasoning as login's generic error."""
    repo = get_user_repository()
    user = await repo.get_by_email(req.email)
    if user is None:
        return {"status": "ok"}

    principal = ApiKeyPrincipal(principal=f"user:{user.id}", scopes=frozenset({RESET_SCOPE}))
    token, _ = issue_token(principal, secret=get_settings().API_SECRET_KEY, ttl_seconds=RESET_TTL_SECONDS)
    logger.info(f"🔑 password reset requested for {req.email}: token={token}")

    settings = get_settings()
    if settings.ENVIRONMENT != "production":
        # Dev convenience: no email service configured yet. Never returned
        # once a real deployment is live.
        return {"status": "ok", "dev_reset_token": token}
    return {"status": "ok"}


@router.post("/reset-password")
async def reset_password(req: ResetPasswordRequest):
    principal = verify_token(req.token, secret=get_settings().API_SECRET_KEY)
    if principal is None or RESET_SCOPE not in principal.scopes or not principal.principal.startswith("user:"):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    if len(req.new_password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters")

    user_id = principal.principal.removeprefix("user:")
    updated = await get_user_repository().set_password(user_id, hash_password(req.new_password))
    if not updated:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    return {"status": "ok"}
