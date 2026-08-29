"""Short-lived scoped bearer tokens (task.md phase 14: "Remove the hardcoded
frontend key from static/index.html; issue short-lived scoped tokens
instead").

A minimal signed token, not a JWT library: `tok.<payload_b64>.<sig_b64>`,
HMAC-SHA256 over the payload keyed by `API_SECRET_KEY` -- the one secret this
codebase already requires at startup (`Settings.API_SECRET_KEY`), repurposed
here as a local signing key rather than a bearer credential in its own right.
No new dependency, no new required secret.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from packages.shared.security.api_keys import ApiKeyPrincipal

TOKEN_PREFIX = "tok."
DEFAULT_TTL_SECONDS = 900  # 15 minutes


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _sign(payload: bytes, *, secret: str) -> str:
    return _b64encode(hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest())


def issue_token(principal: ApiKeyPrincipal, *, secret: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> tuple[str, int]:
    """Returns `(token, expires_at_epoch)`."""
    expires_at = int(time.time()) + ttl_seconds
    payload = json.dumps({
        "principal": principal.principal, "scopes": sorted(principal.scopes), "exp": expires_at,
    }, separators=(",", ":")).encode("utf-8")
    payload_b64 = _b64encode(payload)
    signature = _sign(payload_b64.encode("ascii"), secret=secret)
    return f"{TOKEN_PREFIX}{payload_b64}.{signature}", expires_at


def verify_token(token: str, *, secret: str) -> ApiKeyPrincipal | None:
    if not token.startswith(TOKEN_PREFIX):
        return None
    body = token[len(TOKEN_PREFIX):]
    try:
        payload_b64, signature = body.split(".", 1)
        expected = _sign(payload_b64.encode("ascii"), secret=secret)
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(_b64decode(payload_b64))
    except (ValueError, TypeError, UnicodeDecodeError):
        return None

    if payload.get("exp", 0) < time.time():
        return None
    return ApiKeyPrincipal(principal=payload["principal"], scopes=frozenset(payload.get("scopes", [])))
