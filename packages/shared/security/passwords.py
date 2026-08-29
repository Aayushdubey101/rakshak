"""End-user password hashing.

Stdlib-only, matching `packages/shared/security/tokens.py`'s own "no new
dependency" precedent -- no `bcrypt`/`passlib`/`argon2` in `pyproject.toml`.
PBKDF2-HMAC-SHA256 (OWASP-recommended iteration count) with a random
per-password salt is a legitimate, dependency-free choice for this.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_ITERATIONS = 310_000
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    salt = secrets.token_hex(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), _ITERATIONS)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, expected_hex = stored.split("$", 1)
    except ValueError:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), _ITERATIONS)
    return hmac.compare_digest(digest.hex(), expected_hex)
