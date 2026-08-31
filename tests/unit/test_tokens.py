"""Unit coverage for `packages/shared/security/tokens.py` (task.md phase 14)."""

import freezegun

from packages.shared.security.api_keys import ApiKeyPrincipal
from packages.shared.security.tokens import issue_token, verify_token

SECRET = "test-signing-secret"


def test_issued_token_verifies_back_to_the_same_principal():
    principal = ApiKeyPrincipal(principal="bot", scopes=frozenset({"analyze"}))
    token, expires_at = issue_token(principal, secret=SECRET)

    verified = verify_token(token, secret=SECRET)

    assert verified is not None
    assert verified.principal == "bot"
    assert verified.scopes == frozenset({"analyze"})
    assert expires_at > 0


def test_token_expires():
    principal = ApiKeyPrincipal(principal="bot", scopes=frozenset({"analyze"}))
    with freezegun.freeze_time("2026-01-01T00:00:00Z"):
        token, _ = issue_token(principal, secret=SECRET, ttl_seconds=60)

    with freezegun.freeze_time("2026-01-01T00:02:00Z"):
        assert verify_token(token, secret=SECRET) is None


def test_tampered_signature_is_rejected():
    principal = ApiKeyPrincipal(principal="bot")
    token, _ = issue_token(principal, secret=SECRET)
    tampered = token[:-4] + "xxxx"

    assert verify_token(tampered, secret=SECRET) is None


def test_wrong_secret_is_rejected():
    principal = ApiKeyPrincipal(principal="bot")
    token, _ = issue_token(principal, secret=SECRET)

    assert verify_token(token, secret="a-different-secret") is None


def test_non_token_string_is_rejected():
    assert verify_token("rak_not-a-token", secret=SECRET) is None
    assert verify_token("", secret=SECRET) is None
