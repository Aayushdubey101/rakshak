"""Unit coverage for `packages/shared/security/passwords.py`."""

from packages.shared.security.passwords import hash_password, verify_password


def test_hash_is_not_the_plaintext_and_is_salted():
    a, b = hash_password("correct horse battery staple"), hash_password("correct horse battery staple")
    assert a != "correct horse battery staple"
    assert a != b  # different random salt each time


def test_verify_accepts_the_matching_password():
    stored = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", stored)


def test_verify_rejects_the_wrong_password():
    stored = hash_password("correct horse battery staple")
    assert not verify_password("wrong password", stored)


def test_verify_rejects_a_malformed_stored_value():
    assert not verify_password("anything", "not-a-valid-hash")
