"""packages/agents/honeypot/isolation — the isolation gate (task.md phase 11,
rule #8: a consumer request never enters the honeypot automatically)."""

from packages.agents.honeypot.isolation import (
    RESEARCH_HONEYPOT_SCOPE,
    ResearcherCredential,
    authorize_engagement,
    verify_researcher_credential,
)

_CREDENTIAL = ResearcherCredential(principal="researcher-1")


# --- verify_researcher_credential ---------------------------------------------

def test_no_expected_key_configured_means_no_credential():
    assert verify_researcher_credential("anything", expected_key=None) is None


def test_no_header_value_means_no_credential():
    assert verify_researcher_credential(None, expected_key="secret") is None


def test_wrong_header_value_means_no_credential():
    assert verify_researcher_credential("wrong", expected_key="secret") is None


def test_matching_header_value_grants_a_scoped_credential():
    credential = verify_researcher_credential("secret", expected_key="secret")

    assert credential is not None
    assert RESEARCH_HONEYPOT_SCOPE in credential.scopes


# --- authorize_engagement ------------------------------------------------------

def test_all_three_gates_hold_authorizes():
    assert authorize_engagement(feature_enabled=True, credential=_CREDENTIAL, confirmed_scam=True) is True


def test_feature_flag_off_blocks_even_with_credential_and_confirmed_scam():
    assert authorize_engagement(feature_enabled=False, credential=_CREDENTIAL, confirmed_scam=True) is False


def test_missing_credential_blocks_even_with_flag_and_confirmed_scam():
    assert authorize_engagement(feature_enabled=True, credential=None, confirmed_scam=True) is False


def test_unconfirmed_scam_blocks_even_with_flag_and_credential():
    assert authorize_engagement(feature_enabled=True, credential=_CREDENTIAL, confirmed_scam=False) is False


def test_credential_missing_the_research_scope_blocks():
    unscoped = ResearcherCredential(principal="x", scopes=frozenset({"read:investigations"}))

    assert authorize_engagement(feature_enabled=True, credential=unscoped, confirmed_scam=True) is False
