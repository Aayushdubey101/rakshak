"""packages/ml/url — lexical URL risk signal (no model, no network)."""

from packages.ml.url import score
from packages.shared.schemas.content import UrlObservation
from packages.shared.schemas.signals import SignalSource


def _observation(**kwargs) -> UrlObservation:
    defaults = {"raw": "http://example.com", "normalized": "http://example.com", "host": "example.com"}
    defaults.update(kwargs)
    return UrlObservation(**defaults)


async def test_clean_url_scores_zero_but_still_returns_a_signal():
    """The ruleset always runs -- 0.0 is a real opinion ("nothing here"),
    not an absent signal, unlike an unconfigured ML model."""
    signal = await score(_observation(host="mybank.com"))
    assert signal is not None
    assert signal.source == SignalSource.ML_URL
    assert signal.score == 0.0


async def test_ip_literal_host_is_flagged():
    signal = await score(_observation(host="192.168.1.1"))
    assert signal.score > 0.0
    assert "ip_literal_host" in signal.label


async def test_suspicious_tld_is_flagged():
    signal = await score(_observation(host="sbi-verify-login.xyz"))
    assert signal.score > 0.0
    assert "suspicious_tld:.xyz" in signal.label


async def test_url_shortener_is_flagged():
    signal = await score(_observation(host="bit.ly"))
    assert "url_shortener" in signal.label


async def test_brand_lookalike_is_flagged():
    """The phase-0 golden phishing case: sbi-verify-login.xyz."""
    signal = await score(_observation(host="sbi-verify-login.xyz"))
    assert any("brand_lookalike:sbi" in reason for reason in signal.label.split(", "))


async def test_the_real_brand_domain_is_not_flagged_as_a_lookalike():
    signal = await score(_observation(host="sbi.co.in"))
    assert "brand_lookalike" not in signal.label


async def test_excessive_subdomains_are_flagged():
    signal = await score(_observation(host="a.b.c.d.example.com"))
    assert "excessive_subdomains" in signal.label


async def test_defanged_url_contributes_a_small_bump():
    plain = await score(_observation(host="example.com", was_defanged=False))
    defanged = await score(_observation(host="example.com", was_defanged=True))
    assert defanged.score > plain.score


async def test_score_is_stamped_with_a_configured_weight():
    signal = await score(_observation())
    assert signal.weight > 0.0
