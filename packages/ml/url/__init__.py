"""URL risk signal — lexical analysis, no model, no network.

No phishing-classification model is trained or benchmarked yet (task.md:
"no model family is hard-coded until evaluation justifies it" — that
evaluation hasn't run in this environment). This is the ruleset lite mode's
"pattern + threat-intel signals only, still a valid report" already promises
for text; the same promise for URLs. A real classifier slots in behind
`score()` later without changing the `MLSignal` contract or any call site —
today's ruleset becomes one candidate `scripts/eval_detection.py` compares
against, not something this module needs to know about.

Deliberately never fetches the URL or resolves DNS — `packages/ingestion/url/`
already owns SSRF-safe resolution (phase 4); this module only looks at the
string and the `UrlObservation` ingestion already produced.
"""

from __future__ import annotations

import ipaddress

from packages.domain.risk.fusion import attach_weight
from packages.ml.model_registry import URL_LEXICAL_RULESET
from packages.shared.schemas.content import UrlObservation
from packages.shared.schemas.signals import RiskSignal, SignalSource

# Free/cheap TLDs disproportionately used for throwaway phishing domains.
_SUSPICIOUS_TLDS = frozenset({
    "xyz", "top", "club", "work", "click", "link", "country", "zip", "quest",
    "shop", "monster", "rest", "bar", "cfd", "cyou", "sbs", "cc", "gq", "tk",
})

_SHORTENER_HOSTS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at",
})

# A handful of brands scammers impersonate most often in this product's
# domain (Indian banking/e-commerce/payments) — not a reputation database,
# just enough to catch the crude "sbi-verify-login.xyz" pattern from the
# phase-0 golden set. Phase 9's threat_indicators/domains tables are the
# real reputation source; this is the offline-only floor beneath it.
_WATCHED_BRANDS = ("sbi", "hdfc", "icici", "paytm", "amazon", "flipkart", "axis", "kotak")


def _registrable_labels(host: str) -> list[str]:
    return [label for label in host.lower().split(".") if label]


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _lexical_score(observation: UrlObservation) -> tuple[float, list[str]]:
    host = observation.host.lower()
    reasons: list[str] = []
    score = 0.0

    if _looks_like_ip(host):
        score += 0.3
        reasons.append("ip_literal_host")

    labels = _registrable_labels(host)
    tld = labels[-1] if labels else ""
    if tld in _SUSPICIOUS_TLDS:
        score += 0.25
        reasons.append(f"suspicious_tld:.{tld}")

    if host in _SHORTENER_HOSTS:
        score += 0.15
        reasons.append("url_shortener")

    if len(labels) >= 4:
        score += 0.15
        reasons.append("excessive_subdomains")

    # Brand name present as a label, but the registrable domain isn't the
    # brand's own — e.g. "sbi" appears in "sbi-verify-login.xyz", whose
    # actual domain is "sbi-verify-login.xyz", not "sbi.co.in".
    joined = "-".join(labels)
    for brand in _WATCHED_BRANDS:
        if brand in joined and not any(label == brand for label in labels[:-2] or labels):
            score += 0.35
            reasons.append(f"brand_lookalike:{brand}")
            break

    if observation.was_defanged:
        score += 0.1
        reasons.append("defanged_in_message")

    return min(score, 1.0), reasons


async def score(observation: UrlObservation, **_context) -> RiskSignal | None:
    """Never returns None — unlike a model that might not be loaded, this
    ruleset always runs. A URL with no lexical red flags legitimately scores
    0.0, which is a real opinion ("nothing here"), not an absent signal."""
    risk_score, reasons = _lexical_score(observation)
    signal = RiskSignal(
        source=SignalSource.ML_URL,
        score=risk_score,
        label=", ".join(reasons) if reasons else "no_lexical_flags",
        confidence=1.0 if reasons else 0.5,
        model_id=URL_LEXICAL_RULESET.id,
    )
    return attach_weight(signal)
