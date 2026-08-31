"""Isolation enforced in code, not convention (task.md phase 11, rule #8:
"a consumer request never enters the honeypot automatically. Explicit
authorization + feature gate required.").

`InvestigationOrchestrator.run()` calls `authorize_engagement()` before
invoking ANY engagement hook — even a hook a caller wired up only runs if
every gate here passes. This is what makes isolation a property of the code
path, not of adapters remembering to check something: a forged flag in a
request body cannot satisfy `confirmed_scam` (it comes from the pipeline's
own detection output) or `credential` (only ever set by server-side header
verification below, never by deserializing request JSON into a credential
object).

`ResearcherCredential` / `verify_researcher_credential()` is an interim
stand-in for phase 14's real scoped API keys — `research:honeypot` is the
scope name phase 14's own checklist already reserves for this. It is a real,
testable gate today (a dedicated header checked against a dedicated setting,
distinct from the consumer `x-api-key`), not a placeholder.
"""

from __future__ import annotations

from dataclasses import dataclass, field

RESEARCH_HONEYPOT_SCOPE = "research:honeypot"


@dataclass(frozen=True)
class ResearcherCredential:
    principal: str
    scopes: frozenset[str] = field(default_factory=lambda: frozenset({RESEARCH_HONEYPOT_SCOPE}))


def verify_researcher_credential(header_value: str | None, *, expected_key: str | None) -> ResearcherCredential | None:
    """A dedicated `X-Researcher-Key` header, distinct from the consumer
    `x-api-key`, so a consumer credential never doubles as a researcher one.
    No configured key means researcher access is off entirely, same
    DISABLED-not-a-stub convention the LLM providers use."""
    if not expected_key or not header_value:
        return None
    if header_value != expected_key:
        return None
    return ResearcherCredential(principal="researcher")


def authorize_engagement(*, feature_enabled: bool, credential: ResearcherCredential | None, confirmed_scam: bool) -> bool:
    """All three must hold. The fourth checklist condition — "engagement is
    explicitly requested" — is enforced structurally: this function is only
    ever consulted when a caller wired an `EngagementHook` at all, which only
    the honeypot's own call site does; `/api/v1/investigations` and the
    Telegram/WhatsApp adapters never pass one."""
    if not feature_enabled:
        return False
    if credential is None or RESEARCH_HONEYPOT_SCOPE not in credential.scopes:
        return False
    return confirmed_scam
