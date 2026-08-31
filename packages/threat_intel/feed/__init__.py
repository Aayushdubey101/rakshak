"""Live external scam/phishing feed -- URLhaus (abuse.ch), free and keyless.

Distinct from the rest of `packages/threat_intel`: everything else here
correlates *our own* investigations against each other. This is the one
source of indicators from outside Rakshak, surfaced read-only for the Intel
page's "what's circulating right now" section -- never fed into an
investigation's risk score (an unverified public feed entry is a headline,
not fusion evidence).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
_REQUEST_TIMEOUT_SECONDS = 5.0
_CACHE_TTL_SECONDS = 300  # 5 min -- fresh enough for a "recent scams" list, spares abuse.ch a hit per page load


@dataclass(frozen=True)
class FeedEntry:
    url: str
    host: str
    threat: str
    date_added: str


_cache: tuple[float, tuple[FeedEntry, ...]] | None = None


def _parse(raw: dict) -> tuple[FeedEntry, ...]:
    entries = raw.get("urls") or []
    return tuple(
        FeedEntry(
            url=entry.get("url", ""),
            host=entry.get("host") or "",
            threat=entry.get("threat") or "unknown",
            date_added=entry.get("date_added") or "",
        )
        for entry in entries
        if entry.get("url")
    )


async def recent(*, limit: int = 20) -> tuple[FeedEntry, ...]:
    """Most-recently-reported malicious URLs, newest first. Empty on any
    failure -- same "absent, not a stub" contract as every other optional
    external call in this codebase (packages/threat_intel/reputation, the LLM
    providers): a feed outage degrades the Intel page's live section to
    empty, it never fails the page."""
    global _cache
    now = time.monotonic()
    if _cache is not None and now - _cache[0] < _CACHE_TTL_SECONDS:
        return _cache[1][:limit]

    try:
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.post(URLHAUS_RECENT_URL)
            response.raise_for_status()
            entries = _parse(response.json())
    except (httpx.HTTPError, ValueError):
        entries = _cache[1] if _cache is not None else ()

    _cache = (now, entries)
    return entries[:limit]
