"""Whole-word keyword matching -- shared by `detector.py` and
`intelligence_extractor.py`, which both used to do `keyword in text_lower`.

Plain substring containment matches a keyword inside unrelated words: `"rs"`
inside `"appears"`/`"years"`, `"hr"` inside `"synchronization"`, `"lock"`
inside `"blocking"` (itself usually *negated*: "is not currently blocking").
Those false positives directly corrupted scam-type classification (a
coincidental "rs" hit was the deciding vote for a fabricated "investment
scam" label) and polluted the evidence/indicator lists shown to a user.
"""

from __future__ import annotations

import re

_PATTERN_CACHE: dict[str, re.Pattern[str]] = {}


def _pattern_for(keyword: str) -> re.Pattern[str]:
    pattern = _PATTERN_CACHE.get(keyword)
    if pattern is None:
        pattern = re.compile(rf"(?<!\w){re.escape(keyword)}(?!\w)")
        _PATTERN_CACHE[keyword] = pattern
    return pattern


def contains_word(text_lower: str, keyword: str) -> bool:
    """True if `keyword` (a word or space-separated phrase) appears in
    `text_lower` at word boundaries, not merely as a substring."""
    return _pattern_for(keyword).search(text_lower) is not None
