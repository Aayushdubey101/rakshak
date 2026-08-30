"""Text normalization.

Scammers exploit Unicode: zero-width joiners inside keywords, Cyrillic homoglyph
lookalikes in brand names, full-width characters that read identically. Folding
those before detection is what stops "рaytm" (Cyrillic р) from sliding past a
keyword list — the folded copy feeds detection; the original is kept as evidence.
"""

from __future__ import annotations

import re
import unicodedata

from packages.ingestion.limits import DEFAULT_LIMITS, IngestionLimits

# Characters that render as ASCII but are not. Cyrillic and Greek lookalikes are
# what actually shows up in scam messages impersonating brands.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ⅼ": "l",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "ν": "v",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
})

# Zero-width and bidi controls: invisible, and used to break up keywords.
# The literal characters below are the detection target, not injected
# content -- bandit's trojansource check (B613) flags any file containing
# them; this file's whole job is to strip them from untrusted input.
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿­]")  # nosec B613
_WHITESPACE = re.compile("[ \t  - 　]+")
_NEWLINES = re.compile(r"\n{3,}")


def fold_homoglyphs(text: str) -> str:
    """NFKC, strip invisibles, map lookalike letters to their ASCII twin."""
    if not text:
        return ""
    folded = unicodedata.normalize("NFKC", text)
    folded = _INVISIBLE.sub("", folded)
    return folded.translate(_HOMOGLYPHS)


def normalize_text(text: str | None, *, limits: IngestionLimits = DEFAULT_LIMITS) -> str:
    """Fold, collapse whitespace, and truncate to the character cap."""
    if not text:
        return ""
    normalized = fold_homoglyphs(text)
    normalized = _WHITESPACE.sub(" ", normalized)
    normalized = _NEWLINES.sub("\n\n", normalized)
    normalized = "\n".join(line.strip() for line in normalized.split("\n")).strip()
    return normalized[: limits.max_text_chars]


def detect_language_of(text: str) -> str:
    """Language of the message, or 'en' when the ML layer is unavailable."""
    if not text.strip():
        return "en"
    from packages.ml.inference.hf import detect_language

    try:
        return detect_language(text).get("language", "en") or "en"
    except Exception:  # lite mode, missing model, anything: never fail ingestion
        return "en"
