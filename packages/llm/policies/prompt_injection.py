"""Prompt-injection defense on the input side (task.md phase 14), paired
with the existing output sanitizer on the output side.

Scammer-supplied text is the one input this codebase sends to an LLM that a
hostile party fully controls -- unlike our own prompts, it can contain
"ignore previous instructions" style payloads aimed at hijacking the model.
Two independent layers, neither trusting the other:

* **Delimiting**: untrusted content is wrapped in an explicit boundary the
  surrounding prompt tells the model never to treat as instructions.
* **Instruction-stripping**: known override phrases are neutralized before
  the text is even embedded, so a delimiter bypass isn't the only defense.

Neither is a guarantee against a sufficiently creative payload -- this raises
the bar, it doesn't claim to eliminate the risk. The real backstop is that
the LLM's opinion is never trusted alone: it's one `RiskSignal` fused with
deterministic pattern/ML evidence (`packages/domain/risk/fusion.py`), and
`packages/llm/policies/evidence_override.py` already blocks it from lowering
a high-confidence deterministic verdict.
"""

from __future__ import annotations

import re

_OVERRIDE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in (
        r"ignore (all |any )?(previous|prior|above) instructions",
        r"disregard (all |any )?(previous|prior|above) instructions",
        r"new instructions?\s*:",
        r"system prompt",
        r"you are now (an?|the) ",
        r"act as (an?|the) ",
        r"\bDAN\b",
        r"pretend (you are|to be) ",
        r"reveal your (instructions|prompt|system prompt)",
        r"forget (everything|all) (you know|above)",
    )
]

_REDACTED = "[redacted-instruction-attempt]"

UNTRUSTED_BEGIN = "<<<UNTRUSTED_USER_CONTENT_BEGIN>>>"
UNTRUSTED_END = "<<<UNTRUSTED_USER_CONTENT_END>>>"


def neutralize(text: str) -> str:
    """Strips known instruction-override phrasing from untrusted text."""
    cleaned = text
    for pattern in _OVERRIDE_PATTERNS:
        cleaned = pattern.sub(_REDACTED, cleaned)
    return cleaned


def wrap_untrusted(text: str) -> str:
    """Neutralizes obvious override attempts, then delimits the result so the
    surrounding prompt can tell the model to treat everything between these
    markers as data to analyze, never as instructions to follow."""
    return f"{UNTRUSTED_BEGIN}\n{neutralize(text)}\n{UNTRUSTED_END}"
