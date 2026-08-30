"""Vision ML signal — screenshot analysis, brand/logo detection, visual
scam-pattern detection.

Not implemented. `packages/ingestion/image/` already turns a screenshot into
text via the LLM gateway's vision task (phase 4) — that's OCR, feeding the
same text pipeline every other channel uses. What this module would add is
different: judging the *image itself* (a fake bank-app UI, a forged
payment-confirmation screenshot, an impersonated brand logo) without needing
the words in it to already be scam-shaped. No such model is chosen,
downloaded, or benchmarked in this environment (see
`docs/ml/phase8-evaluation.md`).

`score()` always returns `None` — "vision ML" is absent, not zero, exactly
like any other unconfigured `MLSignal` source. Fusion already renormalizes
around an absent signal, so a report is never missing information because
of this; it just doesn't have a visual opinion yet.
"""

from __future__ import annotations

from packages.shared.schemas.signals import RiskSignal


async def score(image_bytes: bytes, **_context) -> RiskSignal | None:
    return None
