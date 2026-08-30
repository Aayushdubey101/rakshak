"""`MLSignal` — the one shape every ML/pattern layer speaks.

A source that can't run right now (model not loaded, `HF_LITE_MODE`, no
vision model configured) returns `None`, not a synthetic zero-score signal.
`None` means "didn't run"; `packages.domain.risk.fusion.fuse()` treats that
as absent and renormalizes over whatever did run. A zero-score `RiskSignal`
would instead mean "ran, and confidently found nothing" — a different,
stronger claim that a disabled model has no business making.

No model-specific type (an HF pipeline's raw output dict, a torch tensor,
whatever a future vision model returns) is allowed to leak past whatever
module implements this Protocol. Callers of `packages/ml/*` only ever see a
`RiskSignal` or `None`.
"""

from __future__ import annotations

from typing import Any, Protocol

from packages.shared.schemas.signals import RiskSignal


class MLSignal(Protocol):
    async def score(self, text: str, **context: Any) -> RiskSignal | None: ...
