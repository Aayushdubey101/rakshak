"""Campaign clustering.

Indicator-based clustering is real and wired: `packages/threat_intel/correlation`
already creates one `scam_campaigns` row the moment two investigations share an
indicator (`SqlThreatIndicatorRepository.correlate`), and every `ThreatIntelMatch`
it returns carries that row's id. That satisfies task.md phase 9's done-when
("a second investigation with a shared indicator correlates to the first and
both link to one campaign row") without needing an embedding model.

pgvector similarity over message/URL embeddings — the *semantic* clustering
task.md also asks for, catching two investigations that paraphrase the same
scam script with no indicator in common — is not built. `scam_campaigns.embedding`
has existed since phase 7 for exactly this, but no embedding task exists yet:
`packages/llm/gateway/base.py`'s `TaskKind` has no `EMBEDDING` member, so no
provider can produce one. This mirrors `packages/ml/vision`'s stub exactly —
`similarity()` always returns `None` ("absent, not zero") until an embedding
provider is chosen and benchmarked, the same evaluation-before-hardcoding rule
`packages/ml/model_registry.py` already documents.
"""

from __future__ import annotations


async def similarity(_text: str, _campaign_embedding: object) -> float | None:
    return None
