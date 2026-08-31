"""packages/threat_intel/campaigns — not-yet-implemented embedding-similarity
seam, same convention as tests/unit/test_ml_text_and_vision.py's vision stub.
"""

from packages.threat_intel import campaigns


async def test_similarity_always_returns_none():
    result = await campaigns.similarity("some scam text", None)

    assert result is None
