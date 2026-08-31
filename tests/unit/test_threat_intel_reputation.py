from packages.domain.threat_intel.repository import DomainReputation
from packages.shared.schemas.signals import SignalSource
from packages.threat_intel.reputation import NullReputationProvider, score


class _FakeRepository:
    def __init__(self, reputation_score: float, is_repeat: bool = False):
        self._reputation_score = reputation_score
        self._is_repeat = is_repeat
        self.calls: list[tuple[str, float]] = []

    async def record_sighting(self, domain: str, lexical_score: float) -> DomainReputation:
        self.calls.append((domain, lexical_score))
        return DomainReputation(domain=domain, reputation_score=self._reputation_score, is_repeat=self._is_repeat)


class _FakeProvider:
    def __init__(self, value: float | None):
        self._value = value

    async def lookup(self, domain: str) -> float | None:
        return self._value


async def test_score_returns_none_for_a_clean_domain():
    repository = _FakeRepository(reputation_score=0.0)

    signal = await score("example.com", lexical_score=0.0, repository=repository)

    assert signal is None
    assert repository.calls == [("example.com", 0.0)]


async def test_score_reflects_local_history():
    repository = _FakeRepository(reputation_score=0.7, is_repeat=True)

    signal = await score("sbi-verify.xyz", lexical_score=0.6, repository=repository)

    assert signal is not None
    assert signal.source == SignalSource.THREAT_INTEL
    assert signal.score == 0.7
    assert signal.confidence == 0.6  # is_repeat=True


async def test_external_provider_can_raise_the_combined_score_above_local_history():
    repository = _FakeRepository(reputation_score=0.2)

    signal = await score(
        "sbi-verify.xyz", lexical_score=0.2, repository=repository, provider=_FakeProvider(0.9),
    )

    assert signal.score == 0.9


async def test_null_provider_never_raises_the_score():
    repository = _FakeRepository(reputation_score=0.3)

    signal = await score(
        "sbi-verify.xyz", lexical_score=0.3, repository=repository, provider=NullReputationProvider(),
    )

    assert signal.score == 0.3
