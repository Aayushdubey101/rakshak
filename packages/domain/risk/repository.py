"""Repository interfaces for risk signals and model runs. Same boundary as
`packages/domain/investigations/repository.py`: domain code depends on these
Protocols, never on an ORM session. SQLAlchemy implementations live in
`packages/shared/db/repositories.py`.
"""

from __future__ import annotations

from typing import Protocol

from packages.shared.schemas.signals import RiskSignal


class RiskAssessmentRepository(Protocol):
    """Persists the exact `RiskSignal`s a fusion ran over — what makes
    `fusion.fuse()` reproducible from stored evidence months later."""

    async def record_signals(self, investigation_id: str, signals: list[RiskSignal]) -> None: ...

    async def load_signals(self, investigation_id: str) -> list[RiskSignal]: ...


class ModelRunRepository(Protocol):
    """One row per inference — the audit trail `packages/ml/model_registry.py`
    writes to on every call."""

    async def record_model_run(
        self, *, investigation_id: str, stage: str, model_id: str, version: str, duration_ms: int
    ) -> None: ...
