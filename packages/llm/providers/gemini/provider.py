"""Gemini as one provider among several.

Wraps the existing `GeminiPool` rather than reimplementing it: its failover and
per-key cooldown rules were characterized in phase 0 and are still the ones we
want. The pool owns credential state; this class owns the gateway contract.
"""

from __future__ import annotations

from typing import Any

from packages.llm.gateway.base import (
    BaseProvider,
    LLMError,
    LLMResponse,
    ProviderHealth,
    ProviderStatus,
    TaskKind,
    Usage,
)
from packages.llm.providers.gemini.pool import GeminiPool


class GeminiProvider(BaseProvider):
    capabilities = frozenset(
        {TaskKind.REASONING, TaskKind.FAST, TaskKind.STRUCTURED, TaskKind.VISION}
    )

    def __init__(self, pool: GeminiPool, *, model_id: str = "gemini-2.0-flash"):
        super().__init__(credentials=[])  # the pool holds the credentials
        self.name = "gemini"
        self.model_id = model_id
        self.pool = pool

    @property
    def is_configured(self) -> bool:
        return bool(self.pool.keys)

    def health_check(self) -> ProviderHealth:
        if not self.is_configured:
            return ProviderHealth(self.name, ProviderStatus.DISABLED, self.model_id,
                                  detail="no API keys configured")
        available = sum(1 for state in self.pool.key_states.values() if state["available"])
        if available == 0:
            return ProviderHealth(self.name, ProviderStatus.COOLING_DOWN, self.model_id,
                                  detail="all keys cooling down")
        return ProviderHealth(self.name, ProviderStatus.READY, self.model_id, available)

    async def generate(self, prompt: str, **options: Any) -> LLMResponse:
        """The pool already fails over across keys, so this does not."""
        if not self.is_configured:
            raise LLMError("gemini is not configured", exhausted=True)

        images = options.get("images")
        model_id = options.get("model_id") or self.model_id
        text = await self.pool.generate_content(prompt, images=images, model_id=model_id)
        if text is None:
            self._usage += Usage(requests=1, failures=1)
            raise LLMError("gemini: all keys exhausted", exhausted=True)

        self._usage += Usage(requests=1)
        return LLMResponse(text=text, provider=self.name, model_id=self.model_id, latency_ms=0)

