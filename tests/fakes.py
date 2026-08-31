"""Test-only doubles. Never imported by production code.

`FakeProvider` satisfies the `LLMProvider` contract from canned fixtures, so the
suite can exercise routing, failover, and degradation without a network call or
a credential.
"""

from __future__ import annotations

from typing import Any, Sequence

from packages.llm.gateway.base import BaseProvider, LLMError, LLMResponse, TaskKind, Usage


class FakeProvider(BaseProvider):
    """Returns queued replies; raises the queued exceptions.

    `replies` is consumed in order and the last entry repeats, so a provider
    that always fails is `replies=[LLMError("boom")]`.
    """

    def __init__(
        self,
        name: str = "fake",
        replies: Sequence[str | Exception] = ("ok",),
        *,
        configured: bool = True,
        credentials: Sequence[str] = ("k1",),
        capabilities: frozenset[TaskKind] | None = None,
        model_id: str = "fake-1",
    ):
        super().__init__(credentials=list(credentials) if configured else [])
        self.name = name
        self.model_id = model_id
        self.replies = list(replies)
        self.prompts: list[str] = []
        self.options: list[dict[str, Any]] = []
        self.calls = 0
        if capabilities is not None:
            self.capabilities = capabilities

    async def _generate_once(self, prompt: str, credential: str, **options: Any) -> LLMResponse:
        self.prompts.append(prompt)
        self.options.append(options)
        index = min(self.calls, len(self.replies) - 1)
        self.calls += 1

        outcome = self.replies[index]
        if isinstance(outcome, Exception):
            raise outcome
        return LLMResponse(
            text=outcome,
            provider=self.name,
            model_id=self.model_id,
            latency_ms=0,
            usage=Usage(requests=1, prompt_tokens=7, completion_tokens=11),
        )


def always_failing(name: str = "broken") -> FakeProvider:
    return FakeProvider(name, replies=[LLMError(f"{name} is down", exhausted=True)])
