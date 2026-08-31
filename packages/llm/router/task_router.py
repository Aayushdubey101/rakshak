"""Task → ordered provider chain.

Call sites ask for a *task*, never for a model. Which provider serves a task is
configuration, so changing model strategy is a config change and never an edit
at a call site. No model family is hard-coded as "the good one" — the defaults
below are a starting order, and phase 8's benchmarks are what justify changing
them.
"""

from __future__ import annotations

import json
import logging
from typing import Iterable, Mapping, Sequence

from packages.llm.gateway.base import LLMProvider, ProviderStatus, TaskKind

logger = logging.getLogger("uvicorn")

# Ordered by capability first, cost second. Providers absent from a chain are
# never used for that task; unconfigured ones are skipped at call time.
DEFAULT_CHAINS: Mapping[TaskKind, tuple[str, ...]] = {
    TaskKind.REASONING: ("gemini", "anthropic", "openai", "openrouter", "groq", "ollama"),
    TaskKind.FAST: ("groq", "gemini", "ollama", "openai", "openrouter", "anthropic"),
    TaskKind.VISION: ("gemini", "anthropic", "openai", "openrouter"),
    TaskKind.STRUCTURED: ("gemini", "openai", "anthropic", "groq", "openrouter", "ollama"),
}


def parse_task_routes(raw: str | None) -> dict[TaskKind, tuple[str, ...]]:
    """Parse `LLM_TASK_ROUTES`, e.g. `{"reasoning": ["ollama", "gemini"]}`."""
    if not raw or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.error("⚠️ LLM_TASK_ROUTES is not valid JSON; using default chains")
        return {}

    routes: dict[TaskKind, tuple[str, ...]] = {}
    for task_name, chain in (parsed or {}).items():
        try:
            task = TaskKind(task_name)
        except ValueError:
            logger.warning(f"⚠️ LLM_TASK_ROUTES: unknown task '{task_name}' ignored")
            continue
        if isinstance(chain, str):
            chain = [chain]
        routes[task] = tuple(str(name) for name in chain)
    return routes


class TaskRouter:
    """Resolves a task to the providers that can actually serve it right now."""

    def __init__(
        self,
        providers: Mapping[str, LLMProvider],
        *,
        overrides: Mapping[TaskKind, Sequence[str]] | None = None,
        preferred: str | None = None,
    ):
        self.providers = providers
        self.overrides = dict(overrides or {})
        self.preferred = preferred or None

    def chain_for(self, task: TaskKind) -> tuple[str, ...]:
        """Configured order for a task, before availability is considered."""
        chain = tuple(self.overrides.get(task) or DEFAULT_CHAINS.get(task, ()))
        if self.preferred:
            chain = (self.preferred,) + tuple(n for n in chain if n != self.preferred)
        return chain

    def resolve(self, task: TaskKind) -> tuple[LLMProvider, ...]:
        """Providers to try, in order: configured, capable, and not disabled."""
        return tuple(self._usable(task, self.chain_for(task)))

    def _usable(self, task: TaskKind, names: Iterable[str]) -> Iterable[LLMProvider]:
        for name in names:
            provider = self.providers.get(name)
            if provider is None:
                logger.warning(f"⚠️ unknown provider '{name}' in the {task.value} chain")
                continue
            if task not in provider.capabilities:
                continue
            if provider.health_check().status is ProviderStatus.DISABLED:
                continue
            yield provider
