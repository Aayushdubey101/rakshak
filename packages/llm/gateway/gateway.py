"""The LLM Gateway: one entry point for every model call.

Provider SDKs live behind it, credentials never leave it, and a caller that
loses every provider gets a typed failure it can degrade on — not an exception
from someone's HTTP client.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from packages.llm.gateway.base import (
    LLMError,
    LLMProvider,
    LLMResponse,
    NoProviderAvailable,
    ProviderHealth,
    TaskKind,
    Usage,
    parse_json_reply,
)
from packages.llm.providers import build_providers
from packages.llm.router.task_router import TaskRouter, parse_task_routes

logger = logging.getLogger("uvicorn")


class LLMGateway:
    def __init__(self, providers: dict[str, LLMProvider], router: TaskRouter):
        self.providers = providers
        self.router = router

    async def generate(self, task: TaskKind, prompt: str, **options: Any) -> LLMResponse:
        """First provider in the chain that answers. Ordered failover, no retry."""
        chain = self.router.resolve(task)
        if not chain:
            raise NoProviderAvailable(f"no provider configured for task '{task.value}'")

        last_error: Exception | None = None
        for provider in chain:
            try:
                response = await provider.generate(prompt, **options)
            except LLMError as exc:
                last_error = exc
                logger.warning(f"⚠️ provider '{provider.name}' failed for {task.value}: {exc}")
                continue
            logger.debug(f"✅ {task.value} served by '{provider.name}' ({response.latency_ms}ms)")
            return response

        raise NoProviderAvailable(f"every provider failed for '{task.value}': {last_error}")

    async def structured_output(
        self, task: TaskKind, prompt: str, **options: Any
    ) -> dict[str, Any]:
        response = await self.generate(task, prompt, json_mode=True, **options)
        return parse_json_reply(response.text)

    async def try_generate(self, task: TaskKind, prompt: str, **options: Any) -> str | None:
        """`generate`, degraded: None instead of an exception.

        Call sites that must always answer (the honeypot agent, detection) use
        this — losing the LLM degrades a report, it never fails a request.
        """
        try:
            return (await self.generate(task, prompt, **options)).text
        except LLMError as exc:
            logger.warning(f"⚠️ LLM unavailable for {task.value}: {exc}")
            return None

    def has_provider_for(self, task: TaskKind) -> bool:
        """Whether anything can serve this task right now, without calling it."""
        return bool(self.router.resolve(task))

    def health(self) -> tuple[ProviderHealth, ...]:
        return tuple(provider.health_check() for provider in self.providers.values())

    def usage(self) -> Usage:
        total = Usage()
        for provider in self.providers.values():
            total += provider.usage()
        return total


def build_gateway(settings) -> LLMGateway:
    providers = build_providers(settings)
    router = TaskRouter(
        providers,
        overrides=parse_task_routes(settings.LLM_TASK_ROUTES),
        preferred=settings.LLM_PROVIDER,
    )
    return LLMGateway(providers, router)


@lru_cache
def get_gateway() -> LLMGateway:
    """Process-wide gateway. Built lazily so importing does not read credentials."""
    from packages.shared.config.settings import get_settings

    return build_gateway(get_settings())
