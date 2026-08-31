"""Provider registry.

Every provider is constructed, always. One without credentials reports DISABLED
and the router skips it — nothing raises `NotImplementedError`, and there are no
stub implementations pretending to be providers.

Ollama is opt-in (`OLLAMA_ENABLED`) rather than on-by-default: a local endpoint
that is usually absent would otherwise make every investigation pay a connection
refusal before failing over.
"""

from __future__ import annotations

from packages.llm.gateway.base import LLMProvider, TaskKind
from packages.llm.providers.anthropic import AnthropicProvider
from packages.llm.providers.gemini.pool import gemini_pool
from packages.llm.providers.gemini.provider import GeminiProvider
from packages.llm.providers.openai_compatible import OpenAICompatibleProvider

__all__ = [
    "AnthropicProvider",
    "GeminiProvider",
    "OpenAICompatibleProvider",
    "build_providers",
]


def _split_keys(value: str | None) -> list[str]:
    return [part.strip() for part in (value or "").split(",") if part.strip()]


def build_providers(settings) -> dict[str, LLMProvider]:
    """Construct every provider from configuration. Unconfigured ones are DISABLED."""
    timeout = settings.LLM_TIMEOUT_SECONDS
    ollama_body = {"seed": settings.LLM_SEED} if settings.LLM_SEED is not None else {}

    providers: list[LLMProvider] = [
        GeminiProvider(gemini_pool),
        OpenAICompatibleProvider(
            "ollama",
            base_url=settings.OLLAMA_BASE_URL,
            model_id=settings.OLLAMA_MODEL,
            credentials=["-"] if settings.OLLAMA_ENABLED else [],
            timeout_seconds=timeout,
            extra_body=ollama_body,
        ),
        OpenAICompatibleProvider(
            "openai",
            base_url=settings.OPENAI_BASE_URL,
            model_id=settings.OPENAI_MODEL,
            credentials=_split_keys(settings.OPENAI_API_KEY),
            timeout_seconds=timeout,
            capabilities=frozenset(TaskKind),
        ),
        AnthropicProvider(
            base_url=settings.ANTHROPIC_BASE_URL,
            model_id=settings.ANTHROPIC_MODEL,
            credentials=_split_keys(settings.ANTHROPIC_API_KEY),
            timeout_seconds=timeout,
        ),
        OpenAICompatibleProvider(
            "groq",
            base_url=settings.GROQ_BASE_URL,
            model_id=settings.GROQ_MODEL,
            credentials=_split_keys(settings.GROQ_API_KEY),
            timeout_seconds=timeout,
        ),
        OpenAICompatibleProvider(
            "openrouter",
            base_url=settings.OPENROUTER_BASE_URL,
            model_id=settings.OPENROUTER_MODEL,
            credentials=_split_keys(settings.OPENROUTER_API_KEY),
            timeout_seconds=timeout,
            capabilities=frozenset(TaskKind),
        ),
    ]
    return {provider.name: provider for provider in providers}
