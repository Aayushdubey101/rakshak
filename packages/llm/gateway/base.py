"""Provider-facing contracts for the LLM Gateway.

Every model call in Rakshak goes through a provider implementing `LLMProvider`.
No provider SDK is imported outside `packages/llm/providers/`, and no credential
leaves this layer.

`CredentialPool` generalizes `GeminiPool.key_states` — the same rules (try each
credential once, mark a failed one unavailable, let it back in after a cooldown)
applied to every provider. Providers that need no credential hold a single
anonymous one, so an unreachable Ollama and an exhausted Gemini key behave the
same way to the router.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock
from typing import Any, AsyncIterator, Protocol, Sequence, runtime_checkable

DEFAULT_COOLDOWN_SECONDS = 300.0
ANONYMOUS_CREDENTIAL = "-"


class TaskKind(str, Enum):
    """What the caller needs, not which model it wants."""

    REASONING = "reasoning"
    FAST = "fast"
    VISION = "vision"
    STRUCTURED = "structured"


class ProviderStatus(str, Enum):
    READY = "ready"
    DISABLED = "disabled"          # not configured; the router skips it
    COOLING_DOWN = "cooling_down"  # every credential failed recently


class LLMError(RuntimeError):
    """A provider call failed. Carries whether the credential should cool down."""

    def __init__(self, message: str, *, exhausted: bool = False):
        super().__init__(message)
        self.exhausted = exhausted


class NoProviderAvailable(LLMError):
    """No configured provider could answer. Callers degrade; they do not crash."""


@dataclass(frozen=True)
class Usage:
    requests: int = 0
    failures: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(
            requests=self.requests + other.requests,
            failures=self.failures + other.failures,
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
        )


@dataclass(frozen=True)
class ProviderHealth:
    name: str
    status: ProviderStatus
    model_id: str | None = None
    available_credentials: int = 0
    detail: str | None = None


@dataclass(frozen=True)
class LLMResponse:
    text: str
    provider: str
    model_id: str
    latency_ms: int
    usage: Usage = field(default_factory=Usage)


@runtime_checkable
class LLMProvider(Protocol):
    """What the gateway requires of every provider."""

    name: str
    model_id: str
    capabilities: frozenset[TaskKind]

    async def generate(self, prompt: str, **options: Any) -> LLMResponse: ...

    def stream(self, prompt: str, **options: Any) -> AsyncIterator[str]: ...

    async def structured_output(self, prompt: str, **options: Any) -> dict[str, Any]: ...

    def health_check(self) -> ProviderHealth: ...

    def usage(self) -> Usage: ...


class CredentialPool:
    """Per-credential availability with cooldown, thread-safe.

    Generalized from `GeminiPool.key_states`: rotate through credentials, take
    the first available one, and let a failed credential back in once its
    cooldown expires.
    """

    def __init__(
        self,
        credentials: Sequence[str],
        *,
        cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS,
    ):
        self.credentials = list(dict.fromkeys(c for c in credentials if c))
        self.cooldown_seconds = cooldown_seconds
        self._states = {c: {"available": True, "failed_at": None} for c in self.credentials}
        self._index = 0
        self._lock = Lock()

    def __bool__(self) -> bool:
        return bool(self.credentials)

    @property
    def available_count(self) -> int:
        return sum(1 for c in self.credentials if self._is_available(c))

    def _is_available(self, credential: str) -> bool:
        with self._lock:
            state = self._states.get(credential)
            if state is None:
                return False
            if state["available"]:
                return True
            failed_at = state["failed_at"]
            if failed_at is not None and time.time() - failed_at > self.cooldown_seconds:
                state.update(available=True, failed_at=None)
                return True
            return False

    def next_available(self) -> str | None:
        """Next usable credential, or None when all are cooling down."""
        for _ in range(len(self.credentials)):
            credential = self.credentials[self._index]
            self._index = (self._index + 1) % len(self.credentials)
            if self._is_available(credential):
                return credential
        return None

    def mark_failed(self, credential: str) -> None:
        with self._lock:
            if credential in self._states:
                self._states[credential].update(available=False, failed_at=time.time())

    def mark_success(self, credential: str) -> None:
        with self._lock:
            if credential in self._states:
                self._states[credential].update(available=True, failed_at=None)


_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def parse_json_reply(text: str) -> dict[str, Any]:
    """Pull an object out of a model reply, fenced or bare.

    Matches the fence handling the current detector already relies on, so
    switching transports does not change how replies are read.
    """
    if not text or not text.strip():
        raise LLMError("empty reply")

    candidate = text.strip()
    fenced = _JSON_FENCE.search(candidate)
    if fenced:
        candidate = fenced.group(1).strip()

    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise LLMError(f"reply was not JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise LLMError("reply JSON was not an object")
    return parsed


class BaseProvider:
    """Shared plumbing: credential rotation, usage counting, default behaviors.

    Subclasses implement `_generate_once(prompt, credential, **options)`.
    """

    name: str = "base"
    model_id: str = ""
    capabilities: frozenset[TaskKind] = frozenset(
        {TaskKind.REASONING, TaskKind.FAST, TaskKind.STRUCTURED}
    )

    def __init__(self, credentials: Sequence[str], *, cooldown_seconds: float = 300.0):
        self._pool = CredentialPool(credentials, cooldown_seconds=cooldown_seconds)
        self._usage = Usage()

    # -- introspection --------------------------------------------------------

    @property
    def is_configured(self) -> bool:
        return bool(self._pool)

    def health_check(self) -> ProviderHealth:
        """Configuration and circuit state. Never a network call — a liveness
        probe belongs to the deployment layer, not to every gateway lookup.
        """
        if not self.is_configured:
            return ProviderHealth(self.name, ProviderStatus.DISABLED, self.model_id,
                                  detail="no credentials configured")
        available = self._pool.available_count
        if available == 0:
            return ProviderHealth(self.name, ProviderStatus.COOLING_DOWN, self.model_id,
                                  detail="all credentials cooling down")
        return ProviderHealth(self.name, ProviderStatus.READY, self.model_id, available)

    def usage(self) -> Usage:
        return self._usage

    # -- calling --------------------------------------------------------------

    async def _generate_once(self, prompt: str, credential: str, **options: Any) -> LLMResponse:
        raise NotImplementedError  # every concrete provider implements this

    async def generate(self, prompt: str, **options: Any) -> LLMResponse:
        """Try each available credential once, in order. Failover, not retry."""
        if not self.is_configured:
            raise LLMError(f"{self.name} is not configured", exhausted=True)

        tried: set[str] = set()
        last_error: Exception | None = None

        while len(tried) < len(self._pool.credentials):
            credential = self._pool.next_available()
            if credential is None or credential in tried:
                break
            tried.add(credential)

            started = time.monotonic()
            try:
                response = await self._generate_once(prompt, credential, **options)
            except LLMError as exc:
                last_error = exc
                self._usage += Usage(requests=1, failures=1)
                if exc.exhausted:
                    self._pool.mark_failed(credential)
                continue
            except Exception as exc:  # transport failure: cool the credential down
                last_error = exc
                self._usage += Usage(requests=1, failures=1)
                self._pool.mark_failed(credential)
                continue

            self._pool.mark_success(credential)
            self._usage += Usage(
                requests=1,
                prompt_tokens=response.usage.prompt_tokens,
                completion_tokens=response.usage.completion_tokens,
            )
            return LLMResponse(
                text=response.text,
                provider=self.name,
                model_id=response.model_id or self.model_id,
                latency_ms=int((time.monotonic() - started) * 1000),
                usage=response.usage,
            )

        raise LLMError(f"{self.name}: all credentials failed ({last_error})", exhausted=True)

    async def structured_output(self, prompt: str, **options: Any) -> dict[str, Any]:
        response = await self.generate(prompt, json_mode=True, **options)
        return parse_json_reply(response.text)

    async def stream(self, prompt: str, **options: Any) -> AsyncIterator[str]:
        """Default: one chunk, the whole reply.

        ponytail: nothing streams tokens yet (the web UI is phase 16). Real SSE
        parsing goes in the concrete provider when a channel needs it.
        """
        response = await self.generate(prompt, **options)
        yield response.text
