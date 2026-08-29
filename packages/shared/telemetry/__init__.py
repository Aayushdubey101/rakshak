"""OpenTelemetry traces + metrics (task.md phase 15).

No `OTEL_EXPORTER_OTLP_ENDPOINT` configured means tracing stays off -- same
DISABLED-not-a-stub convention as every other optional-infra seam in this
codebase (LLM providers, Redis, object storage, phase 7/3). Configuring it
points spans at any OTLP collector: the architecture doc's own observability
stack, a local Jaeger/Tempo, or AWS Distro for OpenTelemetry in front of
CloudWatch/X-Ray once phase 15 is actually deployed.

`investigation_span()` is a no-op context manager when tracing is disabled,
so `packages/domain/investigations/orchestrator.py::investigate()` can wrap
every call unconditionally without an `if` at the call site.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Iterator

from packages.shared.config.settings import get_settings

if TYPE_CHECKING:
    from opentelemetry.trace import Tracer

_tracer: "Tracer | None" = None


def configure_tracing(app: object = None) -> None:
    """Builds the process-wide tracer and, if `app` is given, instruments the
    FastAPI app for automatic per-request spans. Safe to call with tracing
    disabled -- it just does nothing."""
    global _tracer
    endpoint = get_settings().OTEL_EXPORTER_OTLP_ENDPOINT
    if not endpoint:
        return

    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    provider = TracerProvider(
        resource=Resource.create({"service.name": get_settings().APP_NAME})
    )
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer("rakshak")

    if app is not None:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)


def reset_tracing_cache() -> None:
    """Tests call this after monkeypatching OTEL_EXPORTER_OTLP_ENDPOINT."""
    global _tracer
    _tracer = None


@contextmanager
def investigation_span(investigation_id: str, name: str = "investigation") -> Iterator[None]:
    if _tracer is None:
        yield
        return
    with _tracer.start_as_current_span(name) as span:
        span.set_attribute("investigation_id", investigation_id)
        yield
