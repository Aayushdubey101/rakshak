"""Phase 2 contract tests for the universal domain schemas.

These are not characterization tests — they define new behavior. What they
protect: immutability, bounded scores, the "an investigation has content"
invariant, and one investigation id generated once at the edge.
"""

import pytest
from pydantic import ValidationError

from packages.shared.schemas import (
    CanonicalReport,
    ContentType,
    EntityKind,
    ExtractedEntity,
    InvestigationRequest,
    MediaRef,
    Platform,
    RiskSignal,
    Severity,
    SignalSource,
    StageState,
    StageStatus,
    Verdict,
    new_investigation_id,
)


# --- InvestigationRequest ----------------------------------------------------

def test_minimal_text_request():
    request = InvestigationRequest(platform=Platform.WEB, text="you won 25 lakh")

    assert request.investigation_id.startswith("inv_")
    assert request.content_type is ContentType.TEXT
    assert (request.media, request.urls, request.metadata) == ((), (), {})
    assert request.timestamp.tzinfo is not None


def test_request_is_frozen():
    request = InvestigationRequest(platform=Platform.API, text="hi there")
    with pytest.raises(ValidationError):
        request.text = "mutated"


def test_request_needs_content():
    with pytest.raises(ValidationError, match="text, media, or urls"):
        InvestigationRequest(platform=Platform.WEB)
    with pytest.raises(ValidationError, match="text, media, or urls"):
        InvestigationRequest(platform=Platform.WEB, text="   ")


def test_media_or_urls_alone_are_enough():
    media = MediaRef(kind=ContentType.IMAGE, uri="s3://evidence/abc.png", mime_type="image/png")
    assert InvestigationRequest(platform=Platform.WHATSAPP, media=[media]).media == (media,)
    assert InvestigationRequest(platform=Platform.TELEGRAM, urls=["http://x.invalid"]).urls == (
        "http://x.invalid",
    )


def test_unknown_platform_is_rejected():
    with pytest.raises(ValidationError):
        InvestigationRequest(platform="carrier-pigeon", text="hi")


def test_investigation_ids_are_unique():
    assert len({new_investigation_id() for _ in range(100)}) == 100


# --- entities and signals ----------------------------------------------------

def test_entity_comparable_falls_back_to_value():
    raw = ExtractedEntity(
        kind=EntityKind.PHONE, value="+91 98765 43210", confidence=0.9, source="regex.phone"
    )
    normalized = raw.model_copy(update={"normalized_value": "9876543210"})

    assert raw.comparable == "+91 98765 43210"
    assert normalized.comparable == "9876543210"


@pytest.mark.parametrize("confidence", [-0.1, 1.1])
def test_entity_confidence_is_bounded(confidence):
    with pytest.raises(ValidationError):
        ExtractedEntity(
            kind=EntityKind.UPI_ID, value="a@okaxis", confidence=confidence, source="regex.upi"
        )


def test_signal_defaults_to_full_weight():
    signal = RiskSignal(
        source=SignalSource.PATTERN, score=0.4, label="urgency", confidence=0.8
    )
    assert (signal.weight, signal.model_id) == (1.0, None)


@pytest.mark.parametrize("field,value", [("score", 1.5), ("confidence", -0.2), ("weight", -1.0)])
def test_signal_bounds(field, value):
    kwargs = {"source": SignalSource.ML_TEXT, "score": 0.5, "label": "spam", "confidence": 0.5}
    with pytest.raises(ValidationError):
        RiskSignal(**{**kwargs, field: value})


# --- CanonicalReport ---------------------------------------------------------

def _report(**overrides) -> CanonicalReport:
    base = dict(
        investigation_id="inv_test",
        verdict=Verdict.SCAM,
        risk_score=88,
        severity=Severity.HIGH,
        confidence=0.91,
    )
    return CanonicalReport(**{**base, **overrides})


def test_report_defaults_are_empty_not_null():
    report = _report()
    assert report.red_flags == ()
    assert report.extracted_entities == ()
    assert report.stage_status == ()
    assert report.is_degraded is False
    assert report.generated_at.tzinfo is not None


def test_risk_score_is_bounded_to_100():
    with pytest.raises(ValidationError):
        _report(risk_score=101)


def test_report_is_degraded_when_a_stage_failed():
    ok = StageStatus(stage="ingestion", state=StageState.OK, duration_ms=4)
    failed = StageStatus(stage="ml.text", state=StageState.FAILED, error="model unavailable")

    assert _report(stage_status=[ok]).is_degraded is False
    assert _report(stage_status=[ok, failed]).is_degraded is True


def test_entities_of_filters_by_kind():
    upi = ExtractedEntity(
        kind=EntityKind.UPI_ID, value="a@okaxis", confidence=0.95, source="regex.upi"
    )
    phone = ExtractedEntity(
        kind=EntityKind.PHONE, value="9876543210", confidence=0.9, source="regex.phone"
    )
    report = _report(extracted_entities=[upi, phone])

    assert report.entities_of(EntityKind.UPI_ID) == (upi,)
    assert report.entities_of(EntityKind.DOMAIN) == ()


def test_report_round_trips_through_json():
    report = _report(
        red_flags=["urgency", "payment request"],
        stage_status=[StageStatus(stage="llm", state=StageState.SKIPPED)],
    )
    assert CanonicalReport.model_validate_json(report.model_dump_json()) == report
