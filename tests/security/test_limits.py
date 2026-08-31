"""Ingestion limits. Phase 4's other security gate.

Hostile input is not only malicious content — it is also a 900 MB attachment, a
10,000-page PDF, or an executable renamed to .png. Every one of those is a typed
rejection that degrades the investigation, never an exception or an OOM.
"""

import io

import pytest
from pypdf import PdfWriter

from packages.ingestion import ingest
from packages.ingestion.audio import transcribe_audio
from packages.ingestion.image import extract_image_text
from packages.ingestion.limits import DEFAULT_LIMITS, IngestionLimits
from packages.ingestion.pdf import extract_pdf_text
from packages.ingestion.text import normalize_text
from packages.shared.schemas import (
    ContentType,
    InvestigationRequest,
    MediaRef,
    Platform,
    RejectionReason,
)

TINY = IngestionLimits(max_media_bytes=64, max_pdf_pages=2, max_text_chars=20, max_urls=3)
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def _pdf(pages: int) -> bytes:
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=100, height=100)
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


def test_default_limits_are_bounded():
    """Nothing is unlimited by default."""
    assert 0 < DEFAULT_LIMITS.max_media_bytes <= 50 * 1024 * 1024
    assert 0 < DEFAULT_LIMITS.max_pdf_pages <= 200
    assert 0 < DEFAULT_LIMITS.max_urls <= 100
    assert 0 < DEFAULT_LIMITS.request_timeout_seconds <= 30
    assert 0 < DEFAULT_LIMITS.max_redirects <= 10


def test_oversized_pdf_is_rejected():
    rejection = extract_pdf_text(_pdf(1), uri="s3://ev/big.pdf", limits=TINY)
    assert rejection.reason is RejectionReason.TOO_LARGE
    assert "exceeds 64" in rejection.detail


def test_too_many_pages_is_rejected():
    rejection = extract_pdf_text(
        _pdf(5), uri="s3://ev/long.pdf", limits=IngestionLimits(max_pdf_pages=2)
    )
    assert rejection.reason is RejectionReason.TOO_MANY_PAGES


async def test_oversized_image_is_rejected():
    rejection = await extract_image_text(PNG, uri="s3://ev/big.png", limits=TINY)
    assert rejection.reason is RejectionReason.TOO_LARGE


async def test_oversized_audio_is_rejected():
    rejection = await transcribe_audio(b"OggS" + b"\x00" * 100, uri="s3://ev/big.ogg", limits=TINY)
    assert rejection.reason is RejectionReason.TOO_LARGE


@pytest.mark.parametrize(
    "data,uri",
    [
        (b"MZ\x90\x00executable", "s3://ev/payload.png"),   # PE renamed to .png
        (b"#!/bin/sh\nrm -rf /", "s3://ev/script.png"),
    ],
)
async def test_declared_type_does_not_beat_the_bytes(data, uri):
    rejection = await extract_image_text(data, uri=uri)
    assert rejection.reason is RejectionReason.UNSUPPORTED_MEDIA


async def test_unknown_media_is_rejected_through_ingest():
    async def loader(ref):
        return b"MZ\x90\x00 not media at all"

    content = await ingest(
        InvestigationRequest(
            platform=Platform.WEB,
            text="see attachment",
            media=[MediaRef(kind=ContentType.IMAGE, uri="s3://ev/x.bin")],
        ),
        media_loader=loader,
    )

    assert content.media == ()
    assert content.rejections[0].reason is RejectionReason.UNSUPPORTED_MEDIA


async def test_url_count_is_capped_through_ingest():
    text = " ".join(f"site{i}.test" for i in range(50))
    content = await ingest(InvestigationRequest(platform=Platform.WEB, text=text), limits=TINY)
    assert len(content.urls) <= TINY.max_urls


def test_text_cap_applies_before_anything_reads_it():
    assert len(normalize_text("a" * 10_000, limits=TINY)) == TINY.max_text_chars
