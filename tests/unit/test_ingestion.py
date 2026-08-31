"""Phase 4 contract tests for the ingestion layer.

No network and no files: URLs are not resolved unless asked, PDFs are built in
memory by pypdf, and the vision path runs against a stubbed gateway.
"""

import io

import pytest
from pypdf import PdfWriter

from packages.ingestion import ingest
from packages.ingestion.audio import transcribe_audio
from packages.ingestion.image import extract_image_text
from packages.ingestion.limits import IngestionLimits, sniff
from packages.ingestion.pdf import extract_pdf_text
from packages.ingestion.text import fold_homoglyphs, normalize_text
from packages.ingestion.url import canonicalize, extract_urls, refang
from packages.shared.schemas import (
    ContentType,
    IngestionRejection,
    InvestigationRequest,
    MediaRef,
    MediaSummary,
    Platform,
    RejectionReason,
)

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def _pdf(pages: int = 1, *, encrypted: bool = False) -> bytes:
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=200, height=200)
    if encrypted:
        writer.encrypt("secret")
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


def _request(**overrides) -> InvestigationRequest:
    base = dict(platform=Platform.WEB, text="pay now")
    return InvestigationRequest(**{**base, **overrides})


# --- text --------------------------------------------------------------------

def test_homoglyphs_fold_to_ascii():
    """Cyrillic р/а and Greek Η read as ASCII to a human, and now to us."""
    assert fold_homoglyphs("рaytm") == "paytm"
    assert fold_homoglyphs("ΗDFC") == "HDFC"


def test_zero_width_characters_are_stripped():
    assert normalize_text("ur​gent pay‍ment") == "urgent payment"


def test_whitespace_is_collapsed_and_trimmed():
    assert normalize_text("  pay  now  \n\n\n\n  today ") == "pay now\n\ntoday"


def test_text_is_truncated_to_the_cap():
    assert normalize_text("x" * 500, limits=IngestionLimits(max_text_chars=10)) == "x" * 10


@pytest.mark.parametrize("value", [None, "", "   "])
def test_empty_text_normalizes_to_empty(value):
    assert normalize_text(value) == ""


# --- urls --------------------------------------------------------------------

@pytest.mark.parametrize(
    "defanged,expected",
    [
        ("hxxp://evil[.]test/pay", "http://evil.test/pay"),
        ("evil(.)test", "evil.test"),
        ("hXXps://a[.]b[.]test", "https://a.b.test"),
    ],
)
def test_refang_undoes_defanging(defanged, expected):
    assert refang(defanged) == expected


def test_canonicalize_normalizes_scheme_host_and_port():
    assert canonicalize("HTTP://Example.TEST:80/a?b=1#frag") == "http://example.test/a?b=1"
    assert canonicalize("example.test") == "http://example.test/"
    assert canonicalize("https://example.test:8443/x") == "https://example.test:8443/x"


def test_extract_urls_finds_plain_and_defanged():
    text = "click http://a.test/pay or hxxp://b[.]test then call 9876543210"
    assert extract_urls(text) == ("http://a.test/pay", "hxxp://b[.]test")


def test_extract_urls_ignores_non_hosts_and_deduplicates():
    assert extract_urls("pay 5000 to me@okaxis, see a.test and a.test") == ("a.test",)
    assert extract_urls("no links here at all") == ()


def test_extract_urls_respects_the_cap():
    text = " ".join(f"site{i}.test" for i in range(30))
    assert len(extract_urls(text, limits=IngestionLimits(max_urls=5))) == 5


# --- sniffing ----------------------------------------------------------------

@pytest.mark.parametrize(
    "data,kind",
    [
        (PNG, ContentType.IMAGE),
        (b"%PDF-1.7\n", ContentType.PDF),
        (b"\xff\xd8\xff\xe0", ContentType.IMAGE),
        (b"RIFF\x00\x00\x00\x00WEBP", ContentType.IMAGE),
        (b"OggS\x00", ContentType.AUDIO),
        (b"just text", None),
    ],
)
def test_sniff_identifies_by_magic_bytes(data, kind):
    assert sniff(data)[1] is kind


# --- pdf ---------------------------------------------------------------------

def test_pdf_extraction_reports_pages():
    summary = extract_pdf_text(_pdf(pages=3), uri="s3://ev/doc.pdf")
    assert isinstance(summary, MediaSummary)
    assert (summary.pages, summary.extractor, summary.kind) == (3, "pypdf", ContentType.PDF)


def test_encrypted_pdf_is_rejected():
    rejection = extract_pdf_text(_pdf(encrypted=True), uri="s3://ev/locked.pdf")
    assert isinstance(rejection, IngestionRejection)
    assert rejection.reason is RejectionReason.ENCRYPTED


def test_non_pdf_bytes_are_rejected():
    assert extract_pdf_text(PNG, uri="s3://ev/not.pdf").reason is RejectionReason.UNSUPPORTED_MEDIA


def test_corrupt_pdf_is_a_typed_rejection_not_a_crash():
    rejection = extract_pdf_text(b"%PDF-1.7\nshredded", uri="s3://ev/broken.pdf")
    assert isinstance(rejection, IngestionRejection)
    assert rejection.reason is RejectionReason.EXTRACTION_FAILED


# --- image -------------------------------------------------------------------

class _Gateway:
    def __init__(self, available=True, reply="TRANSCRIBED TEXT"):
        self.available, self.reply = available, reply
        self.options = []

    def has_provider_for(self, task):
        return self.available

    async def try_generate(self, task, prompt, **options):
        self.options.append(options)
        return self.reply


async def test_image_without_a_vision_provider_is_kept_but_unread(monkeypatch):
    monkeypatch.setattr("packages.ingestion.image.get_gateway", lambda: _Gateway(available=False))
    summary = await extract_image_text(PNG, uri="s3://ev/shot.png")

    assert isinstance(summary, MediaSummary)
    assert summary.extracted_text == "" and summary.extractor is None
    assert summary.mime_type == "image/png"


async def test_image_is_transcribed_through_the_vision_task(monkeypatch):
    gateway = _Gateway()
    monkeypatch.setattr("packages.ingestion.image.get_gateway", lambda: gateway)

    summary = await extract_image_text(PNG, uri="s3://ev/shot.png")

    assert summary.extracted_text == "TRANSCRIBED TEXT"
    assert summary.extractor == "llm.vision"
    assert gateway.options[0]["images"][0].startswith("data:image/png;base64,")


async def test_non_image_bytes_are_rejected():
    rejection = await extract_image_text(b"%PDF-1.7\n", uri="s3://ev/fake.png")
    assert rejection.reason is RejectionReason.UNSUPPORTED_MEDIA


# --- audio -------------------------------------------------------------------

async def test_audio_is_declared_but_deferred():
    rejection = await transcribe_audio(b"OggS\x00" + b"\x00" * 32, uri="s3://ev/note.ogg")
    assert isinstance(rejection, IngestionRejection)
    assert rejection.reason is RejectionReason.NOT_IMPLEMENTED


async def test_registered_asr_backend_is_used():
    from packages.ingestion import audio

    class Backend:
        name = "fake-asr"

        async def transcribe(self, data, *, mime_type=None):
            return "send me the otp"

    audio.register_backend(Backend())
    try:
        summary = await transcribe_audio(b"OggS\x00" + b"\x00" * 32, uri="s3://ev/note.ogg")
    finally:
        audio.register_backend(None)

    assert summary.extracted_text == "send me the otp"
    assert summary.extractor == "fake-asr"


# --- ingest ------------------------------------------------------------------

async def test_ingest_normalizes_and_observes_without_resolving():
    content = await ingest(_request(text="pаy at hxxp://evil[.]test/now"))

    assert content.text == "pay at hxxp://evil[.]test/now"  # homoglyph folded
    assert len(content.urls) == 1
    observation = content.urls[0]
    assert observation.normalized == "http://evil.test/now"
    assert observation.was_defanged is True
    assert observation.final_url is None  # nothing was fetched
    assert content.rejections == ()


async def test_ingest_keeps_media_unread_without_a_loader():
    ref = MediaRef(kind=ContentType.PDF, uri="s3://ev/doc.pdf")
    content = await ingest(_request(media=[ref]))

    assert content.media[0].uri == "s3://ev/doc.pdf"
    assert content.media[0].extracted_text == ""


async def test_ingest_reads_media_through_the_loader():
    pdf = _pdf()

    async def loader(ref):
        return pdf

    content = await ingest(
        _request(media=[MediaRef(kind=ContentType.PDF, uri="s3://ev/d.pdf")]), media_loader=loader
    )

    assert content.media[0].extractor == "pypdf"
    assert content.analyzable_text.startswith("pay now")


async def test_ingest_records_a_loader_failure_as_a_rejection():
    async def loader(ref):
        raise RuntimeError("object storage unavailable")

    content = await ingest(
        _request(media=[MediaRef(kind=ContentType.PDF, uri="s3://ev/d.pdf")]), media_loader=loader
    )

    assert content.media == ()
    assert content.rejections[0].reason is RejectionReason.EXTRACTION_FAILED


async def test_sniffed_type_beats_the_declared_one(monkeypatch):
    """A PNG declared as a PDF is treated as a PNG."""
    monkeypatch.setattr("packages.ingestion.image.get_gateway", lambda: _Gateway(available=False))

    async def loader(ref):
        return PNG

    content = await ingest(
        _request(media=[MediaRef(kind=ContentType.PDF, uri="s3://ev/x.pdf")]), media_loader=loader
    )

    assert content.media[0].kind is ContentType.IMAGE


async def test_ingest_carries_the_investigation_id():
    request = _request()
    assert (await ingest(request)).investigation_id == request.investigation_id
