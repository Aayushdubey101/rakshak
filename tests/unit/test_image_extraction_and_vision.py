import base64
import pytest
from unittest.mock import AsyncMock, MagicMock

from packages.llm.gateway.base import TaskKind
from packages.llm.providers.gemini.pool import GeminiPool
from packages.llm.providers.gemini.provider import GeminiProvider
from packages.llm.providers.anthropic import AnthropicProvider
from packages.ingestion.image import extract_image_text
from packages.ingestion import ingest
from packages.domain.investigations.orchestrator import investigate
from packages.shared.schemas import ContentType, InvestigationRequest, MediaRef, Platform, Verdict

PNG_DATA = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe\xa74e\xfc\x00\x00\x00\x00IEND\xaeB`\x82"
B64_PNG = base64.b64encode(PNG_DATA).decode()
DATA_URL = f"data:image/png;base64,{B64_PNG}"


def test_gemini_pool_prepares_multimodal_contents():
    contents = GeminiPool._prepare_contents("Transcribe this image", images=[DATA_URL])
    assert isinstance(contents, list)
    assert len(contents) == 2
    assert contents[0] == {"mime_type": "image/png", "data": PNG_DATA}
    assert contents[1] == "Transcribe this image"


def test_gemini_pool_prepares_plain_text_without_images():
    contents = GeminiPool._prepare_contents("Plain prompt", images=None)
    assert contents == "Plain prompt"


@pytest.mark.asyncio
async def test_gemini_provider_passes_images_to_pool():
    fake_pool = MagicMock()
    fake_pool.keys = ["key1"]
    fake_pool.key_states = {"key1": {"available": True}}
    fake_pool.generate_content = AsyncMock(return_value="Transcribed scam text")

    provider = GeminiProvider(fake_pool, model_id="gemini-2.0-flash")
    resp = await provider.generate("Test prompt", images=[DATA_URL], model_id="gemini-2.0-flash")

    assert resp.text == "Transcribed scam text"
    fake_pool.generate_content.assert_awaited_once_with(
        "Test prompt", images=[DATA_URL], model_id="gemini-2.0-flash"
    )


def test_anthropic_formats_multimodal_image():
    content = AnthropicProvider._content("Transcribe this image", images=[DATA_URL])
    assert isinstance(content, list)
    assert len(content) == 2
    assert content[0]["type"] == "image"
    assert content[0]["source"]["type"] == "base64"
    assert content[0]["source"]["media_type"] == "image/png"
    assert content[0]["source"]["data"] == B64_PNG
    assert content[1] == {"type": "text", "text": "Transcribe this image"}


@pytest.mark.asyncio
async def test_extract_image_text_falls_back_to_vision(monkeypatch):
    class FakeGateway:
        def has_provider_for(self, task):
            return task is TaskKind.VISION

        async def try_generate(self, task, prompt, **options):
            assert options.get("images") == [DATA_URL]
            return "URGENT: WIN 1 CRORE LOTTERY CALL 9876543210"

    monkeypatch.setattr("packages.ingestion.image.get_gateway", lambda: FakeGateway())
    monkeypatch.setattr("packages.ml.vision.ocr.extract_text", AsyncMock(return_value=""))

    summary = await extract_image_text(PNG_DATA, uri="test.png")
    assert summary.extracted_text == "URGENT: WIN 1 CRORE LOTTERY CALL 9876543210"
    assert summary.extractor == "llm.vision"


@pytest.mark.asyncio
async def test_ingest_handles_inline_data_url_automatically(monkeypatch):
    class FakeGateway:
        def has_provider_for(self, task):
            return task is TaskKind.VISION

        async def try_generate(self, task, prompt, **options):
            return "Your bank account is blocked. Verify KYC at http://phish.test"

    monkeypatch.setattr("packages.ingestion.image.get_gateway", lambda: FakeGateway())
    monkeypatch.setattr("packages.ml.vision.ocr.extract_text", AsyncMock(return_value=""))

    req = InvestigationRequest(
        platform=Platform.API,
        content_type=ContentType.IMAGE,
        media=(MediaRef(kind=ContentType.IMAGE, uri=DATA_URL, mime_type="image/png"),),
    )

    content = await ingest(req, media_loader=None)
    assert "Your bank account is blocked" in content.analyzable_text
    assert len(content.media) == 1
    assert content.media[0].extracted_text.startswith("Your bank account is blocked")


@pytest.mark.asyncio
async def test_orchestrator_detects_scam_from_image_transcription(monkeypatch):
    class FakeGateway:
        def has_provider_for(self, task):
            return True

        async def try_generate(self, task, prompt, **options):
            return "URGENT: WIN 25 LAKH LOTTERY. Contact manager at 9876543210 or pay fee to winner@upi"

    monkeypatch.setattr("packages.ingestion.image.get_gateway", lambda: FakeGateway())
    monkeypatch.setattr("packages.ml.vision.ocr.extract_text", AsyncMock(return_value=""))

    import packages.domain.risk.detector as detector
    async def mock_analyze(text, history=None, **kwargs):
        assert "URGENT: WIN 25 LAKH LOTTERY" in text
        return {
            "isScam": True,
            "scamType": "lottery",
            "confidence": 0.95,
            "riskScore": 95,
            "indicators": ["lottery", "urgent fee"],
        }
    monkeypatch.setattr(detector, "analyze", mock_analyze)

    req = InvestigationRequest(
        platform=Platform.WEB,
        content_type=ContentType.IMAGE,
        media=(MediaRef(kind=ContentType.IMAGE, uri=DATA_URL, mime_type="image/png"),),
    )

    outcome = await investigate(req)
    assert outcome.report.verdict is Verdict.SCAM
    assert outcome.report.scam_type == "lottery"
    assert outcome.report.risk_score > 60
    entities = {e.value for e in outcome.report.extracted_entities}
    assert "9876543210" in entities or "winner@upi" in entities
