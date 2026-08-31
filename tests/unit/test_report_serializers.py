"""packages/reports/serializers -- one CanonicalReport, three renderings.

Telegram/WhatsApp assertions mirror the ones that used to live in
test_telegram_adapter.py / test_whatsapp_adapter.py against the adapters'
own `format_report`; those still pass (the adapters now delegate here), and
these pin the serializers directly, independent of any channel.
"""

from packages.reports.generator import generate_report
from packages.reports.serializers import (
    TELEGRAM_MAX_CHARS,
    WHATSAPP_MAX_CHARS,
    escape_markdown_v2,
    to_telegram,
    to_web,
    to_whatsapp,
)
from packages.shared.schemas import (
    CanonicalReport,
    Severity,
    StageState,
    StageStatus,
    Verdict,
)


def _report(**overrides) -> CanonicalReport:
    base = dict(
        investigation_id="inv_test",
        verdict=Verdict.SCAM,
        risk_score=91,
        severity=Severity.CRITICAL,
        confidence=0.9,
        scam_type="upi_fraud",
    )
    return CanonicalReport(**{**base, **overrides})


def test_markdown_v2_specials_are_escaped():
    assert escape_markdown_v2("pay-now (100%) at a.test!") == r"pay\-now \(100%\) at a\.test\!"


def test_to_telegram_is_short_and_escaped():
    text = to_telegram(_report(red_flags=("urgency", "payment request")))

    assert "Almost certainly a scam" in text
    assert "Risk: 91/100" in text
    assert "• urgency" in text
    assert len(text) <= TELEGRAM_MAX_CHARS


def test_to_whatsapp_is_plain_text():
    text = to_whatsapp(_report(red_flags=("urgency",)))

    assert text == "🚨 Almost certainly a scam\nRisk: 91/100\nType: upi fraud\n\n- urgency"
    assert len(text) <= WHATSAPP_MAX_CHARS


def test_safe_report_does_not_name_a_scam_type_on_either_channel():
    report = _report(verdict=Verdict.LIKELY_SAFE, risk_score=0, severity=Severity.NONE)

    assert "Type:" not in to_telegram(report)
    assert "Type:" not in to_whatsapp(report)


def test_degraded_report_says_so_on_both_channels():
    report = _report(stage_status=(StageStatus(stage="ml.text", state=StageState.FAILED),))

    assert "partial analysis" in to_telegram(report)
    assert "partial analysis" in to_whatsapp(report)


def test_to_web_is_the_full_structured_report():
    body = to_web(_report(red_flags=("urgency",)))

    assert body["investigation_id"] == "inv_test"
    assert body["verdict"] == "scam"
    assert body["red_flags"] == ["urgency"]


def test_the_three_serializers_agree_on_the_same_report():
    """The cross-channel consistency task.md phase 12 asks for: one report,
    rendered three ways, all pointing at the same verdict and risk."""
    report = _report()

    web, telegram, whatsapp = to_web(report), to_telegram(report), to_whatsapp(report)

    assert web["risk_score"] == 91
    assert "91/100" in telegram
    assert "91/100" in whatsapp
    assert web["verdict"] == "scam"
    assert "scam" in telegram.lower()
    assert "scam" in whatsapp.lower()


# --- generator -----------------------------------------------------------


async def test_generate_report_returns_the_report_unchanged():
    report = _report()
    assert await generate_report(report) is report


async def test_generate_report_persists_when_a_repository_is_given():
    saved = []

    class _FakeRepository:
        async def save(self, report):
            saved.append(report)

        async def get(self, investigation_id):
            return saved[-1] if saved else None

    report = _report()
    result = await generate_report(report, repository=_FakeRepository())

    assert result is report
    assert saved == [report]


async def test_generate_report_survives_a_storage_failure():
    class _BrokenRepository:
        async def save(self, report):
            raise RuntimeError("db is down")

        async def get(self, investigation_id):
            return None

    result = await generate_report(_report(), repository=_BrokenRepository())

    assert result.investigation_id == "inv_test"
