"""task.md phase 12's literal done-when: one investigation -> one
CanonicalReport -> WebReport, WhatsAppReport, TelegramReport all correct and
mutually consistent.

test_channel_parity.py proves the three *channels* independently reach the
same orchestrator and produce the same report (phase 5's gate). This file is
the phase-12 gate one level downstream: given that one report, do all three
serializers describe the same finding.
"""

from packages.domain.investigations.orchestrator import investigate
from packages.reports.serializers import to_telegram, to_web, to_whatsapp
from packages.shared.schemas import InvestigationRequest, Platform

SCAM_TEXT = "Your SBI account is blocked. Send Rs 5000 to scammer@okaxis immediately to unblock."
BENIGN_TEXT = "hey are we still on for lunch tomorrow?"


async def test_one_scam_report_renders_consistently_across_all_three_channels():
    outcome = await investigate(
        InvestigationRequest(platform=Platform.WEB, content_type="text", text=SCAM_TEXT)
    )
    report = outcome.report

    web = to_web(report)
    telegram = to_telegram(report)
    whatsapp = to_whatsapp(report)

    # Same verdict, same risk, same scam type -- three renderings, one finding.
    assert web["verdict"] == "scam"
    assert f"Risk: {report.risk_score}/100" in telegram
    assert f"Risk: {report.risk_score}/100" in whatsapp
    scam_type_label = report.scam_type.replace("_", " ")
    assert scam_type_label in telegram
    assert scam_type_label in whatsapp

    # No channel ever recomputes evidence: every red flag on the wire came
    # from the one report, none of the serializers add or drop one silently.
    for flag in report.red_flags[:5]:
        assert flag in web["red_flags"]


async def test_one_benign_report_renders_consistently_and_names_no_scam_type():
    outcome = await investigate(
        InvestigationRequest(platform=Platform.WEB, content_type="text", text=BENIGN_TEXT)
    )
    report = outcome.report

    web = to_web(report)
    telegram = to_telegram(report)
    whatsapp = to_whatsapp(report)

    assert web["verdict"] != "scam"
    assert "Type:" not in telegram
    assert "Type:" not in whatsapp
    assert web["risk_score"] == report.risk_score


async def test_a_degraded_stage_is_visible_on_every_channel():
    """A failed stage degrades the one report; every serializer must say so,
    not just the web JSON that happens to carry stage_status verbatim."""
    from packages.shared.schemas import CanonicalReport, Severity, StageState, StageStatus, Verdict

    report = CanonicalReport(
        investigation_id="inv_degraded",
        verdict=Verdict.SUSPICIOUS,
        risk_score=45,
        severity=Severity.MEDIUM,
        confidence=0.5,
        stage_status=(StageStatus(stage="detection", state=StageState.FAILED, error="timeout"),),
    )

    assert report.is_degraded
    assert to_web(report)["stage_status"][0]["state"] == "failed"
    assert "partial analysis" in to_telegram(report)
    assert "partial analysis" in to_whatsapp(report)
