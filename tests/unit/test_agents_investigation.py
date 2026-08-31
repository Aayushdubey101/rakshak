"""packages/agents/investigation — deeper analysis for ambiguous cases
(task.md phase 10). Pure functions over an already-built CanonicalReport."""

from packages.agents import investigation
from packages.shared.schemas.entities import EntityKind, ExtractedEntity
from packages.shared.schemas.report import CanonicalReport, Severity, ThreatIntelMatch, Verdict


def _report(**overrides) -> CanonicalReport:
    defaults = dict(
        investigation_id="inv_test",
        verdict=Verdict.SUSPICIOUS,
        risk_score=45,
        severity=Severity.MEDIUM,
        confidence=0.4,
    )
    defaults.update(overrides)
    return CanonicalReport(**defaults)


def test_confident_scam_verdict_is_not_ambiguous():
    report = _report(verdict=Verdict.SCAM, confidence=0.95)

    assert investigation.is_ambiguous(report) is False
    assert investigation.follow_up_questions(report) == ()
    assert investigation.entity_expansion(report) == ()


def test_low_confidence_scam_verdict_is_ambiguous():
    report = _report(verdict=Verdict.SCAM, confidence=0.3)

    assert investigation.is_ambiguous(report) is True


def test_suspicious_and_unknown_verdicts_are_ambiguous():
    assert investigation.is_ambiguous(_report(verdict=Verdict.SUSPICIOUS)) is True
    assert investigation.is_ambiguous(_report(verdict=Verdict.UNKNOWN)) is True


def test_likely_safe_is_never_ambiguous():
    report = _report(verdict=Verdict.LIKELY_SAFE, confidence=0.05)

    assert investigation.is_ambiguous(report) is False


def test_follow_up_questions_probe_missing_entities_and_urls():
    report = _report()

    questions = investigation.follow_up_questions(report)

    assert any("phone number" in q for q in questions)
    assert any("link" in q for q in questions)


def test_entity_expansion_flags_kinds_with_fewer_than_two_mentions():
    report = _report(extracted_entities=(
        ExtractedEntity(kind=EntityKind.UPI_ID, value="a@ybl", confidence=0.8, source="regex.upiIds"),
        ExtractedEntity(kind=EntityKind.PHONE, value="9876543210", confidence=0.8, source="regex.phoneNumbers"),
        ExtractedEntity(kind=EntityKind.PHONE, value="9876543211", confidence=0.8, source="regex.phoneNumbers"),
    ))

    thin_kinds = investigation.entity_expansion(report)

    assert EntityKind.UPI_ID in thin_kinds
    assert EntityKind.PHONE not in thin_kinds


def test_threat_intel_drilldown_none_without_matches():
    assert investigation.threat_intel_drilldown(_report()) is None


def test_threat_intel_drilldown_summarizes_campaign_count():
    report = _report(threat_intel=(
        ThreatIntelMatch(indicator="a@ybl", kind=EntityKind.UPI_ID, source="s", confidence=0.6, campaign_id="camp_1"),
        ThreatIntelMatch(indicator="b@ybl", kind=EntityKind.UPI_ID, source="s", confidence=0.6, campaign_id="camp_1"),
    ))

    summary = investigation.threat_intel_drilldown(report)

    assert "2 indicator(s)" in summary
    assert "1 known campaign(s)" in summary


def test_investigate_bundles_all_three_outputs():
    report = _report()

    follow_up = investigation.investigate(report)

    assert follow_up.follow_up_questions
    assert follow_up.threat_intel_summary is None
