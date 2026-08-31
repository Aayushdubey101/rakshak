"""packages/agents/protection — the default consumer agent (task.md phase 10).

Pure functions over an already-built CanonicalReport: no detection, no I/O.
"""

from packages.agents import protection
from packages.shared.schemas.entities import EntityKind, ExtractedEntity
from packages.shared.schemas.report import CanonicalReport, Severity, ThreatIntelMatch, Verdict


def _report(**overrides) -> CanonicalReport:
    defaults = dict(
        investigation_id="inv_test",
        verdict=Verdict.SCAM,
        risk_score=80,
        severity=Severity.HIGH,
        confidence=0.9,
        scam_type="upi_fraud",
        red_flags=("urgent payment request", "unknown UPI ID"),
    )
    defaults.update(overrides)
    return CanonicalReport(**defaults)


def test_safe_report_gets_a_reassuring_explanation_and_no_scary_actions():
    report = _report(verdict=Verdict.LIKELY_SAFE, risk_score=0, severity=Severity.NONE, confidence=0.1)

    assert "does not show signs" in protection.explain(report)
    assert protection.recommend_actions(report) == (
        "No action needed. Stay cautious if the sender later asks for money or personal details.",
    )


def test_scam_report_explanation_names_the_type_and_confidence():
    report = _report()

    explanation = protection.explain(report)

    assert "UPI payment fraud" in explanation
    assert "90%" in explanation
    assert "high risk" in explanation
    assert "urgent payment request" in explanation


def test_scam_actions_always_include_the_base_safety_rules():
    report = _report()

    actions = protection.recommend_actions(report)

    assert "Do not send money or make any payment." in actions
    assert any("UPI ID" in a for a in actions)
    assert any("1930" in a for a in actions)


def test_unmapped_scam_type_still_gets_base_and_report_actions():
    report = _report(scam_type="some_new_type_no_one_mapped_yet")

    actions = protection.recommend_actions(report)

    assert actions[0] == "Do not share OTPs, passwords, authenticator codes, or bank details."
    assert actions[-1].startswith("Report to the National Cyber Crime Helpline")


def test_link_action_only_appears_when_a_url_was_actually_found():
    """Item 9: never tell someone not to click a link that doesn't exist."""
    from packages.shared.schemas.report import UrlFinding

    no_url_report = _report(scam_type="mfa_code_theft")
    assert not any("click any link" in a for a in protection.recommend_actions(no_url_report))

    with_url_report = _report(
        scam_type="phishing",
        url_findings=(UrlFinding(url="http://bad.example/login"),),
    )
    assert any("click any link" in a for a in protection.recommend_actions(with_url_report))


def test_threat_intel_match_adds_the_campaign_action():
    report = _report(threat_intel=(
        ThreatIntelMatch(
            indicator="scammer@ybl", kind=EntityKind.UPI_ID, source="threat_intel.correlation", confidence=0.7,
        ),
    ))

    actions = protection.recommend_actions(report)

    assert any("previously reported scam" in a for a in actions)


def test_protect_attaches_both_fields_and_leaves_everything_else_untouched():
    report = _report()

    protected = protection.protect(report)

    assert protected.explanation
    assert protected.recommended_actions
    assert protected.investigation_id == report.investigation_id
    assert protected.risk_score == report.risk_score
    assert protected.red_flags == report.red_flags


def test_explanation_caps_red_flags_at_three():
    report = _report(red_flags=("a", "b", "c", "d", "e"))

    explanation = protection.explain(report)

    assert explanation.endswith("Red flags: a, b, c.")


def test_entities_do_not_affect_explanation_directly_but_report_still_carries_them():
    report = _report(extracted_entities=(
        ExtractedEntity(kind=EntityKind.UPI_ID, value="scammer@ybl", confidence=0.9, source="regex.upiIds"),
    ))

    protected = protection.protect(report)

    assert protected.extracted_entities == report.extracted_entities
