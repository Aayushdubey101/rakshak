"""packages/agents/incident_response — "I already paid / already clicked"
guidance (task.md phase 10). Action-driven, no report/detection involved."""

from packages.agents import incident_response as ir


def test_no_actions_gets_the_generic_freeze_step():
    guidance = ir.respond(())

    assert guidance.freeze == ("Stop all further contact with the sender; do not send anything else.",)
    assert guidance.report_to
    assert guidance.preserve_evidence


def test_paid_action_recommends_transaction_reversal_and_utr_preservation():
    guidance = ir.respond((ir.UserAction.PAID,))

    assert any("reversal" in step for step in guidance.freeze)
    assert any("UTR" in step for step in guidance.preserve_evidence)


def test_installed_app_recommends_uninstall_and_app_evidence():
    guidance = ir.respond((ir.UserAction.INSTALLED_APP,))

    assert any("Uninstall" in step for step in guidance.freeze)
    assert any("package/installer" in step for step in guidance.preserve_evidence)


def test_multiple_actions_combine_freeze_steps_without_duplicates():
    guidance = ir.respond((ir.UserAction.PAID, ir.UserAction.SHARED_OTP, ir.UserAction.PAID))

    assert len(guidance.freeze) == 2


def test_report_to_always_includes_the_national_helpline():
    guidance = ir.respond((ir.UserAction.CLICKED_LINK,))

    assert any("1930" in ch for ch in guidance.report_to)
