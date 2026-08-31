"""packages/shared/privacy.py — evidence-lifecycle transitions and log redaction."""

from packages.shared.privacy import EvidenceState, can_transition, redact_sensitive


def test_lifecycle_moves_forward_linearly():
    assert can_transition(EvidenceState.INGESTED, EvidenceState.ANALYZED)
    assert can_transition(EvidenceState.ANALYZED, EvidenceState.RETAINED)
    assert can_transition(EvidenceState.RETAINED, EvidenceState.EXPIRED)
    assert can_transition(EvidenceState.EXPIRED, EvidenceState.PURGED)


def test_lifecycle_cannot_skip_backwards():
    assert not can_transition(EvidenceState.RETAINED, EvidenceState.INGESTED)
    assert not can_transition(EvidenceState.PURGED, EvidenceState.RETAINED)


def test_purge_is_reachable_from_any_non_terminal_state():
    for state in (EvidenceState.INGESTED, EvidenceState.ANALYZED, EvidenceState.RETAINED,
                  EvidenceState.EXPIRED):
        assert can_transition(state, EvidenceState.PURGED)


def test_purged_is_terminal():
    for target in EvidenceState:
        assert not can_transition(EvidenceState.PURGED, target)


def test_redact_masks_upi_and_phone_and_email():
    text = "Send to scammer@okaxis or call 9876543210, email me@example.com"
    redacted = redact_sensitive(text)

    assert "scammer@okaxis" not in redacted or "[redacted-upi]" in redacted
    assert "9876543210" not in redacted
    assert "me@example.com" not in redacted


def test_redact_leaves_ordinary_text_alone():
    assert redact_sensitive("hello, how are you?") == "hello, how are you?"
