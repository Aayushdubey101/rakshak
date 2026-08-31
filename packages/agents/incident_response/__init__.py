"""'I already paid / already clicked' guidance.

Unlike protection/investigation, this agent answers a question about what
the *user* already did, not what the pipeline detected — a caller (a future
endpoint or channel intent classifier) supplies which action(s) happened.
It never runs detection or reads a `CanonicalReport`; the guidance is
action-driven, not verdict-driven.

Not wired into the orchestrator's default path for the same reason
protection/investigation aren't required there by task.md phase 10's
done-when: no request carries "the user already acted" intent yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class UserAction(str, Enum):
    PAID = "paid"
    CLICKED_LINK = "clicked_link"
    SHARED_OTP = "shared_otp"
    SHARED_BANK_DETAILS = "shared_bank_details"
    INSTALLED_APP = "installed_app"


@dataclass(frozen=True)
class IncidentGuidance:
    freeze: tuple[str, ...]
    report_to: tuple[str, ...]
    preserve_evidence: tuple[str, ...]


_FREEZE: dict[UserAction, str] = {
    UserAction.PAID: "Contact your bank/UPI app immediately to request a transaction reversal or hold.",
    UserAction.SHARED_OTP: "Call your bank's fraud helpline now to freeze card/net-banking access.",
    UserAction.SHARED_BANK_DETAILS: "Ask your bank to freeze the account and reissue affected credentials.",
    UserAction.INSTALLED_APP: "Uninstall the app immediately and disconnect the device from Wi-Fi/mobile data.",
    UserAction.CLICKED_LINK: "Do not enter any credentials on the site if it's still open; close the tab.",
}

_DEFAULT_FREEZE = ("Stop all further contact with the sender; do not send anything else.",)

_REPORT_TO: tuple[str, ...] = (
    "National Cyber Crime Helpline: 1930",
    "cybercrime.gov.in",
    "Your bank's official fraud-reporting number (from the back of your card, not this message).",
)

_PRESERVE: tuple[str, ...] = (
    "Screenshot the full conversation, including sender ID/number.",
    "Do not delete the message or block the sender until you've reported it.",
)

_PAYMENT_EVIDENCE = "Save the transaction reference number / UTR from the payment."
_APP_EVIDENCE = "Note the app name, package/installer source, and permissions it requested."


def respond(actions: tuple[UserAction, ...]) -> IncidentGuidance:
    """Guidance for one or more things the user says they already did."""
    freeze: list[str] = []
    for action in actions:
        step = _FREEZE.get(action)
        if step and step not in freeze:
            freeze.append(step)

    preserve = list(_PRESERVE)
    if UserAction.PAID in actions:
        preserve.append(_PAYMENT_EVIDENCE)
    if UserAction.INSTALLED_APP in actions:
        preserve.append(_APP_EVIDENCE)

    return IncidentGuidance(
        freeze=tuple(freeze) if freeze else _DEFAULT_FREEZE,
        report_to=_REPORT_TO,
        preserve_evidence=tuple(preserve),
    )
