"""What every channel adapter must provide, and nothing more.

An adapter does platform I/O and translation. It verifies a signature, turns a
webhook into `InvestigationRequest`s, fetches media, renders a report for its
channel, and sends a reply. It contains no detection, no scoring, no ML, no LLM,
no threat intelligence, and no agent logic — those live behind one shared
pipeline that every channel calls.
"""

from typing import Mapping, Protocol, runtime_checkable

from packages.shared.schemas.investigation import InvestigationRequest, MediaRef
from packages.shared.schemas.report import CanonicalReport


class WebhookRejected(Exception):
    """The webhook is not from the platform it claims to be from."""


@runtime_checkable
class PlatformAdapter(Protocol):
    name: str

    def verify_signature(self, headers: Mapping[str, str], body: bytes) -> bool:
        """True only for a request the platform actually signed."""
        ...

    def parse_webhook(self, payload: dict) -> tuple[InvestigationRequest, ...]:
        """Translate a webhook body into universal requests. No analysis here."""
        ...

    async def fetch_media(self, ref: MediaRef) -> bytes:
        """Download media the platform holds behind an id."""
        ...

    def format_report(self, report: CanonicalReport) -> str:
        """Render the canonical report for this channel's constraints."""
        ...

    async def send(self, conversation_id: str, text: str) -> bool:
        """Deliver a message back to the conversation."""
        ...
