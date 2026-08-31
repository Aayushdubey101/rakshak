"""Deeper analysis for ambiguous cases.

Applies when the pipeline's own verdict isn't confident — `SUSPICIOUS`/
`UNKNOWN`, or a `SCAM` verdict at low confidence. Like `packages.agents.
protection`, this never re-runs detection: it only asks better questions of
evidence the report already carries (which entity kinds are thin, whether a
threat-intel match exists, what's still missing).

Not wired into the orchestrator's default path: task.md phase 10's done-when
only requires the protection agent there, and no endpoint yet decides when a
case is "ambiguous enough" to route here. Real and tested, ready for whichever
later phase adds that trigger.
"""

from __future__ import annotations

from dataclasses import dataclass

from packages.shared.schemas.entities import EntityKind
from packages.shared.schemas.report import CanonicalReport, Verdict

_AMBIGUOUS_VERDICTS = {Verdict.SUSPICIOUS, Verdict.UNKNOWN}
_LOW_CONFIDENCE = 0.5
_MIN_SUPPORTING_MENTIONS = 2


@dataclass(frozen=True)
class FollowUp:
    follow_up_questions: tuple[str, ...]
    entities_needing_expansion: tuple[EntityKind, ...]
    threat_intel_summary: str | None


def is_ambiguous(report: CanonicalReport) -> bool:
    if report.verdict in _AMBIGUOUS_VERDICTS:
        return True
    return report.verdict is Verdict.SCAM and report.confidence < _LOW_CONFIDENCE


def follow_up_questions(report: CanonicalReport) -> tuple[str, ...]:
    if not is_ambiguous(report):
        return ()
    questions = ["Can you share the exact wording of the message, including any links?"]
    if not report.extracted_entities:
        questions.append("Did the sender share a phone number, UPI ID, or bank account?")
    if not report.url_findings:
        questions.append("Was there a link involved, and if so, what does the site look like?")
    return tuple(questions)


def entity_expansion(report: CanonicalReport) -> tuple[EntityKind, ...]:
    """Entity kinds present but under-evidenced — fewer supporting mentions
    than `_MIN_SUPPORTING_MENTIONS` — that a follow-up question could firm up."""
    if not is_ambiguous(report):
        return ()
    counts: dict[EntityKind, int] = {}
    for entity in report.extracted_entities:
        counts[entity.kind] = counts.get(entity.kind, 0) + 1
    return tuple(kind for kind, count in counts.items() if count < _MIN_SUPPORTING_MENTIONS)


def threat_intel_drilldown(report: CanonicalReport) -> str | None:
    if not report.threat_intel:
        return None
    matches = report.threat_intel
    campaigns = {m.campaign_id for m in matches if m.campaign_id}
    summary = f"{len(matches)} indicator(s) correlate with prior investigations"
    return summary + (f" across {len(campaigns)} known campaign(s)." if campaigns else ".")


def investigate(report: CanonicalReport) -> FollowUp:
    return FollowUp(
        follow_up_questions=follow_up_questions(report),
        entities_needing_expansion=entity_expansion(report),
        threat_intel_summary=threat_intel_drilldown(report),
    )
