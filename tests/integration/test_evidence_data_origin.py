"""task.md phase 11: "Honeypot data is stored separately from consumer
investigation data." Same physical tables (no new table — phase 7 fixed the
list), but `Investigation.data_origin` scopes every honeypot evidence query,
proven against the real repository.
"""

from packages.shared.db.engine import get_session_factory
from packages.shared.db.models import Entity, Investigation, Report
from packages.shared.db.repositories import get_evidence_repository


async def _seed_consumer_investigation(investigation_id: str) -> None:
    """Simulates a future consumer-investigation write — data_origin defaults
    to "consumer" when nothing sets it, same as any non-honeypot writer."""
    async with get_session_factory()() as db:
        db.add(Investigation(
            id=investigation_id, platform="api", content_type="text", verdict="scam",
        ))
        db.add(Report(investigation_id=investigation_id, payload={"note": "consumer report"}))
        db.add(Entity(investigation_id=investigation_id, kind="upi_id", value="consumer@ybl", source="regex"))
        await db.commit()


async def test_honeypot_evidence_never_includes_a_consumer_investigation():
    await _seed_consumer_investigation("inv_consumer_1")
    repository = get_evidence_repository()
    await repository.log_session({
        "sessionId": "inv_honeypot_1",
        "scamDetected": True,
        "extractedIntelligence": {"upiIds": ["scammer@okaxis"], "phoneNumbers": [], "bankAccounts": [], "phishingLinks": [], "suspiciousKeywords": []},
        "conversationHistory": [],
        "startTime": 0,
    })

    evidence = await repository.get_evidence()

    assert "inv_consumer_1" not in evidence["sessions"]
    assert "inv_honeypot_1" in evidence["sessions"]
    assert "consumer@ybl" not in evidence["masterIntel"]["upiIds"]
    assert "scammer@okaxis" in evidence["masterIntel"]["upiIds"]
    assert evidence["totalScamsDetected"] == 1  # the honeypot session, not the consumer row


async def test_investigation_defaults_to_consumer_origin_when_unset():
    await _seed_consumer_investigation("inv_consumer_2")

    async with get_session_factory()() as db:
        investigation = await db.get(Investigation, "inv_consumer_2")

    assert investigation.data_origin == "consumer"


async def test_honeypot_session_is_tagged_honeypot_research():
    repository = get_evidence_repository()
    await repository.log_session({
        "sessionId": "inv_honeypot_2",
        "scamDetected": False,
        "extractedIntelligence": {"upiIds": [], "phoneNumbers": [], "bankAccounts": [], "phishingLinks": [], "suspiciousKeywords": []},
        "conversationHistory": [],
        "startTime": 0,
    })

    async with get_session_factory()() as db:
        investigation = await db.get(Investigation, "inv_honeypot_2")

    assert investigation.data_origin == "honeypot_research"
