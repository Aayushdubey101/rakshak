"""scripts/migrate_evidence_json.py against a small fixture file — the real
188-session data/evidence.json was migrated by hand during development
(see work.md's phase 7 notes); this pins the script's behavior with a test
double so the suite doesn't depend on that file's contents."""

import json

from scripts.migrate_evidence_json import migrate
from packages.shared.db.repositories import get_evidence_repository


async def test_migrate_imports_every_session(tmp_path):
    evidence_file = tmp_path / "evidence.json"
    evidence_file.write_text(json.dumps({
        "sessions": {
            "legacy-1": {
                "scamDetected": True, "scamType": "upi_scam",
                "conversationHistory": [{"sender": "scammer", "text": "hi", "timestamp": "1700000000"}],
                "extractedIntelligence": {
                    "upiIds": ["a@okaxis"], "phoneNumbers": [], "bankAccounts": [],
                    "phishingLinks": [], "suspiciousKeywords": [],
                },
                "startTime": 1700000000.0,
            },
            "legacy-2": {
                "scamDetected": False, "scamType": None,
                "conversationHistory": [], "extractedIntelligence": {},
                "startTime": 1700000000.0,
            },
        },
        "masterIntel": {}, "totalScamsDetected": 1,
    }))

    count = await migrate(evidence_file)

    assert count == 2
    evidence = await get_evidence_repository().get_evidence()
    assert set(evidence["sessions"]) == {"legacy-1", "legacy-2"}
    assert evidence["totalScamsDetected"] == 1


async def test_migrate_missing_file_is_a_noop(tmp_path):
    count = await migrate(tmp_path / "does-not-exist.json")
    assert count == 0
