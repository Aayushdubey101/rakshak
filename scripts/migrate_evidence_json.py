"""One-shot import of the legacy `data/evidence.json` into the phase-7 database.

    uv run python scripts/migrate_evidence_json.py [path/to/evidence.json]

Idempotent: re-running upserts the same rows (`EvidenceRepository.log_session`
keys on `sessionId`), so it's safe to run again after a partial failure.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path


async def migrate(path: Path) -> int:
    from packages.shared.db.engine import create_all
    from packages.shared.db.repositories import get_evidence_repository

    if not path.exists():
        print(f"No evidence file at {path} — nothing to migrate.")
        return 0

    data = json.loads(path.read_text())
    sessions = data.get("sessions", {})
    if not sessions:
        print("evidence.json has no sessions — nothing to migrate.")
        return 0

    await create_all()
    repo = get_evidence_repository()
    for session_id, session in sessions.items():
        session.setdefault("sessionId", session_id)
        await repo.log_session(session)
        print(f"  migrated {session_id}")

    print(f"Migrated {len(sessions)} session(s) from {path}.")
    return len(sessions)


if __name__ == "__main__":
    evidence_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/evidence.json")
    asyncio.run(migrate(evidence_path))
