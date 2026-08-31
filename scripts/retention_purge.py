"""Retention purge job.

    uv run python scripts/retention_purge.py

Deletes messages/entities/reports for every investigation whose `purge_at`
has passed (set at creation time from `RETENTION_DAYS_MESSAGES`), records one
`audit_logs` row per purge, and reports the count. Meant to run on a
schedule (cron / phase 13's async workers); safe to run manually or
repeatedly — investigations already purged simply won't match again.
"""

from __future__ import annotations

import asyncio


async def main() -> int:
    from packages.shared.db.engine import create_all
    from packages.shared.db.repositories import get_investigation_repository

    await create_all()
    count = await get_investigation_repository().purge_expired()
    print(f"Purged {count} expired investigation(s).")
    return count


if __name__ == "__main__":
    asyncio.run(main())
