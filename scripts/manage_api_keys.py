"""API key lifecycle (task.md phase 14): create, list, revoke.

    uv run python scripts/manage_api_keys.py create --principal telegram-bot --scopes analyze
    uv run python scripts/manage_api_keys.py list
    uv run python scripts/manage_api_keys.py revoke --key-id <id>

The plaintext key is printed exactly once, at creation, and is never stored --
only its hash is. Save it somewhere real; a lost key means creating a new one.
"""

from __future__ import annotations

import argparse
import asyncio

from packages.shared.security.api_keys import ALL_SCOPES


async def _create(principal: str, scopes: list[str]) -> None:
    from packages.shared.db.engine import create_all
    from packages.shared.db.repositories import get_api_key_repository

    unknown = set(scopes) - ALL_SCOPES
    if unknown:
        raise SystemExit(f"unknown scope(s): {', '.join(sorted(unknown))} -- valid: {', '.join(sorted(ALL_SCOPES))}")

    await create_all()
    key_id, plaintext = await get_api_key_repository().create(principal=principal, scopes=frozenset(scopes))
    print(f"Created key {key_id} for '{principal}' with scopes {sorted(scopes)}:\n  {plaintext}")


async def _list() -> None:
    from packages.shared.db.engine import create_all
    from packages.shared.db.repositories import get_api_key_repository

    await create_all()
    for row in await get_api_key_repository().list_keys():
        status = "revoked" if row["revoked_at"] else "active"
        print(f"{row['id']}  {row['principal']:<24} {row['scopes']}  {status}  last_used={row['last_used_at']}")


async def _revoke(key_id: str) -> None:
    from packages.shared.db.engine import create_all
    from packages.shared.db.repositories import get_api_key_repository

    await create_all()
    ok = await get_api_key_repository().revoke(key_id)
    print(f"revoked {key_id}" if ok else f"no active key found for id {key_id}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    create_p = sub.add_parser("create")
    create_p.add_argument("--principal", required=True)
    create_p.add_argument("--scopes", required=True, nargs="+")

    sub.add_parser("list")

    revoke_p = sub.add_parser("revoke")
    revoke_p.add_argument("--key-id", required=True)

    args = parser.parse_args()
    if args.command == "create":
        asyncio.run(_create(args.principal, args.scopes))
    elif args.command == "list":
        asyncio.run(_list())
    elif args.command == "revoke":
        asyncio.run(_revoke(args.key_id))


if __name__ == "__main__":
    main()
