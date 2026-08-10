from __future__ import annotations

import argparse
import sys

from sqlalchemy import select

from app.core.client_ip import normalize_ip_key
from app.core.config import get_settings
from app.db.models import AuthIpPenalty
from app.db.session import SessionLocal
from app.services.login_security import (
    LoginSecurityUnavailable,
    get_login_security_service,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect or release VulnFlanker login IP bans."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List IP penalty records")
    list_parser.add_argument(
        "--all",
        action="store_true",
        help="Include inactive and previously released records",
    )
    list_parser.add_argument("--limit", type=int, default=100)

    release_parser = subparsers.add_parser("release", help="Release a ban by IP")
    release_parser.add_argument("--ip", required=True)
    release_parser.add_argument("--reason", required=True)

    args = parser.parse_args()
    service = get_login_security_service()
    with SessionLocal() as db:
        if args.command == "list":
            rows = service.list_penalties(
                db,
                active_only=not args.all,
                limit=max(1, min(args.limit, 500)),
            )
            if not rows:
                print("No matching login IP penalties.")
                return 0
            for row in rows:
                until = "permanent" if row.is_permanent else row.banned_until
                print(f"{row.id}\t{row.ip_key}\tlevel={row.level}\tuntil={until}")
            return 0

        settings = get_settings()
        try:
            ip_key = normalize_ip_key(
                args.ip,
                ipv6_prefix_length=settings.login_ipv6_prefix_length,
            )
        except ValueError:
            print("Invalid IP address.", file=sys.stderr)
            return 2
        row = db.scalar(
            select(AuthIpPenalty).where(AuthIpPenalty.ip_key == ip_key)
        )
        if row is None:
            print(f"No penalty record found for {ip_key}.", file=sys.stderr)
            return 1
        try:
            released = service.unblock_penalty(
                db,
                penalty_id=row.id,
                released_by="cli",
                reason=args.reason.strip(),
            )
        except LoginSecurityUnavailable:
            print(
                "Redis is unavailable; the ban was not released because cache and database "
                "must be updated together.",
                file=sys.stderr,
            )
            return 3
        if released is None:
            print("Penalty disappeared before it could be released.", file=sys.stderr)
            return 1
        print(f"Released {released.ip_key} (record {released.id}).")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

