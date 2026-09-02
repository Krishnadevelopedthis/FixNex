"""Management commands.

    python -m app.cli init-db          # create tables without Alembic
    python -m app.cli migrate          # apply Alembic migrations
    python -m app.cli seed-demo        # seed the labelled demo dataset
    python -m app.cli create-user ...  # create an account
    python -m app.cli check            # report component health
"""
from __future__ import annotations

import argparse
import sys

from app.core.logging import configure_logging


def cmd_init_db(_: argparse.Namespace) -> int:
    from app.db.base import Base
    from app.db.session import engine
    import app.models  # noqa: F401

    Base.metadata.create_all(engine)
    print(f"Created {len(Base.metadata.tables)} tables.")
    return 0


def cmd_migrate(_: argparse.Namespace) -> int:
    from alembic import command
    from alembic.config import Config
    from app.core.config import BACKEND_ROOT

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "migrations"))
    command.upgrade(config, "head")
    print("Migrations applied.")
    return 0


def cmd_seed_demo(args: argparse.Namespace) -> int:
    from app.db.session import session_scope
    from app.seed.demo import seed_demo_data

    with session_scope() as db:
        summary = seed_demo_data(db, reset=not args.keep_existing)
    print("Demonstration dataset seeded:")
    for key, value in summary.items():
        print(f"  {key:16} {value}")
    return 0


def cmd_create_user(args: argparse.Namespace) -> int:
    from app.db.session import session_scope
    from app.services.auth import create_user

    with session_scope() as db:
        user = create_user(
            db,
            email=args.email,
            full_name=args.name,
            password=args.password,
            role=args.role,
        )
        print(f"Created {user.email} with role {user.role}.")
    return 0


def cmd_check(_: argparse.Namespace) -> int:
    from app.db.session import check_database
    from app.scanners.registry import scanner_registry
    from app.storage import get_storage
    from app.workers.runner import get_task_runner

    ok, detail = check_database()
    print(f"{'OK ' if ok else 'FAIL'} database        {detail}")

    storage = get_storage()
    s_ok, s_detail = storage.health()
    print(f"{'OK ' if s_ok else 'FAIL'} storage         {storage.name}: {s_detail}")

    runner = get_task_runner()
    r_ok, r_detail = runner.health()
    print(f"{'OK ' if r_ok else 'WARN'} task runner     {runner.name}: {r_detail}")

    print("\nScanner adapters:")
    for entry in scanner_registry.availability_report():
        mark = "OK  " if entry["available"] else "--  "
        print(f"  {mark}{entry['name']:18} {entry['kind']:9} {entry['availability_detail'][:70]}")
    return 0 if ok else 1


def main() -> int:
    configure_logging()
    parser = argparse.ArgumentParser(prog="app.cli", description="FixNex management commands")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="Create all tables directly").set_defaults(func=cmd_init_db)
    sub.add_parser("migrate", help="Apply Alembic migrations").set_defaults(func=cmd_migrate)
    sub.add_parser("check", help="Report component health").set_defaults(func=cmd_check)

    seed = sub.add_parser("seed-demo", help="Seed the labelled demonstration dataset")
    seed.add_argument("--keep-existing", action="store_true", help="Do not remove existing demo data")
    seed.set_defaults(func=cmd_seed_demo)

    create = sub.add_parser("create-user", help="Create a user account")
    create.add_argument("--email", required=True)
    create.add_argument("--name", required=True)
    create.add_argument("--password", required=True)
    create.add_argument("--role", default="ADMIN")
    create.set_defaults(func=cmd_create_user)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
