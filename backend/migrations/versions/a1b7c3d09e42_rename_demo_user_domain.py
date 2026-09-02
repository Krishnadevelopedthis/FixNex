"""rename seeded demo users from prcampus.io to fixnex.io

Revision ID: a1b7c3d09e42
Revises: c65a5f51070a
Create Date: 2026-09-02 18:52:10.000000

The demo accounts were seeded under the project's pre-rename domain. Changing
DEMO_USERS alone only affects a database seeded from scratch — an existing one
keeps the old addresses, so the sign-in page would advertise six accounts that
cannot authenticate. Re-seeding does not fix it either: the reset step clears
demo assessments and assets but deliberately leaves users alone, so it would
add a second set rather than rename the first.

Scoped to the demo domain by an exact address list, so any real account is
untouched.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = 'a1b7c3d09e42'
down_revision = 'c65a5f51070a'
branch_labels = None
depends_on = None

LOCAL_PARTS = ("admin", "lead", "engineer", "analyst", "developer", "auditor")


def _rename(old_domain: str, new_domain: str) -> None:
    conn = op.get_bind()
    for local in LOCAL_PARTS:
        conn.execute(
            sa.text("UPDATE users SET email = :new WHERE lower(email) = :old"),
            {"new": f"{local}@{new_domain}", "old": f"{local}@{old_domain}"},
        )


def upgrade() -> None:
    _rename("prcampus.io", "fixnex.io")


def downgrade() -> None:
    _rename("fixnex.io", "prcampus.io")
