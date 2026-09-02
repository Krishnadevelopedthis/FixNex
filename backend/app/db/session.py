"""SQLAlchemy engine / session management."""
from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

logger = logging.getLogger("prcampus.db")

engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DB_ECHO,
    pool_pre_ping=True,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False, class_=Session)


def get_db() -> Iterator[Session]:
    """FastAPI request-scoped session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for workers and scripts."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def check_database() -> tuple[bool, str]:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, "connected"
    except Exception as exc:  # pragma: no cover - surfaced on the system health page
        return False, f"{type(exc).__name__}: {exc}"[:200]


def run_migrations() -> tuple[bool, str]:
    """Apply Alembic migrations to head.

    Used at startup on hosts that offer no release phase or shell (Render's
    free tier), where the schema would otherwise never be created. Returns
    (ok, detail) rather than raising: a failure here should be loud in the
    logs but must not stop the process from booting, or the operator loses
    /health and /api/docs and has no way to diagnose it.
    """
    from alembic import command
    from alembic.config import Config

    from app.core.config import BACKEND_ROOT

    try:
        config = Config(str(BACKEND_ROOT / "alembic.ini"))
        config.set_main_option("script_location", str(BACKEND_ROOT / "migrations"))
        config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)
        command.upgrade(config, "head")
        return True, "schema is at head"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"[:300]
