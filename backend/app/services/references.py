"""Human-readable reference identifiers (ASM-0001, FND-0104, ...)."""
from __future__ import annotations

from uuid import uuid4

from sqlalchemy.orm import Session

PREFIXES = {
    "Assessment": "ASM",
    "Asset": "AST",
    "Target": "TGT",
    "ScanJob": "SCN",
    "Finding": "FND",
    "Report": "RPT",
}


def assign_reference(db: Session, instance) -> str:
    """Derive a reference from the instance's primary key.

    The primary key only exists after the row is inserted, but `reference` is
    NOT NULL and unique, so the row is first flushed with a unique placeholder
    and then updated with the final value.
    """
    if getattr(instance, "reference", None):
        return instance.reference

    prefix = PREFIXES.get(type(instance).__name__, "OBJ")
    instance.reference = f"{prefix}-TMP-{uuid4().hex[:12]}"
    db.flush()
    instance.reference = f"{prefix}-{instance.id:04d}"
    db.flush()
    return instance.reference
