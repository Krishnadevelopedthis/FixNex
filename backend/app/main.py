"""PR-CAMPUS API entrypoint."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware, SecureHeadersMiddleware

logger = logging.getLogger("prcampus")

DESCRIPTION = """
**PR-CAMPUS** centralises the full web application security assessment lifecycle:

`Security tools → Scanner adapters → Normalised findings → Correlation →
Verification → Evidence → CVSS / CWE / CVE → Contextual risk → Triage →
Remediation → Retest → Closure → Audit trail → Report`

All scanning is constrained to targets inside an assessment's explicitly
authorised scope.
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    from app.db.session import check_database
    from app.scanners.registry import scanner_registry
    from app.storage import get_storage
    from app.workers.runner import get_task_runner

    ok, detail = check_database()
    logger.info("Database: %s (%s)", "connected" if ok else "UNAVAILABLE", detail)

    storage = get_storage()
    logger.info("Evidence storage backend: %s", storage.name)

    runner = get_task_runner()
    logger.info("Task runner: %s", runner.name)

    available = [s.name for s in scanner_registry.all() if s.availability().available]
    logger.info("Scanners available: %s", ", ".join(available) or "none")

    if settings.SEED_ON_STARTUP:
        from app.seed.demo import seed_if_empty

        seed_if_empty()

    yield
    runner.shutdown()
    logger.info("PR-CAMPUS API shutting down.")


app = FastAPI(
    title=settings.APP_NAME,
    description=DESCRIPTION,
    version=settings.VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID", "Content-Disposition"],
)
app.add_middleware(SecureHeadersMiddleware)
app.add_middleware(RequestContextMiddleware)

register_exception_handlers(app)
app.include_router(api_router, prefix=settings.API_PREFIX)


@app.get("/health", tags=["System"], summary="Liveness probe")
def health() -> dict:
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.VERSION}
