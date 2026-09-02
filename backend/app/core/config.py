"""Application configuration.

Every external dependency (Redis, MinIO, scanner binaries, third-party APIs)
is optional: the platform degrades to a local, self-contained mode when a
dependency is absent so that the full assessment workflow always remains
demonstrable. Secrets are only ever read from the environment.
"""
from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_ROOT.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(REPO_ROOT / ".env", BACKEND_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------ app
    APP_NAME: str = "FixNex"
    APP_DESCRIPTION: str = "Centralized Web Application Security Assessment Platform"
    VERSION: str = "1.0.0"
    ENVIRONMENT: Literal["development", "production", "test"] = "development"
    DEBUG: bool = True
    API_PREFIX: str = "/api"

    # ------------------------------------------------------------- database
    DATABASE_URL: str = "postgresql+psycopg2://prcampus:prcampus@localhost:5432/prcampus"
    DB_ECHO: bool = False
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    # --------------------------------------------------------------- auth
    JWT_SECRET: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    PASSWORD_MIN_LENGTH: int = 10

    # Simple in-memory throttle for the authentication endpoints.
    AUTH_RATE_LIMIT_ATTEMPTS: int = 10
    AUTH_RATE_LIMIT_WINDOW_SECONDS: int = 300

    # --------------------------------------------------------------- CORS
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173"

    # -------------------------------------------------- background processing
    # auto  -> use Celery when a broker is reachable, otherwise an in-process
    #          thread pool so scans still run on a laptop with no Redis.
    TASK_RUNNER: Literal["auto", "celery", "thread"] = "auto"
    REDIS_URL: str = ""
    CELERY_BROKER_URL: str = ""
    CELERY_RESULT_BACKEND: str = ""
    MAX_CONCURRENT_SCANS: int = 4

    # ---------------------------------------------------- evidence storage
    # auto -> MinIO when reachable, otherwise the local filesystem.
    STORAGE_BACKEND: Literal["auto", "minio", "local"] = "auto"
    MINIO_ENDPOINT: str = ""
    MINIO_ACCESS_KEY: str = ""
    MINIO_SECRET_KEY: str = ""
    MINIO_BUCKET: str = "pr-campus-evidence"
    MINIO_SECURE: bool = False
    LOCAL_STORAGE_PATH: str = str(REPO_ROOT / "storage")

    MAX_UPLOAD_BYTES: int = 25 * 1024 * 1024
    ALLOWED_EVIDENCE_CONTENT_TYPES: str = (
        "image/png,image/jpeg,image/gif,image/webp,text/plain,text/html,"
        "application/json,application/xml,text/xml,application/pdf,text/csv"
    )

    # ------------------------------------------------------ enrichment APIs
    OFFLINE_MODE: bool = False
    NVD_API_KEY: str = ""
    NVD_API_BASE: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_TIMEOUT_SECONDS: int = 20
    SSL_LABS_API_KEY: str = ""
    SSL_LABS_API_BASE: str = "https://api.ssllabs.com/api/v3"
    ENRICHMENT_CACHE_TTL_HOURS: int = 24

    # ---------------------------------------------------------- scanners
    NMAP_PATH: str = "nmap"
    NUCLEI_PATH: str = "nuclei"
    WHATWEB_PATH: str = "whatweb"
    ZAP_API_URL: str = ""
    ZAP_API_KEY: str = ""
    SCANNER_TIMEOUT_SECONDS: int = 900
    HTTP_SCAN_TIMEOUT_SECONDS: int = 15

    # ------------------------------------------------------------- SLA (h)
    SLA_HOURS_CRITICAL: int = 24
    SLA_HOURS_HIGH: int = 72
    SLA_HOURS_MEDIUM: int = 168
    SLA_HOURS_LOW: int = 336
    SLA_HOURS_INFORMATIONAL: int = 720
    SLA_DUE_SOON_RATIO: float = 0.75

    # ------------------------------------------------------- AI triage (opt-in)
    # Entirely optional. With no key configured the feature reports itself as
    # unavailable, exactly as an uninstalled scanner does, and nothing else in
    # the platform changes behaviour.
    AI_TRIAGE_ENABLED: bool = True
    ANTHROPIC_API_KEY: str = ""
    AI_TRIAGE_MODEL: str = "claude-opus-5"
    # Triage is a bounded judgement an analyst still reviews, so the default
    # trades a little depth for cost; raise to "high" if suggestions look thin.
    AI_TRIAGE_EFFORT: Literal["low", "medium", "high", "xhigh", "max"] = "medium"
    AI_TRIAGE_TIMEOUT_SECONDS: int = 60
    AI_TRIAGE_CACHE_HOURS: int = 168

    # ------------------------------------------------- migrations on startup
    # For hosts with no release phase or shell access (Render's free tier),
    # apply migrations as the app boots. Off by default: where a proper
    # pre-deploy hook exists, that is the better place to run them.
    RUN_MIGRATIONS_ON_STARTUP: bool = False

    # ------------------------------------------------------------ demo mode
    DEMO_MODE: bool = True
    SEED_ON_STARTUP: bool = False

    # --------------------------------------------------------- validators
    @field_validator("JWT_SECRET")
    @classmethod
    def _validate_secret(cls, value: str, info) -> str:
        if value:
            return value
        env = (info.data or {}).get("ENVIRONMENT", "development")
        if env == "production":
            raise ValueError(
                "JWT_SECRET must be set via the environment in production. "
                "Generate one with: python -c \"import secrets;print(secrets.token_urlsafe(48))\""
            )
        # Ephemeral development secret: tokens simply do not survive a restart.
        return secrets.token_urlsafe(48)

    # --------------------------------------------------------- properties
    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def allowed_evidence_types(self) -> set[str]:
        return {t.strip() for t in self.ALLOWED_EVIDENCE_CONTENT_TYPES.split(",") if t.strip()}

    @property
    def broker_url(self) -> str:
        return self.CELERY_BROKER_URL or self.REDIS_URL

    @property
    def result_backend(self) -> str:
        return self.CELERY_RESULT_BACKEND or self.REDIS_URL

    @property
    def sla_hours(self) -> dict[str, int]:
        return {
            "CRITICAL": self.SLA_HOURS_CRITICAL,
            "HIGH": self.SLA_HOURS_HIGH,
            "MEDIUM": self.SLA_HOURS_MEDIUM,
            "LOW": self.SLA_HOURS_LOW,
            "INFORMATIONAL": self.SLA_HOURS_INFORMATIONAL,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
