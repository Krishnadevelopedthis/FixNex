from __future__ import annotations

from pydantic import BaseModel, Field


class ComponentHealth(BaseModel):
    name: str
    label: str
    kind: str           # database | cache | storage | scanner | worker
    available: bool
    detail: str
    version: str | None = None
    required: bool = False


class SystemHealthResponse(BaseModel):
    healthy: bool
    degraded_components: list[str] = Field(default_factory=list)
    components: list[ComponentHealth] = Field(default_factory=list)
    task_runner: str
    storage_backend: str
    offline_mode: bool
    demo_mode: bool
    version: str


class SLASettings(BaseModel):
    CRITICAL: int = Field(ge=1, le=8760)
    HIGH: int = Field(ge=1, le=8760)
    MEDIUM: int = Field(ge=1, le=8760)
    LOW: int = Field(ge=1, le=8760)
    INFORMATIONAL: int = Field(ge=1, le=8760)
