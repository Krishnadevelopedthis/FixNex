from __future__ import annotations

from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UserBrief(ORMModel):
    id: int
    full_name: str
    email: str
    role: str


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
    pages: int

    @classmethod
    def build(cls, items: list[T], total: int, page: int, page_size: int) -> "Page[T]":
        pages = (total + page_size - 1) // page_size if page_size else 1
        return cls(items=items, total=total, page=page, page_size=page_size, pages=max(pages, 1))


class PaginationParams(BaseModel):
    page: int = Field(1, ge=1, le=1_000_000)
    page_size: int = Field(25, ge=1, le=200)

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


class MessageResponse(BaseModel):
    message: str
    detail: str | None = None


class CountByKey(BaseModel):
    key: str
    label: str | None = None
    count: int


class TimelineEvent(BaseModel):
    id: int
    event_type: str
    actor_name: str | None = None
    note: str | None = None
    from_status: str | None = None
    to_status: str | None = None
    metadata: dict = Field(default_factory=dict)
    created_at: datetime
