"""Pydantic request schemas (responses are plain dicts produced by the hybrid engine)."""
from pydantic import BaseModel, Field, field_validator

from config import settings


class UrlRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=settings.max_url_length, description="URL to analyse (never fetched)")

    @field_validator("url")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class EmailRequest(BaseModel):
    subject: str = Field("", max_length=500)
    body: str = Field(..., min_length=1, max_length=settings.max_email_chars)
    sender: str | None = Field(None, max_length=320)

    @field_validator("body")
    @classmethod
    def _body(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Email body must not be empty.")
        return v
