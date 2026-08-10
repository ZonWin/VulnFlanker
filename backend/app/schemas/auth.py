from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=150)
    password: str = Field(..., min_length=1, max_length=1024)
    captcha_id: str | None = Field(default=None, max_length=128)
    captcha_answer: str | None = Field(default=None, max_length=32)


class SetupAdminRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=150)
    password: str = Field(..., min_length=8, max_length=1024)
    display_name: str | None = Field(default=None, max_length=255)
    captcha_id: str | None = Field(default=None, max_length=128)
    captcha_answer: str | None = Field(default=None, max_length=32)


class CaptchaOut(BaseModel):
    captcha_id: str
    image_base64: str
    expires_in: int


class CurrentUserOut(BaseModel):
    id: str
    username: str
    display_name: str | None = None
    is_superuser: bool


class LoginResponse(BaseModel):
    user: CurrentUserOut


class SetupStatusOut(BaseModel):
    needs_setup: bool
    has_active_superuser: bool


class AuthIpPenaltyOut(BaseModel):
    id: str
    ip_key: str
    last_ip_address: str
    level: int
    banned_until: datetime | None = None
    is_permanent: bool
    last_failure_at: datetime | None = None
    last_banned_at: datetime | None = None
    released_at: datetime | None = None
    released_by: str | None = None
    release_reason: str | None = None
    updated_at: datetime


class AuthIpPenaltyReleaseRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)
