from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, PositiveInt


class SSHCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expires_in_minutes: PositiveInt | None = Field(None, title="Expires In Minutes")
    evict_oldest: bool = Field(False, title="Evict Oldest")


class SSHTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(..., title="Token")


class SSHAccessResponse(BaseModel):
    token: str = Field(..., title="Token")
    gateway_url: str = Field(..., title="Gateway Url")
    username: str = Field(..., title="Username")
    expires_at: str | None = Field(None, title="Expires At")
    sandbox_id: str | None = Field(None, title="Sandbox Id")


class SSHValidationResponse(BaseModel):
    valid: bool = Field(..., title="Valid")
    sandbox_id: str | None = Field(None, title="Sandbox Id")
