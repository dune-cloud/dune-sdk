from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class ExecRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: constr(min_length=1) = Field(..., title="Command")
    cwd: str | None = Field(None, title="Cwd")
    env: dict[str, str] | None = Field(None, title="Env")
    timeout_seconds: conint(ge=0) | None = Field(None, title="Timeout Seconds")


class ExecResultResponse(BaseModel):
    exit_code: int = Field(..., title="Exit Code")
    stdout: str | None = Field("", title="Stdout")
    stderr: str | None = Field("", title="Stderr")
    duration_ms: int | None = Field(0, title="Duration Ms")
