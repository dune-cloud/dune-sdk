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


class SessionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: constr(min_length=1, max_length=64) = Field(..., title="Session Id")
    cwd: str | None = Field(None, title="Cwd")
    env: dict[str, str] | None = Field(None, title="Env")


class SessionExecRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: constr(min_length=1) = Field(..., title="Command")
    merge_stderr: bool | None = Field(None, title="Merge Stderr")


class SessionExecResponse(BaseModel):
    cmd_id: str = Field(..., title="Cmd Id")


class SessionCommandModel(BaseModel):
    id: str = Field(..., title="Id")
    command: str = Field("", title="Command")
    exit_code: int | None = Field(None, title="Exit Code")
    merge_stderr: bool = Field(False, title="Merge Stderr")
    submitted_at: str | None = Field(None, title="Submitted At")
    started_at: str | None = Field(None, title="Started At")
    ended_at: str | None = Field(None, title="Ended At")
    stdout_size: int = Field(0, title="Stdout Size")
    stderr_size: int = Field(0, title="Stderr Size")


class SessionModel(BaseModel):
    session_id: str = Field(..., title="Session Id")
    created_at: str | None = Field(None, title="Created At")
    alive: bool = Field(True, title="Alive")
    pid: int | None = Field(None, title="Pid")
    cwd: str | None = Field(None, title="Cwd")
    command_count: int = Field(0, title="Command Count")
    exit_status: str | None = Field(None, title="Exit Status")
    commands: list[SessionCommandModel] = Field(default_factory=list, title="Commands")


class SessionListResponse(BaseModel):
    sessions: list[SessionModel] = Field(default_factory=list, title="Sessions")
