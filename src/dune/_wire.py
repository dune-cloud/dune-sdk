# GENERATED FILE — do not edit by hand.
# Regenerate from dune-api/openapi.json with:
#   python scripts/generate_wire.py

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class CreateSandboxRequest(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    snapshot: constr(min_length=1) = Field(..., title='Snapshot')
    namespace: (
        constr(pattern=r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', max_length=32) | None
    ) = Field(
        None,
        description='Logical grouping bucket (stored as a label)',
        title='Namespace',
    )
    auto_delete_after_seconds: conint(le=604800, gt=0) | None = Field(
        3600, title='Auto Delete After Seconds'
    )
    network_blocklist: list[str] | None = Field(None, title='Network Blocklist')
    network_allowlist: list[str] | None = Field(None, title='Network Allowlist')


class ErrorResponse(BaseModel):
    code: str = Field(..., title='Code')
    message: str = Field(..., title='Message')


class ExtendSandboxRequest(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    seconds: conint(le=604800, gt=0) = Field(..., title='Seconds')


class FailureReason(StrEnum):
    deadline_exceeded = 'deadline_exceeded'
    evicted = 'evicted'
    oom_killed = 'oom_killed'
    pod_failed = 'pod_failed'
    container_terminated = 'container_terminated'
    startup_failed = 'startup_failed'


class NetworkMode(StrEnum):
    open = 'open'
    blocklist = 'blocklist'
    allowlist = 'allowlist'


class NetworkPolicyRequest(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    mode: NetworkMode
    cidrs: list[str] | None = Field(None, title='Cidrs')


class NetworkPolicyResponse(BaseModel):
    mode: NetworkMode
    cidrs: list[str] | None = Field(None, title='Cidrs')


class SandboxState(StrEnum):
    pending = 'pending'
    ready = 'ready'
    completed = 'completed'
    failed = 'failed'
    not_found = 'not_found'


class StatusRequest(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    ids: list[str] = Field(..., min_length=1, title='Ids')


class StatusResponse(BaseModel):
    states: dict[str, SandboxState] = Field(..., title='States')


class ValidationError(BaseModel):
    loc: list[str | int] = Field(..., title='Location')
    msg: str = Field(..., title='Message')
    type: str = Field(..., title='Error Type')
    input: Any | None = Field(None, title='Input')
    ctx: dict[str, Any] | None = Field(None, title='Context')


class BatchCreateSandboxRequest(BaseModel):
    model_config = ConfigDict(
        extra='forbid',
    )
    params: CreateSandboxRequest
    count: conint(ge=1) = Field(..., description='Number of sandboxes', title='Count')


class HTTPValidationError(BaseModel):
    detail: list[ValidationError] | None = Field(None, title='Detail')


class SandboxResponse(BaseModel):
    id: str = Field(..., title='Id')
    name: str = Field(..., title='Name')
    namespace: str = Field(..., title='Namespace')
    snapshot: str = Field(..., title='Snapshot')
    image: str = Field(..., title='Image')
    state: SandboxState
    created_at: str | None = Field(None, title='Created At')
    cpu: int = Field(..., title='Cpu')
    memory: int = Field(..., title='Memory')
    disk: int | None = Field(None, title='Disk')
    auto_delete_after_seconds: int | None = Field(
        None, title='Auto Delete After Seconds'
    )
    termination_reason: str | None = Field(None, title='Termination Reason')
    failure_reason: FailureReason | None = None
    app_oom: bool | None = Field(False, title='App Oom')


class BatchSandboxResponse(BaseModel):
    sandboxes: list[SandboxResponse] = Field(..., title='Sandboxes')


class SandboxListResponse(BaseModel):
    items: list[SandboxResponse] = Field(..., title='Items')
    next_cursor: str | None = Field(None, title='Next Cursor')
