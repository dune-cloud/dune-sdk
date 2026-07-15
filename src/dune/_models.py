from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pydantic import TypeAdapter, ValidationError

from . import _daemon_wire, _ssh_wire, _wire
from ._codec import build_request, parse_response, to_payload
from .errors import DuneValidationError

_namespace_adapter = TypeAdapter(_wire.CreateSandboxRequest.model_fields["namespace"].annotation)
_NAMESPACE_MAX_LEN = next(
    s["maxLength"] for s in _namespace_adapter.json_schema()["anyOf"] if s["type"] == "string"
)


def validate_namespace(namespace: str | None) -> None:
    try:
        _namespace_adapter.validate_python(namespace)
    except ValidationError as exc:
        raise DuneValidationError(
            f"invalid namespace {namespace!r}: must be 1-{_NAMESPACE_MAX_LEN} characters of "
            "lowercase letters, digits and '-', starting and ending with a letter or digit"
        ) from exc


def validate_public_cidrs(cidrs: Iterable[str]) -> None:
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError as exc:
            raise DuneValidationError(f"invalid IP/CIDR: {c!r}") from exc
        if not net.is_global:
            raise DuneValidationError(
                f"{c!r} is not a public IP/CIDR; block/allow lists govern public "
                "destinations only (private/cluster ranges are always denied)"
            )


class SandboxState(StrEnum):
    PENDING = "PENDING"
    STARTED = "STARTED"
    ERROR = "ERROR"
    DELETED = "DELETED"


@dataclass
class SandboxParams:
    snapshot: str
    namespace: str | None = None
    auto_delete_after_seconds: int | None = None
    network_blocklist: list[str] | None = None
    network_allowlist: list[str] | None = None

    def __post_init__(self) -> None:
        if not self.snapshot:
            raise DuneValidationError("SandboxParams.snapshot is required")
        validate_namespace(self.namespace)
        if self.network_blocklist is not None and self.network_allowlist is not None:
            raise DuneValidationError(
                "network_blocklist and network_allowlist are mutually exclusive"
            )
        if self.network_blocklist is not None:
            validate_public_cidrs(self.network_blocklist)
        if self.network_allowlist is not None:
            validate_public_cidrs(self.network_allowlist)

    def to_wire(self) -> dict[str, Any]:
        req = build_request(
            _wire.CreateSandboxRequest,
            snapshot=self.snapshot,
            namespace=self.namespace,
            auto_delete_after_seconds=self.auto_delete_after_seconds,
            network_blocklist=self.network_blocklist,
            network_allowlist=self.network_allowlist,
        )
        return to_payload(req)


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int


@dataclass
class SSHAccess:
    token: str = field(repr=False)
    gateway_url: str
    username: str
    expires_at: str | None = None
    sandbox_id: str | None = None


@dataclass
class SSHAccessValidation:
    valid: bool
    sandbox_id: str | None = None


class NetworkMode(StrEnum):
    OPEN = "open"            # no restriction (default)
    BLOCKLIST = "blocklist"  # allow all public except the listed CIDRs
    ALLOWLIST = "allowlist"  # deny all public except the listed CIDRs


@dataclass
class NetworkPolicy:
    mode: NetworkMode
    cidrs: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Wire codecs — pure, transport-agnostic
# --------------------------------------------------------------------------- #


def exec_to_wire(
    command: str,
    *,
    cwd: str | None,
    env: dict[str, str] | None,
    timeout: float | None,
) -> dict[str, Any]:
    req = build_request(
        _daemon_wire.ExecRequest,
        command=command,
        cwd=cwd,
        env=env,
        timeout_seconds=int(timeout) if timeout is not None else None,
    )
    return to_payload(req)


def exec_result_from_wire(data: dict[str, Any]) -> ExecResult:
    m = parse_response(_daemon_wire.ExecResultResponse, data)
    return ExecResult(
        exit_code=m.exit_code,
        stdout=m.stdout or "",
        stderr=m.stderr or "",
        duration_ms=m.duration_ms or 0,
    )


def ssh_access_from_wire(data: dict[str, Any]) -> SSHAccess:
    m = parse_response(_ssh_wire.SSHAccessResponse, data)
    return SSHAccess(
        token=m.token,
        gateway_url=m.gateway_url,
        username=m.username,
        expires_at=m.expires_at,
        sandbox_id=m.sandbox_id,
    )


def ssh_validation_from_wire(data: dict[str, Any]) -> SSHAccessValidation:
    m = parse_response(_ssh_wire.SSHValidationResponse, data)
    return SSHAccessValidation(valid=m.valid, sandbox_id=m.sandbox_id)


def network_policy_to_wire(mode: NetworkMode, cidrs: list[str]) -> dict[str, Any]:
    if mode is not NetworkMode.OPEN:
        validate_public_cidrs(cidrs)
    req = build_request(_wire.NetworkPolicyRequest, mode=_wire.NetworkMode(mode.value), cidrs=cidrs)
    return to_payload(req)


def network_policy_from_wire(data: dict[str, Any]) -> NetworkPolicy:
    m = parse_response(_wire.NetworkPolicyResponse, data)
    return NetworkPolicy(mode=NetworkMode(m.mode.value), cidrs=list(m.cidrs or []))
