from __future__ import annotations

import asyncio
import io
import os
import tempfile
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from . import _ssh_wire, _wire
from ._codec import build_request, parse_response, to_payload
from ._models import (
    ExecResult,
    SandboxState,
    SSHAccess,
    SSHAccessValidation,
    exec_result_from_wire,
    exec_to_wire,
    ssh_access_from_wire,
    ssh_validation_from_wire,
)
from .errors import DuneConflictError, DuneValidationError

if TYPE_CHECKING:
    from ._http import AsyncHttpClient, SyncHttpClient


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


def _files_url(sid: str, action: str) -> str:
    return f"/v1/sandboxes/{sid}/files/{action}"


EXEC_GRACE = 5


def _exec_total(timeout: int | None) -> int | None:
    if timeout is not None and timeout <= 0:
        raise DuneValidationError("timeout must be a positive number of seconds, or None for no timeout")
    return timeout + EXEC_GRACE if timeout else None


def _ssh_create_body(expires_in_minutes: int | None, evict_oldest: bool) -> dict[str, Any]:
    return to_payload(
        build_request(
            _ssh_wire.SSHCreateRequest,
            expires_in_minutes=expires_in_minutes,
            evict_oldest=evict_oldest,
        )
    )


def _ssh_token_body(token: str) -> dict[str, Any]:
    return to_payload(build_request(_ssh_wire.SSHTokenRequest, token=token))


def _apply_wire(sb: Sandbox | AsyncSandbox, data: dict[str, Any]) -> None:
    m = parse_response(_wire.SandboxResponse, data)
    sb.state = SandboxState(m.state)


# --------------------------------------------------------------------------- #
# Process — command execution
# --------------------------------------------------------------------------- #


class _ProcessSync:
    def __init__(self, http: SyncHttpClient, sandbox_id: str) -> None:
        self._http = http
        self._sid = sandbox_id

    def exec(
        self,
        command: str,
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> ExecResult:
        body = exec_to_wire(command, cwd=cwd, env=env, timeout=timeout)
        data = self._http.post_json(
            f"/v1/sandboxes/{self._sid}/exec",
            body,
            timeout=_exec_total(timeout),
        )
        return exec_result_from_wire(data)


class _ProcessAsync:
    def __init__(self, http: AsyncHttpClient, sandbox_id: str) -> None:
        self._http = http
        self._sid = sandbox_id

    async def exec(
        self,
        command: str,
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> ExecResult:
        body = exec_to_wire(command, cwd=cwd, env=env, timeout=timeout)
        data = await self._http.post_json(
            f"/v1/sandboxes/{self._sid}/exec",
            body,
            timeout=_exec_total(timeout),
        )
        return exec_result_from_wire(data)


# --------------------------------------------------------------------------- #
# FileSystem — byte transfer
# --------------------------------------------------------------------------- #


_CHUNK = 1 << 20


def _file_chunks(f: Any) -> Iterator[bytes]:
    while chunk := f.read(_CHUNK):
        yield chunk


async def _afile_chunks(f: Any) -> AsyncIterator[bytes]:
    while chunk := await asyncio.to_thread(f.read, _CHUNK):
        yield chunk


def _bytes_chunks(data: bytes) -> Iterator[bytes]:
    for i in range(0, len(data), _CHUNK):
        yield data[i : i + _CHUNK]


async def _abytes_chunks(data: bytes) -> AsyncIterator[bytes]:
    for i in range(0, len(data), _CHUNK):
        yield data[i : i + _CHUNK]


def _open_dest(local_path: str, *, replace_if_exist: bool, create_parents: bool) -> tuple[int, str]:
    if not replace_if_exist and os.path.exists(local_path):
        raise DuneConflictError(f"local path {local_path!r} already exists (set replace_if_exist)")
    parent = os.path.dirname(local_path) or "."
    if create_parents:
        os.makedirs(parent, exist_ok=True)
    return tempfile.mkstemp(dir=parent)


def _unlink_quiet(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


class _FileSystemSync:
    def __init__(self, http: SyncHttpClient, sandbox_id: str) -> None:
        self._http = http
        self._sid = sandbox_id

    def _upload_params(self, path: str, replace_if_exist: bool, create_parents: bool) -> dict[str, Any]:
        return {
            "path": path,
            "replace_if_exist": replace_if_exist,
            "create_parents": create_parents,
        }

    def upload_bytes(
        self,
        data: bytes,
        remote_path: str,
        *,
        replace_if_exist: bool = True,
        create_parents: bool = True,
        timeout: int | None = None,
    ) -> None:
        self._http.request(
            "POST",
            _files_url(self._sid, "upload"),
            content=_bytes_chunks(data),
            content_type="application/octet-stream",
            params=self._upload_params(remote_path, replace_if_exist, create_parents),
            timeout=timeout,
        )

    def upload_file(
        self,
        local_path: str,
        remote_path: str,
        *,
        replace_if_exist: bool = True,
        create_parents: bool = True,
        timeout: int | None = None,
    ) -> None:
        with open(local_path, "rb") as f:
            self._http.request(
                "POST",
                _files_url(self._sid, "upload"),
                content=_file_chunks(f),
                content_type="application/octet-stream",
                params=self._upload_params(remote_path, replace_if_exist, create_parents),
                timeout=timeout,
            )

    def download_bytes(self, remote_path: str, *, timeout: int | None = None) -> bytes:
        buf = io.BytesIO()
        self._http.download_to(
            _files_url(self._sid, "download"),
            buf,
            params={"path": remote_path},
            timeout=timeout,
        )
        return buf.getvalue()

    def download_file(
        self,
        remote_path: str,
        local_path: str,
        *,
        replace_if_exist: bool = True,
        create_parents: bool = True,
        timeout: int | None = None,
    ) -> None:
        fd, tmp = _open_dest(local_path, replace_if_exist=replace_if_exist, create_parents=create_parents)
        try:
            with os.fdopen(fd, "wb") as f:
                self._http.download_to(
                    _files_url(self._sid, "download"),
                    f,
                    params={"path": remote_path},
                    timeout=timeout,
                )
            os.replace(tmp, local_path)
        except BaseException:
            _unlink_quiet(tmp)
            raise

    def read_text(self, remote_path: str, *, encoding: str = "utf-8", timeout: int | None = None) -> str:
        return self.download_bytes(remote_path, timeout=timeout).decode(encoding)

    def write_text(
        self,
        remote_path: str,
        content: str,
        *,
        encoding: str = "utf-8",
        replace_if_exist: bool = True,
        create_parents: bool = True,
        timeout: int | None = None,
    ) -> None:
        self.upload_bytes(
            content.encode(encoding), remote_path, replace_if_exist=replace_if_exist,
            create_parents=create_parents, timeout=timeout,
        )


class _FileSystemAsync:
    def __init__(self, http: AsyncHttpClient, sandbox_id: str) -> None:
        self._http = http
        self._sid = sandbox_id

    def _upload_params(self, path: str, replace_if_exist: bool, create_parents: bool) -> dict[str, Any]:
        return {
            "path": path,
            "replace_if_exist": replace_if_exist,
            "create_parents": create_parents,
        }

    async def upload_bytes(
        self,
        data: bytes,
        remote_path: str,
        *,
        replace_if_exist: bool = True,
        create_parents: bool = True,
        timeout: int | None = None,
    ) -> None:
        await self._http.request(
            "POST",
            _files_url(self._sid, "upload"),
            content=_abytes_chunks(data),
            content_type="application/octet-stream",
            params=self._upload_params(remote_path, replace_if_exist, create_parents),
            timeout=timeout,
        )

    async def upload_file(
        self,
        local_path: str,
        remote_path: str,
        *,
        replace_if_exist: bool = True,
        create_parents: bool = True,
        timeout: int | None = None,
    ) -> None:
        with open(local_path, "rb") as f:
            await self._http.request(
                "POST",
                _files_url(self._sid, "upload"),
                content=_afile_chunks(f),
                content_type="application/octet-stream",
                params=self._upload_params(remote_path, replace_if_exist, create_parents),
                timeout=timeout,
            )

    async def download_bytes(self, remote_path: str, *, timeout: int | None = None) -> bytes:
        buf = io.BytesIO()
        await self._http.download_to(
            _files_url(self._sid, "download"),
            buf,
            params={"path": remote_path},
            timeout=timeout,
        )
        return buf.getvalue()

    async def download_file(
        self,
        remote_path: str,
        local_path: str,
        *,
        replace_if_exist: bool = True,
        create_parents: bool = True,
        timeout: int | None = None,
    ) -> None:
        fd, tmp = _open_dest(local_path, replace_if_exist=replace_if_exist, create_parents=create_parents)
        try:
            with os.fdopen(fd, "wb") as f:
                await self._http.download_to(
                    _files_url(self._sid, "download"),
                    f,
                    params={"path": remote_path},
                    timeout=timeout,
                )
            os.replace(tmp, local_path)
        except BaseException:
            _unlink_quiet(tmp)
            raise

    async def read_text(self, remote_path: str, *, encoding: str = "utf-8", timeout: int | None = None) -> str:
        return (await self.download_bytes(remote_path, timeout=timeout)).decode(encoding)

    async def write_text(
        self,
        remote_path: str,
        content: str,
        *,
        encoding: str = "utf-8",
        replace_if_exist: bool = True,
        create_parents: bool = True,
        timeout: int | None = None,
    ) -> None:
        await self.upload_bytes(
            content.encode(encoding), remote_path, replace_if_exist=replace_if_exist,
            create_parents=create_parents, timeout=timeout,
        )


# --------------------------------------------------------------------------- #
# Sandbox handles
# --------------------------------------------------------------------------- #


@dataclass
class Sandbox:
    _http: SyncHttpClient
    _data_http: SyncHttpClient
    _ssh_http: SyncHttpClient
    id: str
    name: str
    namespace: str
    snapshot: str
    image: str
    state: SandboxState
    created_at: str | None = None
    cpu: int | None = None
    memory: int | None = None
    disk: int | None = None
    auto_delete_after_seconds: int | None = None

    process: _ProcessSync = field(init=False, repr=False, compare=False)
    fs: _FileSystemSync = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.process = _ProcessSync(self._data_http, self.id)
        self.fs = _FileSystemSync(self._data_http, self.id)

    def _refresh(self) -> None:
        data = self._http.get_json(f"/v1/sandboxes/{self.id}")
        _apply_wire(self, data)

    # ----- SSH access (always synchronous) ----------------------------------

    def create_ssh_access(
        self, expires_in_minutes: int | None = None, *, evict_oldest: bool = False
    ) -> SSHAccess:
        data = self._ssh_http.post_json(
            f"/v1/sandboxes/{self.id}/ssh", _ssh_create_body(expires_in_minutes, evict_oldest)
        )
        return ssh_access_from_wire(data)

    def validate_ssh_access(self, token: str) -> SSHAccessValidation:
        data = self._ssh_http.post_json(
            f"/v1/sandboxes/{self.id}/ssh/validate", _ssh_token_body(token)
        )
        return ssh_validation_from_wire(data)

    def revoke_ssh_access(self, token: str) -> None:
        self._ssh_http.post_json(f"/v1/sandboxes/{self.id}/ssh/revoke", _ssh_token_body(token))


@dataclass
class AsyncSandbox:
    _ahttp: AsyncHttpClient
    _http: SyncHttpClient
    _adata_http: AsyncHttpClient
    _ssh_http: SyncHttpClient
    id: str
    name: str
    namespace: str
    snapshot: str
    image: str
    state: SandboxState
    created_at: str | None = None
    cpu: int | None = None
    memory: int | None = None
    disk: int | None = None
    auto_delete_after_seconds: int | None = None

    process: _ProcessAsync = field(init=False, repr=False, compare=False)
    fs: _FileSystemAsync = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.process = _ProcessAsync(self._adata_http, self.id)
        self.fs = _FileSystemAsync(self._adata_http, self.id)

    async def _refresh(self) -> None:
        data = await self._ahttp.get_json(f"/v1/sandboxes/{self.id}")
        _apply_wire(self, data)

    # ----- SSH access (always synchronous) ----------------------------------

    def create_ssh_access(
        self, expires_in_minutes: int | None = None, *, evict_oldest: bool = False
    ) -> SSHAccess:
        data = self._ssh_http.post_json(
            f"/v1/sandboxes/{self.id}/ssh", _ssh_create_body(expires_in_minutes, evict_oldest)
        )
        return ssh_access_from_wire(data)

    def validate_ssh_access(self, token: str) -> SSHAccessValidation:
        data = self._ssh_http.post_json(
            f"/v1/sandboxes/{self.id}/ssh/validate", _ssh_token_body(token)
        )
        return ssh_validation_from_wire(data)

    def revoke_ssh_access(self, token: str) -> None:
        self._ssh_http.post_json(f"/v1/sandboxes/{self.id}/ssh/revoke", _ssh_token_body(token))


def sandbox_from_wire(
    http: SyncHttpClient, data_http: SyncHttpClient, ssh_http: SyncHttpClient, data: dict[str, Any]
) -> Sandbox:
    m = parse_response(_wire.SandboxResponse, data)
    return Sandbox(
        _http=http,
        _data_http=data_http,
        _ssh_http=ssh_http,
        id=m.id,
        name=m.name,
        namespace=m.namespace,
        snapshot=m.snapshot,
        image=m.image,
        state=SandboxState(m.state),
        created_at=m.created_at,
        cpu=m.cpu,
        memory=m.memory,
        disk=m.disk,
        auto_delete_after_seconds=m.auto_delete_after_seconds,
    )


def async_sandbox_from_wire(
    ahttp: AsyncHttpClient,
    http: SyncHttpClient,
    adata_http: AsyncHttpClient,
    ssh_http: SyncHttpClient,
    data: dict[str, Any],
) -> AsyncSandbox:
    m = parse_response(_wire.SandboxResponse, data)
    return AsyncSandbox(
        _ahttp=ahttp,
        _http=http,
        _adata_http=adata_http,
        _ssh_http=ssh_http,
        id=m.id,
        name=m.name,
        namespace=m.namespace,
        snapshot=m.snapshot,
        image=m.image,
        state=SandboxState(m.state),
        created_at=m.created_at,
        cpu=m.cpu,
        memory=m.memory,
        disk=m.disk,
        auto_delete_after_seconds=m.auto_delete_after_seconds,
    )
