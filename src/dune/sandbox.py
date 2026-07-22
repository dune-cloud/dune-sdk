from __future__ import annotations

import asyncio
import io
import os
import tempfile
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Literal

from . import _ssh_wire, _wire
from ._codec import build_request, parse_response, to_payload
from ._models import (
    ExecResult,
    FailureReason,
    SandboxState,
    SessionCommand,
    SessionExecResult,
    SessionInfo,
    SSHAccess,
    SSHAccessValidation,
    exec_result_from_wire,
    exec_to_wire,
    session_cmd_id_from_wire,
    session_command_from_wire,
    session_create_to_wire,
    session_exec_to_wire,
    session_info_from_wire,
    session_list_from_wire,
    ssh_access_from_wire,
    ssh_validation_from_wire,
)
from .errors import (
    DuneConflictError,
    DuneConnectionError,
    DuneTimeoutError,
    DuneValidationError,
)

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


_WAIT_CHUNK = 30
_LOG_POLL = 0.2

Stream = Literal["stdout", "stderr"]


def _sessions_url(sid: str, tail: str = "") -> str:
    return f"/v1/sandboxes/{sid}/sessions{tail}"


def _cid(cmd: SessionCommand | str) -> str:
    return cmd.id if isinstance(cmd, SessionCommand) else cmd


def _new_session_id() -> str:
    return uuid.uuid4().hex


def _decode(data: bytes) -> str:
    return data.decode("utf-8", "replace")


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
    sb.termination_reason = m.termination_reason
    sb.failure_reason = FailureReason(m.failure_reason) if m.failure_reason else None
    sb.app_oom = m.app_oom
    sb.auto_delete_after_seconds = m.auto_delete_after_seconds


def _deadline_far_enough(sb: Sandbox | AsyncSandbox) -> bool:
    if not sb.created_at or not sb.auto_delete_after_seconds:
        return False
    deadline = datetime.fromisoformat(sb.created_at) + timedelta(
        seconds=sb.auto_delete_after_seconds
    )
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    margin = timedelta(seconds=sb.auto_extend_seconds or 0)
    return deadline >= datetime.now(timezone.utc) + margin


# --------------------------------------------------------------------------- #
# Process — command execution
# --------------------------------------------------------------------------- #


class _ProcessSync:
    def __init__(self, http: SyncHttpClient, sandbox_id: str, keepalive: Any) -> None:
        self._http = http
        self._sid = sandbox_id
        self._keepalive = keepalive

    def exec(
        self,
        command: str,
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> ExecResult:
        self._keepalive()
        body = exec_to_wire(command, cwd=cwd, env=env, timeout=timeout)
        data = self._http.post_json(
            f"/v1/sandboxes/{self._sid}/exec",
            body,
            timeout=_exec_total(timeout),
        )
        return exec_result_from_wire(data)

    def create_session(
        self,
        session_id: str | None = None,
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> _SessionSync:
        self._keepalive()
        sid = session_id or _new_session_id()
        self._http.post_json(
            _sessions_url(self._sid), session_create_to_wire(sid, cwd=cwd, env=env)
        )
        return _SessionSync(self._http, self._sid, sid, self._keepalive)

    def session(self, session_id: str) -> _SessionSync:
        return _SessionSync(self._http, self._sid, session_id, self._keepalive)

    def sessions(self) -> list[SessionInfo]:
        self._keepalive()
        return session_list_from_wire(self._http.get_json(_sessions_url(self._sid)))


class _ProcessAsync:
    def __init__(self, http: AsyncHttpClient, sandbox_id: str, keepalive: Any) -> None:
        self._http = http
        self._sid = sandbox_id
        self._keepalive = keepalive

    async def exec(
        self,
        command: str,
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> ExecResult:
        await self._keepalive()
        body = exec_to_wire(command, cwd=cwd, env=env, timeout=timeout)
        data = await self._http.post_json(
            f"/v1/sandboxes/{self._sid}/exec",
            body,
            timeout=_exec_total(timeout),
        )
        return exec_result_from_wire(data)

    async def create_session(
        self,
        session_id: str | None = None,
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> _SessionAsync:
        await self._keepalive()
        sid = session_id or _new_session_id()
        await self._http.post_json(
            _sessions_url(self._sid), session_create_to_wire(sid, cwd=cwd, env=env)
        )
        return _SessionAsync(self._http, self._sid, sid, self._keepalive)

    def session(self, session_id: str) -> _SessionAsync:
        return _SessionAsync(self._http, self._sid, session_id, self._keepalive)

    async def sessions(self) -> list[SessionInfo]:
        await self._keepalive()
        return session_list_from_wire(await self._http.get_json(_sessions_url(self._sid)))


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
    def __init__(self, http: SyncHttpClient, sandbox_id: str, keepalive: Any) -> None:
        self._http = http
        self._sid = sandbox_id
        self._keepalive = keepalive

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
        self._keepalive()
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
        self._keepalive()
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
        self._keepalive()
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
                self._keepalive()
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
    def __init__(self, http: AsyncHttpClient, sandbox_id: str, keepalive: Any) -> None:
        self._http = http
        self._sid = sandbox_id
        self._keepalive = keepalive

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
        await self._keepalive()
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
        await self._keepalive()
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
        await self._keepalive()
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
                await self._keepalive()
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
# Sessions
# --------------------------------------------------------------------------- #


class _SessionSync:
    def __init__(self, http: SyncHttpClient, sandbox_id: str, session_id: str, keepalive: Any) -> None:
        self._http = http
        self._sid = sandbox_id
        self.id = session_id
        self._keepalive = keepalive

    def __enter__(self) -> _SessionSync:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.delete()

    def _url(self, tail: str = "") -> str:
        return _sessions_url(self._sid, f"/{self.id}{tail}")

    def exec_async(self, command: str, *, merge_stderr: bool = False) -> SessionCommand:
        self._keepalive()
        data = self._http.post_json(
            self._url("/exec"), session_exec_to_wire(command, merge_stderr=merge_stderr)
        )
        return SessionCommand(
            id=session_cmd_id_from_wire(data), command=command, merge_stderr=merge_stderr
        )

    def exec(
        self,
        command: str,
        *,
        wait_timeout: int | None = None,
        merge_stderr: bool = False,
    ) -> SessionExecResult:
        cmd = self.exec_async(command, merge_stderr=merge_stderr)
        rec = self.wait(cmd, timeout=wait_timeout)
        stdout = _decode(self.logs(rec, "stdout")) if rec.stdout_size else ""
        stderr = "" if rec.merge_stderr or not rec.stderr_size else _decode(self.logs(rec, "stderr"))
        return SessionExecResult(
            cmd_id=rec.id, exit_code=rec.exit_code, stdout=stdout, stderr=stderr
        )

    def command(self, cmd: SessionCommand | str) -> SessionCommand:
        self._keepalive()
        return session_command_from_wire(self._http.get_json(self._url(f"/commands/{_cid(cmd)}")))

    def wait(self, cmd: SessionCommand | str, *, timeout: int | None = None) -> SessionCommand:
        cid = _cid(cmd)
        deadline = time.monotonic() + timeout if timeout else None
        while True:
            remaining = (deadline - time.monotonic()) if deadline is not None else None
            if remaining is not None and remaining <= 0:
                raise DuneTimeoutError(f"command {cid} is still running", pending=[cid])
            chunk = _WAIT_CHUNK if remaining is None else max(1, min(_WAIT_CHUNK, int(remaining)))
            self._keepalive()
            try:
                data = self._http.get_json(
                    self._url(f"/commands/{cid}"),
                    params={"wait": 1, "wait_timeout_seconds": chunk},
                    timeout=chunk + EXEC_GRACE,
                )
            except (DuneTimeoutError, DuneConnectionError):
                continue
            rec = session_command_from_wire(data)
            if rec.finished:
                return rec

    def logs(self, cmd: SessionCommand | str, stream: Stream = "stdout", *, offset: int = 0) -> bytes:
        self._keepalive()
        resp = self._http.request(
            "GET",
            self._url(f"/commands/{_cid(cmd)}/logs"),
            params={"stream": stream, "offset": offset},
        )
        return resp.data

    def stream_logs(
        self, cmd: SessionCommand | str, stream: Stream = "stdout", *, poll: float = _LOG_POLL
    ) -> Iterator[bytes]:
        cid = _cid(cmd)
        offset = 0
        while True:
            chunk = self.logs(cid, stream, offset=offset)
            if chunk:
                offset += len(chunk)
                yield chunk
                continue
            if self.command(cid).finished:
                tail = self.logs(cid, stream, offset=offset)
                if not tail:
                    return
                offset += len(tail)
                yield tail
                continue
            time.sleep(poll)

    def info(self) -> SessionInfo:
        self._keepalive()
        return session_info_from_wire(self._http.get_json(self._url()))

    def delete(self) -> None:
        self._http.delete(self._url())


class _SessionAsync:
    def __init__(self, http: AsyncHttpClient, sandbox_id: str, session_id: str, keepalive: Any) -> None:
        self._http = http
        self._sid = sandbox_id
        self.id = session_id
        self._keepalive = keepalive

    async def __aenter__(self) -> _SessionAsync:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.delete()

    def _url(self, tail: str = "") -> str:
        return _sessions_url(self._sid, f"/{self.id}{tail}")

    async def exec_async(self, command: str, *, merge_stderr: bool = False) -> SessionCommand:
        await self._keepalive()
        data = await self._http.post_json(
            self._url("/exec"), session_exec_to_wire(command, merge_stderr=merge_stderr)
        )
        return SessionCommand(
            id=session_cmd_id_from_wire(data), command=command, merge_stderr=merge_stderr
        )

    async def exec(
        self,
        command: str,
        *,
        wait_timeout: int | None = None,
        merge_stderr: bool = False,
    ) -> SessionExecResult:
        cmd = await self.exec_async(command, merge_stderr=merge_stderr)
        rec = await self.wait(cmd, timeout=wait_timeout)
        stdout = _decode(await self.logs(rec, "stdout")) if rec.stdout_size else ""
        stderr = (
            "" if rec.merge_stderr or not rec.stderr_size else _decode(await self.logs(rec, "stderr"))
        )
        return SessionExecResult(
            cmd_id=rec.id, exit_code=rec.exit_code, stdout=stdout, stderr=stderr
        )

    async def command(self, cmd: SessionCommand | str) -> SessionCommand:
        await self._keepalive()
        return session_command_from_wire(
            await self._http.get_json(self._url(f"/commands/{_cid(cmd)}"))
        )

    async def wait(self, cmd: SessionCommand | str, *, timeout: int | None = None) -> SessionCommand:
        cid = _cid(cmd)
        deadline = time.monotonic() + timeout if timeout else None
        while True:
            remaining = (deadline - time.monotonic()) if deadline is not None else None
            if remaining is not None and remaining <= 0:
                raise DuneTimeoutError(f"command {cid} is still running", pending=[cid])
            chunk = _WAIT_CHUNK if remaining is None else max(1, min(_WAIT_CHUNK, int(remaining)))
            await self._keepalive()
            try:
                data = await self._http.get_json(
                    self._url(f"/commands/{cid}"),
                    params={"wait": 1, "wait_timeout_seconds": chunk},
                    timeout=chunk + EXEC_GRACE,
                )
            except (DuneTimeoutError, DuneConnectionError):
                continue
            rec = session_command_from_wire(data)
            if rec.finished:
                return rec

    async def logs(
        self, cmd: SessionCommand | str, stream: Stream = "stdout", *, offset: int = 0
    ) -> bytes:
        await self._keepalive()
        resp = await self._http.request(
            "GET",
            self._url(f"/commands/{_cid(cmd)}/logs"),
            params={"stream": stream, "offset": offset},
        )
        return resp.data

    async def stream_logs(
        self, cmd: SessionCommand | str, stream: Stream = "stdout", *, poll: float = _LOG_POLL
    ) -> AsyncIterator[bytes]:
        cid = _cid(cmd)
        offset = 0
        while True:
            chunk = await self.logs(cid, stream, offset=offset)
            if chunk:
                offset += len(chunk)
                yield chunk
                continue
            if (await self.command(cid)).finished:
                tail = await self.logs(cid, stream, offset=offset)
                if not tail:
                    return
                offset += len(tail)
                yield tail
                continue
            await asyncio.sleep(poll)

    async def info(self) -> SessionInfo:
        await self._keepalive()
        return session_info_from_wire(await self._http.get_json(self._url()))

    async def delete(self) -> None:
        await self._http.delete(self._url())


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
    termination_reason: str | None = None
    failure_reason: FailureReason | None = None
    app_oom: bool = False
    auto_extend_seconds: int | None = None

    process: _ProcessSync = field(init=False, repr=False, compare=False)
    fs: _FileSystemSync = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.process = _ProcessSync(self._data_http, self.id, self._keepalive)
        self.fs = _FileSystemSync(self._data_http, self.id, self._keepalive)

    def refresh(self) -> None:
        data = self._http.get_json(f"/v1/sandboxes/{self.id}")
        _apply_wire(self, data)

    def extend(self, seconds: int) -> None:
        data = self._http.post_json(f"/v1/sandboxes/{self.id}/extend", {"seconds": seconds})
        _apply_wire(self, data)

    def _keepalive(self) -> None:
        if self.auto_extend_seconds is None or _deadline_far_enough(self):
            return
        self.extend(self.auto_extend_seconds)

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
    termination_reason: str | None = None
    failure_reason: FailureReason | None = None
    app_oom: bool = False
    auto_extend_seconds: int | None = None

    process: _ProcessAsync = field(init=False, repr=False, compare=False)
    fs: _FileSystemAsync = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.process = _ProcessAsync(self._adata_http, self.id, self._keepalive)
        self.fs = _FileSystemAsync(self._adata_http, self.id, self._keepalive)

    async def refresh(self) -> None:
        data = await self._ahttp.get_json(f"/v1/sandboxes/{self.id}")
        _apply_wire(self, data)

    async def extend(self, seconds: int) -> None:
        data = await self._ahttp.post_json(f"/v1/sandboxes/{self.id}/extend", {"seconds": seconds})
        _apply_wire(self, data)

    async def _keepalive(self) -> None:
        if self.auto_extend_seconds is None or _deadline_far_enough(self):
            return
        await self.extend(self.auto_extend_seconds)

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
        termination_reason=m.termination_reason,
        failure_reason=FailureReason(m.failure_reason) if m.failure_reason else None,
        app_oom=m.app_oom,
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
        termination_reason=m.termination_reason,
        failure_reason=FailureReason(m.failure_reason) if m.failure_reason else None,
        app_oom=m.app_oom,
    )
