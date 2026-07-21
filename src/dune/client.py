from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable, Sequence
from dataclasses import replace
from typing import Any

from ._http import AsyncHttpClient, SyncHttpClient
from ._models import (
    NetworkMode,
    NetworkPolicy,
    SandboxParams,
    SandboxState,
    network_policy_from_wire,
    network_policy_to_wire,
)
from .config import DuneConfig
from .errors import DuneError, DuneNotFoundError, DuneTimeoutError, DuneValidationError
from .sandbox import (
    AsyncSandbox,
    Sandbox,
    async_sandbox_from_wire,
    sandbox_from_wire,
)

__all__ = ("Dune", "DuneAsync")

_TERMINAL_FAILURE_STATES = {SandboxState.FAILED, SandboxState.COMPLETED, SandboxState.NOT_FOUND}
_LIVE_STATES = {SandboxState.PENDING, SandboxState.READY}

# Fixed interval between readiness polls in create()/batch_create().
_POLL_INTERVAL = 0.5


def _apply_namespace(params: SandboxParams, default_ns: str | None) -> SandboxParams:
    return replace(params, namespace=params.namespace or default_ns)


def _terminal_error_sync(http: SyncHttpClient, sid: str, state: SandboxState) -> DuneError:
    reason = None
    try:
        reason = http.get_json(f"/v1/sandboxes/{sid}").get("termination_reason")
    except DuneError:
        pass
    detail = f": {reason}" if reason else ""
    return DuneError(f"sandbox {sid} reached terminal state {state.value} before ready{detail}")


async def _terminal_error_async(ahttp: AsyncHttpClient, sid: str, state: SandboxState) -> DuneError:
    reason = None
    try:
        reason = (await ahttp.get_json(f"/v1/sandboxes/{sid}")).get("termination_reason")
    except DuneError:
        pass
    detail = f": {reason}" if reason else ""
    return DuneError(f"sandbox {sid} reached terminal state {state.value} before ready{detail}")


def _wait_ready_sync(sandboxes: Sequence[Sandbox], timeout: int | None) -> None:
    if not sandboxes:
        return
    deadline = time.monotonic() + timeout if timeout else None
    http = sandboxes[0]._http
    pending = {sb.id: sb for sb in sandboxes}
    while pending:
        states = http.post_json("/v1/sandboxes/status", {"ids": list(pending)})["states"]
        for sid, sb in list(pending.items()):
            sb.state = SandboxState(states.get(sid, SandboxState.PENDING.value))
            if sb.state == SandboxState.READY:
                del pending[sid]
            elif sb.state in _TERMINAL_FAILURE_STATES:
                raise _terminal_error_sync(http, sid, sb.state)
        if not pending:
            return
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DuneTimeoutError(
                    f"{len(pending)} sandbox(es) did not reach ready within {timeout}s",
                    pending=list(pending),
                )
            time.sleep(min(_POLL_INTERVAL, remaining))
        else:
            time.sleep(_POLL_INTERVAL)


async def _wait_ready_async(sandboxes: Sequence[AsyncSandbox]) -> None:
    if not sandboxes:
        return
    ahttp = sandboxes[0]._ahttp
    pending = {sb.id: sb for sb in sandboxes}
    while pending:
        data = await ahttp.post_json("/v1/sandboxes/status", {"ids": list(pending)})
        states = data["states"]
        for sid, sb in list(pending.items()):
            sb.state = SandboxState(states.get(sid, SandboxState.PENDING.value))
            if sb.state == SandboxState.READY:
                del pending[sid]
            elif sb.state in _TERMINAL_FAILURE_STATES:
                raise await _terminal_error_async(ahttp, sid, sb.state)
        if pending:
            await asyncio.sleep(_POLL_INTERVAL)


# --------------------------------------------------------------------------- #
# Network namespace — synchronous on both clients
# --------------------------------------------------------------------------- #


class _NetworkNamespace:
    def __init__(self, http: SyncHttpClient, namespace: str | None) -> None:
        self._http = http
        self._ns = namespace

    def set_blocklist(self, cidrs: Iterable[str]) -> None:
        self._set(NetworkMode.BLOCKLIST, list(cidrs))

    def set_allowlist(self, cidrs: Iterable[str]) -> None:
        self._set(NetworkMode.ALLOWLIST, list(cidrs))

    def clear(self) -> None:
        self._set(NetworkMode.OPEN, [])

    def get_policy(self) -> NetworkPolicy:
        data = self._http.get_json("/v1/network/policy", params={"namespace": self._ns})
        return network_policy_from_wire(data)

    def _set(self, mode: NetworkMode, cidrs: list[str]) -> None:
        self._http.put_json(
            "/v1/network/policy",
            network_policy_to_wire(mode, cidrs),
            params={"namespace": self._ns},
        )


# --------------------------------------------------------------------------- #
# Sandbox namespace — synchronous
# --------------------------------------------------------------------------- #


class _SyncSandboxNamespace:
    def __init__(
        self,
        http: SyncHttpClient,
        data_http: SyncHttpClient,
        ssh_http: SyncHttpClient,
        default_ns: str | None,
    ) -> None:
        self._http = http
        self._data_http = data_http
        self._ssh_http = ssh_http
        self._ns = default_ns

    def create(
        self,
        params: SandboxParams,
        *,
        auto_extend_seconds: int | None = None,
        timeout: int | None = 120,
    ) -> Sandbox:
        if timeout is not None and timeout < 0:
            raise DuneValidationError("timeout must be non-negative")
        eff = _apply_namespace(params, self._ns)
        sb = sandbox_from_wire(
            self._http,
            self._data_http,
            self._ssh_http,
            self._http.post_json("/v1/sandboxes", eff.to_wire()),
        )
        sb.auto_extend_seconds = auto_extend_seconds
        if timeout == 0:
            return sb
        try:
            _wait_ready_sync([sb], timeout)
        except BaseException:
            self._safe_delete(sb)
            raise
        return sb

    def batch_create(
        self,
        params: SandboxParams,
        count: int,
        *,
        auto_extend_seconds: int | None = None,
        timeout: int | None = 120,
    ) -> list[Sandbox]:
        if timeout is not None and timeout < 0:
            raise DuneValidationError("timeout must be non-negative")
        eff = _apply_namespace(params, self._ns)
        data = self._http.post_json(
            "/v1/sandboxes/batch", {"params": eff.to_wire(), "count": count}
        )
        sandboxes = [
            sandbox_from_wire(self._http, self._data_http, self._ssh_http, d)
            for d in _batch_items(data)
        ]
        for sb in sandboxes:
            sb.auto_extend_seconds = auto_extend_seconds
        if len(sandboxes) != count:
            self._safe_delete_all(sandboxes)
            raise DuneError(f"service returned {len(sandboxes)} sandboxes for count={count}")
        if timeout == 0:
            return sandboxes
        try:
            _wait_ready_sync(sandboxes, timeout)
        except BaseException:
            self._safe_delete_all(sandboxes)
            raise
        return sandboxes

    def get(self, sandbox: Sandbox | str) -> Sandbox:
        data = self._http.get_json(f"/v1/sandboxes/{_sid(sandbox)}")
        return sandbox_from_wire(self._http, self._data_http, self._ssh_http, data)

    def extend(self, sandbox: Sandbox | str, seconds: int) -> Sandbox:
        data = self._http.post_json(
            f"/v1/sandboxes/{_sid(sandbox)}/extend", {"seconds": seconds}
        )
        return sandbox_from_wire(self._http, self._data_http, self._ssh_http, data)

    def delete(self, sandbox: Sandbox | str) -> None:
        sid = _sid(sandbox)
        try:
            self._http.delete(f"/v1/sandboxes/{sid}")
        except DuneNotFoundError:
            pass
        if isinstance(sandbox, Sandbox):
            sandbox.state = SandboxState.COMPLETED

    def list(self) -> list[Sandbox]:
        out: list[Sandbox] = []
        for data in _list_pages(self._http, self._ns):
            sb = sandbox_from_wire(self._http, self._data_http, self._ssh_http, data)
            if sb.state in _LIVE_STATES:
                out.append(sb)
        return out

    def _safe_delete(self, sandbox: Sandbox) -> None:
        try:
            self.delete(sandbox)
        except DuneError:
            pass

    def _safe_delete_all(self, sandboxes: Iterable[Sandbox]) -> None:
        for sb in sandboxes:
            self._safe_delete(sb)


class _AsyncSandboxNamespace:
    def __init__(
        self,
        ahttp: AsyncHttpClient,
        http: SyncHttpClient,
        adata_http: AsyncHttpClient,
        ssh_http: SyncHttpClient,
        default_ns: str | None,
    ) -> None:
        self._ahttp = ahttp
        self._http = http
        self._adata_http = adata_http
        self._ssh_http = ssh_http
        self._ns = default_ns

    async def create(
        self, params: SandboxParams, *, auto_extend_seconds: int | None = None
    ) -> AsyncSandbox:
        eff = _apply_namespace(params, self._ns)
        data = await self._ahttp.post_json("/v1/sandboxes", eff.to_wire())
        sb = async_sandbox_from_wire(self._ahttp, self._http, self._adata_http, self._ssh_http, data)
        sb.auto_extend_seconds = auto_extend_seconds
        try:
            await _wait_ready_async([sb])
        except BaseException:
            await asyncio.shield(self._safe_delete_all([sb]))
            raise
        return sb

    async def batch_create(
        self, params: SandboxParams, count: int, *, auto_extend_seconds: int | None = None
    ) -> list[AsyncSandbox]:
        eff = _apply_namespace(params, self._ns)
        data = await self._ahttp.post_json(
            "/v1/sandboxes/batch", {"params": eff.to_wire(), "count": count}
        )
        sandboxes = [
            async_sandbox_from_wire(self._ahttp, self._http, self._adata_http, self._ssh_http, d)
            for d in _batch_items(data)
        ]
        for sb in sandboxes:
            sb.auto_extend_seconds = auto_extend_seconds
        if len(sandboxes) != count:
            await asyncio.shield(self._safe_delete_all(sandboxes))
            raise DuneError(f"service returned {len(sandboxes)} sandboxes for count={count}")
        try:
            await _wait_ready_async(sandboxes)
        except BaseException:
            await asyncio.shield(self._safe_delete_all(sandboxes))
            raise
        return sandboxes

    async def get(self, sandbox: AsyncSandbox | str) -> AsyncSandbox:
        data = await self._ahttp.get_json(f"/v1/sandboxes/{_sid(sandbox)}")
        return async_sandbox_from_wire(
            self._ahttp, self._http, self._adata_http, self._ssh_http, data
        )

    async def extend(self, sandbox: AsyncSandbox | str, seconds: int) -> AsyncSandbox:
        data = await self._ahttp.post_json(
            f"/v1/sandboxes/{_sid(sandbox)}/extend", {"seconds": seconds}
        )
        return async_sandbox_from_wire(
            self._ahttp, self._http, self._adata_http, self._ssh_http, data
        )

    async def delete(self, sandbox: AsyncSandbox | str) -> None:
        sid = _sid(sandbox)
        try:
            await self._ahttp.delete(f"/v1/sandboxes/{sid}")
        except DuneNotFoundError:
            pass
        if isinstance(sandbox, AsyncSandbox):
            sandbox.state = SandboxState.COMPLETED

    def list(self) -> list[AsyncSandbox]:
        out: list[AsyncSandbox] = []
        for data in _list_pages(self._http, self._ns):
            sb = async_sandbox_from_wire(
                self._ahttp, self._http, self._adata_http, self._ssh_http, data
            )
            if sb.state in _LIVE_STATES:
                out.append(sb)
        return out

    async def _safe_delete_all(self, sandboxes: Iterable[AsyncSandbox]) -> None:
        await asyncio.gather(
            *(self._delete_quiet(sb) for sb in sandboxes), return_exceptions=True
        )

    async def _delete_quiet(self, sandbox: AsyncSandbox) -> None:
        try:
            await self.delete(sandbox)
        except DuneError:
            pass


def _sid(sandbox: Any) -> str:
    if isinstance(sandbox, (Sandbox, AsyncSandbox)):
        return sandbox.id
    return sandbox


def _batch_items(data: Any) -> list[Any]:
    items = data.get("sandboxes") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise DuneError("malformed batch response: missing 'sandboxes'")
    return items


def _list_pages(http: SyncHttpClient, namespace: str | None):
    cursor: str | None = None
    first = True
    while first or cursor:
        first = False
        params: dict[str, Any] = {}
        if namespace:
            params["namespace"] = namespace
        if cursor:
            params["cursor"] = cursor
        data = http.get_json("/v1/sandboxes", params=params)
        yield from data.get("items", [])
        cursor = data.get("next_cursor")


# --------------------------------------------------------------------------- #
# Clients
# --------------------------------------------------------------------------- #


class DuneAsync:
    def __init__(
        self,
        config: DuneConfig | None = None,
        *,
        _pool: Any = None,
        _session: Any = None,
    ) -> None:
        self._config = (config or DuneConfig()).resolved()
        self._ahttp = AsyncHttpClient(self._config, _session=_session)
        self._adata_http = AsyncHttpClient(
            self._config, base_url=self._config.proxy_url, _session=_session
        )
        self._http = SyncHttpClient(self._config, _pool=_pool)
        self._ssh_http = SyncHttpClient(
            self._config, base_url=self._config.ssh_url or self._config.api_url, _pool=_pool
        )
        self.sandbox = _AsyncSandboxNamespace(
            self._ahttp, self._http, self._adata_http, self._ssh_http, self._config.namespace
        )
        self.network = _NetworkNamespace(self._http, self._config.namespace)

    @property
    def config(self) -> DuneConfig:
        return self._config

    async def aclose(self) -> None:
        """Release the connection pools. Call at shutdown."""
        await self._ahttp.aclose()
        await self._adata_http.aclose()
        self._http.close()
        self._ssh_http.close()

    async def __aenter__(self) -> DuneAsync:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()


class Dune:
    def __init__(
        self,
        config: DuneConfig | None = None,
        *,
        _pool: Any = None,
    ) -> None:
        self._config = (config or DuneConfig()).resolved()
        self._http = SyncHttpClient(self._config, _pool=_pool)
        self._data_http = SyncHttpClient(
            self._config, base_url=self._config.proxy_url, _pool=_pool
        )
        self._ssh_http = SyncHttpClient(
            self._config, base_url=self._config.ssh_url or self._config.api_url, _pool=_pool
        )
        self.sandbox = _SyncSandboxNamespace(
            self._http, self._data_http, self._ssh_http, self._config.namespace
        )
        self.network = _NetworkNamespace(self._http, self._config.namespace)

    @property
    def config(self) -> DuneConfig:
        return self._config

    def close(self) -> None:
        self._http.close()
        self._data_http.close()
        self._ssh_http.close()

    def __enter__(self) -> Dune:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
