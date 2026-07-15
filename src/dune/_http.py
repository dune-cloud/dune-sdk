from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterable, Iterable, Mapping
from time import monotonic
from typing import Any
from urllib.parse import urlencode

import aiohttp
import urllib3

from .config import DuneConfig
from .errors import (
    DuneConnectionError,
    DuneError,
    DuneTimeoutError,
    DuneValidationError,
    make_error,
)

_SDK_USER_AGENT = "dune-sdk/0.1.0"
CONNECT_TIMEOUT = 10
_STREAM_CHUNK = 1 << 16
_POOL_MAXSIZE = 100
_MISDIRECTED_STATUS = 421
_MISDIRECTED_RETRIES = 2

def _headers(config: DuneConfig) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {config.api_key}",
        "User-Agent": _SDK_USER_AGENT,
        "Accept": "application/json",
        **config.extra_headers,
    }


def _query(params: dict[str, Any] | None) -> str:
    if not params:
        return ""
    pairs = []
    for k, v in params.items():
        if v is None:
            continue
        pairs.append((k, "true" if v is True else "false" if v is False else str(v)))
    return ("?" + urlencode(pairs)) if pairs else ""


def _sync_timeout(total: float | None) -> urllib3.Timeout:
    return urllib3.Timeout(connect=CONNECT_TIMEOUT, total=total)


def _async_timeout(total: float | None) -> aiohttp.ClientTimeout:
    return aiohttp.ClientTimeout(
        connect=CONNECT_TIMEOUT, sock_connect=CONNECT_TIMEOUT, sock_read=None, total=total
    )


def _check_timeout(timeout: float | None) -> None:
    if timeout is not None and timeout <= 0:
        raise DuneValidationError("timeout must be a positive number of seconds, or None for no timeout")


def _request_body(json_body: Any, content: Any, content_type: str | None, headers: dict[str, str]) -> Any:
    if json_body is not None:
        headers["Content-Type"] = "application/json"
        return json.dumps(json_body).encode()
    if content is not None and content_type is not None:
        headers["Content-Type"] = content_type
    return content


def _replayable(body: Any) -> bool:
    return body is None or isinstance(body, (bytes, bytearray))


def _raise(status: int, data: bytes, headers: Mapping[str, Any]) -> None:
    msg = f"HTTP {status}"
    error_code: str | None = None
    if data:
        try:
            body = json.loads(data)
        except ValueError:
            body = {"text": data.decode(errors="replace")}
        if isinstance(body, dict):
            msg = body.get("message") or body.get("error") or msg
            error_code = body.get("code") or body.get("error_code")
    raise make_error(msg, status_code=status, headers=headers, error_code=error_code)


def _decode(data: bytes, status: int) -> Any:
    try:
        return json.loads(data)
    except ValueError as exc:
        raise DuneError(f"malformed JSON in HTTP {status} response: {exc}") from exc


class SyncHttpClient:
    def __init__(self, config: DuneConfig, *, base_url: str | None = None, _pool: Any = None) -> None:
        self._base = (base_url or config.api_url or "").rstrip("/")
        self._headers = _headers(config)
        self._pool = _pool or urllib3.PoolManager(
            maxsize=_POOL_MAXSIZE, cert_reqs="CERT_REQUIRED" if config.tls_verify else "CERT_NONE"
        )

    def close(self) -> None:
        self._pool.clear()

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        params: dict[str, Any] | None = None,
        content: bytes | Iterable[bytes] | None = None,
        content_type: str | None = None,
        timeout: float | None = None,
    ) -> Any:
        _check_timeout(timeout)
        headers = dict(self._headers)
        body = _request_body(json_body, content, content_type, headers)
        url = self._base + path + _query(params)
        retries = _MISDIRECTED_RETRIES if _replayable(body) else 0
        for attempt in range(retries + 1):
            try:
                resp = self._pool.request(
                    method, url, body=body, headers=headers, timeout=_sync_timeout(timeout),
                    redirect=False, retries=False, preload_content=True,
                )
            except urllib3.exceptions.TimeoutError as e:
                raise DuneTimeoutError(f"{method} {path} timed out: {e}") from e
            except urllib3.exceptions.HTTPError as e:
                raise DuneConnectionError(f"{method} {path} failed: {e}") from e
            if resp.status != _MISDIRECTED_STATUS or attempt == retries:
                break
        if 300 <= resp.status < 400:
            raise DuneError(f"{method} {path}: unexpected redirect ({resp.status})")
        if resp.status >= 400:
            _raise(resp.status, resp.data, resp.headers)
        return resp

    def get_json(self, path: str, **kwargs: Any) -> Any:
        resp = self.request("GET", path, **kwargs)
        return _decode(resp.data, resp.status)

    def post_json(self, path: str, body: Any, **kwargs: Any) -> Any:
        resp = self.request("POST", path, json_body=body, **kwargs)
        return _decode(resp.data, resp.status) if resp.data else None

    def put_json(self, path: str, body: Any, **kwargs: Any) -> Any:
        resp = self.request("PUT", path, json_body=body, **kwargs)
        return _decode(resp.data, resp.status) if resp.data else None

    def download_to(
        self, path: str, dest: Any, *, params: dict[str, Any] | None = None, timeout: float | None = None
    ) -> None:
        _check_timeout(timeout)
        deadline = monotonic() + timeout if timeout else None
        url = self._base + path + _query(params)
        received = 0
        while True:
            remaining = (deadline - monotonic()) if deadline is not None else None
            if remaining is not None and remaining <= 0:
                raise DuneTimeoutError(f"GET {path} timed out after {timeout}s")
            start = received
            headers = dict(self._headers)
            if received:
                headers["Range"] = f"bytes={received}-"
            try:
                resp = self._pool.request(
                    "GET", url, headers=headers, timeout=_sync_timeout(remaining),
                    redirect=False, retries=False, preload_content=False,
                )
                try:
                    if 300 <= resp.status < 400:
                        raise DuneError(f"GET {path}: unexpected redirect ({resp.status})")
                    if resp.status >= 400:
                        _raise(resp.status, resp.read(), resp.headers)
                    if received and resp.status != 206:
                        raise DuneError(f"GET {path}: server did not honour Range; cannot resume")
                    for chunk in resp.stream(_STREAM_CHUNK):
                        dest.write(chunk)
                        received += len(chunk)
                finally:
                    resp.release_conn()
                return
            except urllib3.exceptions.TimeoutError as e:
                raise DuneTimeoutError(f"GET {path} timed out: {e}") from e
            except urllib3.exceptions.HTTPError as e:
                if received == start:
                    raise DuneConnectionError(f"GET {path} failed: {e}") from e

    def delete(self, path: str, **kwargs: Any) -> None:
        self.request("DELETE", path, **kwargs)


class AsyncHttpClient:
    def __init__(self, config: DuneConfig, *, base_url: str | None = None, _session: Any = None) -> None:
        self._base = (base_url or config.api_url or "").rstrip("/")
        self._headers = _headers(config)
        self._verify = config.tls_verify
        self._limit = config.connection_limit
        self._session = _session

    async def _session_(self) -> Any:
        if self._session is None:
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(
                    ssl=None if self._verify else False, limit=self._limit
                )
            )
        return self._session

    async def aclose(self) -> None:
        if self._session is not None:
            await self._session.close()

    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        params: dict[str, Any] | None = None,
        content: bytes | AsyncIterable[bytes] | None = None,
        content_type: str | None = None,
        timeout: float | None = None,
    ) -> Any:
        _check_timeout(timeout)
        headers = dict(self._headers)
        body = _request_body(json_body, content, content_type, headers)
        session = await self._session_()
        url = self._base + path + _query(params)
        retries = _MISDIRECTED_RETRIES if _replayable(body) else 0
        for attempt in range(retries + 1):
            try:
                async with session.request(
                    method, url, data=body, headers=headers,
                    timeout=_async_timeout(timeout), allow_redirects=False,
                ) as resp:
                    data = await resp.read()
                    status, hdrs = resp.status, resp.headers
            except (TimeoutError, aiohttp.ClientError) as e:
                if isinstance(e, TimeoutError):
                    raise DuneTimeoutError(f"{method} {path} timed out: {e}") from e
                raise DuneConnectionError(f"{method} {path} failed: {e}") from e
            if status != _MISDIRECTED_STATUS or attempt == retries:
                break
        if 300 <= status < 400:
            raise DuneError(f"{method} {path}: unexpected redirect ({status})")
        if status >= 400:
            _raise(status, data, hdrs)
        return _Body(status, hdrs, data)

    async def get_json(self, path: str, **kwargs: Any) -> Any:
        resp = await self.request("GET", path, **kwargs)
        return _decode(resp.data, resp.status)

    async def post_json(self, path: str, body: Any, **kwargs: Any) -> Any:
        resp = await self.request("POST", path, json_body=body, **kwargs)
        return _decode(resp.data, resp.status) if resp.data else None

    async def download_to(
        self, path: str, dest: Any, *, params: dict[str, Any] | None = None, timeout: float | None = None
    ) -> None:
        _check_timeout(timeout)
        deadline = monotonic() + timeout if timeout else None
        url = self._base + path + _query(params)
        session = await self._session_()
        received = 0
        while True:
            remaining = (deadline - monotonic()) if deadline is not None else None
            if remaining is not None and remaining <= 0:
                raise DuneTimeoutError(f"GET {path} timed out after {timeout}s")
            start = received
            headers = dict(self._headers)
            if received:
                headers["Range"] = f"bytes={received}-"
            try:
                async with session.get(url, headers=headers, timeout=_async_timeout(remaining), allow_redirects=False) as resp:
                    if 300 <= resp.status < 400:
                        raise DuneError(f"GET {path}: unexpected redirect ({resp.status})")
                    if resp.status >= 400:
                        _raise(resp.status, await resp.read(), resp.headers)
                    if received and resp.status != 206:
                        raise DuneError(f"GET {path}: server did not honour Range; cannot resume")
                    async for chunk in resp.content.iter_chunked(_STREAM_CHUNK):
                        await asyncio.to_thread(dest.write, chunk)
                        received += len(chunk)
                return
            except (TimeoutError, aiohttp.ClientError) as e:
                if isinstance(e, TimeoutError):
                    raise DuneTimeoutError(f"GET {path} timed out: {e}") from e
                if received == start:
                    raise DuneConnectionError(f"GET {path} failed: {e}") from e

    async def delete(self, path: str, **kwargs: Any) -> None:
        await self.request("DELETE", path, **kwargs)


class _Body:
    def __init__(self, status: int, headers: Mapping[str, Any], data: bytes) -> None:
        self.status = status
        self.headers = headers
        self.data = data
