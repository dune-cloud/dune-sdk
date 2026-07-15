from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class DuneError(Exception):
    """Base error for the Dune SDK."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        headers: Mapping[str, Any] | None = None,
        error_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message: str = message
        self.status_code: int | None = status_code
        self.error_code: str | None = error_code
        self.headers: dict[str, Any] = dict(headers or {})


class DuneValidationError(DuneError):
    """Input validation failed (HTTP 400 or client-side pre-flight)."""


class DuneAuthenticationError(DuneError):
    """Authentication failed (HTTP 401)."""


class DuneAuthorizationError(DuneError):
    """Request forbidden (HTTP 403)."""


class DuneNotFoundError(DuneError):
    """Resource not found (HTTP 404)."""


class DuneConflictError(DuneError):
    """Resource conflict (HTTP 409)."""


class DuneGoneError(DuneError):
    """A server-side resource the cluster no longer has (HTTP 410)."""


class DuneRateLimitError(DuneError):
    """Rate limit exceeded (HTTP 429)."""


class DuneQuotaExceededError(DuneRateLimitError):
    """Namespace resource budget exhausted (HTTP 429, code ``quota_exceeded``)."""


class DuneTransportError(DuneError):
    """The sandbox exec transport failed server-side (HTTP 502)."""


class DuneTimeoutError(DuneError):
    def __init__(
        self,
        message: str,
        *,
        pending: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.pending = pending or []


class DuneConnectionError(DuneError):
    """Network/transport error talking to API server."""


_STATUS_TO_CLASS: dict[int, type[DuneError]] = {
    400: DuneValidationError,
    401: DuneAuthenticationError,
    403: DuneAuthorizationError,
    404: DuneNotFoundError,
    408: DuneTimeoutError,
    409: DuneConflictError,
    410: DuneGoneError,
    429: DuneRateLimitError,
    502: DuneTransportError,
}


_CODE_TO_CLASS: dict[str, type[DuneError]] = {
    "quota_exceeded": DuneQuotaExceededError,
}


def error_for_status(status: int | None) -> type[DuneError]:
    """Return the most-specific ``DuneError`` subclass for an HTTP status."""
    if status is None:
        return DuneError
    return _STATUS_TO_CLASS.get(status, DuneError)


def make_error(
    message: str,
    *,
    status_code: int | None = None,
    headers: Mapping[str, Any] | None = None,
    error_code: str | None = None,
) -> DuneError:
    """Build the right ``DuneError`` subclass for an HTTP failure."""
    cls = _CODE_TO_CLASS.get(error_code or "") or error_for_status(status_code)
    return cls(message, status_code=status_code, headers=headers, error_code=error_code)
