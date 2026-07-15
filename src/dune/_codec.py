from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from .errors import DuneError, DuneValidationError

M = TypeVar("M", bound=BaseModel)


def to_payload(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(exclude_none=True)


def build_request(model_cls: type[M], **fields: Any) -> M:
    try:
        return model_cls(**fields)
    except ValidationError as exc:
        raise DuneValidationError(f"invalid request body: {exc}") from exc


def parse_response(model_cls: type[M], data: Any) -> M:
    try:
        return model_cls.model_validate(data)
    except ValidationError as exc:
        raise DuneError(f"malformed response from dune-api: {exc}") from exc
