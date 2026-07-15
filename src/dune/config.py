from __future__ import annotations

import os
from dataclasses import dataclass, field, replace


@dataclass
class DuneConfig:
    api_url: str | None = None
    proxy_url: str | None = None
    ssh_url: str | None = None
    api_key: str | None = field(default=None, repr=False)
    namespace: str | None = None

    tls_verify: bool = True
    connection_limit: int = 0

    extra_headers: dict[str, str] = field(default_factory=dict)

    def resolved(self) -> DuneConfig:
        from ._models import validate_namespace
        from .errors import DuneValidationError

        api_url = self.api_url or os.environ.get("DUNE_API_URL")
        proxy_url = self.proxy_url or os.environ.get("DUNE_PROXY_URL")
        ssh_url = self.ssh_url or os.environ.get("DUNE_SSH_URL")
        api_key = self.api_key or os.environ.get("DUNE_API_KEY")
        namespace = self.namespace or os.environ.get("DUNE_NAMESPACE") or "default"

        if not api_url:
            raise DuneValidationError(
                "api_url is required: pass DuneConfig(api_url=...) or set DUNE_API_URL"
            )
        if not proxy_url:
            raise DuneValidationError(
                "proxy_url is required: pass DuneConfig(proxy_url=...) or set DUNE_PROXY_URL"
            )
        if not api_key:
            raise DuneValidationError(
                "api_key is required: pass DuneConfig(api_key=...) or set DUNE_API_KEY"
            )
        validate_namespace(namespace)

        return replace(
            self,
            api_url=api_url.rstrip("/"),
            proxy_url=proxy_url.rstrip("/"),
            ssh_url=ssh_url.rstrip("/") if ssh_url else None,
            api_key=api_key,
            namespace=namespace,
            extra_headers=dict(self.extra_headers),
        )
