"""Endpoint definitions for the reMarkable cloud."""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_DISCOVERY_HOST = "https://eu.tectonic.remarkable.com"
DEFAULT_WEBAPP_HOST = "https://webapp-prod.cloud.remarkable.engineering"
DEFAULT_UPLOAD_HOST = "https://internal.cloud.remarkable.com"
DEFAULT_USER_AGENT = "remarkapy/0.2.2"


@dataclass(slots=True)
class EndpointSet:
    """Resolved endpoint hosts for the active reMarkable backend."""

    raw_host: str = DEFAULT_DISCOVERY_HOST
    webapp_host: str = DEFAULT_WEBAPP_HOST
    upload_host: str = DEFAULT_UPLOAD_HOST

    @property
    def register_device(self) -> str:
        """Return the device registration endpoint."""
        return f"{self.webapp_host}/token/json/2/device/new"

    @property
    def revoke_device(self) -> str:
        """Return the device revocation endpoint."""
        return f"{self.webapp_host}/token/json/3/device/delete"

    @property
    def new_user_token(self) -> str:
        """Return the user-token minting endpoint."""
        return f"{self.webapp_host}/token/json/2/user/new"

    @property
    def discovery(self) -> str:
        """Return the discovery endpoint."""
        return f"{self.raw_host}/discovery/v1/endpoints"

    @property
    def root_meta(self) -> str:
        """Return the root metadata endpoint."""
        return f"{self.raw_host}/sync/v4/root"

    @property
    def sync_root(self) -> str:
        """Return the root update endpoint."""
        return f"{self.raw_host}/sync/v3/root"

    @property
    def files_root(self) -> str:
        """Return the file blob prefix."""
        return f"{self.raw_host}/sync/v3/files"

    @property
    def simple_upload(self) -> str:
        """Return the simple upload endpoint."""
        return f"{self.upload_host}/doc/v2/files"


URLS = EndpointSet

__all__ = [
    "DEFAULT_DISCOVERY_HOST",
    "DEFAULT_UPLOAD_HOST",
    "DEFAULT_USER_AGENT",
    "DEFAULT_WEBAPP_HOST",
    "EndpointSet",
    "URLS",
]
