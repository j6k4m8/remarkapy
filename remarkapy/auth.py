"""Authentication and request plumbing for the reMarkable client."""

from __future__ import annotations

import logging
import pathlib
import uuid
from typing import Any

import httpx

from .configfile import RemarkapyConfig, get_config_or_raise, write_config
from .endpoints import (
    DEFAULT_DISCOVERY_HOST,
    DEFAULT_USER_AGENT,
    DEFAULT_WEBAPP_HOST,
    EndpointSet,
)
from .exceptions import ConfigNotFoundError, ExpiredToken, GenerationError, ResponseError

logger = logging.getLogger(__name__)


class AuthenticatedClient:
    """Shared auth/session behavior for the public client."""

    def __init__(
        self,
        configfile: pathlib.Path | str | None = None,
        *,
        device_token: str | None = None,
        user_token: str | None = None,
        http_client: httpx.Client | None = None,
        timeout: float = 20.0,
        user_agent: str = DEFAULT_USER_AGENT,
        interactive: bool = True,
        refresh_on_init: bool = True,
        persist_config: bool | None = None,
    ) -> None:
        """Initialize auth/session state.

        Args:
            configfile: Optional config override path.
            device_token: Explicit device token override.
            user_token: Explicit user token override.
            http_client: Optional injected HTTP client for tests.
            timeout: Request timeout in seconds.
            user_agent: User agent string to send with requests.
            interactive: Whether to allow interactive device pairing.
            refresh_on_init: Whether to mint a fresh user token immediately.
            persist_config: Whether token updates may be written to disk.
        """
        injected_runtime = (
            device_token is not None or user_token is not None or http_client is not None
        )
        self._persist_config = (
            persist_config if persist_config is not None else not injected_runtime
        )
        if injected_runtime and configfile is None:
            loaded_config = RemarkapyConfig()
            config_path = pathlib.Path.cwd() / ".remarkapy.in-memory.conf"
        else:
            loaded_config, config_path = get_config_or_raise(
                configfile, return_path=True, allow_missing=True
            )
        if self._persist_config and injected_runtime and configfile is None:
            raise ValueError(
                "Injected tokens or HTTP clients must not persist to the default config path. "
                "Pass an explicit configfile if you really want persistence."
            )

        self._config = RemarkapyConfig(
            usertoken=user_token or loaded_config.usertoken,
            devicetoken=device_token or loaded_config.devicetoken,
        )
        self._config_path = config_path
        self._interactive = interactive
        self._user_agent = user_agent
        self._root_state: tuple[str, int, int] | None = None

        self._client = http_client or httpx.Client(timeout=timeout, follow_redirects=True)
        self._owns_client = http_client is None
        self.urls = self.discover_endpoints()

        if refresh_on_init and self._config.devicetoken:
            self.refresh_user_token()

    def close(self) -> None:
        """Close the underlying HTTP client if this instance owns it."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "AuthenticatedClient":
        """Enter the context-manager scope."""
        return self

    def __exit__(self, *_: object) -> None:
        """Exit the context-manager scope."""
        self.close()

    def _dump_config(self) -> None:
        """Persist the current tokens to disk if allowed."""
        if self._persist_config:
            write_config(self._config_path, self._config)

    def discover_endpoints(self) -> EndpointSet:
        """Discover the current public endpoint hosts.

        Returns:
            The discovered endpoint set, or defaults if discovery fails.
        """
        try:
            response = self._client.get(
                f"{DEFAULT_DISCOVERY_HOST}/discovery/v1/endpoints",
                headers={"user-agent": self._user_agent},
            )
            response.raise_for_status()
            payload = response.json()
            notifications = payload.get("notifications")
            webapp = payload.get("webapp")
            raw_host = f"https://{notifications}" if notifications else DEFAULT_DISCOVERY_HOST
            webapp_host = f"https://{webapp}" if webapp else DEFAULT_WEBAPP_HOST
            return EndpointSet(raw_host=raw_host, webapp_host=webapp_host)
        except Exception as exc:  # pragma: no cover - safe fallback path
            logger.warning("Failed to discover endpoints, using defaults: %s", exc)
            return EndpointSet()

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        expected_statuses: tuple[int, ...] = (200,),
        retry_on_unauthorized: bool = False,
        **kwargs: Any,
    ) -> httpx.Response:
        """Perform a request with reMarkable-specific error handling."""
        response = self._client.request(method, url, headers=headers, **kwargs)
        if response.status_code == 401 and retry_on_unauthorized:
            self.refresh_user_token(force=True)
            merged_headers = dict(headers or {})
            merged_headers["Authorization"] = f"Bearer {self._config.usertoken}"
            response = self._client.request(method, url, headers=merged_headers, **kwargs)

        if response.status_code in expected_statuses:
            return response

        body_text = response.text
        if response.status_code == 401:
            raise ExpiredToken("Device or user token has expired.")
        if body_text == '{"message":"precondition failed"}\n':
            self._root_state = None
            raise GenerationError(
                "The root generation changed on the server. Refresh and retry."
            )
        raise ResponseError(response.status_code, body_text)

    def _device_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Build request headers using the device token."""
        if not self._config.devicetoken:
            raise ConfigNotFoundError("No device token is available.")
        return {
            "Authorization": f"Bearer {self._config.devicetoken}",
            "user-agent": self._user_agent,
            **(extra or {}),
        }

    def _user_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Build request headers using the current user token."""
        if not self._config.usertoken:
            self.refresh_user_token()
        return {
            "Authorization": f"Bearer {self._config.usertoken}",
            "user-agent": self._user_agent,
            **(extra or {}),
        }

    def refresh_user_token(self, force: bool = False) -> str:
        """Mint and persist a fresh user token."""
        del force
        if not self._config.devicetoken:
            if self._interactive:
                self.register_device_wizard()
            else:
                raise ConfigNotFoundError(
                    "No device token is configured and interactive pairing is disabled."
                )

        response = self._request(
            "POST",
            self.urls.new_user_token,
            headers=self._device_headers(),
            json={},
        )
        self._config.usertoken = response.text
        self._dump_config()
        return self._config.usertoken

    def register_device(self, code: str) -> str:
        """Register a new device using an eight-character pairing code."""
        payload = {
            "code": code,
            "deviceDesc": "desktop-macos",
            "deviceID": str(uuid.uuid4()),
            "secret": "",
        }
        response = self._request(
            "POST",
            self.urls.register_device,
            headers={"User-Agent": "desktop/3.14.0.887 (macos 15.0)"},
            json=payload,
        )
        self._config.devicetoken = response.text
        self._config.usertoken = ""
        self._dump_config()
        return response.text

    def register_device_wizard(self) -> None:
        """Interactively register a device token."""
        print("\n=== REMARKABLE CLOUD ===")
        print("Visit https://my.remarkable.com/pair/app and enter the displayed code.")
        code = ""
        while len(code) != 8:
            code = input("Verification code: ").strip()
        self.register_device(code)

    def delete_device(self) -> bool:
        """Revoke the current device token from the cloud."""
        response = self._request(
            "POST",
            self.urls.revoke_device,
            headers=self._device_headers(),
            expected_statuses=(200, 204),
        )
        return response.status_code == 204


__all__ = ["AuthenticatedClient"]
