"""Tests for config discovery and parsing."""

from __future__ import annotations

import pathlib

import httpx
import pytest

import remarkapy.api as api_module
from remarkapy.api import Client
from remarkapy.configfile import RemarkapyConfig, get_config_or_raise, write_config
from remarkapy.exceptions import ConfigNotFoundError


def test_write_and_read_config_round_trip(tmp_path: pathlib.Path) -> None:
    """A written config file should parse back into the same values."""
    config_path = tmp_path / ".rmapi"
    expected = RemarkapyConfig(usertoken="user-token", devicetoken="device-token")

    write_config(config_path, expected)
    loaded = get_config_or_raise(config_path)

    assert loaded == expected


def test_get_config_raises_when_missing(tmp_path: pathlib.Path) -> None:
    """Missing config files should raise unless explicitly allowed."""
    with pytest.raises(ConfigNotFoundError):
        get_config_or_raise(tmp_path / "missing.conf")


def test_get_config_allows_missing_file(tmp_path: pathlib.Path) -> None:
    """Missing config files can be allowed for first-run client setup."""
    loaded, resolved = get_config_or_raise(
        tmp_path / "missing.conf", return_path=True, allow_missing=True
    )

    assert loaded == RemarkapyConfig()
    assert resolved == (tmp_path / "missing.conf").resolve()


def test_injected_client_does_not_load_default_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Injected/mock clients should not touch default config discovery."""

    def fail_get_config(*args, **kwargs):
        raise AssertionError("default config lookup should not happen")

    monkeypatch.setattr(api_module, "get_config_or_raise", fail_get_config)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/discovery/v1/endpoints":
            return httpx.Response(
                200,
                json={
                    "notifications": "eu.tectonic.remarkable.com",
                    "webapp": "webapp-prod.cloud.remarkable.engineering",
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = Client(
        device_token="fake-device-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        refresh_on_init=False,
    )

    assert client._config.devicetoken == "fake-device-token"


def test_injected_client_requires_explicit_config_for_persistence() -> None:
    """Injected/mock clients must not persist to the default config path."""
    with pytest.raises(ValueError):
        Client(
            device_token="fake-device-token",
            persist_config=True,
            http_client=httpx.Client(
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(
                        200,
                        json={
                            "notifications": "eu.tectonic.remarkable.com",
                            "webapp": "webapp-prod.cloud.remarkable.engineering",
                        },
                    )
                )
            ),
            refresh_on_init=False,
        )
