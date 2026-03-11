"""Helpers for locating and parsing reMarkable token config files."""

from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass

from .exceptions import ConfigNotFoundError


@dataclass(slots=True)
class RemarkapyConfig:
    """Stored authentication tokens for the reMarkable cloud.

    Attributes:
        usertoken: The short-lived user/session token.
        devicetoken: The long-lived device token.
    """

    usertoken: str = ""
    devicetoken: str = ""


DEFAULT_CONFIG_PATH = pathlib.Path.home() / ".rmapi"


def candidate_config_paths() -> list[pathlib.Path]:
    """Return config locations compatible with existing rmapi setups.

    Returns:
        A prioritized list of candidate config paths.
    """
    rmapi_config = os.environ.get("RMAPI_CONFIG")
    xdg_config = os.environ.get("XDG_CONFIG_HOME")

    return [
        pathlib.Path.home() / ".rmapi",
        pathlib.Path(rmapi_config).expanduser() / ".rmapi"
        if rmapi_config
        else pathlib.Path("~").expanduser() / ".rmapi",
        pathlib.Path(rmapi_config).expanduser() / ".rmapi.conf"
        if rmapi_config
        else pathlib.Path("~").expanduser() / ".rmapi.conf",
        pathlib.Path(rmapi_config).expanduser() / "rmapi" / ".rmapi"
        if rmapi_config
        else pathlib.Path("~/.config").expanduser() / "rmapi" / ".rmapi",
        pathlib.Path(rmapi_config).expanduser() / "rmapi" / "rmapi.conf"
        if rmapi_config
        else pathlib.Path("~/.config").expanduser() / "rmapi" / "rmapi.conf",
        pathlib.Path(xdg_config).expanduser() / "rmapi" / ".rmapi"
        if xdg_config
        else pathlib.Path("~/.config").expanduser() / "rmapi" / ".rmapi",
        pathlib.Path("~/Library/Application Support").expanduser() / "rmapi" / ".rmapi",
        pathlib.Path("~/Library/Application Support").expanduser() / "rmapi" / "rmapi.conf",
    ]


def _parse_config_file(config_path: pathlib.Path) -> RemarkapyConfig:
    """Parse an rmapi-compatible config file.

    Args:
        config_path: The file to parse.

    Returns:
        A parsed config object.
    """
    config = RemarkapyConfig()
    with config_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key == "usertoken":
                config.usertoken = value
            elif key == "devicetoken":
                config.devicetoken = value
    return config


def resolve_config_path(
    config_path_override: pathlib.Path | str | None = None,
) -> pathlib.Path:
    """Resolve the config path to use.

    Args:
        config_path_override: An explicit override path.

    Returns:
        The resolved config path, even if it does not yet exist.
    """
    if config_path_override is not None:
        return pathlib.Path(config_path_override).expanduser().resolve()

    for option in candidate_config_paths():
        resolved = option.expanduser().resolve()
        if resolved.exists():
            return resolved

    return DEFAULT_CONFIG_PATH.expanduser().resolve()


def get_config_or_raise(
    config_path_override: pathlib.Path | str | None = None,
    return_path: bool = False,
    allow_missing: bool = False,
) -> RemarkapyConfig | tuple[RemarkapyConfig, pathlib.Path]:
    """Load the token config from disk.

    Args:
        config_path_override: An explicit override path.
        return_path: Whether to return the resolved path alongside the config.
        allow_missing: Whether to allow a missing file and return empty tokens.

    Returns:
        A config object, optionally with the resolved path.

    Raises:
        ConfigNotFoundError: If no readable config file exists and missing files
            are not allowed.
    """
    config_path = resolve_config_path(config_path_override)
    if config_path.exists():
        config = _parse_config_file(config_path)
    elif allow_missing:
        config = RemarkapyConfig()
    else:
        raise ConfigNotFoundError(
            f"Could not find a reMarkable config file at {config_path}"
        )

    if return_path:
        return config, config_path
    return config


def write_config(config_path: pathlib.Path, config: RemarkapyConfig) -> None:
    """Write an rmapi-compatible config file.

    Args:
        config_path: The destination config path.
        config: The config values to write.
    """
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as handle:
        handle.write(f"devicetoken: {config.devicetoken}\n")
        handle.write(f"usertoken: {config.usertoken}\n")
