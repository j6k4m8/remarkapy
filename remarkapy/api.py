"""Backward-compatible public API exports."""

from .client import Client
from .configfile import RemarkapyConfig, get_config_or_raise, resolve_config_path, write_config
from .endpoints import EndpointSet, URLS
from .exceptions import (
    ConfigNotFoundError,
    DocumentNotFound,
    ExpiredToken,
    GenerationError,
    HashNotFoundError,
    RemarkableAPIError,
    ResponseError,
)

__all__ = [
    "Client",
    "ConfigNotFoundError",
    "DocumentNotFound",
    "EndpointSet",
    "ExpiredToken",
    "GenerationError",
    "HashNotFoundError",
    "RemarkableAPIError",
    "RemarkapyConfig",
    "ResponseError",
    "URLS",
    "get_config_or_raise",
    "resolve_config_path",
    "write_config",
]
