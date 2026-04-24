"""Backward-compatible public API exports."""

from .client import Client
from .configfile import RemarkapyConfig, get_config_or_raise, resolve_config_path, write_config
from .entries import IndexedItem
from .export import ExportResult
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
    "ExportResult",
    "EndpointSet",
    "ExpiredToken",
    "GenerationError",
    "HashNotFoundError",
    "IndexedItem",
    "RemarkableAPIError",
    "RemarkapyConfig",
    "ResponseError",
    "URLS",
    "get_config_or_raise",
    "resolve_config_path",
    "write_config",
]
