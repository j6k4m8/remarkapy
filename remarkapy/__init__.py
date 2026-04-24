"""Public package exports for remarkapy."""

from .api import Client, EndpointSet, URLS
from .configfile import RemarkapyConfig, get_config_or_raise, resolve_config_path
from .entries import (
    CollectionEntry,
    DocumentEntry,
    EntriesManifest,
    Entry,
    IndexedItem,
    RawEntry,
    SimpleEntry,
    TemplateEntry,
)
from .export import ExportResult
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
    "CollectionEntry",
    "ConfigNotFoundError",
    "DocumentEntry",
    "ExportResult",
    "DocumentNotFound",
    "EndpointSet",
    "EntriesManifest",
    "Entry",
    "ExpiredToken",
    "GenerationError",
    "HashNotFoundError",
    "IndexedItem",
    "RawEntry",
    "RemarkableAPIError",
    "RemarkapyConfig",
    "ResponseError",
    "SimpleEntry",
    "TemplateEntry",
    "URLS",
    "get_config_or_raise",
    "resolve_config_path",
]
