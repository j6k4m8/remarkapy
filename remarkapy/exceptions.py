"""Exceptions used by the reMarkable client."""

from __future__ import annotations


class RemarkableAPIError(Exception):
    """Base exception for all reMarkable API failures."""


class ConfigNotFoundError(RemarkableAPIError):
    """Raised when a usable configuration file cannot be found."""


class ExpiredToken(RemarkableAPIError):
    """Raised when the stored device token has expired or been revoked."""


class ResponseError(RemarkableAPIError):
    """Raised when the server returns an unexpected response."""

    def __init__(self, status_code: int, message: str) -> None:
        """Initialize the response error.

        Args:
            status_code: The HTTP status code returned by the API.
            message: The human-readable error message.
        """
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.message = message


class GenerationError(RemarkableAPIError):
    """Raised when the root generation is stale and must be refreshed."""


class HashNotFoundError(RemarkableAPIError):
    """Raised when an item hash cannot be found in the current root."""


class AmbiguousItemError(RemarkableAPIError):
    """Raised when a human-friendly item reference matches multiple items."""


class ExportBackendUnavailableError(RemarkableAPIError):
    """Raised when an optional export backend is not installed."""


class ExportFailedError(RemarkableAPIError):
    """Raised when an optional export backend fails to render output."""


class DocumentNotFound(HashNotFoundError):
    """Backward-compatible alias for a missing document or item."""
