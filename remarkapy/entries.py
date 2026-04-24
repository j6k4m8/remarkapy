"""Models and manifest helpers for reMarkable cloud entries."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

HASH_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(
    r"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|trash)?$"
)


@dataclass(slots=True)
class RawEntry:
    """A low-level entry inside a manifest file.

    Attributes:
        id: The file or item identifier.
        hash: The immutable content hash.
        type: The raw manifest type (`0` or `80000000`).
        subfiles: The number of child files or entries.
        size: The total size in bytes.
    """

    id: str
    hash: str
    type: int
    subfiles: int
    size: int


@dataclass(slots=True)
class SimpleEntry:
    """A public item reference consisting of id and current hash."""

    id: str
    hash: str


@dataclass(slots=True, frozen=True)
class IndexedItem:
    """A lightweight library index entry for fast listings and lookups."""

    id: str
    hash: str
    type: Literal["CollectionType", "DocumentType", "TemplateType"]
    visibleName: str
    parent: str

    @property
    def is_collection(self) -> bool:
        """Return whether the indexed item is a folder."""
        return self.type == "CollectionType"


@dataclass(slots=True)
class CollectionEntry:
    """A folder/collection entry visible in the user library."""

    id: str
    hash: str
    type: Literal["CollectionType"]
    visibleName: str
    lastModified: str
    pinned: bool
    parent: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DocumentEntry:
    """A document entry visible in the user library."""

    id: str
    hash: str
    type: Literal["DocumentType"]
    visibleName: str
    lastModified: str
    pinned: bool
    fileType: str
    lastOpened: str
    parent: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TemplateEntry:
    """A template entry visible in the user library."""

    id: str
    hash: str
    type: Literal["TemplateType"]
    visibleName: str
    lastModified: str
    pinned: bool
    parent: str = ""
    createdTime: str | None = None
    source: str | None = None
    new: bool | None = None


Entry = CollectionEntry | DocumentEntry | TemplateEntry


@dataclass(slots=True)
class EntriesManifest:
    """A parsed manifest file.

    Attributes:
        entries: The raw entries contained in the manifest.
        schema_version: The manifest schema version.
        id: The optional schema v4 manifest id.
        size: The optional schema v4 manifest size.
    """

    entries: list[RawEntry]
    schema_version: int
    id: str | None = None
    size: int | None = None


ApiMetadata = dict[str, Any]
ApiContent = dict[str, Any]


def is_hash(value: str) -> bool:
    """Return whether a string is a plausible item hash."""
    return bool(HASH_RE.fullmatch(value))


def is_item_id(value: str) -> bool:
    """Return whether a string is a plausible item id."""
    return value == "" or value == "trash" or bool(ID_RE.fullmatch(value))


def parse_raw_entry_line(line: str) -> RawEntry:
    """Parse one raw manifest line.

    Args:
        line: The line to parse.

    Returns:
        The parsed raw entry.

    Raises:
        ValueError: If the line format is invalid.
    """
    hash_value, entry_type, entry_id, subfiles, size = line.split(":", 4)
    parsed_type = int(entry_type, 16) if entry_type == "80000000" else int(entry_type)
    return RawEntry(
        id=entry_id,
        hash=hash_value,
        type=parsed_type,
        subfiles=int(subfiles),
        size=int(size),
    )


def parse_entries_manifest(raw_text: str) -> EntriesManifest:
    """Parse a manifest file returned by `/sync/v3/files/{hash}`.

    Args:
        raw_text: The manifest text.

    Returns:
        A parsed manifest object.
    """
    lines = raw_text.splitlines()
    if not lines:
        raise ValueError("Manifest was empty.")

    schema_version = int(lines[0])
    if schema_version == 3:
        return EntriesManifest(
            entries=[parse_raw_entry_line(line) for line in lines[1:] if line],
            schema_version=3,
        )
    if schema_version == 4:
        info = lines[1]
        lead, entry_id, count, size = info.split(":", 3)
        if lead != "0":
            raise ValueError(f"Invalid schema 4 info line: {info}")
        entries = [parse_raw_entry_line(line) for line in lines[2:] if line]
        if len(entries) != int(count):
            raise ValueError(
                f"Schema 4 manifest expected {count} entries, found {len(entries)}."
            )
        return EntriesManifest(
            entries=entries,
            schema_version=4,
            id=entry_id,
            size=int(size),
        )
    raise ValueError(f"Unsupported schema version: {schema_version}")


def serialize_entries_manifest(
    manifest_id: str,
    entries: list[RawEntry],
    schema_version: int,
) -> bytes:
    """Serialize raw manifest entries for upload.

    Args:
        manifest_id: The item id or `root` for the root manifest.
        entries: The entries to serialize.
        schema_version: The schema version to emit.

    Returns:
        The encoded manifest bytes.
    """
    ordered = sorted(entries, key=lambda entry: entry.id)
    total_size = sum(entry.size for entry in ordered)
    records = [f"{schema_version}\n"]
    if schema_version == 4:
        schema_id = "." if manifest_id == "root" else manifest_id
        records.append(f"0:{schema_id}:{len(ordered)}:{total_size}\n")
    for entry in ordered:
        entry_type = "80000000" if entry.type == 0x80000000 else str(entry.type)
        records.append(
            f"{entry.hash}:{entry_type}:{entry.id}:{entry.subfiles}:{entry.size}\n"
        )
    return "".join(records).encode("utf-8")


def compute_manifest_hash(entries: list[RawEntry], schema_version: int) -> str:
    """Compute the manifest hash for schema v3 or v4.

    Args:
        entries: The child raw entries.
        schema_version: The schema version.

    Returns:
        The manifest hash.
    """
    ordered = sorted(entries, key=lambda entry: entry.id)
    if schema_version == 3:
        digest_input = b"".join(bytes.fromhex(entry.hash) for entry in ordered)
        return hashlib.sha256(digest_input).hexdigest()
    if schema_version == 4:
        payload = serialize_entries_manifest("root", ordered, schema_version)
        return hashlib.sha256(payload).hexdigest()
    raise ValueError(f"Unsupported schema version: {schema_version}")


def json_dumps(data: Any) -> bytes:
    """Encode JSON using stable compact formatting.

    Args:
        data: The JSON-serializable value.

    Returns:
        UTF-8 encoded JSON bytes.
    """
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


__all__ = [
    "ApiContent",
    "ApiMetadata",
    "CollectionEntry",
    "DocumentEntry",
    "EntriesManifest",
    "Entry",
    "IndexedItem",
    "RawEntry",
    "SimpleEntry",
    "TemplateEntry",
    "compute_manifest_hash",
    "is_hash",
    "is_item_id",
    "json_dumps",
    "parse_entries_manifest",
    "parse_raw_entry_line",
    "serialize_entries_manifest",
]
