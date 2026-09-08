"""Tests for manifest parsing and hashing helpers."""

from __future__ import annotations

import hashlib

from remarkapy.entries import (
    RawEntry,
    compute_manifest_hash,
    parse_entries_manifest,
    serialize_entries_manifest,
)


def test_parse_schema3_manifest() -> None:
    """Schema v3 manifests should parse into raw entries."""
    raw = "3\nabc:0:file.content:0:10\ndef:80000000:item-id:2:20\n"

    parsed = parse_entries_manifest(raw)

    assert parsed.schema_version == 3
    assert parsed.entries[0] == RawEntry(id="file.content", hash="abc", type=0, subfiles=0, size=10)
    assert parsed.entries[1] == RawEntry(id="item-id", hash="def", type=0x80000000, subfiles=2, size=20)


def test_parse_schema4_manifest() -> None:
    """Schema v4 manifests should parse the info line and entries."""
    raw = "4\n0:.:1:10\nabc:0:file.content:0:10\n"

    parsed = parse_entries_manifest(raw)

    assert parsed.schema_version == 4
    assert parsed.id == "."
    assert parsed.size == 10
    assert parsed.entries[0].id == "file.content"


def test_schema3_manifest_hash_uses_concatenated_child_hashes() -> None:
    """Schema v3 manifest hashes should match the backend tree-hash algorithm."""
    first = "00" * 32
    second = "11" * 32
    entries = [
        RawEntry(id="b", hash=second, type=0, subfiles=0, size=2),
        RawEntry(id="a", hash=first, type=0, subfiles=0, size=1),
    ]

    expected = hashlib.sha256(bytes.fromhex(first) + bytes.fromhex(second)).hexdigest()

    assert compute_manifest_hash(entries, schema_version=3) == expected


def test_schema4_manifest_hash_uses_payload_hash() -> None:
    """Schema v4 manifest hashes should be the SHA-256 of the manifest bytes."""
    entries = [RawEntry(id="a", hash="22" * 32, type=0, subfiles=0, size=1)]
    payload = serialize_entries_manifest("root", entries, schema_version=4)

    assert compute_manifest_hash(entries, schema_version=4) == hashlib.sha256(payload).hexdigest()


def test_schema4_serialization_retypes_schema3_item_marker() -> None:
    """Schema-3 `80000000` item markers should become `0` when emitted as schema 4."""
    entries = [RawEntry(id="item-id", hash="33" * 32, type=0x80000000, subfiles=2, size=20)]

    v3 = serialize_entries_manifest("root", entries, schema_version=3).decode("utf-8")
    v4 = serialize_entries_manifest("root", entries, schema_version=4).decode("utf-8")

    assert v3 == f"3\n{'33' * 32}:80000000:item-id:2:20\n"
    assert v4 == f"4\n0:.:1:20\n{'33' * 32}:0:item-id:2:20\n"
