"""High-level library API for the reMarkable cloud."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import pathlib
import uuid
import zipfile
from time import time
from typing import Any

import crc32c

from .auth import AuthenticatedClient
from .entries import (
    ApiContent,
    ApiMetadata,
    CollectionEntry,
    DocumentEntry,
    EntriesManifest,
    Entry,
    IndexedItem,
    RawEntry,
    SimpleEntry,
    TemplateEntry,
    compute_manifest_hash,
    is_hash,
    is_item_id,
    json_dumps,
    parse_entries_manifest,
    serialize_entries_manifest,
)
from .exceptions import AmbiguousItemError, DocumentNotFound, HashNotFoundError

ROOT_SPECIAL_ID = "root"
ROOT_PARENT_ID = ""
TRASH_PARENT_ID = "trash"

# Root manifests are always written as schema 4. Migrated accounts reject
# schema-3 root writes with `400 update-required` ("Software must be updated")
# while `GET /sync/v4/root` still reports `schemaVersion: 3` for the same
# account, so the read-side version cannot drive writes (#24).
ROOT_WRITE_SCHEMA_VERSION = 4


class Client(AuthenticatedClient):
    """A synchronous Python client for the reMarkable cloud API."""

    def _manifest_file_name(self, manifest_id: str) -> str:
        """Return the blob filename used for one manifest read."""
        return f"{manifest_id}.docSchema"

    def _get_hash_bytes(self, hash_value: str, *, file_name: str | None = None) -> bytes:
        """Fetch raw blob bytes by hash."""
        response = self._request(
            "GET",
            f"{self.urls.files_root}/{hash_value}",
            headers=self._user_headers({"rm-filename": file_name} if file_name else None),
            retry_on_unauthorized=True,
        )
        return response.content

    def _get_hash_text(self, hash_value: str, *, file_name: str | None = None) -> str:
        """Fetch text content by hash."""
        return self._get_hash_bytes(hash_value, file_name=file_name).decode("utf-8")

    def get_root_state(self, refresh: bool = False) -> tuple[str, int, int]:
        """Return the current root hash, generation, and schema version."""
        if not refresh and self._root_state is not None:
            return self._root_state

        response = self._request(
            "GET",
            self.urls.root_meta,
            headers=self._user_headers(),
            retry_on_unauthorized=True,
        )
        payload = response.json()
        self._root_state = (
            payload["hash"],
            int(payload["generation"]),
            int(payload.get("schemaVersion", 3)),
        )
        return self._root_state

    def get_entries(
        self, hash_value: str, *, manifest_id: str | None = None
    ) -> EntriesManifest:
        """Return the parsed manifest for an item or the root."""
        if manifest_id is None and self._root_state is not None and hash_value == self._root_state[0]:
            manifest_id = ROOT_SPECIAL_ID
        file_name = self._manifest_file_name(manifest_id or hash_value)
        return parse_entries_manifest(self._get_hash_text(hash_value, file_name=file_name))

    def _get_root_entries(
        self, refresh: bool = False
    ) -> tuple[str, int, int, list[RawEntry]]:
        """Fetch the current root entry list and metadata."""
        root_hash, generation, schema_version = self.get_root_state(refresh=refresh)
        manifest = self.get_entries(root_hash, manifest_id=ROOT_SPECIAL_ID)
        return root_hash, generation, schema_version, list(manifest.entries)

    def list_ids(self, refresh: bool = False) -> list[SimpleEntry]:
        """List item ids and current hashes from the root manifest."""
        _, _, _, entries = self._get_root_entries(refresh=refresh)
        return [SimpleEntry(id=entry.id, hash=entry.hash) for entry in entries]

    def get_item_ids(self, refresh: bool = False) -> list[SimpleEntry]:
        """Backward-compatible alias for `list_ids`."""
        return self.list_ids(refresh=refresh)

    def _entry_label(self, entry: IndexedItem) -> str:
        """Return the display label for one entry in a directory listing."""
        suffix = "/" if entry.is_collection else ""
        return f"{entry.visibleName}{suffix}"

    def _require_child_entry(
        self, manifest: EntriesManifest, suffix: str, item_ref: str
    ) -> RawEntry:
        """Return one manifest child entry or raise a descriptive error."""
        child = self._find_child_entry(manifest, suffix)
        if child is None:
            raise DocumentNotFound(f"{suffix} entry not found for {item_ref}")
        return child

    def _build_indexed_item(self, entry: RawEntry) -> IndexedItem:
        """Load the minimal metadata needed for path resolution and directory listings."""
        manifest = self.get_entries(entry.hash, manifest_id=entry.id)
        metadata_entry = self._require_child_entry(manifest, ".metadata", entry.id)
        metadata = json.loads(
            self._get_hash_text(metadata_entry.hash, file_name=metadata_entry.id)
        )
        return IndexedItem(
            id=entry.id,
            hash=entry.hash,
            type=metadata["type"],
            visibleName=metadata["visibleName"],
            parent=metadata.get("parent", ROOT_PARENT_ID),
        )

    def _indexed_items(self, refresh: bool = False) -> list[IndexedItem]:
        """Build or reuse a lightweight library index for listings and path resolution."""
        root_hash, _, _, root_entries = self._get_root_entries(refresh=refresh)
        cache = getattr(self, "_directory_index_cache", None)
        if cache is not None and cache[0] == root_hash:
            return cache[1]

        if len(root_entries) <= 1:
            indexed = [self._build_indexed_item(entry) for entry in root_entries]
        else:
            worker_count = min(16, len(root_entries))
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                indexed = list(executor.map(self._build_indexed_item, root_entries))

        self._directory_index_cache = (root_hash, indexed)
        return indexed

    def _children_of(self, parent_id: str, refresh: bool = False) -> list[IndexedItem]:
        """Return the direct children of one parent id."""
        items = self._indexed_items(refresh=refresh)
        return sorted(
            [item for item in items if item.parent == parent_id],
            key=lambda item: (item.visibleName.lower(), item.id),
        )

    def _resolve_directory_id(self, directory_ref: str, refresh: bool = False) -> str:
        """Resolve a directory reference to a parent id suitable for listing."""
        if not directory_ref or directory_ref == "/":
            return ROOT_PARENT_ID
        entry = self._resolve_indexed_item(directory_ref.rstrip("/"), refresh=refresh)
        if not entry.is_collection:
            raise DocumentNotFound(f"Directory reference must point to a folder: {directory_ref}")
        return entry.id

    def list_directory(self, directory_ref: str = "", refresh: bool = False) -> list[IndexedItem]:
        """List the direct children of one library directory as lightweight items."""
        parent_id = self._resolve_directory_id(directory_ref, refresh=refresh)
        return self._children_of(parent_id, refresh=refresh)

    def list_directory_hydrated(
        self, directory_ref: str = "", refresh: bool = False
    ) -> list[Entry]:
        """List the direct children of one library directory as hydrated items."""
        parent_id = self._resolve_directory_id(directory_ref, refresh=refresh)
        return [
            self._build_entry(SimpleEntry(id=entry.id, hash=entry.hash))
            for entry in self._children_of(parent_id, refresh=refresh)
        ]

    def list_directory_paths(
        self,
        directory_ref: str = "",
        *,
        recursive: bool = False,
        refresh: bool = False,
    ) -> list[str]:
        """List directory contents as human-friendly relative paths."""
        parent_id = self._resolve_directory_id(directory_ref, refresh=refresh)

        def walk(current_parent: str, prefix: str = "") -> list[str]:
            paths: list[str] = []
            for entry in self._children_of(current_parent, refresh=refresh):
                label = self._entry_label(entry)
                relative = f"{prefix}{label}"
                paths.append(relative)
                if recursive and entry.is_collection:
                    paths.extend(walk(entry.id, prefix=f"{relative}"))
            return paths

        return walk(parent_id)

    def _list_entry_map(self, refresh: bool = False) -> dict[str, SimpleEntry]:
        """Return a mapping from item id to simple entries."""
        return {entry.id: entry for entry in self.list_ids(refresh=refresh)}

    def _path_segments(self, item_ref: str) -> list[str]:
        """Split a human path reference into path segments."""
        return [segment for segment in item_ref.strip("/").split("/") if segment]

    def _resolve_indexed_item_exact(
        self, item_ref: str, refresh: bool = False
    ) -> IndexedItem:
        """Resolve an item reference using exact id/hash matching only."""
        entries = self._indexed_items(refresh=refresh)
        if is_hash(item_ref):
            match = next((entry for entry in entries if entry.hash == item_ref), None)
            if match is None:
                raise DocumentNotFound(f"Could not resolve item reference: {item_ref}")
            return match
        if is_item_id(item_ref):
            match = next((entry for entry in entries if entry.id == item_ref), None)
            if match is None:
                raise DocumentNotFound(f"Could not resolve item reference: {item_ref}")
            return match
        raise DocumentNotFound(f"Could not resolve exact item reference: {item_ref}")

    def _resolve_indexed_item_by_name(
        self, item_ref: str, refresh: bool = False
    ) -> IndexedItem:
        """Resolve an item reference by unique visible name."""
        matches = [item for item in self._indexed_items(refresh=refresh) if item.visibleName == item_ref]
        if not matches:
            raise DocumentNotFound(f"Could not resolve item reference: {item_ref}")
        if len(matches) > 1:
            matches_text = ", ".join(sorted(f"{item.visibleName} ({item.id})" for item in matches))
            raise AmbiguousItemError(
                f"Reference '{item_ref}' matched multiple items: {matches_text}. Use a path like Folder/Name or `get-id`."
            )
        return matches[0]

    def _resolve_indexed_item_by_path(
        self, item_ref: str, refresh: bool = False
    ) -> IndexedItem:
        """Resolve an item reference by slash-delimited library path."""
        segments = self._path_segments(item_ref)
        if not segments:
            raise DocumentNotFound(f"Could not resolve item reference: {item_ref}")
        items = self._indexed_items(refresh=refresh)
        parent = ROOT_PARENT_ID
        current = None
        for segment in segments:
            matches = [item for item in items if item.parent == parent and item.visibleName == segment]
            if not matches:
                raise DocumentNotFound(f"Could not resolve item path: {item_ref}")
            if len(matches) > 1:
                raise AmbiguousItemError(
                    f"Path segment '{segment}' in '{item_ref}' matched multiple items under the same parent. Use `get-id`."
                )
            current = matches[0]
            parent = current.id
        assert current is not None
        return current

    def _resolve_indexed_item(
        self, item_ref: str, refresh: bool = False, exact: bool = False
    ) -> IndexedItem:
        """Resolve an item reference to one indexed entry."""
        if exact:
            return self._resolve_indexed_item_exact(item_ref, refresh=refresh)
        if is_hash(item_ref) or is_item_id(item_ref):
            return self._resolve_indexed_item_exact(item_ref, refresh=refresh)
        if "/" in item_ref.strip("/"):
            return self._resolve_indexed_item_by_path(item_ref, refresh=refresh)
        return self._resolve_indexed_item_by_name(item_ref, refresh=refresh)

    def resolve_hash(
        self, item_ref: str, refresh: bool = False, exact: bool = False
    ) -> str:
        """Resolve an item reference to the current item hash."""
        return self._resolve_indexed_item(item_ref, refresh=refresh, exact=exact).hash

    def resolve_id(
        self,
        item_ref: str,
        refresh: bool = False,
        *,
        exact: bool = False,
        allow_special: bool = True,
    ) -> str:
        """Resolve an item reference to the stable item id."""
        if allow_special and item_ref in {ROOT_PARENT_ID, TRASH_PARENT_ID}:
            return item_ref
        return self._resolve_indexed_item(item_ref, refresh=refresh, exact=exact).id

    def _load_item_manifest(
        self, item_ref: str, refresh: bool = False, exact: bool = False
    ) -> tuple[SimpleEntry, EntriesManifest]:
        """Resolve and fetch an item's manifest."""
        entry = self._resolve_indexed_item(item_ref, refresh=refresh, exact=exact)
        simple_entry = SimpleEntry(id=entry.id, hash=entry.hash)
        return simple_entry, self.get_entries(simple_entry.hash, manifest_id=simple_entry.id)

    def _find_child_entry(
        self, manifest: EntriesManifest, suffix: str
    ) -> RawEntry | None:
        """Find a child raw entry by filename suffix."""
        return next((entry for entry in manifest.entries if entry.id.endswith(suffix)), None)

    def _get_json_child(self, item_ref: str, suffix: str) -> dict[str, Any]:
        """Fetch and decode a JSON child entry."""
        _, manifest = self._load_item_manifest(item_ref)
        child = self._require_child_entry(manifest, suffix, item_ref)
        return json.loads(self._get_hash_text(child.hash, file_name=child.id))

    def _get_binary_child(self, item_ref: str, suffix: str) -> bytes:
        """Fetch a binary child entry."""
        _, manifest = self._load_item_manifest(item_ref)
        child = self._require_child_entry(manifest, suffix, item_ref)
        return self._get_hash_bytes(child.hash, file_name=child.id)

    def get_content(self, item_ref: str) -> ApiContent:
        """Fetch the `.content` JSON for an item."""
        return self._get_json_child(item_ref, ".content")

    def get_metadata(self, item_ref: str) -> ApiMetadata:
        """Fetch the `.metadata` JSON for an item."""
        return self._get_json_child(item_ref, ".metadata")

    def get_pdf(self, item_ref: str) -> bytes:
        """Fetch the original PDF bytes for an item."""
        return self._get_binary_child(item_ref, ".pdf")

    def get_epub(self, item_ref: str) -> bytes:
        """Fetch the original EPUB bytes for an item."""
        return self._get_binary_child(item_ref, ".epub")

    def get_document(self, item_ref: str) -> bytes:
        """Fetch the full raw item bundle as a zip archive."""
        _, manifest = self._load_item_manifest(item_ref)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for entry in manifest.entries:
                archive.writestr(
                    entry.id, self._get_hash_bytes(entry.hash, file_name=entry.id)
                )
        return buffer.getvalue()

    def _write_download(
        self,
        payload: bytes,
        output_path: pathlib.Path | str | None,
        default_name: str,
    ) -> pathlib.Path:
        """Write one downloaded payload to disk and return the saved path."""
        path = pathlib.Path(output_path or default_name).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    def _bundle_file_name(self, visible_name: str) -> str:
        """Return the default zip filename for a raw item bundle."""
        return visible_name if visible_name.lower().endswith('.zip') else f"{visible_name}.zip"

    def _get_original_payload(self, item_ref: str, file_type: str | None) -> bytes:
        """Return the original imported file bytes for one supported item."""
        if file_type == "pdf":
            return self.get_pdf(item_ref)
        if file_type == "epub":
            return self.get_epub(item_ref)
        raise DocumentNotFound(
            "This item does not have an original downloadable PDF/EPUB payload "
            f"(file type: {file_type or 'unknown'}). "
            "Native reMarkable notebooks should be downloaded as raw bundles instead. "
            "Use download_raw_bundle(...) or download_item(..., format='bundle')."
        )

    def download_raw_bundle(
        self, item_ref: str, output_path: pathlib.Path | str
    ) -> pathlib.Path:
        """Download an item's raw bundle to disk."""
        return self._write_download(self.get_document(item_ref), output_path, str(output_path))

    def download_original_file(
        self,
        item_ref: str,
        output_path: pathlib.Path | str | None = None,
    ) -> pathlib.Path:
        """Download the original PDF or EPUB payload for an item."""
        metadata = self.get_metadata(item_ref)
        content = self.get_content(item_ref)
        payload = self._get_original_payload(item_ref, content.get("fileType"))
        return self._write_download(payload, output_path, metadata["visibleName"])

    def download_item(
        self,
        item_ref: str,
        output_path: pathlib.Path | str | None = None,
        *,
        format: str = "auto",
    ) -> pathlib.Path:
        """Download one item in the requested format.

        Args:
            item_ref: Item name, path, id, or hash.
            output_path: Optional destination path.
            format: `auto`, `original`, or `bundle`.

        Returns:
            The path written to disk.

        Raises:
            ValueError: If `format` is unsupported.
            DocumentNotFound: If `original` is requested for a notebook or unsupported item.
        """
        if format not in {"auto", "original", "bundle"}:
            raise ValueError(f"Unsupported download format: {format}")

        metadata = self.get_metadata(item_ref)
        visible_name = metadata["visibleName"]

        if format == "bundle":
            bundle_name = self._bundle_file_name(visible_name)
            return self._write_download(self.get_document(item_ref), output_path, bundle_name)

        content = self.get_content(item_ref)
        file_type = content.get("fileType")
        if format == "auto" and file_type not in {"pdf", "epub"}:
            bundle_name = self._bundle_file_name(visible_name)
            return self._write_download(self.get_document(item_ref), output_path, bundle_name)

        payload = self._get_original_payload(item_ref, file_type)
        return self._write_download(payload, output_path, visible_name)

    def export_item(
        self,
        item_ref: str,
        output_dir: pathlib.Path | str,
        *,
        backend: str = "remarks",
        format: str = "pdf",
        executable: str = "remarks",
        device: str | None = None,
    ):
        """Export one item through an optional external renderer.

        Args:
            item_ref: Item name, path, id, or hash.
            output_dir: Directory where exported files should be copied.
            backend: Export backend name. Currently only ``remarks`` is supported.
            format: Requested export format.
            executable: Command name or path for the external backend.
            device: Optional device override forwarded to the backend.

        Returns:
            An export result describing the copied files.
        """
        from .export import export_item_with_backend

        return export_item_with_backend(
            self,
            item_ref,
            output_dir,
            backend=backend,
            format=format,
            executable=executable,
            device=device,
        )

    def _build_entry(self, simple_entry: SimpleEntry) -> Entry:
        """Hydrate a public item entry from its manifest and metadata."""
        _, manifest = self._load_item_manifest(simple_entry.hash, exact=True)
        metadata_entry = self._find_child_entry(manifest, ".metadata")
        if metadata_entry is None:
            raise DocumentNotFound(
                f"Metadata entry not found for item {simple_entry.id} ({simple_entry.hash})"
            )

        content_entry = self._find_child_entry(manifest, ".content")
        metadata = json.loads(
            self._get_hash_text(metadata_entry.hash, file_name=metadata_entry.id)
        )
        content = (
            json.loads(self._get_hash_text(content_entry.hash, file_name=content_entry.id))
            if content_entry
            else {}
        )
        tag_names = [
            tag.get("name", "") for tag in content.get("tags", []) if tag.get("name")
        ]
        common = {
            "id": simple_entry.id,
            "hash": simple_entry.hash,
            "visibleName": metadata["visibleName"],
            "lastModified": metadata["lastModified"],
            "pinned": metadata.get("pinned", False),
            "parent": metadata.get("parent", ROOT_PARENT_ID),
        }
        if metadata.get("type") == "TemplateType" or "templateVersion" in content:
            return TemplateEntry(
                **common,
                type="TemplateType",
                createdTime=metadata.get("createdTime"),
                source=metadata.get("source"),
                new=metadata.get("new"),
            )
        if content.get("fileType") is None:
            return CollectionEntry(**common, type="CollectionType", tags=tag_names)
        return DocumentEntry(
            **common,
            type="DocumentType",
            fileType=content["fileType"],
            lastOpened=metadata.get("lastOpened", ""),
            tags=tag_names,
        )

    def list_items(self, refresh: bool = False) -> list[IndexedItem]:
        """List lightweight library items for cheap scans and lookups.

        This fetches each item's manifest and metadata, but skips `.content`
        hydration. Use `list_hydrated_items()` when you need the richer
        hydrated `Entry` objects.
        """
        return list(self._indexed_items(refresh=refresh))

    def list_hydrated_items(self, refresh: bool = False) -> list[Entry]:
        """Hydrate all folders and documents in the cloud library."""
        return [self._build_entry(entry) for entry in self.list_ids(refresh=refresh)]

    def list_documents(self, refresh: bool = False) -> list[IndexedItem]:
        """Backward-compatible alias for `list_items`."""
        return self.list_items(refresh=refresh)

    def get_items(self, refresh: bool = False) -> list[IndexedItem]:
        """Backward-compatible alias for `list_items`."""
        return self.list_items(refresh=refresh)

    def get_item(self, item_ref: str, refresh: bool = False) -> Entry:
        """Return a single hydrated item by id or hash."""
        entry = self._resolve_indexed_item(item_ref, refresh=refresh)
        return self._build_entry(SimpleEntry(id=entry.id, hash=entry.hash))

    def get_item_exact(self, item_ref: str, refresh: bool = False) -> Entry:
        """Return a single hydrated item by exact id or hash."""
        entry = self._resolve_indexed_item(item_ref, refresh=refresh, exact=True)
        return self._build_entry(SimpleEntry(id=entry.id, hash=entry.hash))

    def get_item_by_id(self, item_ref: str, refresh: bool = False) -> Entry:
        """Backward-compatible alias for exact id/hash lookup."""
        return self.get_item_exact(item_ref, refresh=refresh)

    def _crc32c_base64(self, payload: bytes) -> str:
        """Compute the base64-encoded CRC32C checksum header value."""
        checksum = crc32c.crc32c(payload)
        return base64.b64encode(checksum.to_bytes(4, byteorder="big")).decode("ascii")

    def _put_blob(self, hash_value: str, file_name: str, payload: bytes) -> None:
        """Upload a raw blob to the immutable hash store."""
        headers = {
            "rm-filename": file_name,
            "x-goog-hash": f"crc32c={self._crc32c_base64(payload)}",
        }
        if file_name == self._manifest_file_name(ROOT_SPECIAL_ID):
            # rmapi sends this on root manifest uploads; httpx sends no
            # content-type for raw bytes.
            headers["content-type"] = "text/plain; charset=UTF-8"
        self._request(
            "PUT",
            f"{self.urls.files_root}/{hash_value}",
            headers=self._user_headers(headers),
            content=payload,
            expected_statuses=(200, 202),
            retry_on_unauthorized=True,
        )

    def put_file(self, file_name: str, payload: bytes) -> RawEntry:
        """Upload a leaf file into the immutable hash store."""
        hash_value = hashlib.sha256(payload).hexdigest()
        self._put_blob(hash_value, file_name, payload)
        return RawEntry(id=file_name, hash=hash_value, type=0, subfiles=0, size=len(payload))

    def put_text(self, file_name: str, payload: str) -> RawEntry:
        """Upload a UTF-8 text file into the immutable hash store."""
        return self.put_file(file_name, payload.encode("utf-8"))

    def put_content(self, file_name: str, payload: ApiContent) -> RawEntry:
        """Upload a `.content` JSON file."""
        return self.put_file(file_name, json_dumps(payload))

    def put_metadata(self, file_name: str, payload: ApiMetadata) -> RawEntry:
        """Upload a `.metadata` JSON file."""
        return self.put_file(file_name, json_dumps(payload))

    def put_entries(
        self,
        manifest_id: str,
        entries: list[RawEntry],
        schema_version: int,
    ) -> RawEntry:
        """Upload an item or root manifest."""
        payload = serialize_entries_manifest(manifest_id, entries, schema_version)
        manifest_hash = (
            hashlib.sha256(payload).hexdigest()
            if schema_version == 4
            else compute_manifest_hash(entries, schema_version)
        )
        self._put_blob(manifest_hash, f"{manifest_id}.docSchema", payload)
        return RawEntry(
            id=manifest_id,
            hash=manifest_hash,
            type=0 if schema_version > 3 else 0x80000000,
            subfiles=len(entries),
            size=sum(entry.size for entry in entries),
        )

    def _put_root_hash(
        self, root_hash: str, generation: int, broadcast: bool = True
    ) -> tuple[str, int]:
        """Commit a new root hash."""
        response = self._request(
            "PUT",
            self.urls.sync_root,
            headers=self._user_headers(),
            content=json.dumps(
                {"hash": root_hash, "generation": generation, "broadcast": broadcast}
            ),
            retry_on_unauthorized=True,
        )
        payload = response.json()
        new_hash = payload["hash"]
        new_generation = int(payload["generation"])
        previous_schema = self._root_state[2] if self._root_state else 3
        self._root_state = (new_hash, new_generation, previous_schema)
        self._directory_index_cache = None
        return new_hash, new_generation

    def _now_millis(self) -> str:
        """Return the current UNIX time in milliseconds as a string."""
        return str(int(time() * 1000))

    def _commit_root_entries(self, root_entries: list[RawEntry], generation: int) -> None:
        """Upload and activate a new root manifest, always in schema 4.

        The cloud keeps reporting the account's own `schemaVersion` afterwards
        (a schema-3 account stays 3), so the cached root state is left to
        `_put_root_hash` and item manifests keep following what the cloud reports.
        """
        new_root_entry = self.put_entries(
            ROOT_SPECIAL_ID, root_entries, ROOT_WRITE_SCHEMA_VERSION
        )
        self._put_root_hash(new_root_entry.hash, generation)

    def _replace_root_entry(
        self,
        current_hash: str,
        new_item_entry: RawEntry,
        *,
        refresh: bool = False,
    ) -> SimpleEntry:
        """Replace one item entry inside the current root manifest."""
        _, generation, _, root_entries = self._get_root_entries(refresh=refresh)
        root_index = next(
            (index for index, entry in enumerate(root_entries) if entry.hash == current_hash),
            None,
        )
        if root_index is None:
            raise HashNotFoundError(f"Could not find item hash {current_hash}")
        root_entries[root_index] = new_item_entry
        self._commit_root_entries(root_entries, generation)
        return SimpleEntry(id=new_item_entry.id, hash=new_item_entry.hash)

    def _append_root_entry(
        self, new_item_entry: RawEntry, *, refresh: bool = False
    ) -> SimpleEntry:
        """Append a new item entry to the current root manifest."""
        _, generation, _, root_entries = self._get_root_entries(refresh=refresh)
        root_entries.append(new_item_entry)
        self._commit_root_entries(root_entries, generation)
        return SimpleEntry(id=new_item_entry.id, hash=new_item_entry.hash)

    def _edit_metadata(
        self,
        item_ref: str,
        updates: dict[str, Any],
        refresh: bool = False,
    ) -> SimpleEntry:
        """Rewrite an item's metadata and root manifest."""
        simple_entry, manifest = self._load_item_manifest(item_ref, refresh=refresh)
        item_entries = list(manifest.entries)
        metadata_index = next(
            (index for index, entry in enumerate(item_entries) if entry.id.endswith(".metadata")),
            None,
        )
        if metadata_index is None:
            raise DocumentNotFound(f"Metadata entry not found for {item_ref}")

        metadata = json.loads(
            self._get_hash_text(
                item_entries[metadata_index].hash,
                file_name=item_entries[metadata_index].id,
            )
        )
        metadata.update(updates)
        item_entries[metadata_index] = self.put_metadata(item_entries[metadata_index].id, metadata)
        _, _, schema_version = self.get_root_state(refresh=refresh)
        new_item_entry = self.put_entries(simple_entry.id, item_entries, schema_version)
        return self._replace_root_entry(simple_entry.hash, new_item_entry, refresh=refresh)

    def rename(self, item_ref: str, visible_name: str, refresh: bool = False) -> SimpleEntry:
        """Rename an item."""
        return self._edit_metadata(item_ref, {"visibleName": visible_name}, refresh)

    def move(self, item_ref: str, parent: str, refresh: bool = False) -> SimpleEntry:
        """Move an item to a new parent folder or special parent."""
        parent_id = self.resolve_id(parent, refresh=refresh, allow_special=True)
        return self._edit_metadata(item_ref, {"parent": parent_id}, refresh)

    def delete(self, item_ref: str, refresh: bool = False) -> SimpleEntry:
        """Soft-delete an item by moving it to trash."""
        return self.move(item_ref, TRASH_PARENT_ID, refresh=refresh)

    def bulk_move(
        self, item_refs: list[str], parent: str, refresh: bool = False
    ) -> dict[str, str]:
        """Move multiple items to the same parent."""
        result: dict[str, str] = {}
        current_refresh = refresh
        for item_ref in item_refs:
            old_hash = self.resolve_hash(item_ref, refresh=current_refresh)
            new_entry = self.move(old_hash, parent, refresh=current_refresh)
            result[old_hash] = new_entry.hash
            current_refresh = True
        return result

    def bulk_delete(self, item_refs: list[str], refresh: bool = False) -> dict[str, str]:
        """Soft-delete multiple items by moving them to trash."""
        return self.bulk_move(item_refs, TRASH_PARENT_ID, refresh=refresh)

    def _build_document_content(self, file_type: str, payload: bytes) -> ApiContent:
        """Build a minimal document `.content` JSON payload."""
        return {
            "coverPageNumber": -1,
            "documentMetadata": {},
            "extraMetadata": {},
            "fileType": file_type,
            "fontName": "",
            "formatVersion": 1,
            "lineHeight": -1,
            "margins": 125,
            "orientation": "portrait",
            "originalPageCount": 1,
            "pageCount": 1,
            "pageTags": [],
            "pages": [str(uuid.uuid4())],
            "redirectionPageMap": [0],
            "sizeInBytes": str(len(payload)),
            "tags": [],
            "textAlignment": "justify",
            "textScale": 1,
            "zoomMode": "bestFit",
        }

    def _build_document_metadata(
        self,
        visible_name: str,
        parent: str,
        pinned: bool = False,
    ) -> ApiMetadata:
        """Build a minimal document `.metadata` JSON payload."""
        now = self._now_millis()
        return {
            "createdTime": now,
            "lastModified": now,
            "lastOpened": "0",
            "lastOpenedPage": 0,
            "parent": parent,
            "pinned": pinned,
            "type": "DocumentType",
            "visibleName": visible_name,
        }

    def _build_collection_metadata(self, visible_name: str, parent: str) -> ApiMetadata:
        """Build a minimal folder `.metadata` JSON payload."""
        now = self._now_millis()
        return {
            "createdTime": now,
            "lastModified": now,
            "parent": parent,
            "pinned": False,
            "type": "CollectionType",
            "visibleName": visible_name,
        }

    def _create_item(
        self,
        item_id: str,
        entries: list[RawEntry],
        *,
        refresh: bool = False,
    ) -> SimpleEntry:
        """Create a new item and append it to the root manifest."""
        _, _, schema_version = self.get_root_state(refresh=refresh)
        item_entry = self.put_entries(item_id, entries, schema_version)
        return self._append_root_entry(item_entry, refresh=refresh)

    def _put_document(
        self,
        visible_name: str,
        payload: bytes,
        *,
        file_type: str,
        parent: str = ROOT_PARENT_ID,
        refresh: bool = False,
    ) -> SimpleEntry:
        """Upload a new PDF or EPUB document."""
        parent_id = self.resolve_id(parent, refresh=refresh, allow_special=True)
        item_id = str(uuid.uuid4())
        entries = [
            self.put_content(
                f"{item_id}.content", self._build_document_content(file_type, payload)
            ),
            self.put_metadata(
                f"{item_id}.metadata",
                self._build_document_metadata(visible_name, parent_id),
            ),
            self.put_text(f"{item_id}.pagedata", "\n"),
            self.put_file(f"{item_id}.{file_type}", payload),
        ]
        return self._create_item(item_id, entries, refresh=refresh)

    def put_pdf(
        self,
        visible_name: str,
        payload: bytes,
        *,
        parent: str = ROOT_PARENT_ID,
        refresh: bool = False,
    ) -> SimpleEntry:
        """Upload a PDF document using the low-level immutable API."""
        return self._put_document(
            visible_name, payload, file_type="pdf", parent=parent, refresh=refresh
        )

    def put_epub(
        self,
        visible_name: str,
        payload: bytes,
        *,
        parent: str = ROOT_PARENT_ID,
        refresh: bool = False,
    ) -> SimpleEntry:
        """Upload an EPUB document using the low-level immutable API."""
        return self._put_document(
            visible_name, payload, file_type="epub", parent=parent, refresh=refresh
        )

    def put_folder(
        self,
        visible_name: str,
        *,
        parent: str = ROOT_PARENT_ID,
        refresh: bool = False,
    ) -> SimpleEntry:
        """Create a folder using the low-level immutable API."""
        parent_id = self.resolve_id(parent, refresh=refresh, allow_special=True)
        item_id = str(uuid.uuid4())
        entries = [
            self.put_content(f"{item_id}.content", {"tags": []}),
            self.put_metadata(
                f"{item_id}.metadata",
                self._build_collection_metadata(visible_name, parent_id),
            ),
        ]
        return self._create_item(item_id, entries, refresh=refresh)

    def upload_file_simple(
        self, visible_name: str, payload: bytes, mime_type: str
    ) -> SimpleEntry:
        """Upload a file using the browser-style simple upload endpoint."""
        meta = base64.b64encode(
            json.dumps({"file_name": visible_name}, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        response = self._request(
            "POST",
            self.urls.simple_upload,
            headers=self._user_headers(
                {
                    "Content-Type": mime_type,
                    "rm-meta": meta,
                    "rm-source": "RoR-Browser",
                }
            ),
            content=payload,
            expected_statuses=(200, 201),
            retry_on_unauthorized=True,
        )
        payload_json = response.json()
        return SimpleEntry(id=payload_json.get("docID") or payload_json.get("id"), hash=payload_json["hash"])

    def upload_pdf(self, visible_name: str, payload: bytes) -> SimpleEntry:
        """Upload a PDF using the simple browser-compatible endpoint."""
        return self.upload_file_simple(visible_name, payload, "application/pdf")

    def upload_epub(self, visible_name: str, payload: bytes) -> SimpleEntry:
        """Upload an EPUB using the simple browser-compatible endpoint."""
        return self.upload_file_simple(visible_name, payload, "application/epub+zip")

    def upload_folder(self, visible_name: str) -> SimpleEntry:
        """Create a folder using the simple browser-compatible endpoint."""
        return self.upload_file_simple(visible_name, b"", "folder")


__all__ = ["Client", "IndexedItem", "ROOT_PARENT_ID", "ROOT_SPECIAL_ID", "TRASH_PARENT_ID"]
