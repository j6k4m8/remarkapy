"""Mock-backed tests for high-level client behavior."""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import uuid
import zipfile
from dataclasses import dataclass
from typing import Any

import httpx

from remarkapy.api import Client
from remarkapy.entries import RawEntry


RAW_HOST = "https://eu.tectonic.remarkable.com"
WEBAPP_HOST = "https://webapp-prod.cloud.remarkable.engineering"
UPLOAD_HOST = "https://internal.cloud.remarkable.com"


@dataclass(slots=True)
class FakeItem:
    """A fully materialized item in the fake cloud."""

    item_id: str
    item_hash: str


class FakeRemarkableCloud:
    """A tiny in-memory reMarkable cloud for unit tests."""

    def __init__(self, *, blob_put_status_code: int = 200) -> None:
        self.device_token = "device-token"
        self.user_token = "user-token"
        self.generation = 100
        self.schema_version = 3
        self.blob_put_status_code = blob_put_status_code
        self.storage: dict[str, bytes] = {}
        self.hash_names: dict[str, str] = {}
        self.root_entries: list[RawEntry] = []
        self.requested_blob_ids: list[str] = []
        self.last_simple_upload: dict[str, Any] | None = None

        self.folder = self._create_folder("Papers", parent="", item_id="11111111-1111-4111-8111-111111111111")
        self.document = self._create_document(
            "Example.pdf",
            parent=self.folder.item_id,
            item_id="22222222-2222-4222-8222-222222222222",
            payload=b"%PDF-1.4\nmock pdf\n",
        )
        self._refresh_root()

    def _sha256(self, payload: bytes) -> str:
        return hashlib.sha256(payload).hexdigest()

    def _store_blob(self, file_name: str, payload: bytes) -> RawEntry:
        hash_value = self._sha256(payload)
        self.storage[hash_value] = payload
        self.hash_names[hash_value] = file_name
        return RawEntry(id=file_name, hash=hash_value, type=0, subfiles=0, size=len(payload))

    def _manifest_payload(self, manifest_id: str, entries: list[RawEntry]) -> bytes:
        ordered = sorted(entries, key=lambda entry: entry.id)
        payload = ["3\n"]
        for entry in ordered:
            entry_type = "80000000" if entry.type == 0x80000000 else str(entry.type)
            payload.append(f"{entry.hash}:{entry_type}:{entry.id}:{entry.subfiles}:{entry.size}\n")
        return "".join(payload).encode("utf-8")

    def _manifest_hash(self, entries: list[RawEntry]) -> str:
        ordered = sorted(entries, key=lambda entry: entry.id)
        digest_input = b"".join(bytes.fromhex(entry.hash) for entry in ordered)
        return hashlib.sha256(digest_input).hexdigest()

    def _put_manifest(self, manifest_id: str, entries: list[RawEntry]) -> RawEntry:
        payload = self._manifest_payload(manifest_id, entries)
        hash_value = self._manifest_hash(entries)
        self.storage[hash_value] = payload
        self.hash_names[hash_value] = f"{manifest_id}.docSchema"
        return RawEntry(
            id=manifest_id,
            hash=hash_value,
            type=0x80000000,
            subfiles=len(entries),
            size=sum(entry.size for entry in entries),
        )

    def _create_folder(self, visible_name: str, parent: str, item_id: str | None = None) -> FakeItem:
        item_id = item_id or str(uuid.uuid4())
        now = "1000"
        content_entry = self._store_blob(f"{item_id}.content", json.dumps({"tags": []}).encode())
        metadata_entry = self._store_blob(
            f"{item_id}.metadata",
            json.dumps(
                {
                    "createdTime": now,
                    "lastModified": now,
                    "parent": parent,
                    "pinned": False,
                    "type": "CollectionType",
                    "visibleName": visible_name,
                }
            ).encode(),
        )
        item_entry = self._put_manifest(item_id, [content_entry, metadata_entry])
        self.root_entries.append(item_entry)
        return FakeItem(item_id=item_id, item_hash=item_entry.hash)

    def _create_document(
        self,
        visible_name: str,
        parent: str,
        item_id: str | None = None,
        payload: bytes = b"%PDF-1.4\n",
    ) -> FakeItem:
        item_id = item_id or str(uuid.uuid4())
        now = "1000"
        content_entry = self._store_blob(
            f"{item_id}.content",
            json.dumps(
                {
                    "coverPageNumber": -1,
                    "documentMetadata": {},
                    "extraMetadata": {},
                    "fileType": "pdf",
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
            ).encode(),
        )
        metadata_entry = self._store_blob(
            f"{item_id}.metadata",
            json.dumps(
                {
                    "createdTime": now,
                    "lastModified": now,
                    "lastOpened": "0",
                    "lastOpenedPage": 0,
                    "parent": parent,
                    "pinned": False,
                    "type": "DocumentType",
                    "visibleName": visible_name,
                }
            ).encode(),
        )
        pagedata_entry = self._store_blob(f"{item_id}.pagedata", b"\n")
        pdf_entry = self._store_blob(f"{item_id}.pdf", payload)
        item_entry = self._put_manifest(
            item_id,
            [content_entry, metadata_entry, pagedata_entry, pdf_entry],
        )
        self.root_entries.append(item_entry)
        return FakeItem(item_id=item_id, item_hash=item_entry.hash)

    def _create_notebook(
        self,
        visible_name: str,
        parent: str,
        item_id: str | None = None,
    ) -> FakeItem:
        item_id = item_id or str(uuid.uuid4())
        now = "1000"
        page_id = str(uuid.uuid4())
        content_entry = self._store_blob(
            f"{item_id}.content",
            json.dumps(
                {
                    "coverPageNumber": -1,
                    "documentMetadata": {},
                    "extraMetadata": {},
                    "fileType": "notebook",
                    "fontName": "",
                    "formatVersion": 1,
                    "lineHeight": -1,
                    "margins": 125,
                    "orientation": "portrait",
                    "pageCount": 1,
                    "pageTags": [],
                    "pages": [page_id],
                    "redirectionPageMap": [0],
                    "sizeInBytes": "0",
                    "tags": [],
                    "textAlignment": "justify",
                    "textScale": 1,
                    "zoomMode": "bestFit",
                }
            ).encode(),
        )
        metadata_entry = self._store_blob(
            f"{item_id}.metadata",
            json.dumps(
                {
                    "createdTime": now,
                    "lastModified": now,
                    "lastOpened": "0",
                    "lastOpenedPage": 0,
                    "parent": parent,
                    "pinned": False,
                    "type": "DocumentType",
                    "visibleName": visible_name,
                }
            ).encode(),
        )
        pagedata_entry = self._store_blob(f"{item_id}.pagedata", f"{page_id}\n".encode())
        page_entry = self._store_blob(page_id, b"notebook-page")
        item_entry = self._put_manifest(
            item_id,
            [content_entry, metadata_entry, pagedata_entry, page_entry],
        )
        self.root_entries.append(item_entry)
        return FakeItem(item_id=item_id, item_hash=item_entry.hash)

    def _refresh_root(self) -> None:
        root_entry = self._put_manifest("root", self.root_entries)
        self.root_hash = root_entry.hash

    def _json(self, data: Any, status_code: int = 200) -> httpx.Response:
        return httpx.Response(status_code, json=data)

    def _text(self, text: str, status_code: int = 200) -> httpx.Response:
        return httpx.Response(status_code, text=text)

    def transport(self, request: httpx.Request) -> httpx.Response:
        """Serve a fake reMarkable API response."""
        path = request.url.path

        if request.method == "GET" and path == "/discovery/v1/endpoints":
            return self._json(
                {
                    "notifications": "eu.tectonic.remarkable.com",
                    "webapp": "webapp-prod.cloud.remarkable.engineering",
                    "mqttbroker": "vernemq-prod.cloud.remarkable.engineering",
                }
            )

        if request.method == "POST" and path == "/token/json/2/user/new":
            auth = request.headers.get("Authorization", "")
            if auth != f"Bearer {self.device_token}":
                return self._text("unauthorized", status_code=401)
            return self._text(self.user_token)

        if request.method == "GET" and path == "/sync/v4/root":
            return self._json(
                {
                    "hash": self.root_hash,
                    "generation": self.generation,
                    "schemaVersion": self.schema_version,
                    "deletedImmutableAction": "rollback",
                }
            )

        if request.method == "GET" and path.startswith("/sync/v3/files/"):
            hash_value = path.rsplit("/", 1)[-1]
            payload = self.storage.get(hash_value)
            if payload is None:
                return self._text("missing", status_code=404)
            self.requested_blob_ids.append(self.hash_names.get(hash_value, hash_value))
            return httpx.Response(200, content=payload)

        if request.method == "PUT" and path.startswith("/sync/v3/files/"):
            hash_value = path.rsplit("/", 1)[-1]
            payload = request.content
            self.storage[hash_value] = payload
            return self._text("ok", status_code=self.blob_put_status_code)

        if request.method == "PUT" and path == "/sync/v3/root":
            payload = json.loads(request.content.decode("utf-8"))
            if int(payload["generation"]) != self.generation:
                return self._text('{"message":"precondition failed"}\n', status_code=412)
            self.root_hash = payload["hash"]
            self.generation += 1
            return self._json({"hash": self.root_hash, "generation": self.generation})

        if request.method == "POST" and path == "/doc/v2/files":
            meta = base64.b64decode(request.headers["rm-meta"]).decode("utf-8")
            visible_name = json.loads(meta)["file_name"]
            mime_type = request.headers["Content-Type"]
            if mime_type == "folder":
                created = self._create_folder(visible_name, parent="")
            else:
                created = self._create_document(visible_name, parent="", payload=request.content)
            self._refresh_root()
            self.last_simple_upload = {"name": visible_name, "mime_type": mime_type}
            return self._json({"docID": created.item_id, "hash": created.item_hash})

        raise AssertionError(f"Unhandled request: {request.method} {request.url}")


def make_client(cloud: FakeRemarkableCloud) -> Client:
    """Create a test client wired to the fake cloud."""
    transport = httpx.MockTransport(cloud.transport)
    http_client = httpx.Client(transport=transport)
    return Client(device_token=cloud.device_token, http_client=http_client, persist_config=False)


def test_list_items_returns_lightweight_documents_and_collections() -> None:
    """The lightweight list should expose folder and document summaries."""
    cloud = FakeRemarkableCloud()
    client = make_client(cloud)

    items = client.list_items()

    assert len(items) == 2
    assert {item.type for item in items} == {"CollectionType", "DocumentType"}
    assert {item.visibleName for item in items} == {"Papers", "Example.pdf"}
    assert not any(name.endswith(".content") for name in cloud.requested_blob_ids)


def test_list_hydrated_items_fetches_content() -> None:
    """The explicit hydrated list should fetch per-item `.content` blobs."""
    cloud = FakeRemarkableCloud()
    client = make_client(cloud)

    items = client.list_hydrated_items()

    assert len(items) == 2
    assert {item.type for item in items} == {"CollectionType", "DocumentType"}
    assert {item.visibleName for item in items} == {"Papers", "Example.pdf"}
    assert any(name.endswith(".content") for name in cloud.requested_blob_ids)


def test_list_directory_returns_lightweight_children() -> None:
    """Directory listings should be lightweight by default."""
    cloud = FakeRemarkableCloud()
    client = make_client(cloud)

    items = client.list_directory("Papers/")

    assert [item.visibleName for item in items] == ["Example.pdf"]
    assert not any(name.endswith(".content") for name in cloud.requested_blob_ids)


def test_list_directory_paths_root_and_folder() -> None:
    """Directory listings should default to one level and support folder paths."""
    cloud = FakeRemarkableCloud()
    client = make_client(cloud)

    root_paths = client.list_directory_paths()
    folder_paths = client.list_directory_paths("Papers/")

    assert root_paths == ["Papers/"]
    assert folder_paths == ["Example.pdf"]


def test_list_directory_paths_recursive() -> None:
    """Recursive directory listings should return nested relative paths."""
    cloud = FakeRemarkableCloud()
    child_folder = client = None
    client = make_client(cloud)
    child_folder = client.put_folder("Subfolder", parent=cloud.folder.item_id)
    client.put_pdf("Nested.pdf", b"%PDF-1.4\nnested\n", parent=child_folder.id, refresh=True)

    paths = client.list_directory_paths("Papers/", recursive=True, refresh=True)

    assert paths == ["Example.pdf", "Subfolder/", "Subfolder/Nested.pdf"]


def test_get_item_supports_name_and_path_references() -> None:
    """Human-friendly names and folder paths should resolve to items."""
    cloud = FakeRemarkableCloud()
    client = make_client(cloud)

    by_name = client.get_item("Example.pdf")
    by_path = client.get_item("Papers/Example.pdf")
    by_exact = client.get_item_exact(cloud.document.item_id)

    assert by_name.id == cloud.document.item_id
    assert by_path.id == cloud.document.item_id
    assert by_exact.id == cloud.document.item_id


def test_get_item_raises_for_ambiguous_names() -> None:
    """Duplicate visible names should require a path or exact id/hash lookup."""
    cloud = FakeRemarkableCloud()
    cloud._create_document(
        "Example.pdf",
        parent="",
        item_id="33333333-3333-4333-8333-333333333333",
        payload=b"%PDF-1.4\nother\n",
    )
    cloud._refresh_root()
    client = make_client(cloud)

    try:
        client.get_item("Example.pdf")
    except Exception as exc:
        message = str(exc)
    else:
        raise AssertionError("Expected ambiguous name lookup to fail")

    assert "matched multiple items" in message


def test_download_item_auto_falls_back_to_bundle_for_notebook(tmp_path) -> None:
    """Notebook downloads should fall back to raw bundles in auto mode."""
    cloud = FakeRemarkableCloud()
    notebook = cloud._create_notebook("Meeting Notes", parent=cloud.folder.item_id)
    cloud._refresh_root()
    client = make_client(cloud)

    output = tmp_path / "meeting-notes.zip"
    path = client.download_item(notebook.item_id, output)

    assert path == output.resolve()
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
    assert f"{notebook.item_id}.content" in names
    assert f"{notebook.item_id}.metadata" in names



def test_download_original_file_explains_notebook_limit() -> None:
    """Notebook original-file downloads should explain the supported fallback."""
    cloud = FakeRemarkableCloud()
    notebook = cloud._create_notebook("Meeting Notes", parent=cloud.folder.item_id)
    cloud._refresh_root()
    client = make_client(cloud)

    try:
        client.download_original_file(notebook.item_id)
    except Exception as exc:
        message = str(exc)
    else:
        raise AssertionError("Expected notebook original download to fail")

    assert "Native reMarkable notebooks" in message
    assert "download_item(..., format='bundle')" in message


def test_rename_updates_metadata_and_root_hash() -> None:
    """Renaming should rewrite metadata and advance the root generation."""
    cloud = FakeRemarkableCloud()
    client = make_client(cloud)
    before_generation = cloud.generation

    renamed = client.rename(cloud.document.item_hash, "Renamed.pdf")
    refreshed = client.get_item(renamed.hash, refresh=True)

    assert refreshed.visibleName == "Renamed.pdf"
    assert refreshed.hash == renamed.hash
    assert cloud.generation == before_generation + 1


def test_move_and_delete_update_parent() -> None:
    """Move should update parent ids and delete should move to trash."""
    cloud = FakeRemarkableCloud()
    client = make_client(cloud)

    moved = client.move(cloud.document.item_hash, "")
    moved_item = client.get_item(moved.hash, refresh=True)
    deleted = client.delete(moved.hash, refresh=True)
    deleted_item = client.get_item(deleted.hash, refresh=True)

    assert moved_item.parent == ""
    assert deleted_item.parent == "trash"


def test_put_folder_and_put_pdf_create_new_items() -> None:
    """Folder and PDF creation should append new items to the root manifest."""
    cloud = FakeRemarkableCloud()
    client = make_client(cloud)

    folder = client.put_folder("Inbox")
    document = client.put_pdf("Hello.pdf", b"%PDF-1.4\nhello\n", parent=folder.id, refresh=True)
    items = client.list_items(refresh=True)

    assert any(item.visibleName == "Inbox" and item.id == folder.id for item in items)
    assert any(item.visibleName == "Hello.pdf" and item.id == document.id for item in items)


def test_put_folder_and_put_pdf_accept_blob_upload_202() -> None:
    """Low-level immutable uploads should tolerate `202 Accepted` blob writes."""
    cloud = FakeRemarkableCloud(blob_put_status_code=202)
    client = make_client(cloud)

    folder = client.put_folder("Inbox")
    document = client.put_pdf("Hello.pdf", b"%PDF-1.4\nhello\n", parent=folder.id, refresh=True)
    items = client.list_items(refresh=True)

    assert any(item.visibleName == "Inbox" and item.id == folder.id for item in items)
    assert any(item.visibleName == "Hello.pdf" and item.id == document.id for item in items)


def test_download_raw_bundle_contains_all_manifest_files(tmp_path: pathlib.Path) -> None:
    """Raw bundle downloads should create a zip with all item files."""
    cloud = FakeRemarkableCloud()
    client = make_client(cloud)
    output = tmp_path / "document.zip"

    client.download_raw_bundle(cloud.document.item_hash, output)

    with zipfile.ZipFile(output) as archive:
        names = sorted(archive.namelist())
    assert any(name.endswith(".content") for name in names)
    assert any(name.endswith(".metadata") for name in names)
    assert any(name.endswith(".pagedata") for name in names)
    assert any(name.endswith(".pdf") for name in names)


def test_simple_upload_pdf_uses_browser_endpoint() -> None:
    """Simple uploads should call the browser-style upload endpoint."""
    cloud = FakeRemarkableCloud()
    client = make_client(cloud)

    created = client.upload_pdf("Browser.pdf", b"%PDF-1.4\nfrom browser\n")
    items = client.list_items(refresh=True)

    assert cloud.last_simple_upload == {"name": "Browser.pdf", "mime_type": "application/pdf"}
    assert any(item.id == created.id for item in items)
