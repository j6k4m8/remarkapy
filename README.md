# remarkapy

A Python package for interacting with the reMarkable Cloud API.

## Quickstart

```python
from remarkapy import Client

client = Client()
items = client.list_items()
for item in items[:5]:
    print(item.type, item.visibleName, item.parent, item.id, item.hash)
```

Use `client.list_items()` for cheap library scans and lookup workflows.
`client.list_hydrated_items()` is the explicit full-hydration variant and
fetches each item's manifest, metadata, and `.content` blob.

Download a raw bundle:

```python
from remarkapy import Client

client = Client()
first = client.list_items()[0]
client.download_raw_bundle(first.hash, "bundle.zip")
```

Upload a PDF:

```python
from remarkapy import Client

client = Client()
with open("example.pdf", "rb") as handle:
    created = client.put_pdf("Example.pdf", handle.read())
print(created)
```

CLI examples:

```bash
uv run remarkapy init
uv run rkpy ls
uv run rkpy ls Papers/
uv run rkpy ls -r Papers/
uv run rkpy get Papers/Example.pdf
uv run rkpy get Papers/Example.pdf --output ./Example.pdf
uv run rkpy get "Meeting Notes" --format bundle
uv run rkpy export "Meeting Notes" ./exports --format pdf
uv run rkpy info Papers/Example.pdf
uv run remarkapy get-id <item-id-or-hash>
uv run rkpy put-pdf ./example.pdf --parent Papers/
uv run rkpy mkdir Inbox
uv run rkpy rename Papers/Example.pdf "New Name"
uv run rkpy move Papers/Example.pdf Inbox/
uv run rkpy trash Papers/Old Draft.pdf
```

## Why another

As far as I can tell, the major reMarkable client SDKs have all suffered from
API churn.

-   `rmapy` is archived.
-   `rmapi` is archived (but resurrected??)
-   reMarkable continues to change endpoints and backend behavior.

`remarkapy` aims to stay useful by:

-   discovering the current public webapp/raw hosts at runtime,
-   supporting the current immutable-manifest sync protocol,
-   exposing a clean Python library API first,
-   keeping real integration tests available behind an explicit opt-in flag.

## Optional export backends

-   `remarkapy` does not render annotations itself.
-   Install the `remarks` command separately if you want export support (for example: `uv tool install git+https://github.com/avncharlie/remarks.git`).
-   `rkpy export` shells out to that installed `remarks` executable by default, but `--remarks-cmd` still lets you override it.
-   For single-file PDF/Markdown exports, you can pass an exact output file path like `./notes.pdf`; otherwise pass an output directory.
-   `remarks` needs the system Cairo library for PDF rendering; on macOS install it with `brew install cairo`.
-   Export output is staged in a temporary bundle and copied back into your requested output directory.

## Features

-   [x] Base authentication and device-token reuse
-   [x] Endpoint discovery
-   [x] List documents and folders
-   [x] Download original PDFs and EPUBs
-   [x] Download raw item bundles as zip archives
-   [x] Upload PDFs and EPUBs
-   [x] Create folders
-   [x] Rename items
-   [x] Move items
-   [x] Delete items by moving them to trash
-   [x] Mock-backed pytest suite
-   [x] Read-only live-account smoke tests

## Roadmap

-   [ ] Download annotated PDFs rendered by the service, if available
-   [x] Add a small CLI wrapper for common operations
-   [ ] Add safer live mutation tests using temporary fixtures
-   [ ] Add sync-to-directory and sync-from-directory helpers
-   [ ] Add device registration from a dedicated command-line flow

---

## Testing

### Dangerzone Safety

There are live tests in this repo that interact with the real reMarkable Cloud API. These tests are marked with the `live` pytest marker and are skipped by default to prevent accidental mutations of real accounts.

The live tests in this repo are intentionally **read-only** by default.

To run them, opt in explicitly:

```bash
REMARKAPY_RUN_LIVE=1 uv run pytest -q -m live
```

The destructive paths (`rename`, `move`, `delete`, `put_*`) are covered by the
mock test suite. Before adding live destructive tests, use temporary folders or
dummy uploads that are safe to clean up.

Injected or mock-backed clients should use in-memory tokens or an explicit test
config path; they must not fall back to the default rmapi config location.
