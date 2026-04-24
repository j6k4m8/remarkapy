"""Read-only live tests against the current authenticated account."""

from __future__ import annotations

import io
import zipfile

import pytest

from remarkapy.api import Client

pytestmark = pytest.mark.live


def test_live_endpoint_discovery_and_list_items() -> None:
    """The live client should discover endpoints and list real items."""
    client = Client()
    items = client.list_items(refresh=True)

    assert client.urls.webapp_host.startswith("https://")
    assert client.urls.raw_host.startswith("https://")
    assert all(len(item.hash) == 64 for item in items)


def test_live_download_raw_bundle_smoke() -> None:
    """The live client should be able to download at least one raw item bundle."""
    client = Client()
    items = client.list_items(refresh=True)
    item = items[0] if items else None
    if item is None:
        pytest.skip("No live items available to download.")

    bundle = client.get_document(item.hash)

    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        assert len(archive.namelist()) >= 2
