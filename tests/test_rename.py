import os

import pytest

from remarkapy.api import Client

pytestmark = pytest.mark.integration


def test_rename_item_smoke():
    item_id = os.environ.get("REMARKAPY_TEST_ITEM_ID")
    if not item_id:
        pytest.skip("Set REMARKAPY_TEST_ITEM_ID to run this test.")

    api = Client()
    api.rename_item(item_id, new_name="coolname")
