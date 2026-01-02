import os

import pytest


def pytest_collection_modifyitems(config, items):
    if os.environ.get("REMARKAPY_RUN_INTEGRATION") == "1":
        return

    skip_integration = pytest.mark.skip(
        reason="Set REMARKAPY_RUN_INTEGRATION=1 to run integration tests."
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)
