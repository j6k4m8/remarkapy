"""Shared pytest configuration for unit and live tests."""

from __future__ import annotations

import os

import pytest


LIVE_FLAG = "REMARKAPY_RUN_LIVE"


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers used in the test suite."""
    config.addinivalue_line("markers", "live: exercises the real reMarkable account")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip live tests unless the caller explicitly opts in."""
    del config
    if os.environ.get(LIVE_FLAG) == "1":
        return

    skip_live = pytest.mark.skip(reason=f"Set {LIVE_FLAG}=1 to run live account tests.")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)
