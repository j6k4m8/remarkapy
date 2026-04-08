"""Tests for the optional external export adapter."""

from __future__ import annotations

import pathlib
import subprocess

import pytest

from remarkapy.export import ExportResult, export_item_with_backend
from remarkapy.exceptions import ExportBackendUnavailableError, ExportFailedError


class DummyClient:
    """Minimal client stub for export tests."""

    def get_metadata(self, item_ref: str) -> dict[str, str]:
        """Return fake metadata for one item."""
        return {"visibleName": f"{item_ref}-name"}

    def get_document(self, item_ref: str) -> bytes:
        """Return a fake raw bundle archive."""
        return f"bundle:{item_ref}".encode("utf-8")


def test_export_item_with_remarks_copies_matching_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """The remarks adapter should stage input and collect only requested outputs."""
    recorded: dict[str, object] = {}

    def fake_which(command: str) -> str:
        assert command == "remarks-bin"
        return "/usr/local/bin/remarks-bin"

    def fake_run(command: list[str], check: bool, capture_output: bool, text: bool):
        del check, capture_output, text
        recorded["command"] = command
        input_bundle = pathlib.Path(command[1])
        raw_output_dir = pathlib.Path(command[2])
        assert input_bundle.suffix == ".rmdoc"
        assert input_bundle.read_bytes() == b"bundle:item-1"
        (raw_output_dir / "Shelf").mkdir(parents=True, exist_ok=True)
        (raw_output_dir / "Shelf" / "Exported.pdf").write_bytes(b"pdf")
        (raw_output_dir / "Shelf" / "Exported.md").write_text("# notes", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr("remarkapy.export.shutil.which", fake_which)
    monkeypatch.setattr("remarkapy.export.subprocess.run", fake_run)

    result = export_item_with_backend(
        DummyClient(),
        "item-1",
        tmp_path / "exports",
        format="pdf",
        executable="remarks-bin",
        device="reMarkable2",
    )

    assert isinstance(result, ExportResult)
    assert recorded["command"] == [
        "/usr/local/bin/remarks-bin",
        recorded["command"][1],
        recorded["command"][2],
        "--device",
        "reMarkable2",
    ]
    assert result.backend == "remarks"
    assert result.format == "pdf"
    assert result.files == [(tmp_path / "exports" / "Shelf" / "Exported.pdf").resolve()]
    assert result.files[0].read_bytes() == b"pdf"
    assert not (tmp_path / "exports" / "Shelf" / "Exported.md").exists()


def test_export_item_can_write_to_exact_pdf_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """Single-file PDF exports should support an exact destination path."""

    monkeypatch.setattr("remarkapy.export.shutil.which", lambda _: "/usr/local/bin/remarks")

    def fake_run(command: list[str], check: bool, capture_output: bool, text: bool):
        del check, capture_output, text
        raw_output_dir = pathlib.Path(command[2])
        (raw_output_dir / "Shelf").mkdir(parents=True, exist_ok=True)
        (raw_output_dir / "Shelf" / "Exported.pdf").write_bytes(b"pdf")
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr("remarkapy.export.subprocess.run", fake_run)

    target = tmp_path / "ubraintest.pdf"
    result = export_item_with_backend(DummyClient(), "item-1", target, format="pdf")

    assert result.output_dir == tmp_path
    assert result.files == [target.resolve()]
    assert target.read_bytes() == b"pdf"


def test_export_item_requires_installed_backend(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    """The adapter should fail clearly when the remarks command is missing."""
    monkeypatch.setattr("remarkapy.export.shutil.which", lambda _: None)

    with pytest.raises(ExportBackendUnavailableError):
        export_item_with_backend(DummyClient(), "item-1", tmp_path / "exports")



def test_export_item_reports_backend_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """The adapter should surface stderr when the external backend fails."""
    monkeypatch.setattr("remarkapy.export.shutil.which", lambda _: "/usr/local/bin/remarks")

    def fake_run(command: list[str], check: bool, capture_output: bool, text: bool):
        del command, check, capture_output, text
        raise subprocess.CalledProcessError(2, ["remarks"], output="", stderr="boom")

    monkeypatch.setattr("remarkapy.export.subprocess.run", fake_run)

    with pytest.raises(ExportFailedError, match="boom"):
        export_item_with_backend(DummyClient(), "item-1", tmp_path / "exports")



def test_export_item_reports_missing_cairo_with_hint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """Cairo loader failures should produce an actionable macOS hint."""
    monkeypatch.setattr("remarkapy.export.shutil.which", lambda _: "/usr/local/bin/remarks")

    def fake_run(command: list[str], check: bool, capture_output: bool, text: bool):
        del command, check, capture_output, text
        raise subprocess.CalledProcessError(
            1,
            ["remarks"],
            output="",
            stderr='OSError: no library called "cairo-2" was found',
        )

    monkeypatch.setattr("remarkapy.export.subprocess.run", fake_run)

    with pytest.raises(ExportFailedError, match="brew install cairo"):
        export_item_with_backend(DummyClient(), "item-1", tmp_path / "exports")
