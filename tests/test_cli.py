"""Tests for the remarkapy CLI wrapper."""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass

import remarkapy.cli as cli


@dataclass
class FakeEntry:
    """Simple fake dataclass returned by the fake CLI client."""

    id: str
    hash: str
    visibleName: str


class FakeClient:
    """Small fake client for CLI tests."""

    def __init__(self, configfile: str | pathlib.Path | None = None, **_: object) -> None:
        self.configfile = configfile
        self.calls: list[tuple] = []

    def __enter__(self) -> "FakeClient":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def refresh_user_token(self) -> str:
        self.calls.append(("refresh_user_token",))
        return "user-token"

    def list_items(self) -> list[FakeEntry]:
        self.calls.append(("list_items",))
        return [FakeEntry(id="1", hash="a" * 64, visibleName="Example.pdf")]

    def list_directory_paths(self, path: str = "", recursive: bool = False) -> list[str]:
        self.calls.append(("list_directory_paths", path, recursive))
        if recursive:
            return ["Papers/", "Papers/Example.pdf"]
        if path in {"", "/"}:
            return ["Papers/", "Inbox/"]
        return ["Example.pdf"]

    def get_item(self, item_ref: str) -> FakeEntry:
        self.calls.append(("get_item", item_ref))
        return FakeEntry(id=item_ref, hash="b" * 64, visibleName="One")

    def get_item_exact(self, item_ref: str) -> FakeEntry:
        self.calls.append(("get_item_exact", item_ref))
        return FakeEntry(id=item_ref, hash="c" * 64, visibleName="Exact")

    def download_item(
        self,
        item_ref: str,
        output: str | None,
        *,
        format: str = "auto",
    ) -> pathlib.Path:
        self.calls.append(("download_item", item_ref, output, format))
        if output is not None:
            return pathlib.Path(output)
        if format == "bundle" or "Notebook" in item_ref:
            return pathlib.Path("output.zip")
        return pathlib.Path("output.pdf")

    def download_original_file(self, item_ref: str, output: str | None) -> pathlib.Path:
        self.calls.append(("download_original_file", item_ref, output))
        return pathlib.Path(output or "output.pdf")

    def download_raw_bundle(self, item_ref: str, output: str) -> pathlib.Path:
        self.calls.append(("download_raw_bundle", item_ref, output))
        return pathlib.Path(output)

    def put_pdf(self, name: str, payload: bytes, parent: str = "") -> FakeEntry:
        self.calls.append(("put_pdf", name, payload, parent))
        return FakeEntry(id="pdf-id", hash="c" * 64, visibleName=name)

    def put_epub(self, name: str, payload: bytes, parent: str = "") -> FakeEntry:
        self.calls.append(("put_epub", name, payload, parent))
        return FakeEntry(id="epub-id", hash="d" * 64, visibleName=name)

    def put_folder(self, name: str, parent: str = "") -> FakeEntry:
        self.calls.append(("put_folder", name, parent))
        return FakeEntry(id="dir-id", hash="e" * 64, visibleName=name)

    def rename(self, item_ref: str, name: str) -> FakeEntry:
        self.calls.append(("rename", item_ref, name))
        return FakeEntry(id=item_ref, hash="f" * 64, visibleName=name)

    def move(self, item_ref: str, parent: str) -> FakeEntry:
        self.calls.append(("move", item_ref, parent))
        return FakeEntry(id=item_ref, hash="0" * 64, visibleName="Moved")

    def delete(self, item_ref: str) -> FakeEntry:
        self.calls.append(("delete", item_ref))
        return FakeEntry(id=item_ref, hash="1" * 64, visibleName="Deleted")


def _install_fake_client(monkeypatch, holder: dict[str, FakeClient]) -> None:
    """Patch the CLI to use one fake client instance per invocation."""

    def factory(*args, **kwargs) -> FakeClient:
        client = FakeClient(*args, **kwargs)
        holder["client"] = client
        return client

    monkeypatch.setattr(cli, "Client", factory)


def test_init_creates_or_refreshes_config(monkeypatch, tmp_path, capsys) -> None:
    """`init` should resolve the config path and refresh the user token."""
    holder: dict[str, FakeClient] = {}
    _install_fake_client(monkeypatch, holder)
    config_path = tmp_path / "rmapi.conf"

    exit_code = cli.main(["init", "--config", str(config_path), "--force"])

    assert exit_code == 0
    assert config_path.exists()
    assert holder["client"].configfile == config_path
    assert holder["client"].calls == [("refresh_user_token",)]
    payload = json.loads(capsys.readouterr().out)
    assert payload["initialized"] is True
    assert payload["config_path"] == str(config_path)


def test_init_prompts_before_overwrite(monkeypatch, tmp_path, capsys) -> None:
    """`init` should abort if the user rejects overwriting an existing config."""
    holder: dict[str, FakeClient] = {}
    _install_fake_client(monkeypatch, holder)
    config_path = tmp_path / "rmapi.conf"
    config_path.write_text("existing", encoding="utf-8")
    monkeypatch.setattr("builtins.input", lambda _: "n")

    exit_code = cli.main(["init", "--config", str(config_path)])

    assert exit_code == 1
    assert "client" not in holder
    assert capsys.readouterr().err.strip() == "Aborted."


def test_ls_outputs_directory_lines(monkeypatch, capsys) -> None:
    """`ls` should print one directory entry per line."""
    holder: dict[str, FakeClient] = {}
    _install_fake_client(monkeypatch, holder)

    exit_code = cli.main(["ls", "--config", "test.conf"])

    assert exit_code == 0
    assert holder["client"].configfile == "test.conf"
    assert holder["client"].calls[0] == ("list_directory_paths", "", False)
    assert capsys.readouterr().out.splitlines() == ["Papers/", "Inbox/"]


def test_ls_supports_path_and_recursive(monkeypatch, capsys) -> None:
    """`ls` should support folder paths and recursive listing."""
    holder: dict[str, FakeClient] = {}
    _install_fake_client(monkeypatch, holder)

    assert cli.main(["ls", "Papers/"]) == 0
    assert holder["client"].calls[0] == ("list_directory_paths", "Papers/", False)
    assert capsys.readouterr().out.splitlines() == ["Example.pdf"]

    assert cli.main(["ls", "-r"]) == 0
    assert holder["client"].calls[0] == ("list_directory_paths", "", True)
    assert capsys.readouterr().out.splitlines() == ["Papers/", "Papers/Example.pdf"]


def test_get_downloads_item_in_auto_mode(monkeypatch, capsys) -> None:
    """`get` should use the smart item download path by default."""
    holder: dict[str, FakeClient] = {}
    _install_fake_client(monkeypatch, holder)

    exit_code = cli.main(["get", "Papers/Example.pdf"])

    assert exit_code == 0
    assert holder["client"].calls[0] == ("download_item", "Papers/Example.pdf", None, "auto")
    payload = json.loads(capsys.readouterr().out)
    assert payload["path"] == "output.pdf"


def test_get_supports_output_path_and_format(monkeypatch, capsys) -> None:
    """`get` should forward explicit output and format options."""
    holder: dict[str, FakeClient] = {}
    _install_fake_client(monkeypatch, holder)

    exit_code = cli.main(["get", "Notebook", "--format", "bundle", "--output", "file.zip"])

    assert exit_code == 0
    assert holder["client"].calls[0] == ("download_item", "Notebook", "file.zip", "bundle")
    payload = json.loads(capsys.readouterr().out)
    assert payload["path"] == "file.zip"



def test_info_outputs_one_item(monkeypatch, capsys) -> None:
    """`info` should print one item as JSON."""
    holder: dict[str, FakeClient] = {}
    _install_fake_client(monkeypatch, holder)

    exit_code = cli.main(["info", "Papers/Example.pdf"])

    assert exit_code == 0
    assert holder["client"].calls[0] == ("get_item", "Papers/Example.pdf")
    payload = json.loads(capsys.readouterr().out)
    assert payload["id"] == "Papers/Example.pdf"


def test_get_id_uses_exact_lookup(monkeypatch, capsys) -> None:
    """`get-id` should dispatch to exact id/hash lookup."""
    holder: dict[str, FakeClient] = {}
    _install_fake_client(monkeypatch, holder)

    exit_code = cli.main(["get-id", "1234-id"])

    assert exit_code == 0
    assert holder["client"].calls[0] == ("get_item_exact", "1234-id")
    payload = json.loads(capsys.readouterr().out)
    assert payload["visibleName"] == "Exact"


def test_put_pdf_reads_source_file(monkeypatch, tmp_path, capsys) -> None:
    """`put-pdf` should read the input file and pass bytes to the client."""
    holder: dict[str, FakeClient] = {}
    _install_fake_client(monkeypatch, holder)
    source = tmp_path / "doc.pdf"
    source.write_bytes(b"%PDF-1.4\nhello\n")

    exit_code = cli.main(["put-pdf", str(source), "--parent", "folder-1"])

    assert exit_code == 0
    assert holder["client"].calls[0] == (
        "put_pdf",
        "doc.pdf",
        b"%PDF-1.4\nhello\n",
        "folder-1",
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["id"] == "pdf-id"


def test_mkdir_rename_move_and_trash(monkeypatch, capsys) -> None:
    """Mutation commands should dispatch to the corresponding client methods."""
    holder: dict[str, FakeClient] = {}
    _install_fake_client(monkeypatch, holder)

    assert cli.main(["mkdir", "Inbox"]) == 0
    assert holder["client"].calls[0] == ("put_folder", "Inbox", "")

    assert cli.main(["rename", "item-1", "Renamed"]) == 0
    assert holder["client"].calls[0] == ("rename", "item-1", "Renamed")

    assert cli.main(["move", "item-1", "folder-2"]) == 0
    assert holder["client"].calls[0] == ("move", "item-1", "folder-2")

    assert cli.main(["trash", "item-1"]) == 0
    assert holder["client"].calls[0] == ("delete", "item-1")
    assert capsys.readouterr().out


def test_download_commands_return_paths(monkeypatch, capsys) -> None:
    """Download commands should print the saved path."""
    holder: dict[str, FakeClient] = {}
    _install_fake_client(monkeypatch, holder)

    assert cli.main(["download-original", "item-1", "--output", "file.pdf"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["path"] == "file.pdf"

    assert cli.main(["download-bundle", "item-1", "bundle.zip"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["path"] == "bundle.zip"
