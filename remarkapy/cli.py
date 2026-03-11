"""Command-line interface for remarkapy."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from dataclasses import asdict, is_dataclass
from typing import Any, Callable

from .api import Client, resolve_config_path


def _print_json(payload: Any) -> None:
    """Print JSON with stable formatting.

    Args:
        payload: The JSON-serializable value to print.
    """
    print(json.dumps(payload, indent=2, sort_keys=True))




def _print_lines(lines: list[str]) -> None:
    """Print one path per line.

    Args:
        lines: The lines to print.
    """
    for line in lines:
        print(line)

def _normalize_output(value: Any) -> Any:
    """Convert client return values into JSON-friendly data.

    Args:
        value: The return value from a client method.

    Returns:
        A JSON-serializable representation.
    """
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, pathlib.Path):
        return {"path": str(value)}
    if isinstance(value, list):
        return [_normalize_output(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize_output(item) for key, item in value.items()}
    return value


def _common_parser() -> argparse.ArgumentParser:
    """Create shared CLI options.

    Returns:
        A parser containing options reused by the root parser and subcommands.
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--config",
        help="Path to an rmapi-compatible config file.",
    )
    return parser


def _build_parser() -> argparse.ArgumentParser:
    """Create the top-level argument parser.

    Returns:
        The configured argument parser.
    """
    common = _common_parser()
    parser = argparse.ArgumentParser(prog="remarkapy", parents=[common])
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser(
        "init",
        help="Initialize or refresh a local remarkapy/rmapi config file.",
        parents=[common],
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing config file without prompting.",
    )
    init_parser.set_defaults(handler=_cmd_init)

    ls_parser = subparsers.add_parser("ls", help="List one library directory.", parents=[common])
    ls_parser.add_argument("path", nargs="?", default="", help="Folder name or path to list. Defaults to root.")
    ls_parser.add_argument("-r", "--recursive", action="store_true", help="List recursively.")
    ls_parser.set_defaults(handler=_cmd_ls)

    get_parser = subparsers.add_parser(
        "get",
        help="Download an item; notebooks fall back to raw bundles by default.",
        parents=[common],
    )
    get_parser.add_argument("item_ref", help="Item name, library path, id, or current hash.")
    get_parser.add_argument("-o", "--output", help="Destination file path.")
    get_parser.add_argument(
        "--format",
        choices=["auto", "original", "bundle"],
        default="auto",
        help="Download mode. Defaults to auto.",
    )
    get_parser.set_defaults(handler=_cmd_get)

    info_parser = subparsers.add_parser(
        "info",
        help="Show one item as JSON by name, path, id, or hash.",
        parents=[common],
    )
    info_parser.add_argument("item_ref", help="Item name, library path, id, or current hash.")
    info_parser.set_defaults(handler=_cmd_info)

    get_id_parser = subparsers.add_parser(
        "get-id", help="Show one item as JSON by exact id or hash.", parents=[common]
    )
    get_id_parser.add_argument("item_ref", help="Exact item id or current hash.")
    get_id_parser.set_defaults(handler=_cmd_get_id)

    download_parser = subparsers.add_parser(
        "download-original",
        help="Download the original PDF or EPUB payload.",
        parents=[common],
    )
    download_parser.add_argument("item_ref", help="Item name, library path, id, or current hash.")
    download_parser.add_argument("--output", help="Destination file path.")
    download_parser.set_defaults(handler=_cmd_download_original)

    bundle_parser = subparsers.add_parser(
        "download-bundle",
        help="Download the raw item bundle as a zip archive.",
        parents=[common],
    )
    bundle_parser.add_argument("item_ref", help="Item name, library path, id, or current hash.")
    bundle_parser.add_argument("output", help="Destination zip path.")
    bundle_parser.set_defaults(handler=_cmd_download_bundle)

    put_pdf_parser = subparsers.add_parser(
        "put-pdf", help="Upload a PDF document.", parents=[common]
    )
    put_pdf_parser.add_argument("path", help="Source PDF path.")
    put_pdf_parser.add_argument("--name", help="Visible name in the library.")
    put_pdf_parser.add_argument("--parent", default="", help="Parent folder id.")
    put_pdf_parser.set_defaults(handler=_cmd_put_pdf)

    put_epub_parser = subparsers.add_parser(
        "put-epub", help="Upload an EPUB document.", parents=[common]
    )
    put_epub_parser.add_argument("path", help="Source EPUB path.")
    put_epub_parser.add_argument("--name", help="Visible name in the library.")
    put_epub_parser.add_argument("--parent", default="", help="Parent folder id.")
    put_epub_parser.set_defaults(handler=_cmd_put_epub)

    mkdir_parser = subparsers.add_parser("mkdir", help="Create a folder.", parents=[common])
    mkdir_parser.add_argument("name", help="Visible folder name.")
    mkdir_parser.add_argument("--parent", default="", help="Parent folder id.")
    mkdir_parser.set_defaults(handler=_cmd_mkdir)

    rename_parser = subparsers.add_parser(
        "rename", help="Rename an item by name, path, id, or hash.", parents=[common]
    )
    rename_parser.add_argument("item_ref", help="Item name, library path, id, or current hash.")
    rename_parser.add_argument("name", help="New visible name.")
    rename_parser.set_defaults(handler=_cmd_rename)

    move_parser = subparsers.add_parser("move", help="Move an item by name, path, id, or hash.", parents=[common])
    move_parser.add_argument("item_ref", help="Item name, library path, id, or current hash.")
    move_parser.add_argument(
        "parent", help="Destination folder name/path/id, empty string for root, or trash."
    )
    move_parser.set_defaults(handler=_cmd_move)

    trash_parser = subparsers.add_parser(
        "trash", help="Move an item to trash by name, path, id, or hash.", parents=[common]
    )
    trash_parser.add_argument("item_ref", help="Item name, library path, id, or current hash.")
    trash_parser.set_defaults(handler=_cmd_trash)

    return parser


def _make_client(args: argparse.Namespace) -> Client:
    """Create a client from parsed CLI arguments.

    Args:
        args: Parsed command-line arguments.

    Returns:
        A configured client instance.
    """
    return Client(configfile=args.config)


def _resolve_init_path(config_arg: str | None) -> pathlib.Path:
    """Resolve the config path used by `init`.

    Args:
        config_arg: Optional explicit config path.

    Returns:
        The resolved config file path.
    """
    return resolve_config_path(config_arg)


def _confirm_overwrite(config_path: pathlib.Path) -> bool:
    """Ask the user whether an existing config file may be overwritten.

    Args:
        config_path: The target config path.

    Returns:
        True when the user confirms overwriting.
    """
    response = input(f'Config file "{config_path}" exists. Overwrite? [y/N]: ')
    return response.strip().lower() in {"y", "yes"}


def _read_input_file(path_text: str) -> tuple[pathlib.Path, bytes]:
    """Read a source document from disk.

    Args:
        path_text: The source path string.

    Returns:
        The resolved path and file bytes.
    """
    path = pathlib.Path(path_text).expanduser().resolve()
    return path, path.read_bytes()


def _visible_name(path: pathlib.Path, override: str | None) -> str:
    """Resolve the visible upload name.

    Args:
        path: The source file path.
        override: Optional explicit name.

    Returns:
        The chosen visible name.
    """
    return override or path.name


def _run_with_client(args: argparse.Namespace, callback: Callable[[Client], Any]) -> int:
    """Run one command handler with a managed client.

    Args:
        args: Parsed command-line arguments.
        callback: Function that performs the command.

    Returns:
        Process exit code.
    """
    try:
        with _make_client(args) as client:
            result = callback(client)
        if result is not None:
            _print_json(_normalize_output(result))
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


def _cmd_init(args: argparse.Namespace) -> int:
    """Handle `init`.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Process exit code.
    """
    config_path = _resolve_init_path(args.config)
    if config_path.exists() and not args.force and not _confirm_overwrite(config_path):
        print("Aborted.", file=sys.stderr)
        return 1

    config_path.parent.mkdir(parents=True, exist_ok=True)
    if not config_path.exists():
        config_path.write_text("", encoding="utf-8")

    try:
        with Client(configfile=config_path, persist_config=True) as client:
            client.refresh_user_token()
        _print_json({"config_path": str(config_path), "initialized": True})
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


def _cmd_ls(args: argparse.Namespace) -> int:
    """Handle `ls`."""
    try:
        with _make_client(args) as client:
            lines = client.list_directory_paths(args.path, recursive=args.recursive)
        _print_lines(lines)
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


def _cmd_get(args: argparse.Namespace) -> int:
    """Handle `get`."""
    return _run_with_client(
        args,
        lambda client: client.download_item(
            args.item_ref,
            args.output,
            format=args.format,
        ),
    )


def _cmd_info(args: argparse.Namespace) -> int:
    """Handle `info`."""
    return _run_with_client(args, lambda client: client.get_item(args.item_ref))


def _cmd_get_id(args: argparse.Namespace) -> int:
    """Handle `get-id`."""
    return _run_with_client(args, lambda client: client.get_item_exact(args.item_ref))


def _cmd_download_original(args: argparse.Namespace) -> int:
    """Handle `download-original`."""
    return _run_with_client(
        args,
        lambda client: client.download_original_file(args.item_ref, args.output),
    )


def _cmd_download_bundle(args: argparse.Namespace) -> int:
    """Handle `download-bundle`."""
    return _run_with_client(
        args,
        lambda client: client.download_raw_bundle(args.item_ref, args.output),
    )


def _cmd_put_pdf(args: argparse.Namespace) -> int:
    """Handle `put-pdf`."""

    def run(client: Client) -> Any:
        path, payload = _read_input_file(args.path)
        return client.put_pdf(_visible_name(path, args.name), payload, parent=args.parent)

    return _run_with_client(args, run)


def _cmd_put_epub(args: argparse.Namespace) -> int:
    """Handle `put-epub`."""

    def run(client: Client) -> Any:
        path, payload = _read_input_file(args.path)
        return client.put_epub(_visible_name(path, args.name), payload, parent=args.parent)

    return _run_with_client(args, run)


def _cmd_mkdir(args: argparse.Namespace) -> int:
    """Handle `mkdir`."""
    return _run_with_client(args, lambda client: client.put_folder(args.name, parent=args.parent))


def _cmd_rename(args: argparse.Namespace) -> int:
    """Handle `rename`."""
    return _run_with_client(args, lambda client: client.rename(args.item_ref, args.name))


def _cmd_move(args: argparse.Namespace) -> int:
    """Handle `move`."""
    return _run_with_client(args, lambda client: client.move(args.item_ref, args.parent))


def _cmd_trash(args: argparse.Namespace) -> int:
    """Handle `trash`."""
    return _run_with_client(args, lambda client: client.delete(args.item_ref))


def main(argv: list[str] | None = None) -> int:
    """Run the remarkapy CLI.

    Args:
        argv: Optional argv override.

    Returns:
        Process exit code.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
