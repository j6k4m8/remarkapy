"""Optional external export backends for remarkapy."""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .exceptions import ExportBackendUnavailableError, ExportFailedError

if TYPE_CHECKING:
    from .client import Client


@dataclass(slots=True)
class ExportResult:
    """Describe files produced by one export operation.

    Attributes:
        backend: The exporter backend used.
        format: The requested export format.
        output_dir: The directory where selected output files were copied.
        files: The exported files copied into ``output_dir``.
    """

    backend: str
    format: str
    output_dir: pathlib.Path
    files: list[pathlib.Path]


class RemarksExporter:
    """Thin adapter around an externally installed ``remarks`` command."""

    _FORMAT_SUFFIXES = {
        "pdf": {".pdf"},
        "md": {".md"},
        "svg": {".svg"},
        "png": {".png"},
        "all": {".pdf", ".md", ".svg", ".png"},
    }

    def __init__(self, executable: str = "remarks") -> None:
        """Initialize the adapter.

        Args:
            executable: The command name or path for the external ``remarks`` tool.
        """
        self.executable = executable

    def export(
        self,
        client: Client,
        item_ref: str,
        output_dir: pathlib.Path | str,
        *,
        format: str = "pdf",
        device: str | None = None,
    ) -> ExportResult:
        """Export one item through ``remarks``.

        Args:
            client: The authenticated remarkapy client.
            item_ref: Item name, path, id, or hash.
            output_dir: Directory where selected exported files should be copied.
            format: Requested export format: ``pdf``, ``md``, ``svg``, ``png``, or ``all``.
            device: Optional device override forwarded to ``remarks``.

        Returns:
            Metadata about the exported files.

        Raises:
            ExportBackendUnavailableError: If the ``remarks`` command is not installed.
            ExportFailedError: If the external exporter fails or produces no matching output.
            ValueError: If ``format`` is unsupported.
        """
        if format not in self._FORMAT_SUFFIXES:
            raise ValueError(f"Unsupported export format: {format}")

        executable_path = shutil.which(self.executable)
        if executable_path is None:
            raise ExportBackendUnavailableError(
                "The `remarks` exporter is not installed or not on PATH. "
                "Install `remarks` separately and retry, or pass an explicit command path."
            )

        destination_path = pathlib.Path(output_dir).expanduser().resolve()
        single_file_target = self._is_single_file_target(destination_path, format)
        if single_file_target:
            destination_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            destination_path.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(prefix="remarkapy-export-") as temp_dir_text:
            temp_dir = pathlib.Path(temp_dir_text)
            input_bundle = self._stage_bundle(client, item_ref, temp_dir)
            raw_output_dir = temp_dir / "out"
            raw_output_dir.mkdir(parents=True, exist_ok=True)
            self._run_remarks(executable_path, input_bundle, raw_output_dir, device=device)
            matched_files = self._collect_outputs(raw_output_dir, format)
            if not matched_files:
                raise ExportFailedError(
                    f"`remarks` completed successfully but produced no `{format}` output files."
                )
            copied_files = self._copy_outputs(
                matched_files,
                raw_output_dir,
                destination_path,
                single_file_target=single_file_target,
            )

        return ExportResult(
            backend="remarks",
            format=format,
            output_dir=destination_path.parent if single_file_target else destination_path,
            files=copied_files,
        )

    def _stage_bundle(self, client: Client, item_ref: str, temp_dir: pathlib.Path) -> pathlib.Path:
        """Download the raw bundle and stage it as an ``.rmdoc`` archive."""
        metadata = client.get_metadata(item_ref)
        visible_name = metadata.get("visibleName", "export") or "export"
        bundle_name = f"{visible_name}.rmdoc"
        input_bundle = temp_dir / bundle_name
        input_bundle.write_bytes(client.get_document(item_ref))
        return input_bundle

    def _run_remarks(
        self,
        executable_path: str,
        input_bundle: pathlib.Path,
        raw_output_dir: pathlib.Path,
        *,
        device: str | None = None,
    ) -> None:
        """Execute the external ``remarks`` command."""
        command = [executable_path, str(input_bundle), str(raw_output_dir)]
        if device:
            command.extend(["--device", device])
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as exc:
            stdout_text = exc.stdout or ""
            stderr_text = exc.stderr or ""
            output = "\n".join(part for part in [stdout_text.strip(), stderr_text.strip()] if part)
            message = f"`remarks` export failed with exit code {exc.returncode}: {output or 'no output'}"
            output_lower = output.lower()
            if 'cairo' in output_lower and ('no library called' in output_lower or 'libcairo' in output_lower):
                message += (
                    "\nHint: the Python package installed, but the system Cairo library is missing. "
                    "On macOS, run `brew install cairo`, then retry `uv run rkpy export ...`."
                )
            raise ExportFailedError(message) from exc


    def _collect_outputs(self, raw_output_dir: pathlib.Path, format: str) -> list[pathlib.Path]:
        """Return exporter output files matching the requested format."""
        suffixes = self._FORMAT_SUFFIXES[format]
        return sorted(
            [path for path in raw_output_dir.rglob("*") if path.is_file() and path.suffix.lower() in suffixes],
            key=lambda path: str(path.relative_to(raw_output_dir)),
        )

    def _is_single_file_target(self, destination_path: pathlib.Path, format: str) -> bool:
        """Return whether the requested output should be treated as one exact file path."""
        return format in {"pdf", "md"} and destination_path.suffix.lower() == f".{format}"

    def _copy_outputs(
        self,
        source_paths: list[pathlib.Path],
        raw_output_dir: pathlib.Path,
        destination_root: pathlib.Path,
        *,
        single_file_target: bool = False,
    ) -> list[pathlib.Path]:
        """Copy matched output files into the requested destination location."""
        if single_file_target:
            if len(source_paths) != 1:
                raise ExportFailedError(
                    f"Expected exactly one `{source_paths[0].suffix if source_paths else 'requested'}` export file, "
                    f"but `remarks` produced {len(source_paths)} matches."
                )
            shutil.copy2(source_paths[0], destination_root)
            return [destination_root.resolve()]

        copied_paths: list[pathlib.Path] = []
        for source_path in source_paths:
            relative_path = source_path.relative_to(raw_output_dir)
            destination_path = destination_root / relative_path
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, destination_path)
            copied_paths.append(destination_path.resolve())
        return copied_paths


def export_item_with_backend(
    client: Client,
    item_ref: str,
    output_dir: pathlib.Path | str,
    *,
    backend: str = "remarks",
    format: str = "pdf",
    executable: str = "remarks",
    device: str | None = None,
) -> ExportResult:
    """Export one item through the requested external backend.

    Args:
        client: The authenticated remarkapy client.
        item_ref: Item name, path, id, or hash.
        output_dir: Directory where selected exported files should be copied.
        backend: Export backend name. Currently only ``remarks`` is supported.
        format: Requested export format.
        executable: Executable name or path for the backend.
        device: Optional device override for the backend.

    Returns:
        Information about the files produced by the export.

    Raises:
        ValueError: If ``backend`` is unsupported.
    """
    if backend != "remarks":
        raise ValueError(f"Unsupported export backend: {backend}")
    exporter = RemarksExporter(executable=executable)
    return exporter.export(
        client,
        item_ref,
        output_dir,
        format=format,
        device=device,
    )


__all__ = ["ExportResult", "RemarksExporter", "export_item_with_backend"]
