import argparse
import pathlib

from .api import Client
from .configfile import get_config_or_raise


def _resolve_config_path(override: str | None) -> pathlib.Path:
    if override:
        return pathlib.Path(override).expanduser().resolve()
    _, config_path = get_config_or_raise(return_path=True)
    return config_path


def _confirm_overwrite(config_path: pathlib.Path) -> bool:
    response = input(
        f'Config file "{config_path}" exists. Overwrite? [y/N]: '
    ).strip().lower()
    return response in {"y", "yes"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a reMarkable token config file for remarkapy."
    )
    parser.add_argument(
        "--config",
        help="Path to write the config file (defaults to rmapi locations).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite any existing config without prompting.",
    )
    args = parser.parse_args(argv)

    config_path = _resolve_config_path(args.config)

    if config_path.exists() and not args.force:
        if not _confirm_overwrite(config_path):
            print("Aborted.")
            return 1

    config_path.parent.mkdir(parents=True, exist_ok=True)
    if not config_path.exists():
        config_path.write_text("", encoding="utf-8")

    print(f"Config file: {config_path}")
    Client(configfile=config_path)
    print(f"Saved tokens to {config_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
