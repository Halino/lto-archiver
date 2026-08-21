from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath


_GLOB_CHARACTERS = frozenset("*?[")


def _normalized_relative_path(entry: str) -> Path:
    if not entry or entry != entry.strip():
        raise ValueError("manifest paths must be nonempty and contain no surrounding whitespace")
    if "\\" in entry:
        raise ValueError(f"manifest path must use forward slashes: {entry!r}")
    if any(character in entry for character in _GLOB_CHARACTERS):
        raise ValueError(f"manifest path must not contain glob syntax: {entry!r}")
    if PurePosixPath(entry).is_absolute() or PureWindowsPath(entry).is_absolute() or PureWindowsPath(entry).drive:
        raise ValueError(f"manifest path must be repository-relative: {entry!r}")
    components = entry.split("/")
    if any(component in ("", ".", "..") for component in components):
        raise ValueError(f"manifest path is not normalized: {entry!r}")
    if any(component.casefold() == ".git" for component in components):
        raise ValueError(f"Git metadata is forbidden in the public snapshot: {entry!r}")
    return Path(*components)


def _reject_symlink_components(root: Path, relative: Path) -> None:
    current = root
    for component in relative.parts:
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError as exc:
            raise ValueError(f"manifest file does not exist: {relative.as_posix()}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"manifest path contains a symlink: {relative.as_posix()}")


def _validate_relative_file(root: Path, relative: Path) -> Path:
    normalized = _normalized_relative_path(relative.as_posix())
    _reject_symlink_components(root, normalized)
    source = root / normalized
    if not source.is_file():
        raise ValueError(f"manifest entry is not a regular file: {normalized.as_posix()}")
    resolved = source.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError(f"manifest path escapes the source tree: {normalized.as_posix()}")
    return normalized


def load_manifest(root: Path, manifest: Path) -> tuple[Path, ...]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"source root is not a directory: {root}")
    if manifest.is_symlink():
        raise ValueError(f"manifest must not be a symlink: {manifest}")
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError(f"manifest is not valid UTF-8: {manifest}") from exc
    if not lines:
        raise ValueError("manifest must contain at least one file")

    entries: list[str] = []
    files: list[Path] = []
    for line_number, entry in enumerate(lines, start=1):
        try:
            relative = _normalized_relative_path(entry)
            relative = _validate_relative_file(root, relative)
        except ValueError as exc:
            raise ValueError(f"invalid manifest line {line_number}: {exc}") from exc
        entries.append(relative.as_posix())
        files.append(relative)

    if len(entries) != len(set(entries)):
        raise ValueError("manifest contains duplicate paths")
    if entries != sorted(entries, key=lambda item: item.encode("utf-8")):
        raise ValueError("manifest paths must be sorted bytewise")
    return tuple(files)


def build_snapshot(root: Path, target: Path, files: tuple[Path, ...]) -> None:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"source root is not a directory: {root}")
    if target.is_symlink():
        raise ValueError(f"snapshot target must not be a symlink: {target}")
    target_resolved = target.resolve(strict=False)
    if target_resolved == root or target_resolved.is_relative_to(root):
        raise ValueError("snapshot target must be outside the source tree")
    if target.exists():
        if not target.is_dir():
            raise ValueError(f"snapshot target is not a directory: {target}")
        if next(target.iterdir(), None) is not None:
            raise ValueError(f"snapshot target must be empty: {target}")

    validated = tuple(_validate_relative_file(root, relative) for relative in files)
    normalized_names = tuple(relative.as_posix() for relative in validated)
    if len(normalized_names) != len(set(normalized_names)):
        raise ValueError("snapshot file list contains duplicates")
    if normalized_names != tuple(sorted(normalized_names, key=lambda item: item.encode("utf-8"))):
        raise ValueError("snapshot file list must be sorted bytewise")

    target.mkdir(parents=True, exist_ok=True)
    for relative in validated:
        source = root / relative
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        _reject_symlink_components(root, relative)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        with os.fdopen(descriptor, "rb") as source_handle, destination.open("xb") as target_handle:
            shutil.copyfileobj(source_handle, target_handle)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build an exact public source snapshot")
    parser.add_argument("--root", type=Path, required=True, help="private source repository root")
    parser.add_argument("--manifest", type=Path, required=True, help="exact public file manifest")
    parser.add_argument("--target", type=Path, required=True, help="nonexistent or empty output directory")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        files = load_manifest(arguments.root, arguments.manifest)
        build_snapshot(arguments.root, arguments.target, files)
    except (OSError, ValueError) as exc:
        print(f"snapshot build failed: {exc}", file=sys.stderr)
        return 2
    print(f"copied {len(files)} manifest files to {arguments.target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
