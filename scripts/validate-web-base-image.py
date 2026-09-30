# ruff: noqa: N999

from __future__ import annotations

import argparse
import re

_IMAGE_COMPONENT = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
_REGISTRY = r"(?:localhost|[a-z0-9]+(?:[.-][a-z0-9]+)+(?:\:[0-9]+)?)"
_UBI_PYTHON = rf"{_REGISTRY}/(?:{_IMAGE_COMPONENT}/)*ubi9/python-311"
_DEVELOPMENT_REFERENCE = re.compile(
    rf"{_UBI_PYTHON}:9(?:[.-][A-Za-z0-9_][A-Za-z0-9_.-]{{0,126}})\Z"
)
_RELEASE_REFERENCE = re.compile(
    rf"{_UBI_PYTHON}(?::9(?:[.-][A-Za-z0-9_][A-Za-z0-9_.-]{{0,126}}))?"
    rf"@sha256:[0-9a-f]{{64}}\Z"
)


def validate_reference(reference: str, *, release: bool) -> None:
    pattern = _RELEASE_REFERENCE if release else _DEVELOPMENT_REFERENCE
    if not pattern.fullmatch(reference):
        mode = "release digest" if release else "development tag"
        raise ValueError(
            "invalid WebUI base image: expected a fully qualified UBI 9 "
            f"Python 3.11 {mode}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--development", action="store_true")
    mode.add_argument("--release", action="store_true")
    parser.add_argument("reference")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        validate_reference(args.reference, release=args.release)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
