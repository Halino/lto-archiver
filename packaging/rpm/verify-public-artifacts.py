#!/usr/bin/python3.11
"""Compare two closed GitHub-built unsigned RPM trees before any signing key is used."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+\Z")
RPM_IDENTITY = re.compile(
    r"(app|runtime)/RPMS/(noarch|x86_64)/"
    r"(lto-archiver(?:-python-runtime)?)-([0-9]+(?:\.[0-9]+)*)-"
    r"([0-9]+)(?:\.el9)\.(noarch|x86_64)\.rpm\Z"
)


class PublicArtifactError(RuntimeError):
    """An unsigned artifact is not an exact, reproducible public build output."""


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _tree_files(root: Path) -> set[str]:
    if not root.is_dir() or root.is_symlink():
        raise PublicArtifactError("artifact root is not an ordinary directory")
    files: set[str] = set()
    for path in root.rglob("*"):
        status = path.lstat()
        if stat.S_ISDIR(status.st_mode):
            continue
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise PublicArtifactError("artifact contains a link or special file")
        relative = path.relative_to(root).as_posix()
        if "\n" in relative or "\r" in relative or "\\" in relative:
            raise PublicArtifactError("artifact name is unsafe for SHA256SUMS")
        files.add(relative)
    return files


def _manifest(root: Path, files: set[str]) -> None:
    manifest = root / "SHA256SUMS"
    if "SHA256SUMS" not in files:
        raise PublicArtifactError("missing SHA256SUMS")
    expected = "".join(
        f"{_sha256(root / name)}  {name}\n" for name in sorted(files - {"SHA256SUMS"})
    )
    if manifest.read_bytes() != expected.encode("ascii"):
        raise PublicArtifactError("manifest does not exactly seal artifact tree")


def _expected_files(expected_rpms: set[str]) -> set[str]:
    if len(expected_rpms) != 4:
        raise PublicArtifactError("four exact RPM and SRPM names required")
    packages: dict[str, tuple[str, str]] = {}
    for name in expected_rpms:
        if not isinstance(name, str):
            raise PublicArtifactError("invalid expected RPM name")
        match = RPM_IDENTITY.fullmatch(name)
        if match:
            group, architecture, package, version, _release, suffix = match.groups()
            if (group, architecture, package, suffix) not in {
                ("app", "noarch", "lto-archiver", "noarch"),
                ("runtime", "x86_64", "lto-archiver-python-runtime", "x86_64"),
            }:
                raise PublicArtifactError("RPM path does not match package identity")
            packages[group] = (package, version)
        elif not re.fullmatch(
            r"(app|runtime)/SRPMS/lto-archiver(?:-python-runtime)?-"
            r"[0-9]+(?:\.[0-9]+)*-[0-9]+\.el9\.src\.rpm",
            name,
        ):
            raise PublicArtifactError("invalid expected RPM name")
    if set(packages) != {"app", "runtime"}:
        raise PublicArtifactError("both binary package identities required")
    for group, (package, version) in packages.items():
        binary = next(
            path for path in expected_rpms if path.startswith(f"{group}/RPMS/")
        )
        source = binary.replace("/RPMS/noarch/", "/SRPMS/").replace(
            "/RPMS/x86_64/", "/SRPMS/"
        )
        source = re.sub(r"\.(?:noarch|x86_64)\.rpm\Z", ".src.rpm", source)
        if (
            source not in expected_rpms
            or package not in source
            or f"-{version}-" not in source
        ):
            raise PublicArtifactError("binary and source package names disagree")
    expected = {
        "EVIDENCE.json",
        "MAIN-RPM.json",
        "SHA256SUMS",
        "app/SHA256SUMS",
        "runtime/SHA256SUMS",
        *expected_rpms,
    }
    for group, (package, version) in packages.items():
        archive = f"{package}-{version}.tar.gz"
        expected.update({f"{group}/SOURCES/{archive}", f"{group}/SPECS/{package}.spec"})
        if group == "runtime":
            expected.update(
                {
                    f"runtime/SOURCES/{archive}.sha256",
                    "runtime/SOURCES/runtime_install.py",
                    "runtime/SOURCES/runtime-payload-authority.json",
                }
            )
    return expected


def _inspect(
    root: Path, expected_files: set[str], tag: str, commit: str
) -> dict[str, str]:
    files = _tree_files(root)
    if files != expected_files:
        raise PublicArtifactError(
            "artifact file closure differs from approved allowlist"
        )
    _manifest(root, files)
    for group in ("app", "runtime"):
        inner = {
            name.removeprefix(f"{group}/")
            for name in files
            if name.startswith(f"{group}/")
        }
        _manifest(root / group, inner)
    try:
        evidence = json.loads((root / "EVIDENCE.json").read_text(encoding="ascii"))
    except (ValueError, UnicodeError) as error:
        raise PublicArtifactError("invalid build evidence") from error
    if (
        type(evidence) is not dict
        or set(evidence)
        != {
            "schema_version",
            "tag",
            "commit",
            "app_source0_sha256",
            "runtime_source0_sha256",
        }
        or evidence["schema_version"] != 1
        or evidence["tag"] != tag
        or evidence["commit"] != commit
        or any(
            not SHA.fullmatch(str(evidence[key]))
            for key in ("app_source0_sha256", "runtime_source0_sha256")
        )
    ):
        raise PublicArtifactError("build evidence has wrong source identity")
    hashes = {name: _sha256(root / name) for name in sorted(files)}
    for group in ("app", "runtime"):
        archives = [
            name
            for name in files
            if re.fullmatch(rf"{group}/SOURCES/[^/]+\.tar\.gz", name)
        ]
        if (
            len(archives) != 1
            or hashes[archives[0]] != evidence[f"{group}_source0_sha256"]
        ):
            raise PublicArtifactError("Source0 digest disagrees with build evidence")
    try:
        main_report = json.loads((root / "MAIN-RPM.json").read_text(encoding="ascii"))
    except (ValueError, UnicodeError) as error:
        raise PublicArtifactError("invalid main RPM verification report") from error
    binaries = [name for name in files if name.startswith("app/RPMS/")]
    if len(binaries) != 1:
        raise PublicArtifactError("main RPM binary closure mismatch")
    binary = binaries[0]
    identity = RPM_IDENTITY.fullmatch(binary)
    if identity is None:
        raise PublicArtifactError("main RPM identity is invalid")
    if (
        type(main_report) is not dict
        or main_report.get("schema_version") != 1
        or main_report.get("status") != "verified"
        or main_report.get("name") != "lto-archiver"
        or main_report.get("architecture") != "noarch"
        or main_report.get("version_release")
        != f"{identity.group(4)}-{identity.group(5)}.el9"
        or main_report.get("rpm_sha256") != hashes[binary]
    ):
        raise PublicArtifactError("main RPM verification does not match built bytes")
    return hashes


def compare_unsigned(
    first: Path, second: Path, expected_names: set[str], tag: str, commit: str
) -> dict[str, object]:
    """Reject extra/missing files and any byte difference, including metadata."""
    if not TAG.fullmatch(tag) or not COMMIT.fullmatch(commit):
        raise PublicArtifactError("invalid reviewed tag/commit")
    expected = _expected_files(set(expected_names))
    first_hashes = _inspect(Path(first), expected, tag, commit)
    second_hashes = _inspect(Path(second), expected, tag, commit)
    if first_hashes != second_hashes:
        raise PublicArtifactError("independent GitHub build bytes differ")
    return {
        "schema_version": 1,
        "status": "identical_unsigned",
        "tag": tag,
        "commit": commit,
        "tree_sha256": first_hashes["SHA256SUMS"],
        "rpm_sha256": {name: first_hashes[name] for name in sorted(expected_names)},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--rpm", action="append", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = compare_unsigned(
            args.first, args.second, set(args.rpm), args.tag, args.commit
        )
        if args.report.exists() or args.report.is_symlink():
            raise PublicArtifactError("comparison report already exists")
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii"
        )
        return 0
    except (PublicArtifactError, OSError, UnicodeError) as error:
        print(f"public artifact comparison refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
