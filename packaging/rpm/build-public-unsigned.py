"""Build closed, unsigned application and runtime RPM trees from a public tag.

This path never loads a signing key. It installs its own unsigned runtime RPM
only inside an explicitly marked disposable GitHub container, for the main
package's build requirement; it never installs anything on the LTO host.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
PACKAGE = {
    "app": ("lto-archiver", "noarch"),
    "runtime": ("lto-archiver-python-runtime", "x86_64"),
}


class PublicBuildError(RuntimeError):
    """An input or build output is outside the reviewed public closure."""


def _run(
    arguments: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            arguments,
            cwd=cwd,
            env=env,
            input=input_bytes,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise PublicBuildError(f"command failed: {arguments[0]}") from error


def _git(repo: Path, *arguments: str) -> str:
    return _run(["git", "-C", str(repo), *arguments]).stdout.decode().strip()


def _sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def validate_source(repo: Path, tag: str, expected_commit: str) -> None:
    if not TAG.fullmatch(tag) or not COMMIT.fullmatch(expected_commit):
        raise PublicBuildError("invalid reviewed tag or commit")
    if _git(repo, "rev-parse", "--show-toplevel") != str(repo.resolve()):
        raise PublicBuildError("source is not the repository root")
    head = _git(repo, "rev-parse", "HEAD")
    resolved = _git(repo, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    if head != expected_commit or resolved != expected_commit:
        raise PublicBuildError("unreviewed source identity")
    if _git(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        raise PublicBuildError("dirty public source tree")
    index_flags = _git(repo, "ls-files", "-v").splitlines()
    if any(row and (row[0].islower() or row[0] == "S") for row in index_flags):
        raise PublicBuildError("unsafe Git index flags")
    if tag != f"v{_spec_identity(repo, 'app')[1]}":
        raise PublicBuildError("release tag differs from application version")


def normalize_output(argument: Path) -> Path:
    output = Path(os.path.abspath(argument))
    if output.exists() or output.is_symlink():
        raise PublicBuildError("output already exists")
    if any(parent.is_symlink() for parent in output.parents):
        raise PublicBuildError("output parent is a symlink")
    return output


def _spec_identity(repo: Path, package: str) -> tuple[str, str, str, Path]:
    name, _arch = PACKAGE[package]
    spec = repo / "packaging" / "rpm" / f"{name}.spec"
    source = spec.read_text(encoding="utf-8")
    values = {}
    for field in ("Name", "Version", "Release"):
        match = re.search(rf"(?m)^{field}:\s*(\S+)", source)
        if match is None:
            raise PublicBuildError(f"missing {field} in {spec.name}")
        values[field] = match.group(1)
    release = values["Release"].split("%", 1)[0]
    if (
        values["Name"] != name
        or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", values["Version"])
        or not release.isdigit()
    ):
        raise PublicBuildError("unexpected RPM spec identity")
    return name, values["Version"], release, spec


def validate_runtime_source0(repo: Path, archive: Path, staging: Path) -> str:
    name, version, _, _ = _spec_identity(repo, "runtime")
    expected_name = f"{name}-{version}.tar.gz"
    authority = repo / "packaging" / "python-runtime"
    if archive.name != expected_name or not archive.is_file() or archive.is_symlink():
        raise PublicBuildError("unexpected runtime Source0")
    digest_file = authority / f"{expected_name}.sha256"
    expected = digest_file.read_text(encoding="ascii").split()
    digest = _sha256(archive)
    if len(expected) != 2 or expected != [digest, expected_name]:
        raise PublicBuildError("runtime Source0 digest mismatch")
    source = staging / f"{name}-{version}"
    source.mkdir()
    with tarfile.open(archive, "r:gz") as source_archive:
        for member in source_archive:
            name_in_archive = PurePosixPath(member.name)
            if (
                name_in_archive.is_absolute()
                or ".." in name_in_archive.parts
                or not name_in_archive.parts
                or name_in_archive.parts[0] != source.name
                or not (member.isdir() or member.isfile())
            ):
                raise PublicBuildError("unsafe runtime Source0 member")
            relative = name_in_archive.parts[1:]
            if not relative:
                continue
            target = source.joinpath(*relative)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = source_archive.extractfile(member)
                if stream is None:
                    raise PublicBuildError("unreadable runtime Source0 member")
                with target.open("xb") as destination:
                    shutil.copyfileobj(stream, destination)
    inventory = json.loads((authority / "wheel-inventory.json").read_text())
    epoch = str(inventory["runtime"]["source_date_epoch"])
    _run(
        [
            sys.executable,
            str(authority / "runtime_source.py"),
            "verify-source0",
            "--source",
            str(source),
            "--archive",
            str(archive),
            "--source-date-epoch",
            epoch,
            "--expected-sha256",
            str(digest_file),
            "--authority-root",
            str(authority),
        ]
    )
    return digest


def build_rpm_once(
    repo: Path,
    package: str,
    archive: Path,
    topdir: Path,
    source_date_epoch: int,
    *,
    rpmbuild: str = "rpmbuild",
) -> None:
    name, version, _, spec = _spec_identity(repo, package)
    if archive.name != f"{name}-{version}.tar.gz" or topdir.exists():
        raise PublicBuildError("unexpected build source or existing build root")
    for directory in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"):
        (topdir / directory).mkdir(parents=True)
    shutil.copyfile(archive, topdir / "SOURCES" / archive.name)
    shutil.copyfile(spec, topdir / "SPECS" / spec.name)
    if package == "runtime":
        authority = repo / "packaging" / "python-runtime"
        for filename in (
            f"{archive.name}.sha256",
            "runtime_install.py",
            "runtime-payload-authority.json",
        ):
            shutil.copyfile(authority / filename, topdir / "SOURCES" / filename)
    clean_home = topdir / "BUILD" / "home"
    clean_home.mkdir()
    environment = os.environ.copy()
    for key in ("GNUPGHOME", "GPG_AGENT_INFO", "RPM_GPG_NAME"):
        environment.pop(key, None)
    environment.update(HOME=str(clean_home), SOURCE_DATE_EPOCH=str(source_date_epoch))
    _run(
        [
            rpmbuild,
            "-ba",
            "--define",
            f"_topdir {topdir}",
            "--define",
            "_buildhost public-build.invalid",
            str(topdir / "SPECS" / spec.name),
        ],
        cwd=repo,
        env=environment,
    )


def validate_rpm_closure(
    topdir: Path, name: str, version: str, release: str, arch: str
) -> tuple[Path, Path]:
    binary_root, source_root = topdir / "RPMS", topdir / "SRPMS"
    files = sorted(
        (path for root in (binary_root, source_root) for path in root.rglob("*")),
        key=str,
    )
    regular = [path for path in files if path.is_file() and not path.is_symlink()]
    if any(
        path.is_symlink() or (not path.is_file() and not path.is_dir())
        for path in files
    ):
        raise PublicBuildError("unsafe RPM output type")
    if len(regular) != 2 or any(path.suffix != ".rpm" for path in regular):
        raise PublicBuildError("RPM artifact closure mismatch")
    binaries = [path for path in regular if path.is_relative_to(binary_root)]
    sources = [path for path in regular if path.is_relative_to(source_root)]
    stem = rf"{re.escape(name)}-{re.escape(version)}-{re.escape(release)}(?:\.[\w]+)*"
    if (
        len(binaries) != 1
        or len(sources) != 1
        or binaries[0].parent != binary_root / arch
        or sources[0].parent != source_root
        or not re.fullmatch(rf"{stem}\.{arch}\.rpm", binaries[0].name)
        or not re.fullmatch(rf"{stem}\.src\.rpm", sources[0].name)
    ):
        raise PublicBuildError("unexpected RPM identity")
    return binaries[0], sources[0]


def compare_rpm_pair(
    first: Path, second: Path, name: str, version: str, release: str, arch: str
) -> tuple[Path, Path]:
    first_binary, first_source = validate_rpm_closure(
        first, name, version, release, arch
    )
    second_binary, second_source = validate_rpm_closure(
        second, name, version, release, arch
    )
    if _sha256(first_binary) != _sha256(second_binary) or _sha256(
        first_source
    ) != _sha256(second_source):
        raise PublicBuildError("unsigned RPM builds differ")
    return first_binary, first_source


def verify_runtime_license_payload(snapshot: object, source_root: Path) -> None:
    """Bind the installed runtime notice, inventory and licenses to Source0."""
    if (
        snapshot.name != "lto-archiver-python-runtime"
        or snapshot.architecture != "x86_64"
        or snapshot.version_release != "0.11.27-3.el9"
    ):
        raise PublicBuildError("runtime RPM header identity mismatch")
    license_root = source_root / "licenses"
    licenses = sorted(license_root.rglob("*"))
    if any(path.is_symlink() or not (path.is_dir() or path.is_file()) for path in licenses):
        raise PublicBuildError("runtime license source is unsafe")
    files = [path for path in licenses if path.is_file()]
    if len(files) != 22:
        raise PublicBuildError("runtime component license closure mismatch")
    prefix = "/usr/share/licenses/lto-archiver-python-runtime"
    components = {
        f"{prefix}/components/{path.relative_to(license_root).as_posix()}": path
        for path in files
    }
    actual_components = {
        path
        for path, metadata in snapshot.payload_metadata.items()
        if path.startswith(f"{prefix}/components/") and metadata[0].startswith("-")
    }
    if actual_components != set(components):
        raise PublicBuildError("runtime component license set mismatch")
    expected = {
        **components,
        f"{prefix}/THIRD_PARTY_NOTICES.md": source_root / "THIRD_PARTY_NOTICES.md",
        "/usr/share/doc/lto-archiver-python-runtime/runtime.spdx.json": (
            source_root / "runtime.spdx.json"
        ),
        "/usr/share/doc/lto-archiver-python-runtime/wheel-inventory.json": (
            source_root / "wheel-inventory.json"
        ),
    }
    for installed, source in expected.items():
        payload = snapshot.extracted_root / installed.removeprefix("/")
        if snapshot.payload_metadata.get(installed) != ("-rw-r--r--", "root", "root"):
            raise PublicBuildError("runtime license metadata mismatch")
        for path in (payload, source):
            try:
                status = path.lstat()
            except OSError as error:
                raise PublicBuildError("runtime license file is missing") from error
            if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                raise PublicBuildError("runtime license file is unsafe")
        if _sha256(payload) != _sha256(source):
            raise PublicBuildError("runtime license bytes differ from Source0")


def verify_built_runtime_licenses(repo: Path, rpm: Path, source_root: Path) -> None:
    """Inspect the actual RPM before a protected signer sees its bytes."""
    checker = runpy.run_path(str(repo / "packaging/rpm/verify-main-rpm.py"))
    snapshot = checker["inspect_rpm"](rpm)
    try:
        verify_runtime_license_payload(snapshot, source_root)
    finally:
        shutil.rmtree(snapshot.extracted_root, ignore_errors=True)


def verify_srpm_sources(
    srpm: Path, expected: dict[str, Path], *, rpm2cpio: str = "rpm2cpio"
) -> None:
    archive = _run([rpm2cpio, str(srpm)]).stdout
    listing = _run(["cpio", "-it", "--quiet"], input_bytes=archive).stdout.decode()
    names = [name.removeprefix("./") for name in listing.splitlines()]
    if (
        len(names) != len(set(names))
        or set(names) != set(expected)
        or any(
            name.startswith("/") or ".." in PurePosixPath(name).parts or "/" in name
            for name in names
        )
    ):
        raise PublicBuildError("SRPM source member closure mismatch")
    with tempfile.TemporaryDirectory(prefix="lto-public-srpm-") as raw:
        extraction = Path(raw)
        _run(
            ["cpio", "-id", "--quiet", "--no-absolute-filenames"],
            cwd=extraction,
            input_bytes=archive,
        )
        for name, trusted in expected.items():
            member = extraction / name
            if (
                not member.is_file()
                or member.is_symlink()
                or _sha256(member) != _sha256(trusted)
            ):
                raise PublicBuildError("SRPM source member differs from public tag")


def _publish_pair(
    repo: Path, first: Path, second: Path, archive: str, spec: str, output: Path
) -> None:
    _run(
        [
            sys.executable,
            str(repo / "packaging/rpm/publish-rpm-tree.py"),
            "--source-root",
            str(first),
            "--second-source-root",
            str(second),
            "--source-archive",
            archive,
            "--spec-name",
            spec,
            "--output",
            str(output),
        ]
    )


def _install_runtime_only_in_disposable_container(binary: Path) -> None:
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("LTO_PUBLIC_EPHEMERAL_CONTAINER") != "1"
        or os.geteuid() != 0
        or not (Path("/.dockerenv").exists() or Path("/run/.containerenv").exists())
    ):
        raise PublicBuildError(
            "runtime installation requires a disposable GitHub build container"
        )
    _run(["rpm", "-Uvh", "--nosignature", "--nodeps", str(binary)])


def _publish_noreplace(staging: Path, output: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, "renameat2"):
        raise PublicBuildError("atomic no-replace publication is unavailable")
    if libc.renameat2(-100, os.fsencode(staging), -100, os.fsencode(output), 1) != 0:
        failure = ctypes.get_errno()
        if failure == errno.EEXIST:
            raise PublicBuildError("output already exists")
        raise PublicBuildError(f"cannot publish output: errno {failure}")


def build_public(
    repo: Path, tag: str, commit: str, runtime_source0: Path, output: Path
) -> None:
    validate_source(repo, tag, commit)
    if output.exists() or output.is_symlink():
        raise PublicBuildError("output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="lto-public-unsigned-") as raw:
        scratch = Path(raw)
        runtime_digest = validate_runtime_source0(repo, runtime_source0, scratch)
        runtime_name, runtime_version, runtime_release, runtime_spec = _spec_identity(
            repo, "runtime"
        )
        app_name, app_version, app_release, app_spec = _spec_identity(repo, "app")
        runtime_epoch = json.loads(
            (repo / "packaging/python-runtime/wheel-inventory.json").read_text()
        )["runtime"]["source_date_epoch"]
        app_epoch = int(_git(repo, "show", "-s", "--format=%ct", "HEAD"))
        builds = scratch / "builds"
        for label in ("runtime-a", "runtime-b"):
            build_rpm_once(
                repo, "runtime", runtime_source0, builds / label, runtime_epoch
            )
        for label in ("runtime-a", "runtime-b"):
            topdir = builds / label
            _, srpm = validate_rpm_closure(
                topdir, runtime_name, runtime_version, runtime_release, "x86_64"
            )
            verify_srpm_sources(
                srpm,
                {
                    path.name: path
                    for path in [*(topdir / "SOURCES").iterdir(), runtime_spec]
                },
            )
        runtime_binary, _ = compare_rpm_pair(
            builds / "runtime-a",
            builds / "runtime-b",
            runtime_name,
            runtime_version,
            runtime_release,
            "x86_64",
        )
        verify_built_runtime_licenses(
            repo, runtime_binary, scratch / f"{runtime_name}-{runtime_version}"
        )
        _install_runtime_only_in_disposable_container(runtime_binary)
        app_archive = scratch / f"{app_name}-{app_version}.tar.gz"
        _run(
            [
                "git",
                "-C",
                str(repo),
                "archive",
                "--format=tar.gz",
                f"--prefix={app_name}-{app_version}/",
                f"--output={app_archive}",
                "HEAD",
                "--",
                ".",
                ":(exclude).superpowers/**",
                ":(exclude)docs/superpowers/**",
            ]
        )
        for label in ("app-a", "app-b"):
            build_rpm_once(repo, "app", app_archive, builds / label, app_epoch)
        for label in ("app-a", "app-b"):
            topdir = builds / label
            binary, srpm = validate_rpm_closure(
                topdir, app_name, app_version, app_release, "noarch"
            )
            verify_srpm_sources(
                srpm, {app_archive.name: app_archive, app_spec.name: app_spec}
            )
            _run(
                [
                    sys.executable,
                    str(repo / "packaging/rpm/verify-main-rpm.py"),
                    "--rpm",
                    str(binary),
                    "--source-root",
                    str(repo),
                    "--contract",
                    str(repo / "packaging/rpm/main-rpm-contract.json"),
                    "--json-output",
                    str(scratch / f"main-rpm-{label}.json"),
                ]
            )
        if (scratch / "main-rpm-app-a.json").read_bytes() != (
            scratch / "main-rpm-app-b.json"
        ).read_bytes():
            raise PublicBuildError("main RPM verification is not reproducible")
        staging = Path(
            tempfile.mkdtemp(prefix=f".{output.name}.staging.", dir=output.parent)
        )
        try:
            _publish_pair(
                repo,
                builds / "runtime-a",
                builds / "runtime-b",
                runtime_source0.name,
                runtime_spec.name,
                staging / "runtime",
            )
            _publish_pair(
                repo,
                builds / "app-a",
                builds / "app-b",
                app_archive.name,
                app_spec.name,
                staging / "app",
            )
            evidence = {
                "schema_version": 1,
                "tag": tag,
                "commit": commit,
                "runtime_source0_sha256": runtime_digest,
                "app_source0_sha256": _sha256(app_archive),
            }
            (staging / "EVIDENCE.json").write_text(
                json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            shutil.copyfile(scratch / "main-rpm-app-a.json", staging / "MAIN-RPM.json")
            paths = sorted(path for path in staging.rglob("*") if path.is_file())
            manifest = "".join(
                f"{_sha256(path)}  {path.relative_to(staging).as_posix()}\n"
                for path in paths
            )
            (staging / "SHA256SUMS").write_text(manifest, encoding="ascii")
            validate_source(repo, tag, commit)
            _publish_noreplace(staging, output)
        finally:
            if staging.exists():
                shutil.rmtree(staging)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--runtime-source0", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        build_public(
            ROOT,
            arguments.tag,
            arguments.commit,
            arguments.runtime_source0.absolute(),
            normalize_output(arguments.output),
        )
        return 0
    except (PublicBuildError, OSError, ValueError, KeyError) as error:
        print(f"public unsigned build refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
