#!/usr/bin/python3.11
"""Fail closed on an approved signed GitHub RPM candidate before publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import runpy
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SHA = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
FPR = re.compile(r"[0-9A-F]{40}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
TAG_REF = re.compile(r"refs/tags/v[0-9]+\.[0-9]+\.[0-9]+\Z")
APPROVED_RPMS = frozenset(
    {
        "signed/app/RPMS/noarch/lto-archiver-0.11.31-155.el9.noarch.rpm",
        "signed/app/SRPMS/lto-archiver-0.11.31-155.el9.src.rpm",
        "signed/runtime/RPMS/x86_64/lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm",
        "signed/runtime/SRPMS/lto-archiver-python-runtime-0.11.27-3.el9.src.rpm",
    }
)
APPROVED_ASSET_NAMES = frozenset(
    {Path(path).name for path in APPROVED_RPMS}
    | {
        "FINAL-RPM-SHA256SUMS",
        "FINAL-RPM-SHA256SUMS.asc",
        "RPM-PUBLIC-KEY.asc",
        "ATTESTATION.json",
    }
)
FINAL_PROOF_IDENTITY_KEYS = frozenset(
    {
        "repo", "tag", "commit", "draft_id", "manifest_sha256",
        "asset_set_sha256", "run_id",
    }
)


class PublicReleaseError(RuntimeError):
    """A signed public asset failed approval or provenance admission."""


def asset_set_sha256(files: Mapping[str, str]) -> str:
    """Digest the exact eight approved Release names and their approved bytes."""
    if not isinstance(files, Mapping):
        raise PublicReleaseError("invalid approved asset set")
    rows = list(files.items())
    if (
        len(rows) != len(APPROVED_ASSET_NAMES)
        or {name for name, _digest in rows} != APPROVED_ASSET_NAMES
        or len({name for name, _digest in rows}) != len(rows)
        or any(type(name) is not str or type(digest) is not str or not SHA.fullmatch(digest)
               for name, digest in rows)
    ):
        raise PublicReleaseError("approved Release asset closure differs")
    encoded = b"".join(
        name.encode("ascii") + b"\0" + digest.encode("ascii") + b"\n"
        for name, digest in sorted(rows)
    )
    return hashlib.sha256(encoded).hexdigest()


def validate_final_proof(
    proof: dict[str, object], expected: dict[str, object], now_epoch: int
) -> None:
    """Admit only the exact fresh protected preflight for one draft."""
    if (
        type(proof) is not dict
        or type(expected) is not dict
        or set(proof) != FINAL_PROOF_IDENTITY_KEYS | {"checked_at"}
        or set(expected) != FINAL_PROOF_IDENTITY_KEYS
        or type(now_epoch) is not int
        or now_epoch < 0
    ):
        raise PublicReleaseError("malformed final immutability proof")
    for identity in (proof, expected):
        if (
            type(identity["repo"]) is not str
            or REPO.fullmatch(identity["repo"]) is None
            or type(identity["tag"]) is not str
            or TAG_REF.fullmatch(f"refs/tags/{identity['tag']}") is None
            or type(identity["commit"]) is not str
            or COMMIT.fullmatch(identity["commit"]) is None
            or any(
                type(identity[key]) is not str or SHA.fullmatch(identity[key]) is None
                for key in ("manifest_sha256", "asset_set_sha256")
            )
            or any(
                type(identity[key]) is not int or identity[key] <= 0
                for key in ("draft_id", "run_id")
            )
        ):
            raise PublicReleaseError("invalid final immutability identity")
    if any(proof[key] != expected[key] for key in FINAL_PROOF_IDENTITY_KEYS):
        raise PublicReleaseError("final immutability proof differs from approved draft")
    checked_at = proof["checked_at"]
    if type(checked_at) is not int or not 0 <= now_epoch - checked_at <= 120:
        raise PublicReleaseError("final immutability proof is stale or from the future")


def make_final_proof(
    repo: str,
    tag: str,
    commit: str,
    draft_id: int,
    manifest_sha256: str,
    asset_set_sha256: str,
    run_id: int,
    checked_at: int,
) -> dict[str, object]:
    proof: dict[str, object] = {
        "repo": repo,
        "tag": tag,
        "commit": commit,
        "draft_id": draft_id,
        "manifest_sha256": manifest_sha256,
        "asset_set_sha256": asset_set_sha256,
        "run_id": run_id,
        "checked_at": checked_at,
    }
    validate_final_proof(
        proof,
        {key: proof[key] for key in FINAL_PROOF_IDENTITY_KEYS},
        checked_at,
    )
    return proof


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_manifest(
    approved_manifest: Path,
    root: Path,
    approved_sha256: str,
    exact_rpms: set[str],
) -> dict[str, str]:
    """Verify the exact four signed RPM bytes against a separately approved hash."""
    if not SHA.fullmatch(approved_sha256) or set(exact_rpms) != APPROVED_RPMS:
        raise PublicReleaseError("unexpected final release identity")
    basenames = {Path(relative).name: relative for relative in exact_rpms}
    if len(basenames) != len(exact_rpms) or root.is_symlink() or not root.is_dir():
        raise PublicReleaseError("unsafe signed candidate root or duplicate RPM name")
    if any(path.is_symlink() for path in root.rglob("*")):
        raise PublicReleaseError("signed candidate contains a symlink")

    try:
        if (
            approved_manifest.is_symlink()
            or _sha256(approved_manifest) != approved_sha256
        ):
            raise PublicReleaseError("final manifest differs from approval")
        text = approved_manifest.read_text(encoding="ascii")
        lines = text.splitlines(keepends=True)
    except (OSError, UnicodeError) as error:
        raise PublicReleaseError("unreadable final manifest") from error
    rows: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n\\]+)\n", line)
        if match is None or match.group(2) in rows:
            raise PublicReleaseError("malformed final manifest")
        rows[match.group(2)] = match.group(1)
    if set(rows) != set(basenames) or lines != [
        f"{rows[Path(relative).name]}  {Path(relative).name}\n"
        for relative in sorted(exact_rpms)
    ]:
        raise PublicReleaseError("final manifest has missing, extra or unordered RPMs")
    actual: set[str] = set()
    for path in root.rglob("*.rpm"):
        if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
            raise PublicReleaseError("RPM is not an ordinary file")
        actual.add(path.relative_to(root).as_posix())
    if actual != exact_rpms:
        raise PublicReleaseError("signed RPM file closure differs from approval")
    for basename, digest in rows.items():
        path = root / basenames[basename]
        status = path.lstat()
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or _sha256(path) != digest
        ):
            raise PublicReleaseError("signed RPM bytes differ from approval")
    return {relative: rows[Path(relative).name] for relative in exact_rpms}


def verify_auxiliary_assets(root: Path, approved: dict[str, str]) -> dict[str, str]:
    """Bind every non-RPM Release asset to a separately approved byte hash."""
    expected = {
        "FINAL-RPM-SHA256SUMS.asc",
        "RPM-PUBLIC-KEY.asc",
        "ATTESTATION.json",
    }
    if set(approved) != expected or any(
        not SHA.fullmatch(value) for value in approved.values()
    ):
        raise PublicReleaseError("incomplete auxiliary asset approval")
    for name, digest in approved.items():
        path = root / name
        status = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
        ):
            raise PublicReleaseError("unsafe auxiliary release asset")
        if _sha256(path) != digest:
            raise PublicReleaseError("auxiliary asset differs from approval")
    return approved


def verify_expected_source(actual: Path, expected: Path) -> None:
    """Reject a source archive or spec differing from the reviewed public tag."""
    if (
        actual.is_symlink()
        or expected.is_symlink()
        or _sha256(actual) != _sha256(expected)
    ):
        raise PublicReleaseError("SRPM source differs from reviewed public tag")


def verify_signature_output(output: bytes, fingerprint: str) -> None:
    if not FPR.fullmatch(fingerprint):
        raise PublicReleaseError("invalid approved public-key fingerprint")
    normalized = output.decode("ascii", errors="replace").lower()
    if (
        "rsa/sha256 signature" not in normalized
        or f"key id {fingerprint[-8:].lower()}: ok" not in normalized
        or "not ok" in normalized
        or "nokey" in normalized
    ):
        raise PublicReleaseError("RPM signature does not match approved key")


def verify_gpg_status(output: bytes, signing_subkey: str) -> None:
    """Require the approved full subkey to sign the detached manifest."""
    if not FPR.fullmatch(signing_subkey):
        raise PublicReleaseError("invalid approved signing subkey")
    found = []
    for line in output.decode("ascii", errors="replace").splitlines():
        fields = line.split()
        if fields[:2] == ["[GNUPG:]", "VALIDSIG"] and len(fields) >= 3:
            found.append(fields[2].upper())
    if found != [signing_subkey]:
        raise PublicReleaseError("manifest signature uses a different subkey")


def verify_public_key_records(output: bytes, primary: str, subkey: str) -> None:
    """Bind the approved RPM signing subkey to the approved primary key."""
    if not FPR.fullmatch(primary) or not FPR.fullmatch(subkey) or primary == subkey:
        raise PublicReleaseError("invalid approved key fingerprints")
    try:
        records = [line.split(":") for line in output.decode("ascii").splitlines()]
    except UnicodeError as error:
        raise PublicReleaseError("invalid public-key listing") from error
    primary_count = 0
    primary_fingerprints: list[str] = []
    subkey_fingerprints: list[str] = []
    awaiting: str | None = None
    for fields in records:
        kind = fields[0]
        if kind == "pub":
            primary_count += 1
            awaiting = "pub"
            if len(fields) < 2 or fields[1].lower() in {"r", "e", "d", "i"}:
                raise PublicReleaseError("unusable public key")
        elif kind == "sub":
            if (
                primary_count != 1
                or len(fields) < 2
                or fields[1].lower() in {"r", "e", "d", "i"}
            ):
                raise PublicReleaseError("unusable signing subkey")
            awaiting = "sub"
        elif kind == "fpr" and awaiting:
            value = fields[9] if len(fields) > 9 else ""
            (primary_fingerprints if awaiting == "pub" else subkey_fingerprints).append(
                value
            )
            awaiting = None
    if (
        primary_count != 1
        or primary_fingerprints != [primary]
        or subkey_fingerprints.count(subkey) != 1
    ):
        raise PublicReleaseError("public key fingerprint differs from approval")


def attestation_command(
    rpm: Path,
    repo: str,
    signer_workflow: str,
    source_ref: str,
    commit: str,
    bundle: Path | None = None,
) -> list[str]:
    expected_workflow = f"{repo}/.github/workflows/build-release.yml"
    if (
        not REPO.fullmatch(repo)
        or signer_workflow != expected_workflow
        or not TAG_REF.fullmatch(source_ref)
        or not COMMIT.fullmatch(commit)
        or not str(rpm).endswith(".rpm")
        or (bundle is not None and bundle.name != "ATTESTATION.json")
    ):
        raise PublicReleaseError("invalid attestation identity")
    return [
        "gh",
        "attestation",
        "verify",
        str(rpm),
        "--repo",
        repo,
        "--signer-workflow",
        signer_workflow,
        "--source-ref",
        source_ref,
        "--source-digest",
        commit,
        "--signer-digest",
        commit,
        "--deny-self-hosted-runners",
    ] + (["--bundle", str(bundle)] if bundle is not None else [])


def install_order(names: set[str]) -> tuple[str, str, str]:
    expected = {"lto-ltfs", "lto-archiver-python-runtime", "lto-archiver"}
    if names != expected:
        raise PublicReleaseError(
            "disposable install requires exact driver/runtime/app tuple"
        )
    return ("lto-ltfs", "lto-archiver-python-runtime", "lto-archiver")


FRESH_INPUT_KEYS = frozenset({
    "app_repo", "app_tag", "app_commit", "app_primary_fingerprint",
    "app_signing_subkey_fingerprint", "app_manifest_sha256",
    "app_signature_sha256", "app_key_sha256", "app_attestation_sha256",
    "driver_repo", "driver_tag", "driver_commit", "driver_approval_file",
    "driver_approval_sha256", "driver_verifier_sha256",
})


def _validate_fresh_approval(approved: dict[str, str]) -> None:
    if (
        type(approved) is not dict or set(approved) != FRESH_INPUT_KEYS
        or any(type(value) is not str for value in approved.values())
        or any(REPO.fullmatch(approved[key]) is None for key in ("app_repo", "driver_repo"))
        or any(TAG_REF.fullmatch("refs/tags/" + approved[key]) is None
               for key in ("app_tag", "driver_tag"))
        or any(COMMIT.fullmatch(approved[key]) is None for key in ("app_commit", "driver_commit"))
        or any(FPR.fullmatch(approved[key]) is None for key in (
            "app_primary_fingerprint", "app_signing_subkey_fingerprint"))
        or any(SHA.fullmatch(approved[key]) is None for key in (
            "app_manifest_sha256", "app_signature_sha256", "app_key_sha256",
            "app_attestation_sha256", "driver_approval_sha256", "driver_verifier_sha256"))
        or not Path(approved["driver_approval_file"]).is_absolute()
    ):
        raise PublicReleaseError("fresh-install approval identity is incomplete or changed")


def _verify_driver_candidate(
    driver_candidate: Path, driver_tag_source: Path, approved: dict[str, str]
) -> None:
    """Load only the exact approved driver-tag verifier after Git identity checks."""
    if driver_tag_source.is_symlink() or not driver_tag_source.is_dir():
        raise PublicReleaseError("reviewed driver source checkout is unsafe")
    _verify_tag(driver_tag_source, approved["driver_tag"], approved["driver_commit"])
    if _run(["git", "-C", str(driver_tag_source), "status", "--porcelain=v1", "--untracked-files=all"]).strip():
        raise PublicReleaseError("reviewed driver source checkout is dirty")
    verifier = driver_tag_source / "scripts/verify-public-release.py"
    approval_file = Path(approved["driver_approval_file"])
    for path, digest in (
        (verifier, approved["driver_verifier_sha256"]),
        (approval_file, approved["driver_approval_sha256"]),
    ):
        status = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or _sha256(path) != digest:
            raise PublicReleaseError("reviewed driver verifier or exact approval differs")
    api = runpy.run_path(str(verifier))
    document = api["parse_approval_document"](approval_file.read_bytes())
    if any(document[key] != approved["driver_" + key] for key in ("repo", "tag", "commit")):
        raise PublicReleaseError("driver approval document differs from selected tag")
    result = api["verify_release"](
        driver_candidate, document["assets"], document["primary_fingerprint"],
        document["signing_subkey_fingerprint"], document["repo"],
        document["tag"], document["commit"], driver_tag_source,
    )
    if result.get("status") != "signed_driver_candidate_verified":
        raise PublicReleaseError("driver signed candidate is not verified")


def verify_fresh_install_inputs(
    app_candidate: Path, driver_candidate: Path, driver_tag_source: Path,
    approved: dict[str, str],
) -> tuple[Path, Path, Path]:
    """Return only the signed, exact driver/runtime/app first-install order."""
    _validate_fresh_approval(approved)
    verify_release(
        approved["app_signing_subkey_fingerprint"], app_candidate,
        approved["app_manifest_sha256"], app_candidate / "RPM-PUBLIC-KEY.asc",
        approved["app_primary_fingerprint"], approved["app_repo"],
        approved["app_tag"], approved["app_commit"],
        approved["app_signature_sha256"], approved["app_key_sha256"],
        approved["app_attestation_sha256"],
    )
    _verify_driver_candidate(driver_candidate, driver_tag_source, approved)
    packages = (
        (driver_candidate / "lto-ltfs-0.1.2-22.el9.x86_64.rpm",
         "lto-ltfs-0.1.2-22.el9.x86_64"),
        (app_candidate / "signed/runtime/RPMS/x86_64/lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm",
         "lto-archiver-python-runtime-0.11.27-3.el9.x86_64"),
        (app_candidate / "signed/app/RPMS/noarch/lto-archiver-0.11.31-155.el9.noarch.rpm",
         "lto-archiver-0.11.31-155.el9.noarch"),
    )
    for path, expected in packages:
        actual = _run(["rpm", "-qp", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n", str(path)])
        if actual.decode("ascii").strip() != expected:
            raise PublicReleaseError("signed fresh-install RPM NEVRA differs from exact tuple")
    requires = _run(["rpm", "-qp", "--requires", str(packages[2][0])]).decode("utf-8").splitlines()
    for name, exact in (
        ("lto-ltfs", "lto-ltfs = 0.1.2-22.el9"),
        ("lto-archiver-python-runtime", "lto-archiver-python-runtime = 0.11.27-3.el9"),
    ):
        matches = [line for line in requires if line == name or line.startswith(name + " ")]
        if matches != [exact]:
            raise PublicReleaseError("signed application dependency tuple differs")
    return tuple(path for path, _expected in packages)


def verify_immutability_response(response: bytes) -> None:
    """Require GitHub's exact repository Administration-read GET response."""
    if not isinstance(response, bytes) or len(response) > 16 * 1024:
        raise PublicReleaseError("immutable-release response is missing or oversized")
    normalized = response.replace(b"\r\n", b"\n")
    try:
        headers, body = normalized.split(b"\n\n", 1)
        first = headers.split(b"\n", 1)[0]
        if not re.fullmatch(rb"HTTP/[0-9](?:\.[0-9])? 200(?: [^\n]*)?", first):
            raise PublicReleaseError("immutable releases were not confirmed with HTTP 200")
        if not any(
            re.fullmatch(
                rb"(?i)content-type: application/(?:json|vnd\.github\+json)(?:;[^\n]*)?",
                line,
            )
            for line in headers.split(b"\n")[1:]
        ):
            raise PublicReleaseError("immutable-release response is not JSON")
        state = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeError) as error:
        raise PublicReleaseError("immutable-release response is malformed") from error
    if not isinstance(state, dict) or state.get("enabled") is not True:
        raise PublicReleaseError("immutable releases are not enabled")


def _run(command: list[str], *, cwd: Path | None = None) -> bytes:
    try:
        return subprocess.run(command, cwd=cwd, check=True, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise PublicReleaseError(
            f"verification command failed: {command[0]}"
        ) from error


def _verify_tag(repo: Path, tag: str, commit: str) -> None:
    if _run(["git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip() != commit:
        raise PublicReleaseError("checked-out source commit is not approved")
    resolved = _run(
        ["git", "-C", str(repo), "rev-parse", f"refs/tags/{tag}^{{commit}}"]
    )
    if resolved.decode().strip() != commit:
        raise PublicReleaseError("tag does not resolve to approved commit")


def _verify_srpm_sources(candidate: Path, tag: str, commit: str) -> None:
    builder = runpy.run_path(str(ROOT / "packaging/rpm/build-public-unsigned.py"))
    _verify_tag(ROOT, tag, commit)
    with tempfile.TemporaryDirectory(prefix="lto-public-release-sources-") as raw:
        scratch = Path(raw)
        app_archive = scratch / "lto-archiver-0.11.31.tar.gz"
        _run(
            [
                "git",
                "-C",
                str(ROOT),
                "archive",
                "--format=tar.gz",
                "--prefix=lto-archiver-0.11.31/",
                f"--output={app_archive}",
                "HEAD",
                "--",
                ".",
                ":(exclude).superpowers/**",
                ":(exclude)docs/superpowers/**",
            ]
        )
        app = candidate / "signed/app"
        runtime = candidate / "signed/runtime"
        verify_expected_source(app / "SOURCES" / app_archive.name, app_archive)
        verify_expected_source(
            app / "SPECS/lto-archiver.spec", ROOT / "packaging/rpm/lto-archiver.spec"
        )
        runtime_archive = runtime / "SOURCES/lto-archiver-python-runtime-0.11.27.tar.gz"
        builder["validate_runtime_source0"](ROOT, runtime_archive, scratch / "runtime")
        verify_expected_source(
            runtime / "SPECS/lto-archiver-python-runtime.spec",
            ROOT / "packaging/rpm/lto-archiver-python-runtime.spec",
        )
        for name in (
            "lto-archiver-python-runtime-0.11.27.tar.gz.sha256",
            "runtime_install.py",
            "runtime-payload-authority.json",
        ):
            verify_expected_source(
                runtime / "SOURCES" / name, ROOT / "packaging/python-runtime" / name
            )
        builder["verify_srpm_sources"](
            app / "SRPMS/lto-archiver-0.11.31-155.el9.src.rpm",
            {
                app_archive.name: app_archive,
                "lto-archiver.spec": ROOT / "packaging/rpm/lto-archiver.spec",
            },
        )
        builder["verify_srpm_sources"](
            runtime / "SRPMS/lto-archiver-python-runtime-0.11.27-3.el9.src.rpm",
            {
                path.name: path
                for path in (
                    *sorted((runtime / "SOURCES").iterdir()),
                    ROOT / "packaging/rpm/lto-archiver-python-runtime.spec",
                )
            },
        )


def verify_release(
    signing_subkey_fingerprint: str,
    candidate: Path,
    approved_manifest_sha256: str,
    public_key: Path,
    fingerprint: str,
    repo: str,
    tag: str,
    commit: str,
    approved_signature_sha256: str,
    approved_key_sha256: str,
    approved_attestation_sha256: str,
) -> dict[str, object]:
    source_ref = f"refs/tags/{tag}"
    signer = f"{repo}/.github/workflows/build-release.yml"
    if not TAG_REF.fullmatch(source_ref) or not COMMIT.fullmatch(commit):
        raise PublicReleaseError("invalid source identity")
    hashes = verify_manifest(
        candidate / "FINAL-RPM-SHA256SUMS",
        candidate,
        approved_manifest_sha256,
        set(APPROVED_RPMS),
    )
    auxiliary = verify_auxiliary_assets(
        candidate,
        {
            "FINAL-RPM-SHA256SUMS.asc": approved_signature_sha256,
            "RPM-PUBLIC-KEY.asc": approved_key_sha256,
            "ATTESTATION.json": approved_attestation_sha256,
        },
    )
    if public_key != candidate / "RPM-PUBLIC-KEY.asc":
        raise PublicReleaseError("unexpected public key path")
    _verify_srpm_sources(candidate, tag, commit)
    key_records = _run(
        ["gpg", "--batch", "--with-colons", "--show-keys", str(public_key)]
    )
    verify_public_key_records(key_records, fingerprint, signing_subkey_fingerprint)
    with tempfile.TemporaryDirectory(prefix="lto-public-rpmdb-") as raw:
        rpmdb = Path(raw)
        gpg_home = rpmdb / "gnupg"
        gpg_home.mkdir(mode=0o700)
        _run(
            ["gpg", "--homedir", str(gpg_home), "--batch", "--import", str(public_key)]
        )
        status = _run(
            [
                "gpg",
                "--homedir",
                str(gpg_home),
                "--batch",
                "--status-fd",
                "1",
                "--verify",
                str(candidate / "FINAL-RPM-SHA256SUMS.asc"),
                str(candidate / "FINAL-RPM-SHA256SUMS"),
            ]
        )
        verify_gpg_status(status, signing_subkey_fingerprint)
        _run(["rpmkeys", "--dbpath", str(rpmdb), "--import", str(public_key)])
        for relative in sorted(hashes):
            path = candidate / relative
            output = _run(
                [
                    "rpmkeys",
                    "--dbpath",
                    str(rpmdb),
                    "--checksig",
                    "--verbose",
                    str(path),
                ]
            )
            verify_signature_output(output, signing_subkey_fingerprint)
            _run(["rpm", "--dbpath", str(rpmdb), "-K", str(path)])
            _run(
                attestation_command(
                    path,
                    repo,
                    signer,
                    source_ref,
                    commit,
                    candidate / "ATTESTATION.json",
                )
            )
    return {
        "schema_version": 1,
        "status": "signed_candidate_verified",
        "tag": tag,
        "signing_subkey_fingerprint": signing_subkey_fingerprint,
        "commit": commit,
        "repo": repo,
        "signer_workflow": signer,
        "public_key_fingerprint": fingerprint,
        "approved_manifest_sha256": approved_manifest_sha256,
        "auxiliary_sha256": auxiliary,
        "rpm_sha256": hashes,
    }


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--verify-immutability-http":
        try:
            verify_immutability_response(Path(sys.argv[2]).read_bytes())
        except (PublicReleaseError, OSError) as error:
            print(f"immutable release preflight refused: {error}", file=sys.stderr)
            return 2
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signing-subkey-fingerprint", required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--approved-manifest-sha256", required=True)
    parser.add_argument("--approved-signature-sha256", required=True)
    parser.add_argument("--approved-key-sha256", required=True)
    parser.add_argument("--approved-attestation-sha256", required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify_release(
            args.signing_subkey_fingerprint,
            args.candidate,
            args.approved_manifest_sha256,
            args.public_key,
            args.fingerprint,
            args.repo,
            args.tag,
            args.commit,
            args.approved_signature_sha256,
            args.approved_key_sha256,
            args.approved_attestation_sha256,
        )
        if args.report.exists() or args.report.is_symlink():
            raise PublicReleaseError("verification report already exists")
        args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        return 0
    except (PublicReleaseError, OSError, ValueError, TypeError) as error:
        print(f"public release refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
