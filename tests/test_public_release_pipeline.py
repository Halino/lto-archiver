"""Exercise the producer's candidate layout through the publication verifier."""

from __future__ import annotations

import hashlib
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
GATE = runpy.run_path(str(ROOT / "packaging/rpm/verify-public-release.py"))
PACKAGES = (
    "signed/app/RPMS/noarch/lto-archiver-0.11.28-155.el9.noarch.rpm",
    "signed/app/SRPMS/lto-archiver-0.11.28-155.el9.src.rpm",
    "signed/runtime/RPMS/x86_64/lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm",
    "signed/runtime/SRPMS/lto-archiver-python-runtime-0.11.27-3.el9.src.rpm",
)
PRIMARY = "B" * 40
SUBKEY = "C" * 40


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def producer_candidate(root: Path) -> str:
    for relative in PACKAGES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(relative.encode())
    rows = [
        f"{digest((root / relative).read_bytes())}  {Path(relative).name}\n"
        for relative in sorted(PACKAGES)
    ]
    manifest = root / "FINAL-RPM-SHA256SUMS"
    manifest.write_text("".join(rows), encoding="ascii")
    (root / "FINAL-RPM-SHA256SUMS.asc").write_bytes(b"signature")
    (root / "RPM-PUBLIC-KEY.asc").write_bytes(b"key")
    (root / "ATTESTATION.json").write_bytes(b"bundle")
    return digest(manifest.read_bytes())


class PublicReleasePipelineTests(unittest.TestCase):
    def test_producer_order_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            approved = producer_candidate(root)
            GATE["verify_manifest"](
                root / "FINAL-RPM-SHA256SUMS", root, approved, set(PACKAGES)
            )

    def test_signed_candidate_checks_nested_rpm_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            approved = producer_candidate(root)
            key_records = (
                f"pub:-:4096:1:BBBBBBBBBBBBBBBB::::::\nfpr:::::::::{PRIMARY}:\n"
                f"sub:-:4096:1:CCCCCCCCCCCCCCCC::::::\nfpr:::::::::{SUBKEY}:\n"
            ).encode()
            commands: list[list[str]] = []

            def run(command: list[str], *, cwd: Path | None = None) -> bytes:
                commands.append(command)
                if command[0] == "gpg" and "--show-keys" in command:
                    return key_records
                if command[0] == "gpg" and "--verify" in command:
                    return (
                        "[GNUPG:] VALIDSIG " + SUBKEY + " 2026 0 0 0 0 0 0\n"
                    ).encode()
                if command[0] == "rpmkeys" and "--checksig" in command:
                    return b"Header V4 RSA/SHA256 Signature, key ID cccccccc: OK\n"
                return b""

            globals_ = GATE["verify_release"].__globals__
            with patch.dict(
                globals_, {"_run": run, "_verify_srpm_sources": lambda *args: None}
            ):
                GATE["verify_release"](
                    SUBKEY,
                    root,
                    approved,
                    root / "RPM-PUBLIC-KEY.asc",
                    PRIMARY,
                    "example/lto-archiver",
                    "v0.11.28",
                    "a" * 40,
                    digest((root / "FINAL-RPM-SHA256SUMS.asc").read_bytes()),
                    digest((root / "RPM-PUBLIC-KEY.asc").read_bytes()),
                    digest((root / "ATTESTATION.json").read_bytes()),
                )
            checked = {
                command[-1]
                for command in commands
                if command[0] == "rpmkeys" and "--checksig" in command
            }
            self.assertEqual(checked, {str(root / relative) for relative in PACKAGES})


if __name__ == "__main__":
    unittest.main()
