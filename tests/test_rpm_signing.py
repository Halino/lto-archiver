from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SIGNER = ROOT / "packaging" / "rpm" / "sign-rpm-tree.py"
PRIMARY = "720A3739260F7F170F6775D671BFB166903560F7"
SUBKEY = "B89E149F0793DA2E3C7C5D3C442162C8A68E868D"


def load_signer():
    spec = importlib.util.spec_from_file_location("task9_rpm_signer", SIGNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SigningFixture:
    def __init__(self, root: Path, signer) -> None:
        self.root = root
        self.signer = signer
        self.unsigned = root / "unsigned"
        self.output = root / "signed"
        self.gnupg = root / "private-gnupg"
        self.tools_dir = root / "tools"
        self.gnupg.mkdir(mode=0o700)
        self.tools_dir.mkdir()
        binary = self.unsigned / "RPMS/noarch/lto-archiver-0.11.27-102.noarch.rpm"
        source = self.unsigned / "SRPMS/lto-archiver-0.11.27-102.src.rpm"
        binary.parent.mkdir(parents=True)
        source.parent.mkdir(parents=True)
        binary.write_bytes(b"unsigned binary\n")
        source.write_bytes(b"unsigned source\n")
        binary.chmod(0o644)
        source.chmod(0o644)
        spec = self.unsigned / "SPECS/lto-archiver.spec"
        spec.parent.mkdir()
        spec.write_text("Name: lto-archiver\n")
        spec.chmod(0o644)
        self._write_manifest()
        self.original = {
            path.relative_to(self.unsigned).as_posix(): path.read_bytes()
            for path in self.unsigned.rglob("*")
            if path.is_file()
        }
        self.public_key = ROOT / "packaging/signing/lto-archiver-task9-rpm-public.asc"
        self.policy = ROOT / "packaging/deployment/app-runtime-signing-policy.json"
        for name in ("gpg", "rpm", "rpmkeys", "rpmsign"):
            tool = self.tools_dir / name
            tool.write_text("#!/bin/sh\nexit 99\n")
            tool.chmod(0o755)
        self.tools = signer.SigningTools(
            gpg=self.tools_dir / "gpg",
            rpm=self.tools_dir / "rpm",
            rpmkeys=self.tools_dir / "rpmkeys",
            rpmsign=self.tools_dir / "rpmsign",
        )
        self.commands: list[tuple[tuple[str, ...], dict[str, str]]] = []
        self.rpmsign_modes: list[int] = []
        self.fail_operation = ""
        self.unsigned_check_result = False
        self.manifest_hash_algorithm = "8"
        self.rpm_signature_algorithm = "RSA/SHA256"

    def _write_manifest(self) -> None:
        rows = []
        for path in sorted(self.unsigned.rglob("*")):
            if path.is_file() and path.name != "SHA256SUMS":
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                rows.append(f"{digest}  {path.relative_to(self.unsigned).as_posix()}\n")
        manifest = self.unsigned / "SHA256SUMS"
        manifest.write_text("".join(rows))
        manifest.chmod(0o644)

    def run(self, command, **kwargs):
        argv = tuple(os.fspath(item) for item in command)
        env = dict(kwargs.get("env", {}))
        self.commands.append((argv, env))
        if self.fail_operation and self.fail_operation in argv:
            return subprocess.CompletedProcess(command, 71, stdout=b"", stderr=b"redacted")
        if "--list-secret-keys" in argv:
            payload = (
                f"sec:-:3072:1:903560F7:0:0:::::::\n"
                f"fpr:::::::::{PRIMARY}:\n"
                f"ssb:-:3072:1:A68E868D:0:0::::::s:\n"
                f"fpr:::::::::{SUBKEY}:\n"
            ).encode()
            return subprocess.CompletedProcess(command, 0, stdout=payload, stderr=b"")
        if "--show-keys" in argv:
            payload = (
                f"pub:-:3072:1:903560F7:0:0:::::::\n"
                f"fpr:::::::::{PRIMARY}:\n"
                f"sub:-:3072:1:A68E868D:0:0::::::s:\n"
                f"fpr:::::::::{SUBKEY}:\n"
            ).encode()
            return subprocess.CompletedProcess(command, 0, stdout=payload, stderr=b"")
        if argv[0] == os.fspath(self.tools.rpm) and "--qf" in argv:
            return subprocess.CompletedProcess(
                command, 0, stdout=b"lto-archiver\n", stderr=b""
            )
        if argv[0] == os.fspath(self.tools.rpmsign):
            target = Path(argv[-1])
            self.rpmsign_modes.append(target.stat().st_mode & 0o777)
            signed = target.with_name(f".{target.name}.signed")
            signed.write_bytes(target.read_bytes() + b"signed\n")
            signed.chmod(target.stat().st_mode & 0o777)
            os.replace(signed, target)
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")
        if "--checksig" in argv:
            output = (
                b"digests OK\n"
                if self.unsigned_check_result
                else (
                    "Header V4 "
                    f"{self.rpm_signature_algorithm} Signature, "
                    "key ID a68e868d: OK\n"
                ).encode()
            )
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr=b"")
        if "--detach-sign" in argv:
            Path(argv[argv.index("--output") + 1]).write_bytes(b"detached signature\n")
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")
        if "--verify" in argv:
            status = (
                f"[GNUPG:] VALIDSIG {SUBKEY} 0 0 0 0 0 1 "
                f"{self.manifest_hash_algorithm} 00 {PRIMARY}\n"
            )
            return subprocess.CompletedProcess(command, 0, stdout=status.encode(), stderr=b"")
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")


class RpmSigningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = load_signer()

    def test_signs_exact_binary_and_source_with_explicit_private_home_and_key(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = SigningFixture(Path(raw), self.signer)
            report = self.signer.sign_tree(
                fixture.unsigned,
                fixture.output,
                package_name="lto-archiver",
                gnupg_home=fixture.gnupg,
                primary_fingerprint=PRIMARY,
                signing_subkey_fingerprint=SUBKEY,
                policy_file=fixture.policy,
                public_key=fixture.public_key,
                tools=fixture.tools,
                run_command=fixture.run,
            )

            self.assertEqual("signed", report["status"])
            self.assertEqual([0o600, 0o600], fixture.rpmsign_modes)
            self.assertEqual(PRIMARY, report["primary_fingerprint"])
            self.assertEqual(SUBKEY, report["signing_subkey_fingerprint"])
            self.assertEqual(
                hashlib.sha256(fixture.original["SHA256SUMS"]).hexdigest(),
                report["unsigned_manifest_sha256"],
            )
            self.assertEqual(2, len(report["unsigned_rpm_sha256"]))
            self.assertTrue((fixture.output / "SHA256SUMS").is_file())
            self.assertTrue((fixture.output / "SHA256SUMS.asc").is_file())
            self.assertEqual(
                fixture.original,
                {
                    path.relative_to(fixture.unsigned).as_posix(): path.read_bytes()
                    for path in fixture.unsigned.rglob("*")
                    if path.is_file()
                },
            )
            sign_calls = [row for row in fixture.commands if row[0][0] == os.fspath(fixture.tools.rpmsign)]
            self.assertEqual(2, len(sign_calls))
            for argv, env in sign_calls:
                self.assertIn(f"_gpg_name {SUBKEY}!", argv)
                self.assertEqual(os.fspath(fixture.gnupg), env["GNUPGHOME"])
                self.assertNotIn("HOME", env)
            self.assertTrue(
                all(Path(argv[0]).is_absolute() for argv, _env in fixture.commands)
            )

    def test_signs_realistic_read_only_inputs_and_publishes_read_only_rpms(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = SigningFixture(Path(raw), self.signer)
            unsigned_rpms = tuple(fixture.unsigned.rglob("*.rpm"))
            for rpm_path in unsigned_rpms:
                rpm_path.chmod(0o444)

            report = self.signer.sign_tree(
                fixture.unsigned,
                fixture.output,
                package_name="lto-archiver",
                gnupg_home=fixture.gnupg,
                primary_fingerprint=PRIMARY,
                signing_subkey_fingerprint=SUBKEY,
                policy_file=fixture.policy,
                public_key=fixture.public_key,
                tools=fixture.tools,
                run_command=fixture.run,
            )

            self.assertEqual("signed", report["status"])
            self.assertEqual(
                [0o444, 0o444],
                sorted(path.stat().st_mode & 0o777 for path in unsigned_rpms),
            )
            self.assertEqual(
                [0o444, 0o444],
                sorted(
                    path.stat().st_mode & 0o777
                    for path in fixture.output.rglob("*.rpm")
                ),
            )

    def test_uses_rpmkeys_for_the_isolated_verification_database(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = SigningFixture(Path(raw), self.signer)

            self.signer.sign_tree(
                fixture.unsigned,
                fixture.output,
                package_name="lto-archiver",
                gnupg_home=fixture.gnupg,
                primary_fingerprint=PRIMARY,
                signing_subkey_fingerprint=SUBKEY,
                policy_file=fixture.policy,
                public_key=fixture.public_key,
                tools=fixture.tools,
                run_command=fixture.run,
            )

            rpm_commands = [
                argv
                for argv, _env in fixture.commands
                if argv[0] == os.fspath(fixture.tools.rpm)
            ]
            rpmkeys_commands = [
                argv
                for argv, _env in fixture.commands
                if argv[0] == os.fspath(fixture.tools.rpmkeys)
            ]
            self.assertFalse(
                any("--initdb" in argv or "--import" in argv for argv in rpm_commands)
            )
            import_commands = [
                argv for argv in rpmkeys_commands if "--import" in argv
            ]
            self.assertEqual(1, len(import_commands))
            self.assertEqual("--dbpath", import_commands[0][1])
            self.assertEqual("--import", import_commands[0][3])
            self.assertEqual(os.fspath(fixture.public_key), import_commands[0][4])
            self.assertEqual(
                2,
                sum("--checksig" in argv for argv in rpmkeys_commands),
            )

    def test_rejects_staged_rpm_replacement_during_signing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = SigningFixture(Path(raw), self.signer)
            victim = Path(raw) / "outside.rpm"
            victim.write_bytes(b"outside must survive\n")
            victim.chmod(0o644)

            def replace_on_sign(command, **kwargs):
                argv = tuple(os.fspath(item) for item in command)
                if argv[0] == os.fspath(fixture.tools.rpmsign):
                    target = Path(argv[-1])
                    target.unlink()
                    target.symlink_to(victim)
                    return subprocess.CompletedProcess(
                        command, 0, stdout=b"", stderr=b""
                    )
                return fixture.run(command, **kwargs)

            with self.assertRaises(self.signer.SigningError):
                self.signer.sign_tree(
                    fixture.unsigned,
                    fixture.output,
                    package_name="lto-archiver",
                    gnupg_home=fixture.gnupg,
                    primary_fingerprint=PRIMARY,
                    signing_subkey_fingerprint=SUBKEY,
                    policy_file=fixture.policy,
                    public_key=fixture.public_key,
                    tools=fixture.tools,
                    run_command=replace_on_sign,
                )

            self.assertFalse(fixture.output.exists())
            self.assertEqual(b"outside must survive\n", victim.read_bytes())
            self.assertEqual(0o644, victim.stat().st_mode & 0o777)

    def test_late_staged_hardlink_is_restored_read_only_on_every_failure(self) -> None:
        for outcome in ("replacement", "tool-failure"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as raw:
                fixture = SigningFixture(Path(raw), self.signer)
                escaped = Path(raw) / "escaped-staged-inode.rpm"

                def hardlink_during_sign(command, **kwargs):
                    argv = tuple(os.fspath(item) for item in command)
                    if argv[0] != os.fspath(fixture.tools.rpmsign):
                        return fixture.run(command, **kwargs)
                    target = Path(argv[-1])
                    os.link(target, escaped)
                    if outcome == "tool-failure":
                        return subprocess.CompletedProcess(
                            command, 71, stdout=b"", stderr=b"redacted"
                        )
                    return fixture.run(command, **kwargs)

                with self.assertRaises(self.signer.SigningError):
                    self.signer.sign_tree(
                        fixture.unsigned,
                        fixture.output,
                        package_name="lto-archiver",
                        gnupg_home=fixture.gnupg,
                        primary_fingerprint=PRIMARY,
                        signing_subkey_fingerprint=SUBKEY,
                        policy_file=fixture.policy,
                        public_key=fixture.public_key,
                        tools=fixture.tools,
                        run_command=hardlink_during_sign,
                    )

                self.assertFalse(fixture.output.exists())
                self.assertTrue(escaped.is_file())
                self.assertEqual(0o444, escaped.stat().st_mode & 0o777)

    def test_rejects_wrong_explicit_fingerprint_or_modified_public_anchor(self) -> None:
        for mutation in ("primary", "subkey", "public-key"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                fixture = SigningFixture(Path(raw), self.signer)
                primary = "0" * 40 if mutation == "primary" else PRIMARY
                subkey = "1" * 40 if mutation == "subkey" else SUBKEY
                public_key = fixture.public_key
                if mutation == "public-key":
                    public_key = Path(raw) / "changed.asc"
                    public_key.write_bytes(fixture.public_key.read_bytes() + b"changed\n")
                with self.assertRaises(self.signer.SigningError):
                    self.signer.sign_tree(
                        fixture.unsigned,
                        fixture.output,
                        package_name="lto-archiver",
                        gnupg_home=fixture.gnupg,
                        primary_fingerprint=primary,
                        signing_subkey_fingerprint=subkey,
                        policy_file=fixture.policy,
                        public_key=public_key,
                        tools=fixture.tools,
                        run_command=fixture.run,
                    )
                self.assertFalse(fixture.output.exists())

    def test_tool_failure_never_publishes_a_partial_signed_tree(self) -> None:
        for operation in ("--addsign", "--checksig", "--detach-sign", "--verify"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as raw:
                fixture = SigningFixture(Path(raw), self.signer)
                fixture.fail_operation = operation
                with self.assertRaises(self.signer.SigningError):
                    self.signer.sign_tree(
                        fixture.unsigned,
                        fixture.output,
                        package_name="lto-archiver",
                        gnupg_home=fixture.gnupg,
                        primary_fingerprint=PRIMARY,
                        signing_subkey_fingerprint=SUBKEY,
                        policy_file=fixture.policy,
                        public_key=fixture.public_key,
                        tools=fixture.tools,
                        run_command=fixture.run,
                    )
                self.assertFalse(fixture.output.exists())

    def test_successful_digest_only_rpmkeys_result_is_not_a_signature(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = SigningFixture(Path(raw), self.signer)
            fixture.unsigned_check_result = True

            with self.assertRaises(self.signer.SigningError):
                self.signer.sign_tree(
                    fixture.unsigned,
                    fixture.output,
                    package_name="lto-archiver",
                    gnupg_home=fixture.gnupg,
                    primary_fingerprint=PRIMARY,
                    signing_subkey_fingerprint=SUBKEY,
                    policy_file=fixture.policy,
                    public_key=fixture.public_key,
                    tools=fixture.tools,
                    run_command=fixture.run,
                )

            self.assertFalse(fixture.output.exists())

    def test_rejects_non_sha256_rpm_or_manifest_signature(self) -> None:
        for mutation in ("rpm", "manifest"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                fixture = SigningFixture(Path(raw), self.signer)
                if mutation == "rpm":
                    fixture.rpm_signature_algorithm = "RSA/SHA1"
                else:
                    fixture.manifest_hash_algorithm = "2"
                with self.assertRaises(self.signer.SigningError):
                    self.signer.sign_tree(
                        fixture.unsigned,
                        fixture.output,
                        package_name="lto-archiver",
                        gnupg_home=fixture.gnupg,
                        primary_fingerprint=PRIMARY,
                        signing_subkey_fingerprint=SUBKEY,
                        policy_file=fixture.policy,
                        public_key=fixture.public_key,
                        tools=fixture.tools,
                        run_command=fixture.run,
                    )
                self.assertFalse(fixture.output.exists())

    def test_rejects_source_generation_swap_between_prehash_and_copy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = SigningFixture(Path(raw), self.signer)
            def swap_then_copy(source, destination, **kwargs):
                binary = fixture.unsigned / (
                    "RPMS/noarch/lto-archiver-0.11.27-102.noarch.rpm"
                )
                binary.write_bytes(b"attacker generation\n")
                binary.chmod(0o644)
                fixture._write_manifest()
                destination.mkdir()
                for source_path in source.rglob("*"):
                    target = destination / source_path.relative_to(source)
                    if source_path.is_dir():
                        target.mkdir()
                    else:
                        target.write_bytes(source_path.read_bytes())
                        target.chmod(source_path.stat().st_mode & 0o777)
                return destination

            with (
                patch.object(self.signer.shutil, "copytree", side_effect=swap_then_copy),
                self.assertRaises(self.signer.SigningError),
            ):
                self.signer.sign_tree(
                    fixture.unsigned,
                    fixture.output,
                    package_name="lto-archiver",
                    gnupg_home=fixture.gnupg,
                    primary_fingerprint=PRIMARY,
                    signing_subkey_fingerprint=SUBKEY,
                    policy_file=fixture.policy,
                    public_key=fixture.public_key,
                    tools=fixture.tools,
                    run_command=fixture.run,
                )

            self.assertFalse(fixture.output.exists())

    def test_late_competing_output_is_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = SigningFixture(Path(raw), self.signer)
            real_publish = self.signer._rename_noreplace

            def compete_then_publish(source_fd, source_name, target_fd, target_name):
                fixture.output.mkdir()
                marker = fixture.output / "competitor"
                marker.write_bytes(b"must survive\n")
                return real_publish(source_fd, source_name, target_fd, target_name)

            with (
                patch.object(
                    self.signer,
                    "_rename_noreplace",
                    side_effect=compete_then_publish,
                ),
                self.assertRaises(self.signer.SigningError),
            ):
                self.signer.sign_tree(
                    fixture.unsigned,
                    fixture.output,
                    package_name="lto-archiver",
                    gnupg_home=fixture.gnupg,
                    primary_fingerprint=PRIMARY,
                    signing_subkey_fingerprint=SUBKEY,
                    policy_file=fixture.policy,
                    public_key=fixture.public_key,
                    tools=fixture.tools,
                    run_command=fixture.run,
                )

            self.assertEqual(b"must survive\n", (fixture.output / "competitor").read_bytes())

    def test_rejects_extra_rpm_symlink_and_existing_output(self) -> None:
        for mutation in ("extra", "symlink", "output"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                fixture = SigningFixture(Path(raw), self.signer)
                if mutation == "extra":
                    extra = fixture.unsigned / "RPMS/noarch/extra.rpm"
                    extra.write_bytes(b"extra\n")
                    fixture._write_manifest()
                elif mutation == "symlink":
                    link = fixture.unsigned / "RPMS/noarch/unsafe"
                    link.symlink_to("lto-archiver-0.11.27-102.noarch.rpm")
                else:
                    fixture.output.mkdir()
                with self.assertRaises(self.signer.SigningError):
                    self.signer.sign_tree(
                        fixture.unsigned,
                        fixture.output,
                        package_name="lto-archiver",
                        gnupg_home=fixture.gnupg,
                        primary_fingerprint=PRIMARY,
                        signing_subkey_fingerprint=SUBKEY,
                        policy_file=fixture.policy,
                        public_key=fixture.public_key,
                        tools=fixture.tools,
                        run_command=fixture.run,
                    )


if __name__ == "__main__":
    unittest.main()
