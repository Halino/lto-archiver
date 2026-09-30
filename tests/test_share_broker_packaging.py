from __future__ import annotations

import configparser
import importlib.util
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
KEYS = (
    "share-broker-capability",
    "share-broker-proof-key",
    "share-store-request-key",
    "share-request-key",
)


def read_unit(name: str) -> tuple[str, configparser.ConfigParser]:
    raw = (ROOT / "packaging/systemd" / name).read_text(encoding="utf-8")
    parser = configparser.ConfigParser(strict=False)
    parser.optionxform = str
    parser.read_string(raw)
    return raw, parser


def load_provisioner():
    path = ROOT / "packaging/scripts/provision-credentials.py"
    spec = importlib.util.spec_from_file_location("share_key_provisioner", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ShareBrokerPackagingTests(unittest.TestCase):
    def test_selinux_source_contract_rejects_share_authority_mutations(self) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        contexts = (ROOT / "packaging/selinux/lto_archiver.fc").read_text()

        required_policy = {
            "systemd_userdbd_stream_connect(lto_archiver_share_broker_t)",
            "init_status(lto_archiver_share_broker_t)",
            "init_start_transient_unit(lto_archiver_share_broker_t)",
            "init_stop_transient_unit(lto_archiver_share_broker_t)",
            "allow lto_archiver_share_broker_t init_t:system { start stop };",
            (
                "allow lto_archiver_share_broker_t systemd_unit_file_t:service "
                "{ status stop };"
            ),
            "allow lto_archiver_t init_t:dir search;",
            (
                "allow lto_archiver_t lto_archiver_share_source_t:dir "
                "{ getattr search };"
            ),
            (
                "allow lto_archiver_share_broker_t lto_archiver_config_t:file "
                "{ getattr ioctl open read };"
            ),
            ("allow lto_archiver_share_broker_t lto_archiver_state_t:dir getattr;"),
            ("allow lto_archiver_share_broker_t lto_archiver_mount_t:dir getattr;"),
            "allow lto_archiver_share_broker_t nfs_t:dir getattr;",
            ("allow lto_archiver_broker_t lto_archiver_share_source_t:dir getattr;"),
            "allow mount_t lto_archiver_config_t:dir search;",
            (
                "allow mount_t lto_archiver_share_credential_t:dir "
                "{ getattr open read search };"
            ),
            (
                "allow mount_t lto_archiver_share_credential_t:file "
                "{ getattr open read };"
            ),
            (
                "allow mount_t lto_archiver_share_source_t:dir "
                "{ getattr mounton open read search };"
            ),
            (
                "allow lto_archiver_share_broker_t "
                "lto_archiver_share_source_t:dir manage_dir_perms;"
            ),
            (
                "type_transition lto_archiver_share_broker_t "
                "lto_archiver_share_source_t:dir lto_archiver_share_source_t;"
            ),
        }
        required_contexts = {
            "/var/lib/lto-archiver-share-broker(/.*)?": (
                "lto_archiver_share_broker_state_t"
            ),
            "/etc/lto-archiver/share-credentials(/.*)?": (
                "lto_archiver_share_credential_t"
            ),
            "/mnt/lto-archiver/sources(/.*)?": "lto_archiver_share_source_t",
        }

        def verify_source(candidate_policy: str, candidate_contexts: str) -> None:
            for statement in required_policy:
                if statement not in candidate_policy.splitlines():
                    raise AssertionError(f"missing policy authority: {statement}")
            expected_init_authority = {
                (
                    "init_daemon_domain(lto_archiver_share_broker_t, "
                    "lto_archiver_share_broker_exec_t)"
                ),
                "init_nnp_daemon_domain(lto_archiver_share_broker_t)",
                "init_dbus_chat(lto_archiver_share_broker_t)",
                "init_status(lto_archiver_share_broker_t)",
                "init_start_transient_unit(lto_archiver_share_broker_t)",
                "init_stop_transient_unit(lto_archiver_share_broker_t)",
            }
            actual_init_authority = {
                line.strip()
                for line in candidate_policy.splitlines()
                if line.strip().startswith("init_")
                and "lto_archiver_share_broker_t" in line
            }
            if actual_init_authority != expected_init_authority:
                raise AssertionError("share systemd authority is not exact")
            share_authority_lines = tuple(
                line.strip()
                for line in candidate_policy.splitlines()
                if "lto_archiver_share_broker_t" in line
                and not line.lstrip().startswith("#")
            )
            for forbidden in (
                "device",
                "generic_sg",
                "tape",
                "scsi",
                "fuse",
                "raw",
                "sys_admin",
                "sys_rawio",
            ):
                if any(
                    forbidden in authority.lower()
                    for authority in share_authority_lines
                ):
                    raise AssertionError(f"forbidden share authority: {forbidden}")
            if any(
                authority.lower().startswith("dev_")
                for authority in share_authority_lines
            ):
                raise AssertionError("forbidden share authority: dev macro")
            for path, context_type in required_contexts.items():
                pattern = re.compile(
                    rf"(?m)^{re.escape(path)}\s+"
                    rf"gen_context\(system_u:object_r:{context_type},s0\)$"
                )
                if pattern.search(candidate_contexts) is None:
                    raise AssertionError(f"missing file context: {path}")

        verify_source(policy, contexts)
        mutations = {
            "credential traversal removed": (
                policy.replace(
                    "allow mount_t lto_archiver_share_credential_t:dir "
                    "{ getattr open read search };",
                    "",
                    1,
                ),
                contexts,
            ),
            "systemd status removed": (
                policy.replace("init_status(lto_archiver_share_broker_t)", "", 1),
                contexts,
            ),
            "PID1 mountinfo traversal removed": (
                policy.replace("allow lto_archiver_t init_t:dir search;", "", 1),
                contexts,
            ),
            "transient mount start removed": (
                policy.replace(
                    "init_start_transient_unit(lto_archiver_share_broker_t)",
                    "",
                    1,
                ),
                contexts,
            ),
            "transient mount stop removed": (
                policy.replace(
                    "init_stop_transient_unit(lto_archiver_share_broker_t)",
                    "",
                    1,
                ),
                contexts,
            ),
            "generic transient start permission removed": (
                policy.replace(
                    "allow lto_archiver_share_broker_t init_t:system { start stop };",
                    "",
                    1,
                ),
                contexts,
            ),
            "transient mount status and stop permission removed": (
                policy.replace(
                    "allow lto_archiver_share_broker_t "
                    "systemd_unit_file_t:service { status stop };",
                    "",
                    1,
                ),
                contexts,
            ),
            "transient unit management broadened": (
                policy + "\ninit_manage_transient_unit(lto_archiver_share_broker_t)\n",
                contexts,
            ),
            "persistent unit enable granted": (
                policy + "\ninit_enable_transient_unit(lto_archiver_share_broker_t)\n",
                contexts,
            ),
            "persistent unit disable granted": (
                policy + "\ninit_disable_transient_unit(lto_archiver_share_broker_t)\n",
                contexts,
            ),
            "unit reload granted": (
                policy + "\ninit_reload_transient_unit(lto_archiver_share_broker_t)\n",
                contexts,
            ),
            "share config widened to write": (
                policy.replace(
                    "allow lto_archiver_share_broker_t "
                    "lto_archiver_config_t:file { getattr ioctl open read };",
                    "allow lto_archiver_share_broker_t "
                    "lto_archiver_config_t:file "
                    "{ getattr ioctl open read write };",
                    1,
                ),
                contexts,
            ),
            "share NFS metadata widened to traversal": (
                policy.replace(
                    "allow lto_archiver_share_broker_t nfs_t:dir getattr;",
                    "allow lto_archiver_share_broker_t nfs_t:dir "
                    "{ getattr open read search };",
                    1,
                ),
                contexts,
            ),
            "command broker managed-source metadata widened to traversal": (
                policy.replace(
                    "allow lto_archiver_broker_t "
                    "lto_archiver_share_source_t:dir getattr;",
                    "allow lto_archiver_broker_t "
                    "lto_archiver_share_source_t:dir "
                    "{ getattr open read search };",
                    1,
                ),
                contexts,
            ),
            "raw tape granted": (
                policy
                + "\nallow lto_archiver_share_broker_t "
                "tape_device_t:chr_file read;\n",
                contexts,
            ),
            "raw I/O granted": (
                policy
                + "\nallow lto_archiver_share_broker_t "
                "self:capability sys_rawio;\n",
                contexts,
            ),
            "system administration granted": (
                policy
                + "\nallow lto_archiver_share_broker_t "
                "self:capability sys_admin;\n",
                contexts,
            ),
            "generic SCSI macro granted": (
                policy + "\ndev_rw_generic_sg(lto_archiver_share_broker_t)\n",
                contexts,
            ),
            "generic device macro granted": (
                policy + "\ndev_rw_all_chr_files(lto_archiver_share_broker_t)\n",
                contexts,
            ),
            "tape macro granted": (
                policy + "\ndev_rw_tape(lto_archiver_share_broker_t)\n",
                contexts,
            ),
            "FUSE macro granted": (
                policy + "\nfs_mount_fusefs(lto_archiver_share_broker_t)\n",
                contexts,
            ),
            "raw storage macro granted": (
                policy
                + "\nstorage_raw_read_fixed_disk("
                "lto_archiver_share_broker_t)\n",
                contexts,
            ),
            **{
                f"file context removed: {path}": (
                    policy,
                    contexts.replace(path, f"/removed/{index}(/.*)?", 1),
                )
                for index, path in enumerate(required_contexts)
            },
        }
        for label, (candidate_policy, candidate_contexts) in mutations.items():
            with self.subTest(mutation=label), self.assertRaises(AssertionError):
                verify_source(candidate_policy, candidate_contexts)

    def test_installed_compiled_selinux_policy_has_exact_share_authority_when_available(
        self,
    ) -> None:
        sesearch = shutil.which("sesearch")
        semodule = shutil.which("semodule")
        policy = Path("/sys/fs/selinux/policy")
        if sesearch is None or semodule is None or not policy.is_file():
            self.skipTest("installed enforcing SELinux query tooling is unavailable")
        installed = subprocess.run(
            [semodule, "-l"], check=False, capture_output=True, text=True
        )
        if not any(
            line.split()[:1] == ["lto_archiver"]
            for line in installed.stdout.splitlines()
        ):
            self.skipTest("lto_archiver policy is not installed")

        def query(source: str, target: str, object_class: str, permission: str):
            return subprocess.run(
                [
                    sesearch,
                    "-A",
                    "-s",
                    source,
                    "-t",
                    target,
                    "-c",
                    object_class,
                    "-p",
                    permission,
                    str(policy),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        for source, target, object_class, permission in (
            ("mount_t", "lto_archiver_share_credential_t", "file", "read"),
            ("mount_t", "lto_archiver_share_source_t", "dir", "mounton"),
            (
                "lto_archiver_share_broker_t",
                "lto_archiver_share_source_t",
                "dir",
                "create",
            ),
            (
                "lto_archiver_share_broker_t",
                "lto_archiver_config_t",
                "file",
                "ioctl",
            ),
            (
                "lto_archiver_share_broker_t",
                "lto_archiver_state_t",
                "dir",
                "getattr",
            ),
            (
                "lto_archiver_share_broker_t",
                "lto_archiver_mount_t",
                "dir",
                "getattr",
            ),
            ("lto_archiver_share_broker_t", "nfs_t", "dir", "getattr"),
            (
                "lto_archiver_broker_t",
                "lto_archiver_share_source_t",
                "dir",
                "getattr",
            ),
            ("lto_archiver_share_broker_t", "init_t", "system", "status"),
            ("lto_archiver_share_broker_t", "init_t", "service", "status"),
            ("lto_archiver_share_broker_t", "init_t", "service", "start"),
            ("lto_archiver_share_broker_t", "init_t", "service", "stop"),
            ("lto_archiver_t", "init_t", "dir", "search"),
            (
                "lto_archiver_t",
                "lto_archiver_share_source_t",
                "dir",
                "search",
            ),
        ):
            with self.subTest(positive=(source, target, object_class, permission)):
                completed = query(source, target, object_class, permission)
                self.assertEqual(0, completed.returncode, completed.stderr)
                # sesearch filters on the effective source/target relation but
                # may print the stored rule through expanded policy attributes.
                self.assertTrue(completed.stdout.strip())
        for source, target, object_class, permission in (
            (
                "lto_archiver_share_broker_t",
                "lto_archiver_config_t",
                "file",
                "write",
            ),
            (
                "lto_archiver_share_broker_t",
                "lto_archiver_state_t",
                "dir",
                "read",
            ),
            (
                "lto_archiver_share_broker_t",
                "lto_archiver_mount_t",
                "dir",
                "search",
            ),
            ("lto_archiver_share_broker_t", "nfs_t", "dir", "search"),
            (
                "lto_archiver_broker_t",
                "lto_archiver_share_source_t",
                "dir",
                "search",
            ),
            ("lto_archiver_share_broker_t", "init_t", "system", "reload"),
            ("lto_archiver_share_broker_t", "init_t", "system", "start"),
            ("lto_archiver_share_broker_t", "init_t", "system", "stop"),
            ("lto_archiver_share_broker_t", "init_t", "service", "reload"),
            ("lto_archiver_share_broker_t", "init_t", "service", "enable"),
            ("lto_archiver_share_broker_t", "init_t", "service", "disable"),
            ("lto_archiver_t", "init_t", "dir", "getattr"),
            ("lto_archiver_t", "init_t", "dir", "open"),
            ("lto_archiver_t", "init_t", "dir", "read"),
            ("lto_archiver_t", "init_t", "dir", "write"),
            ("lto_archiver_t", "init_t", "process", "getattr"),
            (
                "lto_archiver_t",
                "lto_archiver_share_source_t",
                "dir",
                "open",
            ),
            (
                "lto_archiver_t",
                "lto_archiver_share_source_t",
                "dir",
                "read",
            ),
            (
                "lto_archiver_t",
                "lto_archiver_share_source_t",
                "dir",
                "write",
            ),
        ):
            with self.subTest(negative=(source, target, object_class, permission)):
                completed = query(source, target, object_class, permission)
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual("", completed.stdout.strip())
        for target, object_class, permission in (
            ("tape_device_t", "chr_file", "read"),
            ("scsi_generic_device_t", "chr_file", "read"),
            ("fuse_device_t", "chr_file", "read"),
            ("lto_archiver_share_broker_t", "capability", "sys_admin"),
            ("lto_archiver_share_broker_t", "capability", "sys_rawio"),
        ):
            with self.subTest(negative=(target, object_class, permission)):
                completed = query(
                    "lto_archiver_share_broker_t", target, object_class, permission
                )
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual("", completed.stdout.strip())

    def test_share_keys_are_pairwise_distinct_exact_and_upgrade_idempotent(
        self,
    ) -> None:
        provisioner = load_provisioner()
        self.assertTrue(set(KEYS).issubset(set(provisioner.NAMES)))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "credentials"
            provisioner.provision(
                directory, expected_uid=os.getuid(), expected_gid=os.getgid()
            )
            before = {name: (directory / name).read_bytes() for name in KEYS}
            self.assertEqual(4, len(set(before.values())))
            for name, value in before.items():
                status = (directory / name).stat()
                self.assertEqual(32, len(value))
                self.assertEqual(0o400, stat.S_IMODE(status.st_mode))
                self.assertEqual(1, status.st_nlink)
            provisioner.provision(
                directory, expected_uid=os.getuid(), expected_gid=os.getgid()
            )
            self.assertEqual(
                before, {name: (directory / name).read_bytes() for name in KEYS}
            )

    def test_each_share_key_rejects_symlink_weak_mode_and_wrong_owner(self) -> None:
        provisioner = load_provisioner()
        for name in KEYS:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "credentials"
                provisioner.provision(
                    directory, expected_uid=os.getuid(), expected_gid=os.getgid()
                )
                key = directory / name
                key.chmod(0o600)
                with self.assertRaises(RuntimeError):
                    provisioner.provision(
                        directory,
                        expected_uid=os.getuid(),
                        expected_gid=os.getgid(),
                    )
                key.chmod(0o400)
                target = directory / "outside-key"
                target.write_bytes(b"x" * 32)
                key.unlink()
                key.symlink_to(target)
                with self.assertRaises(OSError):
                    provisioner.provision(
                        directory,
                        expected_uid=os.getuid(),
                        expected_gid=os.getgid(),
                    )
                key.unlink()
                key.write_bytes(b"k" * 32)
                key.chmod(0o400)
                directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    real_fstat = os.fstat

                    def wrong_owner(fd: int, real_fstat=real_fstat):
                        status = real_fstat(fd)
                        values = list(status)
                        values[4] = os.getuid() + 1
                        return os.stat_result(values)

                    with (
                        patch.object(provisioner.os, "fstat", side_effect=wrong_owner),
                        self.assertRaises(RuntimeError),
                    ):
                        provisioner._read_valid(
                            directory_fd,
                            name,
                            expected_uid=os.getuid(),
                            expected_gid=os.getgid(),
                        )
                finally:
                    os.close(directory_fd)

    def test_socket_and_service_are_exact_privilege_separated_boundaries(self) -> None:
        _socket_raw, socket_unit = read_unit("lto-archiver-share-broker.socket")
        service_raw, service_unit = read_unit("lto-archiver-share-broker.service")
        socket_section = socket_unit["Socket"]
        service = service_unit["Service"]
        self.assertEqual(
            "/run/lto-archiver-share-broker/control.sock",
            socket_section["ListenSequentialPacket"],
        )
        self.assertEqual("share-broker", socket_section["FileDescriptorName"])
        self.assertEqual("root", socket_section["SocketUser"])
        self.assertEqual("lto-archiver", socket_section["SocketGroup"])
        self.assertEqual("0660", socket_section["SocketMode"])
        self.assertEqual("0750", socket_section["DirectoryMode"])
        self.assertEqual("yes", socket_section["RemoveOnStop"])
        self.assertEqual("root", service["User"])
        self.assertEqual("root", service["Group"])
        self.assertEqual(
            "lto-archiver-share-broker.socket",
            service_unit["Unit"]["PartOf"],
        )
        self.assertEqual("", service["CapabilityBoundingSet"])
        self.assertEqual("closed", service["DevicePolicy"])
        self.assertEqual(
            "/usr/bin/lto-archiver-share-broker --fence-all",
            service["ExecStopPost"],
        )
        self.assertNotIn("[Install]", service_raw)
        self.assertEqual("AF_UNIX AF_INET AF_INET6", service["RestrictAddressFamilies"])
        self.assertIn("SystemCallFilter=~@mount", service_raw)
        for forbidden in (
            "CAP_SYS_RAWIO",
            "CAP_SYS_ADMIN",
            "DeviceAllow=/dev/tape",
            "DeviceAllow=/dev/sg",
            "DeviceAllow=/dev/fuse",
            "ProtectSystem=",
            "PrivateTmp=",
            "ReadWritePaths=",
            "PrivateMounts=",
        ):
            self.assertNotIn(forbidden, service_raw)
        loads = [
            line.removeprefix("LoadCredential=")
            for line in service_raw.splitlines()
            if line.startswith("LoadCredential=")
        ]
        self.assertEqual(
            [
                "share-broker-capability:/etc/lto-archiver/credentials/share-broker-capability",
                "share-broker-proof-key:/etc/lto-archiver/credentials/share-broker-proof-key",
                "share-store-request-key:/etc/lto-archiver/credentials/share-store-request-key",
            ],
            loads,
        )

    def test_daemon_depends_on_share_socket_and_receives_only_its_three_keys(
        self,
    ) -> None:
        raw, unit = read_unit("lto-archiverd.service")
        self.assertIn("lto-archiver-share-broker.socket", unit["Unit"]["Requires"])
        self.assertIn("lto-archiver-share-broker.socket", unit["Unit"]["After"])
        self.assertIn("SystemCallFilter=~@mount", raw)
        self.assertEqual("/mnt/lto-archiver/sources", unit["Service"]["ReadOnlyPaths"])
        loads = {
            line.removeprefix("LoadCredential=")
            for line in raw.splitlines()
            if line.startswith("LoadCredential=")
        }
        self.assertIn(
            "share-broker-capability:/etc/lto-archiver/credentials/share-broker-capability",
            loads,
        )
        self.assertIn(
            "share-broker-proof-key:/etc/lto-archiver/credentials/share-broker-proof-key",
            loads,
        )
        self.assertIn(
            "share-request-key:/etc/lto-archiver/credentials/share-request-key",
            loads,
        )
        self.assertFalse(any("share-store-request-key" in value for value in loads))

    def test_tmpfiles_and_selinux_have_exact_distinct_share_authorities(self) -> None:
        tmpfiles = (ROOT / "packaging/systemd/lto-archiver.tmpfiles").read_text()
        for line in (
            "d /var/lib/lto-archiver-share-broker 0700 root root -",
            "d /etc/lto-archiver/share-credentials 0700 root root -",
            "d /run/lto-archiver-share-broker 0750 root lto-archiver -",
            "d /mnt/lto-archiver/sources 0750 root lto-archiver -",
        ):
            self.assertIn(line, tmpfiles.splitlines())
        self.assertFalse(
            any(
                line.startswith(("r ", "R ", "D ", "e "))
                for line in tmpfiles.splitlines()
            )
        )
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        contexts = (ROOT / "packaging/selinux/lto_archiver.fc").read_text()
        interfaces = (ROOT / "packaging/selinux/lto_archiver.if").read_text()
        generic_config = "/etc/lto-archiver(/.*)?"
        share_credentials = "/etc/lto-archiver/share-credentials(/.*)?"

        def verify_config_context_precedence(candidate: str) -> None:
            patterns = [
                line.split(None, 1)[0]
                for line in candidate.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            if patterns.count(generic_config) != 1:
                raise AssertionError("generic config file-context must be unique")
            if patterns.count(share_credentials) != 1:
                raise AssertionError("share credential file-context must be unique")
            if patterns.index(generic_config) >= patterns.index(share_credentials):
                raise AssertionError(
                    "the specific module file-context must follow its generic fallback"
                )

        verify_config_context_precedence(contexts)
        generic_line = next(
            line for line in contexts.splitlines() if line.startswith(generic_config)
        )
        with self.assertRaisesRegex(AssertionError, "generic.*unique"):
            verify_config_context_precedence(f"{contexts}\n{generic_line}\n")
        self.assertIn("policy_module(lto_archiver, 1.1.36)", policy)
        for authority in (
            "lto_archiver_share_broker_t",
            "lto_archiver_share_broker_exec_t",
            "lto_archiver_share_broker_state_t",
            "lto_archiver_share_broker_runtime_t",
            "lto_archiver_share_credential_t",
            "lto_archiver_share_source_t",
        ):
            self.assertIn(authority, policy + contexts)
        share_rules = "\n".join(
            line
            for line in policy.splitlines()
            if "lto_archiver_share_broker_t" in line
        )
        for forbidden in (
            "tape_device_t",
            "scsi_generic_device_t",
            "fuse_device_t",
            "sys_admin",
            "sys_rawio",
        ):
            self.assertNotIn(forbidden, share_rules)
        self.assertIn(
            "allow mount_t lto_archiver_share_credential_t:file { getattr open read };",
            policy,
        )
        self.assertIn(
            "allow mount_t lto_archiver_share_source_t:dir { getattr mounton open read search };",
            policy,
        )
        self.assertIn(
            "allow lto_archiver_share_broker_t lto_archiver_share_source_t:dir manage_dir_perms;",
            policy,
        )
        self.assertIn(
            "type_transition lto_archiver_share_broker_t "
            "lto_archiver_share_source_t:dir lto_archiver_share_source_t;",
            policy,
        )
        self.assertIn("interface(`lto_archiver_connect_share_broker'", interfaces)
        self.assertIn(
            "allow $1 lto_archiver_share_broker_t:unix_stream_socket connectto;",
            interfaces,
        )
        for forbidden_reader in (
            "lto_archiver_t",
            "lto_archiver_web_t",
            "lto_archiver_broker_t",
        ):
            self.assertNotRegex(
                policy,
                rf"allow {forbidden_reader} lto_archiver_share_credential_t:file",
            )

    def test_rpm_release_dependencies_assets_and_non_destructive_lifecycle(
        self,
    ) -> None:
        spec = (ROOT / "packaging/rpm/lto-archiver.spec").read_text()
        version = re.findall(r"(?m)^Version:\s+([^\s]+)$", spec)
        release = re.findall(r"(?m)^Release:\s+([1-9][0-9]*)%\{\?dist\}$", spec)
        self.assertEqual(1, len(version))
        self.assertEqual(1, len(release))
        release_identity = f"{version[0]}-{release[0]}"
        release_notes = ROOT / f"docs/release-notes-{release_identity}.md"
        self.assertTrue(release_notes.is_file())
        self.assertTrue(
            release_notes.read_text(encoding="utf-8").startswith(
                f"# LTO Archiver {release_identity}"
            )
        )
        self.assertIn(
            "- Make managed-share automatic connection lifecycle-driven: active\n"
            "  shares connect automatically and disabled shares disconnect safely.",
            spec,
        )
        self.assertIn(
            "* Fri Aug 28 2026 LTO Archiver Engineering "
            "<noreply@example.invalid> - 0.11.27-97\n"
            "- Require the native RHEL NFS and CIFS packages rather than merged-usr "
            "helper\n"
            "  paths that DNF cannot resolve from package metadata.",
            spec,
        )
        self.assertIn(
            "- Show native, LTFS-usable, reserved, effective, allocated, and "
            "available\n"
            "  cassette capacity in the authenticated WebUI planning flow.",
            spec,
        )
        for dependency in (
            "Requires:       nfs-utils",
            "Requires:       cifs-utils",
            "Requires:       systemd-libs",
        ):
            self.assertIn(dependency, spec)
        for asset in (
            "lto-archiver-share-broker",
            "lto-archiver-share-broker.service",
            "lto-archiver-share-broker.socket",
        ):
            self.assertIn(asset, spec)
        lifecycle = spec.split("%preun\n", 1)[1].split("\n%files", 1)[0]
        self.assertIn(
            "%systemd_preun lto-archiver-command-broker.socket "
            "lto-archiver-share-broker.socket lto-archiver-log-reader.socket "
            "lto-archiver-log-reader.service lto-archiverd.socket "
            "lto-archiver-web.service",
            lifecycle,
        )
        self.assertIn(
            "%systemd_postun_with_restart lto-archiver-command-broker.service "
            "lto-archiver-share-broker.service lto-archiver-log-reader.socket "
            "lto-archiver-log-reader.service lto-archiverd.service "
            "lto-archiver-web.service",
            lifecycle,
        )
        self.assertNotIn("/etc/lto-archiver/share-credentials", lifecycle)
        self.assertNotIn("rm ", lifecycle)
        self.assertNotIn("unlink", lifecycle)
        files = spec.split("%files -f %{pyproject_files}\n", 1)[1]
        self.assertNotRegex(files, r"%\{_sysconfdir\}/lto-archiver/credentials/")
        self.assertNotRegex(files, r"share-credentials/(?:\*|\.\*)")
        self.assertNotRegex(files, r"%\{_sysconfdir\}/lto-archiver/share-credentials/")


if __name__ == "__main__":
    unittest.main()
