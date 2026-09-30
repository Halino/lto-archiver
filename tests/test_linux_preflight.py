from __future__ import annotations

import io
import json
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ltobackup.broker.client import BrokerUnavailable
from ltobackup.errors import ValidationError
from ltobackup.linux_settings import LinuxSettings
from ltobackup.preflight import AccountIdentity, PreflightHost, main, run_preflight
from ltobackup.share_broker.client import ShareBrokerClient
from ltobackup.tape.command_supervisor import BrokeredCgroupScopeToken

ROOT = Path(__file__).resolve().parents[1]

_SELINUX_ALLOW_RULE = re.compile(
    r"(?m)^[ \t]*allow[ \t]+(?P<source>[A-Za-z_][A-Za-z0-9_]*)[ \t]+"
    r"(?P<target>[A-Za-z_][A-Za-z0-9_]*):"
    r"(?P<object_class>[A-Za-z_][A-Za-z0-9_]*)[ \t]+"
    r"(?:\{(?P<braced>[^}]*)\}|(?P<singleton>[A-Za-z_][A-Za-z0-9_]*))"
    r"[ \t]*;[ \t]*$"
)


def _selinux_allow_rules(
    policy: str,
) -> list[tuple[str, str, str, frozenset[str]]]:
    return [
        (
            match.group("source"),
            match.group("target"),
            match.group("object_class"),
            frozenset(
                (
                    match.group("braced")
                    if match.group("braced") is not None
                    else match.group("singleton")
                ).split()
            ),
        )
        for match in _SELINUX_ALLOW_RULE.finditer(policy)
    ]


class PassingHost(PreflightHost):
    def __init__(self) -> None:
        self.rhel9 = True
        self.enforcing = True
        self.accounts = {
            "lto-archiver": AccountIdentity(998, (998, 999)),
            "lto-web": AccountIdentity(997, (997,)),
        }
        self.devices = True
        self.tools = True
        self.provenance = True
        self.fuse_boundary = True
        self.share_helpers = True
        self.share_boundary = True
        self.share_paths = True
        self.sources = True
        self.mount = True
        self.state = True
        self.windows_inactive = True
        self.calls: list[str] = []

    def is_rhel_major_9(self) -> bool:
        self.calls.append("platform")
        return self.rhel9

    def is_selinux_enforcing(self) -> bool:
        self.calls.append("selinux")
        return self.enforcing

    def account(self, name: str) -> AccountIdentity | None:
        self.calls.append(f"account:{name}")
        return self.accounts.get(name)

    def stable_devices_ready(self, settings: LinuxSettings) -> bool:
        self.calls.append("devices")
        return self.devices

    def tools_ready(self) -> bool:
        self.calls.append("tools")
        return self.tools

    def ltfs_provenance_ready(self) -> bool:
        self.calls.append("provenance")
        return self.provenance

    def fuse_session_boundary_ready(
        self,
        *,
        broker_socket_path: Path,
        broker_capability_path: Path,
    ) -> bool:
        self.calls.append("fuse-session-boundary")
        return self.fuse_boundary

    def share_helpers_ready(self) -> bool:
        self.calls.append("share-helpers")
        return self.share_helpers

    def share_broker_boundary_ready(self, **_kwargs) -> bool:
        self.calls.append("share-broker-boundary")
        return self.share_boundary

    def share_paths_ready(
        self, settings: LinuxSettings, daemon: AccountIdentity
    ) -> bool:
        self.calls.append("share-paths")
        return self.share_paths

    def sources_readable(
        self, settings: LinuxSettings, account: AccountIdentity
    ) -> bool:
        self.calls.append("sources")
        return self.sources

    def managed_mount_ready(self, settings: LinuxSettings) -> bool:
        self.calls.append("managed-mount")
        return self.mount

    def state_paths_ready(
        self,
        settings: LinuxSettings,
        daemon: AccountIdentity,
        web: AccountIdentity,
    ) -> bool:
        self.calls.append("state")
        return self.state

    def windows_owner_inactive(self) -> bool:
        self.calls.append("windows-owner")
        return self.windows_inactive


def settings() -> LinuxSettings:
    return LinuxSettings(
        tape_device_path=Path("/dev/tape/by-id/scsi-configured-drive-nst"),
        scsi_device_path=Path("/dev/lto-archiver-scsi-configured-drive"),
        source_roots=(Path("/srv/archive-sources/library"),),
        restore_roots=(Path("/srv/archive-restores/output"),),
    )


class LinuxPreflightTests(unittest.TestCase):
    def test_empty_local_source_allowlist_is_ready_for_managed_network_shares(
        self,
    ) -> None:
        empty_settings = LinuxSettings(
            tape_device_path=Path(
                "/dev/tape/by-id/scsi-configured-drive-nst"
            ),
            scsi_device_path=Path(
                "/dev/lto-archiver-scsi-configured-drive"
            ),
            source_roots=(),
            restore_roots=(Path("/srv/archive-restores/output"),),
        )

        self.assertTrue(
            PreflightHost().sources_readable(
                empty_settings,
                AccountIdentity(uid=998, gids=(998, 999)),
            )
        )

    def _assert_broker_cgroup_filesystem_contract(self, policy: str) -> None:
        cgroup_filesystem_rules = [
            rule
            for rule in _selinux_allow_rules(policy)
            if rule[1] == "cgroup_t" and rule[2] == "filesystem"
        ]
        self.assertEqual(
            [
                (
                    "lto_archiver_broker_t",
                    "cgroup_t",
                    "filesystem",
                    frozenset({"getattr"}),
                )
            ],
            cgroup_filesystem_rules,
        )

    def _assert_init_device_link_read_contract(self, policy: str) -> None:
        init_device_rules = [
            rule
            for rule in _selinux_allow_rules(policy)
            if rule[0] == "init_t" and rule[1].endswith("device_t")
        ]
        self.assertEqual(
            [
                (
                    "init_t",
                    "lto_archiver_device_t",
                    "lnk_file",
                    frozenset({"read"}),
                )
            ],
            init_device_rules,
        )

    def _assert_daemon_fuse_filesystem_contract(self, policy: str) -> None:
        daemon_fuse_filesystem_rules = [
            rule
            for rule in _selinux_allow_rules(policy)
            if rule[0] == "lto_archiver_t"
            and rule[1] == "fusefs_t"
            and rule[2] == "filesystem"
        ]
        self.assertEqual(
            [
                (
                    "lto_archiver_t",
                    "fusefs_t",
                    "filesystem",
                    frozenset({"getattr"}),
                )
            ],
            daemon_fuse_filesystem_rules,
        )

    def test_policy_allows_init_to_read_only_the_managed_device_symlink(
        self,
    ) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        self._assert_init_device_link_read_contract(policy)

    def test_broker_can_identify_only_the_cgroup_filesystem(self) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        self._assert_broker_cgroup_filesystem_contract(policy)

    def test_daemon_can_identify_only_the_fuse_filesystem(self) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        self._assert_daemon_fuse_filesystem_contract(policy)

    def test_daemon_fuse_filesystem_contract_rejects_broad_mutations(self) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        exact = "allow lto_archiver_t fusefs_t:filesystem getattr;"
        self.assertIn(exact, policy)
        mutations = {
            "extra permission in braced rule": policy.replace(
                exact,
                "allow lto_archiver_t fusefs_t:filesystem { getattr mount };",
            ),
            "split extra singleton permission": policy.replace(
                exact,
                exact + "\nallow lto_archiver_t fusefs_t:filesystem mount;",
            ),
            "broader target type": policy.replace(
                exact,
                "allow lto_archiver_t fs_t:filesystem getattr;",
            ),
            "broader object class": policy.replace(
                exact,
                "allow lto_archiver_t fusefs_t:dir getattr;",
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(mutation=name), self.assertRaises(AssertionError):
                self._assert_daemon_fuse_filesystem_contract(mutation)

    def test_log_reader_journal_and_daemon_socket_contract_is_least_privilege(self) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        self.assertIn(
            "allow lto_archiver_log_reader_t syslogd_var_run_t:file { getattr map open read };",
            policy,
        )
        self.assertIn(
            "allow lto_archiver_log_reader_t syslogd_t:unix_stream_socket connectto;",
            policy,
        )
        self.assertIn(
            "allow lto_archiver_log_reader_t tmpfs_t:filesystem getattr;",
            policy,
        )
        self.assertIn("journalctl_exec(lto_archiver_log_reader_t)", policy)
        self.assertIn(
            "allow lto_archiver_t lto_archiver_log_reader_t:unix_stream_socket connectto;",
            policy,
        )
        self.assertIn(
            "allow lto_archiver_log_reader_t lto_archiver_t:unix_stream_socket { accept getattr getopt read setopt shutdown write };",
            policy,
        )
        for forbidden_domain in (
            "lto_archiver_web_t",
            "lto_archiver_broker_t",
            "lto_archiver_share_broker_t",
        ):
            self.assertNotIn(
                f"allow {forbidden_domain} lto_archiver_log_reader_t:unix_stream_socket connectto;",
                policy,
            )

    def test_operational_event_domains_are_syslog_clients(self) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        clients = set(
            re.findall(r"^logging_send_syslog_msg\(([^)]+)\)$", policy, re.MULTILINE)
        )
        datagram_rules = {
            rule
            for rule in _selinux_allow_rules(policy)
            if rule[1:] == (
                "self",
                "unix_dgram_socket",
                frozenset(
                    {
                        "connect",
                        "create",
                        "getattr",
                        "getopt",
                        "read",
                        "setopt",
                        "shutdown",
                        "write",
                    }
                ),
            )
        }

        self.assertEqual(
            {
                "lto_archiver_t",
                "lto_archiver_broker_t",
                "lto_archiver_share_broker_t",
            },
            clients,
        )
        self.assertEqual(
            {
                (
                    domain,
                    "self",
                    "unix_dgram_socket",
                    frozenset(
                        {
                            "connect",
                            "create",
                            "getattr",
                            "getopt",
                            "read",
                            "setopt",
                            "shutdown",
                            "write",
                        }
                    ),
                )
                for domain in clients
            },
            datagram_rules,
        )

    def test_broker_cgroup_filesystem_contract_rejects_broad_mutations(self) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        exact = "allow lto_archiver_broker_t cgroup_t:filesystem getattr;"
        mutations = {
            "extra permission": policy.replace(
                exact,
                "allow lto_archiver_broker_t cgroup_t:filesystem "
                "{ getattr mount };",
            ),
            "daemon grant": policy.replace(
                exact,
                exact + "\nallow lto_archiver_t cgroup_t:filesystem getattr;",
            ),
            "broader object class": policy.replace(
                exact,
                "allow lto_archiver_broker_t cgroup_t:dir getattr;",
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(mutation=name), self.assertRaises(AssertionError):
                self._assert_broker_cgroup_filesystem_contract(mutation)

    def test_init_device_link_read_contract_rejects_broad_mutations(self) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        exact = "allow init_t lto_archiver_device_t:lnk_file read;"
        self.assertIn(exact, policy)
        mutations = {
            "extra permission in braced rule": policy.replace(
                exact,
                "allow init_t lto_archiver_device_t:lnk_file { getattr read };",
            ),
            "split extra singleton permission": policy.replace(
                exact,
                exact + "\nallow init_t lto_archiver_device_t:lnk_file getattr;",
            ),
            "broader target type": policy.replace(
                exact,
                "allow init_t device_t:lnk_file read;",
            ),
            "broader object class": policy.replace(
                exact,
                "allow init_t lto_archiver_device_t:dir read;",
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(mutation=name), self.assertRaises(AssertionError):
                self._assert_init_device_link_read_contract(mutation)

    def test_platform_probe_reads_the_etc_bound_rhel_release_file(self) -> None:
        with patch("ltobackup.preflight.Path") as path_type:
            path_type.return_value.read_text.return_value = (
                "Red Hat Enterprise Linux release 9.8 (Plow)\n"
            )
            self.assertTrue(PreflightHost().is_rhel_major_9())

        path_type.assert_called_once_with("/etc/redhat-release")
        path_type.return_value.read_text.assert_called_once_with()

    def test_platform_probe_rejects_other_products_and_major_versions(self) -> None:
        for release in (
            "Red Hat Enterprise Linux release 8.10 (Ootpa)\n",
            "CentOS Stream release 9\n",
            "Red Hat Enterprise Linux release 90.1 (Future)\n",
        ):
            with (
                self.subTest(release=release),
                patch.object(Path, "read_text", return_value=release),
            ):
                self.assertFalse(PreflightHost().is_rhel_major_9())

    def test_preflight_runs_every_read_only_gate_and_succeeds(self) -> None:
        host = PassingHost()
        result = run_preflight(settings(), host)
        self.assertTrue(result.ok)
        self.assertEqual(
            (
                "platform.rhel9",
                "selinux.enforcing",
                "accounts.present",
                "devices.stable",
                "ltfs.tools",
                "ltfs.provenance",
                "ltfs.fuse_boundary",
                "shares.helpers",
                "shares.broker_boundary",
                "shares.permissions",
                "sources.readable",
                "mount.empty_unmounted",
                "state.permissions",
                "windows.inactive",
            ),
            tuple(check.name for check in result.checks),
        )
        self.assertEqual(15, len(host.calls))

    def test_each_failed_prerequisite_closes_admission_without_short_circuit(
        self,
    ) -> None:
        attributes = (
            "rhel9",
            "enforcing",
            "devices",
            "tools",
            "provenance",
            "fuse_boundary",
            "share_helpers",
            "share_boundary",
            "share_paths",
            "sources",
            "mount",
            "state",
            "windows_inactive",
        )
        for attribute in attributes:
            with self.subTest(attribute=attribute):
                host = PassingHost()
                setattr(host, attribute, False)
                result = run_preflight(settings(), host)
                self.assertFalse(result.ok)
                self.assertEqual(14, len(result.checks))

    def test_share_broker_feature_proof_requires_both_keys_and_exact_client(self) -> None:
        loader = Mock(side_effect=(b"c" * 32, b"p" * 32))
        api = Mock(spec=ShareBrokerClient)
        api.assert_ready.return_value = None
        factory = Mock(return_value=api)
        host = PreflightHost(
            share_credential_loader=loader,
            share_broker_factory=factory,
        )
        socket_path = Path("/run/lto-archiver-share-broker/control.sock")
        capability_path = Path("/run/credentials/daemon/share-broker-capability")
        proof_path = Path("/run/credentials/daemon/share-broker-proof-key")
        self.assertTrue(
            host.share_broker_boundary_ready(
                socket_path=socket_path,
                capability_path=capability_path,
                proof_key_path=proof_path,
            )
        )
        self.assertEqual(
            [((capability_path,), {}), ((proof_path,), {})], loader.call_args_list
        )
        factory.assert_called_once_with(
            socket_path, capability=b"c" * 32, proof_key=b"p" * 32
        )
        api.assert_ready.assert_called_once_with()
        for capability, proof_key in (
            (b"short", b"p" * 32),
            (b"c" * 32, b"short"),
            (b"same" * 8, b"same" * 8),
        ):
            with self.subTest(invalid_keys=(len(capability), len(proof_key))):
                invalid = PreflightHost(
                    share_credential_loader=Mock(
                        side_effect=(capability, proof_key)
                    ),
                    share_broker_factory=Mock(return_value=api),
                )
                self.assertFalse(
                    invalid.share_broker_boundary_ready(
                        socket_path=socket_path,
                        capability_path=capability_path,
                        proof_key_path=proof_path,
                    )
                )

    def test_share_preflight_requires_helpers_and_exact_private_directories(self) -> None:
        host = PreflightHost()
        self.assertEqual(
            (Path("/usr/sbin/mount.nfs"), Path("/usr/sbin/mount.cifs")),
            host._SHARE_HELPERS,
        )
        daemon = AccountIdentity(991, (991, 992), 991)
        statuses = {
            Path("/var/lib/lto-archiver-share-broker"): (0, 0, 0o700),
            Path("/etc/lto-archiver/share-credentials"): (0, 0, 0o700),
            Path("/run/lto-archiver-share-broker"): (0, 991, 0o750),
            Path("/mnt/lto-archiver/sources"): (0, 991, 0o750),
        }

        def directory_status(path: Path, **_kwargs):
            uid, gid, mode = statuses[path]
            return type(
                "Status",
                (),
                {"st_mode": stat.S_IFDIR | mode, "st_uid": uid, "st_gid": gid},
            )()

        with (
            patch.object(Path, "stat", autospec=True, side_effect=directory_status),
            patch.object(Path, "is_symlink", return_value=False),
        ):
            self.assertTrue(host.share_paths_ready(settings(), daemon))
            statuses[Path("/run/lto-archiver-share-broker")] = (0, 992, 0o750)
            self.assertFalse(host.share_paths_ready(settings(), daemon))
            statuses[Path("/run/lto-archiver-share-broker")] = (0, 991, 0o750)
            statuses[Path("/mnt/lto-archiver/sources")] = (0, 992, 0o750)
            self.assertFalse(host.share_paths_ready(settings(), daemon))
            statuses[Path("/mnt/lto-archiver/sources")] = (0, 991, 0o750)
            statuses[Path("/etc/lto-archiver/share-credentials")] = (0, 0, 0o750)
            self.assertFalse(host.share_paths_ready(settings(), daemon))

    def test_share_preflight_rejects_non_packaged_managed_source_root(self) -> None:
        configured = settings()
        configured = LinuxSettings(
            **{
                **configured.__dict__,
                "managed_source_mount_root": Path("/opt/lto-archiver/sources"),
            }
        )
        with patch("ltobackup.preflight._owned_directory", return_value=True):
            self.assertFalse(
                PreflightHost().share_paths_ready(
                    configured, AccountIdentity(991, (991,), 991)
                )
            )

    def test_broker_feature_proof_opens_fuse_boundary(self) -> None:
        capability = BrokeredCgroupScopeToken(b"c" * 32)
        api = Mock(unsafe=True)
        api.assert_ready.return_value = None
        loader = Mock(return_value=capability)
        factory = Mock(return_value=api)
        host = PreflightHost(
            broker_capability_loader=loader,
            broker_api_factory=factory,
        )
        socket_path = Path("/run/lto-archiver-broker/control.sock")
        capability_path = Path(
            "/run/credentials/lto-archiverd.service/broker-capability"
        )

        self.assertTrue(
            host.fuse_session_boundary_ready(
                broker_socket_path=socket_path,
                broker_capability_path=capability_path,
            )
        )

        loader.assert_called_once_with(capability_path)
        factory.assert_called_once_with(socket_path, capability)
        api.assert_ready.assert_called_once_with()

    def test_nonconforming_readiness_result_keeps_fuse_boundary_closed(self) -> None:
        capability = BrokeredCgroupScopeToken(b"c" * 32)
        api = Mock(unsafe=True)
        api.assert_ready.return_value = True
        host = PreflightHost(
            broker_capability_loader=Mock(return_value=capability),
            broker_api_factory=Mock(return_value=api),
        )
        self.assertFalse(
            host.fuse_session_boundary_ready(
                broker_socket_path=Path("/private/socket"),
                broker_capability_path=Path("/private/capability"),
            )
        )

    def test_missing_or_tampered_capability_keeps_fuse_boundary_closed(self) -> None:
        for error in (FileNotFoundError("private path"), ValueError("private hash")):
            with self.subTest(error=type(error).__name__):
                host = PreflightHost(
                    broker_capability_loader=Mock(side_effect=error),
                    broker_api_factory=Mock(),
                )
                self.assertFalse(
                    host.fuse_session_boundary_ready(
                        broker_socket_path=Path("/private/socket"),
                        broker_capability_path=Path("/private/capability"),
                    )
                )

    def test_missing_socket_or_rejected_peer_keeps_fuse_boundary_closed(self) -> None:
        capability = BrokeredCgroupScopeToken(b"c" * 32)
        for error in (FileNotFoundError("private socket"), BrokerUnavailable()):
            with self.subTest(error=type(error).__name__):
                api = Mock(unsafe=True)
                api.assert_ready.side_effect = error
                host = PreflightHost(
                    broker_capability_loader=Mock(return_value=capability),
                    broker_api_factory=Mock(return_value=api),
                )
                self.assertFalse(
                    host.fuse_session_boundary_ready(
                        broker_socket_path=Path("/private/socket"),
                        broker_capability_path=Path("/private/capability"),
                    )
                )

    def test_preflight_requires_the_qualified_fuse2_helper(self) -> None:
        self.assertIn(Path("/usr/bin/fusermount"), PreflightHost._TOOLS)
        self.assertNotIn(Path("/usr/bin/fusermount3"), PreflightHost._TOOLS)

    def test_tool_probe_accepts_only_the_role_specific_fuse2_setuid_mode(
        self,
    ) -> None:
        def status(path: Path, **_kwargs):
            mode = 0o4755 if path == Path("/usr/bin/fusermount") else 0o755
            return type(
                "Status",
                (),
                {
                    "st_mode": stat.S_IFREG | mode,
                    "st_uid": 0,
                    "st_nlink": 1,
                },
            )()

        with (
            patch.object(Path, "stat", autospec=True, side_effect=status),
            patch.object(Path, "is_symlink", return_value=False),
        ):
            self.assertTrue(PreflightHost().tools_ready())

        for path, wrong_mode in (
            (Path("/usr/bin/fusermount"), 0o755),
            (Path("/usr/bin/ltfs"), 0o4755),
        ):
            with self.subTest(path=path, wrong_mode=oct(wrong_mode)):
                def mutated_status(
                    candidate: Path,
                    target_path: Path = path,
                    target_mode: int = wrong_mode,
                    **_kwargs,
                ):
                    current = status(candidate)
                    if candidate == target_path:
                        current.st_mode = stat.S_IFREG | target_mode
                    return current

                with (
                    patch.object(
                        Path,
                        "stat",
                        autospec=True,
                        side_effect=mutated_status,
                    ),
                    patch.object(Path, "is_symlink", return_value=False),
                ):
                    self.assertFalse(PreflightHost().tools_ready())

    def test_tool_probe_rejects_a_hardlinked_fuse2_helper(self) -> None:
        def status(path: Path, **_kwargs):
            mode = 0o4755 if path == Path("/usr/bin/fusermount") else 0o755
            return type(
                "Status",
                (),
                {
                    "st_mode": stat.S_IFREG | mode,
                    "st_uid": 0,
                    "st_nlink": 2
                    if path == Path("/usr/bin/fusermount")
                    else 1,
                },
            )()

        with (
            patch.object(Path, "stat", autospec=True, side_effect=status),
            patch.object(Path, "is_symlink", return_value=False),
        ):
            self.assertFalse(PreflightHost().tools_ready())

    def test_missing_account_blocks_dependent_checks_without_exception(self) -> None:
        host = PassingHost()
        del host.accounts["lto-web"]
        result = run_preflight(settings(), host)
        self.assertFalse(result.ok)
        by_name = {check.name: check.ok for check in result.checks}
        self.assertFalse(by_name["accounts.present"])
        self.assertFalse(by_name["state.permissions"])

    def test_json_cli_is_redacted_and_returns_two_on_failure(self) -> None:
        host = PassingHost()
        host.devices = False
        output = io.StringIO()
        with tempfile.NamedTemporaryFile(suffix=".toml") as config:
            code = main(
                ["--config", config.name, "--json"],
                stdout=output,
                settings_loader=lambda _path: settings(),
                host_factory=lambda: host,
            )
        payload = json.loads(output.getvalue())
        self.assertEqual(2, code)
        self.assertFalse(payload["ok"])
        serialized = json.dumps(payload)
        self.assertNotIn("/dev/", serialized)
        self.assertNotIn("/srv/", serialized)

    def test_offline_cli_keeps_schema_one_and_redacts_broker_inputs(self) -> None:
        private_socket = Path("/private/broker-control.sock")
        private_capability = Path("/private/broker-capability")
        host = PassingHost()
        host.fuse_boundary = False
        output = io.StringIO()
        code = main(
            [
                "--config",
                "/private/config.toml",
                "--json",
                "--broker-socket",
                str(private_socket),
                "--broker-capability-file",
                str(private_capability),
            ],
            stdout=output,
            settings_loader=lambda _path: settings(),
            host_factory=lambda: host,
        )

        payload = json.loads(output.getvalue())
        self.assertEqual(2, code)
        self.assertEqual(1, payload["schema"])
        self.assertFalse(payload["ok"])
        self.assertFalse(
            next(
                check["ok"]
                for check in payload["checks"]
                if check["name"] == "ltfs.fuse_boundary"
            )
        )
        serialized = json.dumps(payload)
        self.assertNotIn(str(private_socket), serialized)
        self.assertNotIn(str(private_capability), serialized)
        self.assertNotIn("sha256", serialized)

    def test_invalid_config_is_schema_one_exit_two_and_redacted(self) -> None:
        output = io.StringIO()
        code = main(
            ["--config", "/private/config.toml", "--json"],
            stdout=output,
            settings_loader=Mock(
                side_effect=ValidationError(
                    "unable to read /private/config.toml containing secret-value"
                )
            ),
        )

        payload = json.loads(output.getvalue())
        self.assertEqual(2, code)
        self.assertEqual(
            {
                "schema": 1,
                "ok": False,
                "checks": [{"name": "config.valid", "ok": False}],
            },
            payload,
        )
        serialized = json.dumps(payload)
        self.assertNotIn("/private/config.toml", serialized)
        self.assertNotIn("secret-value", serialized)

    def test_entrypoint_is_direct_python_without_a_second_confined_exec(
        self,
    ) -> None:
        script = ROOT / "scripts/preflight-rhel9.sh"
        self.assertEqual(
            (
                "#!/usr/bin/python3.11 -I",
                "import sys",
                "sys.dont_write_bytecode = True",
                'sys.path.insert(0, "/usr/lib64/lto-archiver/python-runtime/3.11/site-packages")',
                'sys.path.insert(0, "/usr/lib/python3.11/site-packages")',
                "from ltobackup.preflight import main",
                "raise SystemExit(main())",
            ),
            tuple(
                line
                for line in script.read_text().splitlines()
                if line and not line.startswith("# ")
            ),
        )
        self.assertNotIn("exec /usr/bin/python", script.read_text())

    def test_policy_has_exact_domains_and_peer_transitions_without_broad_grants(
        self,
    ) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        self.assertIn("type root_t;", policy)
        self.assertNotIn("files_search_root(", policy)
        for domain in (
            "lto_archiver_t",
            "lto_archiver_broker_t",
            "lto_archiver_share_broker_t",
            "lto_archiver_log_reader_t",
            "lto_archiver_web_t",
        ):
            self.assertIn(f"type {domain};", policy)
        for nnp_domain in (
            "lto_archiver_t",
            "lto_archiver_broker_t",
            "lto_archiver_log_reader_t",
        ):
            self.assertIn(f"init_nnp_daemon_domain({nnp_domain})", policy)
        self.assertEqual(
            {
                "corecmd_exec_bin(lto_archiver_t)",
                "corecmd_exec_bin(lto_archiver_broker_t)",
                "corecmd_exec_bin(lto_archiver_share_broker_t)",
                "corecmd_exec_bin(lto_archiver_log_reader_t)",
                "corecmd_exec_bin(lto_archiver_web_t)",
            },
            {
                line.strip()
                for line in policy.splitlines()
                if line.strip().startswith("corecmd_exec_bin(")
            },
        )
        for preflight_read_interface in (
            "auth_use_nsswitch(lto_archiver_t)",
            "corecmd_getattr_bin_files(lto_archiver_t)",
            "files_getattr_usr_files(lto_archiver_t)",
            "files_read_etc_files(lto_archiver_t)",
            "kernel_read_system_state(lto_archiver_t)",
            "selinux_get_enforce_mode(lto_archiver_t)",
        ):
            self.assertIn(preflight_read_interface, policy)
        self.assertIn(
            "allow lto_archiver_t lto_archiver_ltfs_tool_exec_t:file "
            "{ execute execute_no_trans getattr map open read };",
            policy,
        )
        for confined_probe_grant in (
            "allow lto_archiver_t device_t:dir search;",
            "allow lto_archiver_t device_t:lnk_file { getattr read };",
            "allow lto_archiver_t lto_archiver_broker_state_t:dir getattr;",
            "allow lto_archiver_t lto_archiver_web_state_t:dir getattr;",
        ):
            self.assertIn(confined_probe_grant, policy)
        self.assertNotIn("files_read_usr_files(lto_archiver_t)", policy)
        self.assertIn(
            "allow lto_archiver_t lto_archiver_broker_t:unix_stream_socket connectto;",
            policy,
        )
        self.assertIn(
            "allow lto_archiver_t lto_archiver_broker_runtime_t:dir { getattr open search };",
            policy,
        )
        self.assertNotIn(
            "allow lto_archiver_t lto_archiver_broker_runtime_t:dir { getattr open read search write };",
            policy,
        )
        self.assertIn(
            "allow lto_archiver_web_t lto_archiver_t:unix_stream_socket connectto;",
            policy,
        )
        self.assertIn("allow lto_archiver_t fusefs_t:dir manage_dir_perms;", policy)
        self.assertIn("allow lto_archiver_t fusefs_t:file manage_file_perms;", policy)
        self._assert_daemon_fuse_filesystem_contract(policy)
        self.assertNotIn("allow lto_archiver_t fuse_device_t:chr_file", policy)
        self.assertIn(
            "allow lto_archiver_broker_t self:capability { sys_admin sys_rawio };",
            policy,
        )
        self.assertIn(
            "allow lto_archiver_broker_t fuse_device_t:chr_file { getattr ioctl open read write };",
            policy,
        )
        self.assertIn(
            "allow lto_archiver_broker_t fusefs_t:filesystem { getattr mount remount unmount };",
            policy,
        )
        self.assertIn(
            "allow lto_archiver_broker_t lto_archiver_mount_t:dir { getattr mounton open read search write };",
            policy,
        )
        self.assertIn(
            "allow lto_archiver_broker_t lto_archiver_ltfs_tool_exec_t:file { execute execute_no_trans getattr map open read };",
            policy,
        )
        for state_domain in (
            "lto_archiver_t",
            "lto_archiver_broker_t",
            "lto_archiver_share_broker_t",
            "lto_archiver_web_t",
        ):
            self.assertIn(f"allow {state_domain} root_t:dir search;", policy)
            self.assertIn(f"files_search_var_lib({state_domain})", policy)
        self.assertIn("files_search_mnt(lto_archiver_broker_t)", policy)
        self.assertNotIn("allow lto_archiver_t self:capability sys_admin;", policy)
        self.assertNotIn("allow lto_archiver_t self:capability sys_rawio;", policy)
        for forbidden in (
            "unconfined_domain",
            "unconfined_t",
            "network_admin",
            "net_admin",
        ):
            self.assertNotIn(forbidden, policy)

    def test_daemon_proc_probe_reads_only_broker_processes_and_suppresses_denied_noise(
        self,
    ) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        self.assertIn("attribute domain;", policy)
        self.assertIn(
            "allow lto_archiver_t lto_archiver_broker_t:dir { getattr search };",
            policy,
        )
        self.assertIn(
            "allow lto_archiver_t lto_archiver_broker_t:file { getattr open read };",
            policy,
        )
        self.assertIn(
            "dontaudit lto_archiver_t domain:dir { getattr search };", policy
        )
        self.assertIn(
            "dontaudit lto_archiver_t domain:file { getattr open read };", policy
        )
        self.assertNotIn("allow lto_archiver_t domain:dir", policy)
        self.assertNotIn("allow lto_archiver_t domain:file", policy)

    def test_policy_allows_confined_preflight_config_probe_and_account_lookup(
        self,
    ) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        self.assertIn(
            "allow lto_archiver_t lto_archiver_config_t:file { getattr ioctl open read };",
            policy,
        )
        self.assertIn("systemd_userdbd_stream_connect(lto_archiver_t)", policy)
        self.assertIn("fs_read_nfs_files(lto_archiver_t)", policy)
        self.assertNotIn(
            "allow lto_archiver_t lto_archiver_config_t:file manage_file_perms;",
            policy,
        )
        self.assertNotIn("fs_manage_nfs_dirs(lto_archiver_t)", policy)
        self.assertNotIn("fs_manage_nfs_files(lto_archiver_t)", policy)
        self.assertNotIn(
            "systemd_userdbd_stream_connect(lto_archiver_broker_t)", policy
        )

    def test_policy_allows_only_read_only_web_startup_identity_and_cert_lookups(
        self,
    ) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        for required_interface in (
            "auth_use_nsswitch(lto_archiver_web_t)",
            "systemd_userdbd_stream_connect(lto_archiver_web_t)",
            "miscfiles_read_generic_certs(lto_archiver_web_t)",
        ):
            with self.subTest(required_interface=required_interface):
                self.assertIn(required_interface, policy)
        self.assertIn(
            "allow lto_archiver_web_t kernel_t:unix_stream_socket connectto;",
            policy,
        )
        for forbidden_interface in (
            "auth_read_shadow(lto_archiver_web_t)",
            "auth_manage_shadow(lto_archiver_web_t)",
            "miscfiles_read_all_certs(lto_archiver_web_t)",
            "miscfiles_manage_generic_cert_dirs(lto_archiver_web_t)",
            "miscfiles_manage_generic_cert_files(lto_archiver_web_t)",
            "systemd_manage_userdbd_runtime_sock_files(lto_archiver_web_t)",
        ):
            with self.subTest(forbidden_interface=forbidden_interface):
                self.assertNotIn(forbidden_interface, policy)
        for base_policy_type in (
            "passwd_file_t",
            "sssd_var_lib_t",
            "systemd_userdbd_runtime_t",
            "cert_t",
        ):
            with self.subTest(base_policy_type=base_policy_type):
                self.assertNotIn(
                    f"allow lto_archiver_web_t {base_policy_type}", policy
                )

    def test_policy_allows_only_the_observed_host_preflight_metadata_reads(
        self,
    ) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        expected = {
            "allow lto_archiver_t mount_exec_t:file getattr;",
            "allow lto_archiver_t init_t:dir search;",
            "allow lto_archiver_t init_t:file { getattr open read };",
        }

        def contract_is_exact(source: str) -> bool:
            grants = {
                line.strip()
                for line in source.splitlines()
                if line.strip().startswith("allow lto_archiver_t mount_exec_t:")
                or line.strip().startswith("allow lto_archiver_t init_t:")
            }
            return "type mount_exec_t;" in source and grants == expected

        self.assertTrue(contract_is_exact(policy))
        mutations = (
            policy.replace(
                "allow lto_archiver_t mount_exec_t:file getattr;",
                "allow lto_archiver_t mount_exec_t:file { getattr open read };",
            ),
            policy.replace(
                "allow lto_archiver_t init_t:file { getattr open read };",
                "allow lto_archiver_t init_t:file { getattr open read write };",
            ),
            policy.replace("allow lto_archiver_t init_t:dir search;\n", "", 1),
            policy.replace(
                "allow lto_archiver_t init_t:dir search;",
                "allow lto_archiver_t init_t:dir { getattr open read search write };",
            ),
            policy + "\nallow lto_archiver_t init_t:process getattr;\n",
            policy.replace("    type mount_exec_t;\n", ""),
        )
        for mutation in mutations:
            with self.subTest(mutation=hash(mutation)):
                self.assertFalse(contract_is_exact(mutation))

    def test_policy_allows_only_observed_r48_broker_and_dynamic_user_probes(
        self,
    ) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        for exact_grant in (
            (
                "allow lto_archiver_broker_t lto_archiver_config_t:file "
                "{ getattr ioctl open read };"
            ),
            "allow lto_archiver_broker_t lto_archiver_state_t:dir getattr;",
            "allow lto_archiver_broker_t nfs_t:dir getattr;",
            "allow lto_archiver_t kernel_t:unix_stream_socket connectto;",
            "allow lto_archiver_broker_t kernel_t:unix_stream_socket connectto;",
            "allow lto_archiver_web_t kernel_t:unix_stream_socket connectto;",
        ):
            with self.subTest(exact_grant=exact_grant):
                self.assertIn(exact_grant, policy)
        for forbidden_grant in (
            (
                "allow lto_archiver_broker_t lto_archiver_state_t:dir "
                "{ getattr open read search };"
            ),
            "allow lto_archiver_broker_t lto_archiver_state_t:file",
            "allow lto_archiver_broker_t nfs_t:dir { getattr open read search };",
            "allow lto_archiver_broker_t nfs_t:file",
        ):
            with self.subTest(forbidden_grant=forbidden_grant):
                self.assertNotIn(forbidden_grant, policy)

    def test_command_capture_uses_a_dedicated_private_tmp_file_type(self) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        required = {
            "type lto_archiver_command_tmp_t;",
            "files_tmp_file(lto_archiver_command_tmp_t)",
            (
                "manage_files_pattern(lto_archiver_t, tmp_t, "
                "lto_archiver_command_tmp_t)"
            ),
            (
                "files_tmp_filetrans(lto_archiver_t, "
                "lto_archiver_command_tmp_t, file)"
            ),
        }
        self.assertTrue(required.issubset(set(policy.splitlines())))
        self.assertNotIn(
            "manage_files_pattern(lto_archiver_t, tmp_t, tmp_t)", policy
        )
        self.assertNotIn(
            "manage_files_pattern(lto_archiver_broker_t, tmp_t, ", policy
        )
        self.assertNotIn(
            "manage_files_pattern(lto_archiver_web_t, tmp_t, ", policy
        )

    def test_policy_allows_only_the_observed_blocked_child_identity_probe(self) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        for exact_grant in (
            "allow lto_archiver_t self:process setrlimit;",
            (
                "allow lto_archiver_broker_t lto_archiver_t:dir "
                "{ getattr open read search };"
            ),
            (
                "allow lto_archiver_broker_t lto_archiver_t:file "
                "{ getattr open read };"
            ),
            (
                "allow lto_archiver_broker_t lto_archiver_t:fifo_file "
                "{ getattr ioctl write };"
            ),
        ):
            with self.subTest(exact_grant=exact_grant):
                self.assertIn(exact_grant, policy)
        for forbidden_grant in (
            "allow lto_archiver_t self:process { setrlimit signal };",
            "allow lto_archiver_broker_t lto_archiver_t:dir manage_dir_perms;",
            "allow lto_archiver_broker_t lto_archiver_t:file manage_file_perms;",
            (
                "allow lto_archiver_broker_t lto_archiver_t:fifo_file "
                "{ getattr ioctl read write };"
            ),
        ):
            with self.subTest(forbidden_grant=forbidden_grant):
                self.assertNotIn(forbidden_grant, policy)

    def test_policy_allows_only_init_to_create_typed_runtime_and_credentials(
        self,
    ) -> None:
        policy = (ROOT / "packaging/selinux/lto_archiver.te").read_text()
        self.assertNotIn("files_runtime_file(", policy)
        self.assertEqual(
            {
                "files_pid_file(lto_archiver_runtime_t)",
                "files_pid_file(lto_archiver_broker_runtime_t)",
                "files_pid_file(lto_archiver_share_broker_runtime_t)",
                "files_pid_file(lto_archiver_log_reader_runtime_t)",
                "files_pid_file(lto_archiver_credential_t)",
            },
            {
                line.strip()
                for line in policy.splitlines()
                if line.strip().startswith("files_pid_file(")
            },
        )
        required = (
            "allow init_t lto_archiver_runtime_t:dir manage_dir_perms;",
            "allow init_t lto_archiver_runtime_t:sock_file manage_sock_file_perms;",
            "allow init_t lto_archiver_broker_runtime_t:dir manage_dir_perms;",
            "allow init_t lto_archiver_broker_runtime_t:sock_file manage_sock_file_perms;",
            "allow init_t lto_archiver_share_broker_runtime_t:dir manage_dir_perms;",
            "allow init_t lto_archiver_share_broker_runtime_t:sock_file manage_sock_file_perms;",
            "allow init_t lto_archiver_log_reader_runtime_t:dir manage_dir_perms;",
            "allow init_t lto_archiver_log_reader_runtime_t:sock_file manage_sock_file_perms;",
            "allow init_t lto_archiver_credential_t:dir manage_dir_perms;",
            "allow init_t lto_archiver_credential_t:file manage_file_perms;",
            "allow lto_archiver_t lto_archiver_credential_t:dir search;",
            "allow lto_archiver_t tmpfs_t:file { getattr open read };",
            "allow lto_archiver_t lto_archiver_config_t:dir search;",
            "allow lto_archiver_broker_t lto_archiver_credential_t:dir search;",
            "allow lto_archiver_broker_t tmpfs_t:file { getattr open read };",
            "allow lto_archiver_t lto_archiver_broker_runtime_t:dir { getattr open search };",
            "allow lto_archiver_web_t lto_archiver_runtime_t:dir search;",
            "allow lto_archiver_t lto_archiver_device_t:dir search;",
        )
        for statement in required:
            with self.subTest(statement=statement):
                self.assertIn(statement, policy)
        for transition in (
            'type_transition init_t var_run_t:dir lto_archiver_runtime_t "lto-archiver";',
            'type_transition init_t var_run_t:dir lto_archiver_broker_runtime_t "lto-archiver-broker";',
            'type_transition init_t var_run_t:dir lto_archiver_share_broker_runtime_t "lto-archiver-share-broker";',
            'type_transition init_t var_run_t:dir lto_archiver_log_reader_runtime_t "lto-archiver-log-reader";',
            "type_transition init_t lto_archiver_runtime_t:sock_file lto_archiver_runtime_t;",
            "type_transition init_t lto_archiver_broker_runtime_t:sock_file lto_archiver_broker_runtime_t;",
            "type_transition init_t lto_archiver_share_broker_runtime_t:sock_file lto_archiver_share_broker_runtime_t;",
            "type_transition init_t lto_archiver_log_reader_runtime_t:sock_file lto_archiver_log_reader_runtime_t;",
            'type_transition init_t var_run_t:dir lto_archiver_credential_t "lto-archiverd.service";',
            'type_transition init_t var_run_t:dir lto_archiver_credential_t "lto-archiver-command-broker.service";',
            'type_transition init_t var_run_t:dir lto_archiver_credential_t "lto-archiver-preflight.service";',
        ):
            with self.subTest(transition=transition):
                self.assertIn(transition, policy)
        contexts = (ROOT / "packaging/selinux/lto_archiver.fc").read_text()
        for fragment in (
            "/var/run/lto-archiver(/.*)?",
            "lto_archiver_runtime_t",
            "/var/run/lto-archiver-broker(/.*)?",
            "lto_archiver_broker_runtime_t",
            "/var/run/lto-archiver-share-broker(/.*)?",
            "lto_archiver_share_broker_runtime_t",
            "/var/lock/lto-ltfs(/.*)?",
            "/var/run/credentials/lto-archiverd\\.service(/.*)?",
            "/var/run/credentials/lto-archiver-command-broker\\.service(/.*)?",
            "/var/run/credentials/lto-archiver-ltfs-qualification\\.service(/.*)?",
            "/var/run/credentials/lto-archiver-preflight\\.service(/.*)?",
            "lto_archiver_credential_t",
            "/dev/lto-archiver-scsi-[^/]+",
            "lto_archiver_device_t",
        ):
            with self.subTest(file_context=fragment):
                self.assertIn(fragment, contexts)
        self.assertNotRegex(contexts, r"(?m)^/run/(?:credentials|lock|lto-archiver)")
        self.assertNotRegex(policy, r"allow lto_archiver_(?:broker_)?t tmpfs_t:dir")
        self.assertNotRegex(
            policy,
            r"allow lto_archiver_(?:broker_)?t tmpfs_t:file \{[^}]*write",
        )
        self.assertNotIn("/dev/lto-archiver(/.*)?", contexts)
        self.assertNotIn("/dev/lto-archiver-scsi-.*", contexts)
        self.assertIn("/usr/bin/ltfs", contexts)
        self.assertIn("/usr/bin/fusermount", contexts)
        self.assertIn("lto_archiver_ltfs_tool_exec_t", contexts)
        self.assertRegex(
            contexts,
            r"/usr/libexec/lto-archiver/preflight-rhel9\\\.sh\s+--\s+gen_context\(system_u:object_r:lto_archiver_exec_t,s0\)",
        )
        self.assertNotIn("allow init_t lto_archiver_state_t", policy)

    def test_policy_compiles_when_selinux_development_tooling_is_available(
        self,
    ) -> None:
        makefile = Path("/usr/share/selinux/devel/Makefile")
        if shutil.which("make") is None or not makefile.exists():
            self.skipTest("SELinux development policy is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            for suffix in ("te", "if", "fc"):
                shutil.copy2(
                    ROOT / f"packaging/selinux/lto_archiver.{suffix}",
                    Path(temporary) / f"lto_archiver.{suffix}",
                )
            completed = subprocess.run(
                ["make", "-f", str(makefile), "lto_archiver.pp"],
                cwd=temporary,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_compiled_policy_matches_canonical_and_run_aliases_when_available(
        self,
    ) -> None:
        from tests.selinux_policy_fixture import (
            match_compiled_runtime_contexts,
            unpack_policy_file_contexts,
        )

        makefile = Path("/usr/share/selinux/devel/Makefile")
        unpacker = shutil.which("semodule_unpackage")
        matcher = shutil.which("matchpathcon")
        if (
            shutil.which("make") is None
            or not makefile.exists()
            or unpacker is None
            or matcher is None
        ):
            self.skipTest("SELinux compile and lookup tooling is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            for suffix in ("te", "if", "fc"):
                shutil.copy2(
                    ROOT / f"packaging/selinux/lto_archiver.{suffix}",
                    output / f"lto_archiver.{suffix}",
                )
            completed = subprocess.run(
                ["make", "-f", str(makefile), "lto_archiver.pp"],
                cwd=output,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                0, completed.returncode, completed.stdout + completed.stderr
            )
            contexts = unpack_policy_file_contexts(
                output / "lto_archiver.pp", output, unpacker
            )
            match_compiled_runtime_contexts(contexts, matcher)

    def test_udev_rule_derives_scsi_link_without_production_identity(self) -> None:
        rule = (ROOT / "packaging/udev/70-lto-archiver-scsi.rules").read_text()
        self.assertIn('SUBSYSTEM=="scsi_generic"', rule)
        self.assertIn('ATTRS{type}=="1"', rule)
        self.assertIn("$env{ID_SERIAL}", rule)
        self.assertIn('SYMLINK+="lto-archiver-scsi-', rule)
        self.assertNotIn("lto-archiver/by-id", rule)
        self.assertNotRegex(rule, r"[A-Fa-f0-9]{16,}")

    def test_udev_scsi_id_export_populates_serial_before_symlink_rule(self) -> None:
        rule = (ROOT / "packaging/udev/70-lto-archiver-scsi.rules").read_text()
        import_match = re.search(r'IMPORT\{program\}="([^"]+)"', rule)
        self.assertIsNotNone(import_match)
        command = shlex.split(import_match.group(1))
        self.assertEqual("/usr/lib/udev/scsi_id", command[0])
        self.assertIn("--export", command)

        def fake_scsi_id(argv: list[str]) -> str:
            return "ID_SERIAL=TEST_DRIVE\n" if "--export" in argv else "TEST_DRIVE\n"

        environment = dict(
            line.split("=", 1)
            for line in fake_scsi_id(command).splitlines()
            if "=" in line
        )
        self.assertEqual("TEST_DRIVE", environment.get("ID_SERIAL"))
        self.assertIn(
            "lto-archiver-scsi-TEST_DRIVE",
            rule.replace("$env{ID_SERIAL}", environment["ID_SERIAL"]),
        )

    def test_rpm_includes_policy_udev_and_preflight_assets(self) -> None:
        spec = (ROOT / "packaging/rpm/lto-archiver.spec").read_text()
        for asset in (
            "lto_archiver.pp",
            "lto_archiver.fc",
            "70-lto-archiver-scsi.rules",
            "preflight-rhel9.sh",
            "configure-device-policy.py",
            "relabel-device-aliases.py",
        ):
            self.assertIn(asset, spec)

    def test_own_ltfs_root_owned_group_executable_is_accepted(self) -> None:
        from unittest.mock import patch

        from ltobackup.preflight import _trusted_executable

        status = type("Status", (), {"st_mode": 0o100750, "st_uid": 0})()
        candidate = Path("/usr/bin/mkltfs")
        with (
            patch.object(Path, "stat", return_value=status),
            patch.object(Path, "is_symlink", return_value=False),
        ):
            self.assertTrue(_trusted_executable(candidate))

    def test_share_helpers_reject_symlink_non_root_and_writable_modes(self) -> None:
        host = PreflightHost()
        candidate = Path("/usr/sbin/mount.nfs")
        for uid, mode, symlink in (
            (1, 0o100755, False),
            (0, 0o100775, False),
            (0, 0o100755, True),
        ):
            status = type("Status", (), {"st_mode": mode, "st_uid": uid})()
            with (
                self.subTest(uid=uid, mode=oct(mode), symlink=symlink),
                patch.object(Path, "stat", return_value=status),
                patch.object(Path, "is_symlink", return_value=symlink),
            ):
                self.assertFalse(host.share_helpers_ready())
        self.assertIn(candidate, host._SHARE_HELPERS)

    def test_share_helpers_accept_only_the_exact_rhel_nfs_setuid_contract(
        self,
    ) -> None:
        host = PreflightHost()
        statuses = {
            Path("/usr/sbin/mount.nfs"): (0, stat.S_IFREG | 0o4755, 1),
            Path("/usr/sbin/mount.cifs"): (0, stat.S_IFREG | 0o755, 1),
        }
        symlinks: set[Path] = set()

        def helper_status(path: Path, **_kwargs):
            uid, mode, nlink = statuses[path]
            return type(
                "Status",
                (),
                {"st_mode": mode, "st_uid": uid, "st_nlink": nlink},
            )()

        with (
            patch.object(Path, "stat", autospec=True, side_effect=helper_status),
            patch.object(
                Path,
                "is_symlink",
                autospec=True,
                side_effect=lambda path: path in symlinks,
            ),
        ):
            self.assertTrue(host.share_helpers_ready())
            for path, invalid in (
                (Path("/usr/sbin/mount.nfs"), (0, stat.S_IFREG | 0o6755, 1)),
                (Path("/usr/sbin/mount.nfs"), (1, stat.S_IFREG | 0o4755, 1)),
                (Path("/usr/sbin/mount.nfs"), (0, stat.S_IFREG | 0o4755, 2)),
                (Path("/usr/sbin/mount.cifs"), (0, stat.S_IFREG | 0o4755, 1)),
                (Path("/usr/sbin/mount.cifs"), (0, stat.S_IFREG | 0o750, 1)),
            ):
                with self.subTest(path=path, invalid=invalid):
                    original = statuses[path]
                    statuses[path] = invalid
                    self.assertFalse(host.share_helpers_ready())
                    statuses[path] = original
            symlinks.add(Path("/usr/sbin/mount.nfs"))
            self.assertFalse(host.share_helpers_ready())

    def test_managed_mount_uses_pid1_mountinfo_not_the_service_namespace(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            mount_path = Path(temporary) / "tape"
            mount_path.mkdir()
            configured = LinuxSettings(
                **{**settings().__dict__, "mount_path": mount_path}
            )
            target = str(mount_path.resolve())

            def mountinfo(path: Path, **_kwargs) -> str:
                if path == Path("/proc/1/mountinfo"):
                    return "1 0 0:1 / / rw - xfs /dev/root rw\n"
                if path == Path("/proc/self/mountinfo"):
                    return f"2 1 0:1 / {target} rw - xfs /dev/root rw\n"
                raise AssertionError(f"unexpected read: {path}")

            with patch.object(
                Path, "read_text", autospec=True, side_effect=mountinfo
            ) as read_text:
                self.assertTrue(PreflightHost().managed_mount_ready(configured))
            self.assertEqual(
                [((Path("/proc/1/mountinfo"),), {})], read_text.call_args_list
            )

    def test_managed_mount_rejects_a_real_pid1_mount_and_unreadable_mountinfo(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            mount_path = Path(temporary) / "tape"
            mount_path.mkdir()
            configured = LinuxSettings(
                **{**settings().__dict__, "mount_path": mount_path}
            )
            target = str(mount_path.resolve())
            mounted = f"2 1 0:1 / {target} rw - fuse.ltfs ltfs rw\n"
            with patch.object(Path, "read_text", return_value=mounted):
                self.assertFalse(PreflightHost().managed_mount_ready(configured))
            with patch.object(Path, "read_text", side_effect=PermissionError):
                self.assertFalse(PreflightHost().managed_mount_ready(configured))

    def test_managed_mount_rejects_empty_truncated_and_malformed_mountinfo(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            mount_path = Path(temporary) / "tape"
            mount_path.mkdir()
            configured = LinuxSettings(
                **{**settings().__dict__, "mount_path": mount_path}
            )
            for payload in (
                "",
                "\n",
                "1 0 0:1 / / rw\n",
                "1 0 0:1 / / rw xfs /dev/root rw\n",
                "1 0 invalid / / rw - xfs /dev/root rw\n",
                "1 0 0:1 relative / rw - xfs /dev/root rw\n",
            ):
                with (
                    self.subTest(payload=payload),
                    patch.object(Path, "read_text", return_value=payload),
                ):
                    self.assertFalse(
                        PreflightHost().managed_mount_ready(configured)
                    )

    def test_managed_mount_decodes_an_escaped_pid1_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            mount_path = Path(temporary) / "tape archive"
            mount_path.mkdir()
            configured = LinuxSettings(
                **{**settings().__dict__, "mount_path": mount_path}
            )
            encoded_target = str(mount_path.resolve()).replace(" ", "\\040")
            mounted = (
                f"2 1 0:1 / {encoded_target} rw - fuse.ltfs ltfs rw\n"
            )
            with patch.object(Path, "read_text", return_value=mounted):
                self.assertFalse(PreflightHost().managed_mount_ready(configured))

    def test_source_access_rejects_non_searchable_ancestor(self) -> None:
        from ltobackup.preflight import _account_can_access

        class Node:
            def __init__(self, mode: int, parent: Node | None = None) -> None:
                self._status = type(
                    "Status",
                    (),
                    {"st_mode": 0o040000 | mode, "st_uid": 123, "st_gid": 456},
                )()
                self.parent = parent or self

            def stat(self):
                return self._status

        root = Node(0o755)
        blocked = Node(0o000, root)
        source = Node(0o750, blocked)
        identity = AccountIdentity(123, (456,))
        self.assertFalse(_account_can_access(source, identity, read=True, write=False))


if __name__ == "__main__":
    unittest.main()
