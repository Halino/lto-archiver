from __future__ import annotations

import configparser
import importlib.util
import json
import stat
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def read_unit(name: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read(ROOT / "packaging" / "systemd" / name)
    return parser


def load_deployment_verifier():
    script = ROOT / "packaging" / "scripts" / "verify-deployment-rhel9.py"
    spec = importlib.util.spec_from_file_location("task6_live_verifier", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load deployment verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class LogReaderPackagingTests(unittest.TestCase):
    def test_log_reader_socket_is_daemon_only_and_web_never_joins_group(self) -> None:
        socket = read_unit("lto-archiver-log-reader.socket")["Socket"]
        daemon = read_unit("lto-archiverd.service")["Service"]
        web = read_unit("lto-archiver-web.service")["Service"]

        self.assertEqual("/run/lto-archiver-log-reader/control.sock", socket["ListenStream"])
        self.assertEqual("root", socket["SocketUser"])
        self.assertEqual("lto-log-read", socket["SocketGroup"])
        self.assertEqual("0660", socket["SocketMode"])
        self.assertEqual("log-reader", socket["FileDescriptorName"])
        self.assertIn("lto-log-read", daemon["SupplementaryGroups"].split())
        self.assertNotIn("lto-log-read", web["SupplementaryGroups"].split())
        tmpfiles = (
            ROOT / "packaging" / "systemd" / "lto-archiver.tmpfiles"
        ).read_text()
        self.assertIn(
            "d /run/lto-archiver-log-reader 0750 root lto-log-read -",
            tmpfiles.splitlines(),
        )

    def test_log_reader_is_socket_activated_and_has_no_writable_service_paths(self) -> None:
        socket = read_unit("lto-archiver-log-reader.socket")
        service = read_unit("lto-archiver-log-reader.service")["Service"]

        self.assertEqual("lto-archiver-log-reader.service", socket["Socket"]["Service"])
        self.assertEqual("/usr/bin/lto-archiver-log-reader --socket-fd 3", service["ExecStart"])
        self.assertEqual("root", service["User"])
        self.assertEqual("", service["AmbientCapabilities"])
        self.assertEqual("yes", service["NoNewPrivileges"])
        self.assertEqual("strict", service["ProtectSystem"])
        self.assertEqual("yes", service["ProtectHome"])
        self.assertEqual("yes", service["PrivateDevices"])
        self.assertEqual("no", service["ProtectKernelLogs"])
        self.assertEqual("AF_UNIX", service["RestrictAddressFamilies"])
        self.assertEqual("closed", service["DevicePolicy"])
        for key in ("ReadWritePaths", "StateDirectory", "RuntimeDirectory", "CacheDirectory"):
            self.assertNotIn(key, service)

    def test_launcher_selinux_rpm_and_activation_contract_are_closed(self) -> None:
        launcher = (ROOT / "packaging" / "launchers" / "lto-archiver-log-reader").read_text()
        self.assertIn("from ltobackup.log_reader.main import main", launcher)

        sysusers = (ROOT / "packaging" / "systemd" / "lto-archiver.sysusers").read_text()
        self.assertIn("g lto-log-read -", sysusers.splitlines())
        self.assertNotIn(
            'g lto-log-read - "LTO Archiver log reader clients"', sysusers
        )
        self.assertIn("m lto-archiver lto-log-read", sysusers)
        self.assertNotIn("m lto-web lto-log-read", sysusers)

        policy = (ROOT / "packaging" / "selinux" / "lto_archiver.te").read_text()
        self.assertIn("type lto_archiver_log_reader_t;", policy)
        self.assertIn("type lto_archiver_log_reader_exec_t;", policy)
        self.assertIn("type lto_archiver_log_reader_runtime_t;", policy)
        self.assertIn(
            "allow lto_archiver_log_reader_t syslogd_var_run_t:file { getattr map open read };",
            policy,
        )
        self.assertNotIn("systemd_journal_t", policy)
        self.assertIn(
            "allow lto_archiver_log_reader_t syslogd_t:unix_stream_socket connectto;",
            policy,
        )
        self.assertIn("auth_read_passwd_file(lto_archiver_log_reader_t)", policy)
        self.assertIn("journalctl_exec(lto_archiver_log_reader_t)", policy)
        self.assertIn(
            "allow lto_archiver_log_reader_t tmpfs_t:filesystem getattr;",
            policy,
        )
        self.assertIn(
            "allow lto_archiver_t lto_archiver_log_reader_runtime_t:dir search;",
            policy,
        )
        interfaces = (
            ROOT / "packaging" / "selinux" / "lto_archiver.if"
        ).read_text()
        self.assertIn(
            "allow $1 lto_archiver_log_reader_runtime_t:dir search;",
            interfaces,
        )
        self.assertIn(
            "allow lto_archiver_t lto_archiver_log_reader_runtime_t:sock_file { getattr open write };",
            policy,
        )
        self.assertIn(
            "allow lto_archiver_log_reader_t lto_archiver_t:unix_stream_socket { accept getattr getopt read setopt shutdown write };",
            policy,
        )
        self.assertNotIn("allow lto_archiver_web_t lto_archiver_log_reader_runtime_t", policy)
        self.assertNotIn("allow lto_archiver_broker_t lto_archiver_log_reader_runtime_t", policy)

        contexts = (ROOT / "packaging" / "selinux" / "lto_archiver.fc").read_text()
        self.assertIn("/usr/bin/lto-archiver-log-reader", contexts)
        self.assertIn("/var/run/lto-archiver-log-reader(/.*)?", contexts)

        contract = json.loads((ROOT / "packaging" / "rpm" / "main-rpm-contract.json").read_text())
        authority = contract["required_source_authorities"]
        root_identity = "root"
        self.assertEqual(
            {
                "group": "root",
                "mode": "-rwxr-xr-x",
                "source": "packaging/launchers/lto-archiver-log-reader",
                "user": root_identity,
            },
            authority["/usr/bin/lto-archiver-log-reader"],
        )
        for path in (
            "/usr/lib/systemd/system/lto-archiver-log-reader.socket",
            "/usr/lib/systemd/system/lto-archiver-log-reader.service",
        ):
            self.assertEqual("-rw-r--r--", authority[path]["mode"])

        activation = (ROOT / "packaging" / "scripts" / "activate-rhel9.py").read_text()
        self.assertIn('"lto-archiver-log-reader.socket",', activation)
        self.assertNotIn('"lto-archiver-log-reader.service",\n)', activation)

        spec = (ROOT / "packaging" / "rpm" / "lto-archiver.spec").read_text()
        for macro in ("%systemd_post", "%systemd_preun", "%systemd_postun_with_restart"):
            line = next(line for line in spec.splitlines() if line.startswith(macro))
            self.assertIn("lto-archiver-log-reader.socket", line)
            self.assertIn("lto-archiver-log-reader.service", line)

    def test_live_verifier_rejects_any_effective_group_boundary_mutation(self) -> None:
        module = load_deployment_verifier()
        expected = module._LOG_READER_EFFECTIVE_SERVICE_GROUPS
        self.assertEqual(
            frozenset(
                {
                    "lto-archiverd.service",
                    "lto-archiver-web.service",
                    "lto-archiver-command-broker.service",
                    "lto-archiver-share-broker.service",
                    "lto-archiver-ltfs-qualification.service",
                    "lto-archiver-archive-runner-qualification.service",
                    "lto-archiver-log-reader.service",
                }
            ),
            frozenset(expected),
        )
        self.assertEqual(
            frozenset({"tape", "lto-admin", "lto-web", "lto-log-read"}),
            expected["lto-archiverd.service"],
        )

        def boundary_ok(
            groups: dict[str, frozenset[str]],
            *,
            runtime_mode: int = 0o750,
            runtime_gid: int = 123,
        ) -> bool:
            root_identity = "root"
            log_group_name = "lto-log-read"
            reader_properties = {
                "User": root_identity,
                "Group": root_identity,
                "ExecStart": "{ path=/usr/bin/lto-archiver-log-reader ; argv[]=/usr/bin/lto-archiver-log-reader --socket-fd 3 ; ignore_errors=no ; }",
                "CapabilityBoundingSet": "",
                "AmbientCapabilities": "",
                "NoNewPrivileges": "yes",
                "ProtectSystem": "strict",
                "ProtectHome": "yes",
                "PrivateDevices": "yes",
                "ProtectKernelLogs": "no",
                "RestrictAddressFamilies": "AF_UNIX",
                "DevicePolicy": "closed",
                **{name: "" for name in module._LOG_READER_EMPTY_PATH_PROPERTIES},
            }
            socket_properties = {
                "SocketUser": root_identity,
                "SocketGroup": log_group_name,
                "SocketMode": "0660",
                "FileDescriptorName": "log-reader",
            }

            def output(values: list[str]) -> str:
                return "\n".join(values) + "\n"

            def command(*argv: object) -> str:
                if "--property=SupplementaryGroups" in argv:
                    return " ".join(sorted(groups[str(argv[-1])])) + "\n"
                if argv[0] == module._MATCHPATHCON:
                    return "system_u:object_r:lto_archiver_log_reader_runtime_t:s0\n"
                requested = [
                    str(value).split("=", 1)[1]
                    for value in argv
                    if str(value).startswith("--property=")
                ]
                self.assertEqual(1, len(requested))
                if str(argv[-1]) == "lto-archiver-log-reader.socket":
                    return output([socket_properties[requested[0]]])
                if str(argv[-1]) == "lto-archiver-log-reader.service":
                    return output([reader_properties[requested[0]]])
                raise AssertionError(argv)

            host = SimpleNamespace(
                _command=command,
                _daemon_get=lambda _endpoint: {"items": []},
            )
            socket_details = SimpleNamespace(
                st_mode=stat.S_IFSOCK | 0o660,
                st_uid=0,
                st_gid=123,
            )
            runtime_details = SimpleNamespace(
                st_mode=stat.S_IFDIR | runtime_mode,
                st_uid=0,
                st_gid=runtime_gid,
            )
            reader_group = SimpleNamespace(gr_gid=123, gr_mem=["lto-archiver"])
            with (
                mock.patch.object(
                    module.Path,
                    "stat",
                    side_effect=[runtime_details, socket_details],
                ),
                mock.patch.object(module.grp, "getgrnam", return_value=reader_group),
                mock.patch.object(
                    module.os,
                    "getxattr",
                    return_value=b"system_u:object_r:lto_archiver_log_reader_runtime_t:s0\0",
                ),
            ):
                return module.SystemLiveHost._log_reader_boundary_ok(host)

        self.assertTrue(boundary_ok(dict(expected)))
        self.assertFalse(boundary_ok(dict(expected), runtime_mode=0o755))
        self.assertFalse(boundary_ok(dict(expected), runtime_gid=0))
        for unit, group_set in expected.items():
            with self.subTest(unit=unit):
                mutated = dict(expected)
                if unit == "lto-archiverd.service":
                    mutated[unit] = group_set - {"lto-log-read"}
                else:
                    mutated[unit] = group_set | {"lto-log-read"}
                self.assertFalse(boundary_ok(mutated))


if __name__ == "__main__":
    unittest.main()
