from __future__ import annotations

import importlib.util
import tempfile
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from starlette.requests import Request

import ltobackup.daemon.main as daemon_main
from ltobackup.catalog import Catalog
from ltobackup.daemon.main import build_parser
from ltobackup.daemon.models import DaemonFence
from ltobackup.daemon.service import (
    PEER_CREDENTIAL_SCOPE_KEY,
    TrustedPrincipalResolver,
    UntrustedPeer,
)
from ltobackup.errors import ValidationError
from ltobackup.linux_settings import LinuxSettings
from ltobackup.tape.command_supervisor import BrokeredCgroupScopeToken


class LinuxEntrypointTests(unittest.TestCase):
    def test_daemon_composition_rejects_non_packaged_managed_source_root(
        self,
    ) -> None:
        configured = LinuxSettings(
            managed_source_mount_root=Path("/opt/lto-archiver/sources")
        )
        with (
            patch.object(daemon_main, "load_linux_settings", return_value=configured),
            self.assertRaisesRegex(
                ValidationError, "managed_source_mount_root must be the packaged path"
            ),
        ):
            daemon_main.main(["--config", "/etc/lto-archiver/config.toml"])

    def test_daemon_main_reuses_one_authenticated_client_for_cgroup_and_ltfs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = MagicMock()
            paths = SimpleNamespace(
                socket_path=root / "daemon.sock",
                catalog_file=root / "catalog.db",
                backup_dir=root / "backups",
            )
            capability = BrokeredCgroupScopeToken(b"c" * 32)
            broker_api = MagicMock(unsafe=True)
            share_broker = MagicMock(unsafe=True)
            share_request_key = b"r" * 32
            activated_socket = MagicMock()
            operational_sink = MagicMock()
            with (
                patch.object(daemon_main, "load_linux_settings", return_value=settings),
                patch.object(
                    daemon_main.LinuxPaths, "from_settings", return_value=paths
                ),
                patch.object(
                    daemon_main.grp,
                    "getgrnam",
                    return_value=SimpleNamespace(gr_gid=1100),
                ),
                patch.object(
                    daemon_main,
                    "activated_unix_listener",
                    return_value=activated_socket,
                ),
                patch.object(daemon_main, "TrustedPrincipalResolver") as principals,
                patch.object(daemon_main, "BackupManager"),
                patch.object(
                    daemon_main, "load_broker_capability", return_value=capability
                ),
                patch.object(
                    daemon_main,
                    "UnixBrokeredCgroupScopeApi",
                    return_value=broker_api,
                ),
                patch.object(
                    daemon_main,
                    "load_share_runtime",
                    return_value=(share_broker, share_request_key),
                ),
                patch.object(
                    daemon_main, "BrokeredCgroupExecutionScopeManager"
                ) as scope_manager,
                patch.object(daemon_main, "ReadOnlyCgroupPrivilegeBoundary"),
                patch.object(daemon_main, "ProductionArchiveResume") as resume,
                patch.object(daemon_main, "ProductionNativeArchive") as native,
                patch.object(daemon_main, "DaemonService") as service,
                patch.object(daemon_main, "EventBus"),
                patch.object(daemon_main, "create_app"),
                patch.object(daemon_main.uvicorn, "Config"),
                patch.object(daemon_main, "SocketOwnershipServer") as server,
                patch.object(
                    daemon_main,
                    "JournalOperationalEventSink",
                    return_value=operational_sink,
                ) as journal_sink_type,
            ):
                principals.return_value.resolve_webui_uid.return_value = 2200
                self.assertEqual(
                    0,
                    daemon_main.main(
                        [
                            "--config",
                            str(root / "config.toml"),
                            "--broker-socket",
                            str(root / "broker.sock"),
                            "--broker-capability-file",
                            str(root / "capability"),
                        ]
                    ),
                )

                # The production factory must place boundary reconciliation
                # before source checkpoint/admission, not just expose a helper.
                catalog = Catalog(paths.catalog_file)
                self.addCleanup(catalog.close)
                catalog.initialize()
                fence = catalog.claim_daemon_owner("entrypoint-test")
                catalog.close()
                boundary = service.return_value.boundary_dispatcher.return_value
                boundary.reconcile_once.return_value = False
                sequence_factory = service.call_args.kwargs["sequence_coordinator_factory"]
                group = sequence_factory(SimpleNamespace(daemon_fence=fence))
                self.assertIsNone(group._coordinators[0].reconcile_once())
                boundary.reconcile_once.assert_called_once_with()
                service.return_value._admit_sequence_candidate.assert_not_called()

        self.assertIs(broker_api, scope_manager.call_args.args[0])
        self.assertIs(capability, scope_manager.call_args.args[1])
        self.assertIs(broker_api, resume.call_args.kwargs["ltfs_sessions"])
        journal_sink_type.assert_called_once()
        self.assertEqual(
            "lto-archiverd",
            journal_sink_type.call_args.kwargs["syslog_identifier"],
        )
        on_journal_error = journal_sink_type.call_args.kwargs["on_error"]
        on_journal_error("journald_unavailable")
        service.return_value.record_log.assert_called_once_with(
            "warning", "journald_unavailable"
        )
        self.assertIs(resume.call_args.kwargs["event_sink"], operational_sink)
        self.assertIs(native.call_args.kwargs["event_sink"], operational_sink)
        self.assertIs(
            service.call_args.kwargs["operational_event_sink"], operational_sink
        )
        self.assertIs(broker_api.assert_ready, resume.call_args.kwargs["broker_ready"])
        self.assertIs(
            resume.return_value.reconcile_pending_ltfs_startup,
            service.call_args.kwargs["startup_reconciler"],
        )
        factory = service.call_args.kwargs["recovery_coordinator_factory"]
        operations = SimpleNamespace(daemon_fence=DaemonFence("daemon-test", 2))
        coordinator = factory(operations)
        self.assertIsInstance(
            coordinator, daemon_main.AutomaticRecoveryCoordinator
        )
        self.assertIsInstance(
            coordinator._decision_source,
            daemon_main.ProductionRecoveryDecisionSource,
        )
        self.assertIsInstance(
            coordinator._executor, daemon_main.ProductionRecoveryExecutor
        )
        runtime = coordinator._decision_source._probe_source
        self.assertIs(native.return_value, runtime._native_archive)
        self.assertEqual(
            runtime.retry_current_cassette,
            coordinator._executor._retry_current_cassette,
        )
        self.assertEqual(
            runtime.prove_incomplete,
            coordinator._executor._prove_incomplete,
        )
        self.assertIs(share_broker, service.call_args.kwargs["share_broker"])
        self.assertEqual(
            share_request_key,
            service.call_args.kwargs["share_credential_request_key"],
        )
        server.return_value.run.assert_called_once_with(sockets=[activated_socket])
        activated_socket.close.assert_called_once_with()

    def test_webui_host_identity_resolves_uid_at_startup(self) -> None:
        resolver = TrustedPrincipalResolver(
            administrator_uids={1000: "admin"},
            webui_user="example",
        )
        with patch(
            "ltobackup.daemon.service.pwd.getpwnam",
            return_value=SimpleNamespace(pw_uid=2000),
        ) as getpwnam:
            self.assertEqual(2000, resolver.resolve_webui_uid())
        getpwnam.assert_called_once_with("example")

    def test_webui_host_identity_is_configurable_at_daemon_boundary(self) -> None:
        args = build_parser().parse_args(["--webui-user", "web-ui"])
        self.assertEqual("web-ui", args.webui_user)

    def test_trusted_principal_resolver_uses_request_scope_credentials(self) -> None:
        resolver = TrustedPrincipalResolver(
            administrator_uids={1000: "admin"},
            webui_uid=2000,
        )
        administrator_request = Request(
            {
                "type": "http",
                "headers": [(b"x-authenticated-principal", b"spoofed")],
                PEER_CREDENTIAL_SCOPE_KEY: (11, 1000, 1000),
            }
        )
        webui_request = Request(
            {
                "type": "http",
                "headers": [
                    (b"x-authenticated-principal", b"operator-1"),
                    (b"x-authenticated-role", b"operator"),
                ],
                PEER_CREDENTIAL_SCOPE_KEY: (12, 2000, 2000),
            }
        )
        administrator = resolver.require_mutation_principal(administrator_request)
        web_operator = resolver.require_mutation_principal(webui_request)
        self.assertEqual("admin", administrator.name)
        self.assertTrue(administrator.direct_local_admin)
        self.assertEqual("operator-1", web_operator.name)
        self.assertEqual("operator", web_operator.role)
        self.assertFalse(web_operator.direct_local_admin)
        self.assertEqual(
            "admin", resolver.require_direct_local_admin(administrator_request).name
        )
        with self.assertRaises(UntrustedPeer):
            resolver.require_direct_local_admin(webui_request)
        with self.assertRaises(UntrustedPeer):
            resolver.require_mutation_principal(
                Request({"type": "http", "headers": []})
            )

    def test_linux_package_installs_daemon_and_unprivileged_web_entrypoints(
        self,
    ) -> None:
        scripts = tomllib.loads(Path("pyproject.toml").read_text())["project"][
            "scripts"
        ]
        self.assertEqual(
            {
                "lto-archiver-admin": "ltobackup.admin_cli:main",
                "lto-archiver-command-broker": "ltobackup.broker.main:main",
                "lto-archiver-share-broker": "ltobackup.share_broker.main:main",
                "lto-archiverd": "ltobackup.daemon.main:main",
                "lto-archiver-web": "ltobackup.web.main:main",
                "lto-archiver-migrate": "ltobackup.migration.cli:main",
                "lto-archiver-qualify-ltfs": "ltobackup.qualification.cli:main",
            },
            scripts,
        )

    def test_legacy_module_entrypoints_are_absent(self) -> None:
        for module_name in ("ltobackup.__main__", "ltobackup.cli"):
            with self.subTest(module=module_name):
                self.assertIsNone(importlib.util.find_spec(module_name))


if __name__ == "__main__":
    unittest.main()
