from __future__ import annotations

import argparse
import grp
import os
import socket
import struct
import sys
from pathlib import Path

import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

from ..broker.client import UnixBrokeredCgroupScopeApi
from ..catalog import Catalog
from ..linux_settings import LinuxPaths, load_linux_settings
from ..log_reader.client import UnixJournalReaderClient
from ..operational_log import JournalOperationalEventSink
from ..share_broker.client import ShareBrokerClient
from ..share_broker.main import load_systemd_credential
from ..systemd_activation import activated_unix_listener
from ..tape.command_supervisor import (
    BrokeredCgroupExecutionScopeManager,
    ReadOnlyCgroupPrivilegeBoundary,
)
from .api import create_app
from .archive_runtime import (
    ProductionArchiveResume,
    ProductionRecoveryRuntime,
    load_broker_capability,
)
from .backups import BackupManager
from .events import EventBus
from .native_frozen import NativeSourceCheckpoint
from .native_runtime import ProductionNativeArchive
from .recovery_coordinator import (
    AutomaticRecoveryCoordinator,
    ProductionRecoveryDecisionSource,
    ProductionRecoveryExecutor,
)
from .restore_coordinator import (
    ProductionRestoreRuntime,
    RestoreSequenceCoordinator,
    SequenceCoordinatorGroup,
)
from .sequence_coordinator import NativeSequenceCoordinator
from .service import (
    PEER_CREDENTIAL_SCOPE_KEY,
    DaemonService,
    TrustedPrincipalResolver,
)
from .timeouts import validate_shutdown_timeout


def _shutdown_timeout_seconds(value: str) -> float:
    try:
        return validate_shutdown_timeout(float(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


class PeerCredentialH11Protocol(H11Protocol):
    """Attach Linux SO_PEERCRED to every ASGI scope on this connection."""

    def connection_made(self, transport) -> None:
        super().connection_made(transport)
        connected_socket = transport.get_extra_info("socket")
        if connected_socket is None or connected_socket.family != socket.AF_UNIX:
            return
        packed = connected_socket.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        credentials = tuple(struct.unpack("3i", packed))
        application = self.app

        async def peer_verified_app(scope, receive, send):
            verified_scope = dict(scope)
            verified_scope[PEER_CREDENTIAL_SCOPE_KEY] = credentials
            await application(verified_scope, receive, send)

        self.app = peer_verified_app


class SocketOwnershipServer(uvicorn.Server):
    def __init__(self, config, socket_path: Path, socket_gid: int) -> None:
        super().__init__(config)
        self._socket_path = Path(socket_path)
        self._socket_gid = socket_gid

    async def startup(self, sockets=None) -> None:
        await super().startup(sockets=sockets)
        os.chmod(self._socket_path, 0o660)
        os.chown(self._socket_path, -1, self._socket_gid)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lto-archiverd")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/lto-archiver/config.toml"),
    )
    parser.add_argument(
        "--broker-socket",
        type=Path,
        default=Path("/run/lto-archiver-broker/control.sock"),
    )
    parser.add_argument(
        "--broker-capability-file",
        type=Path,
        default=Path("/run/credentials/lto-archiverd.service/broker-capability"),
    )
    parser.add_argument(
        "--ltfs-info-binary",
        type=Path,
        default=Path("/usr/libexec/lto-archiver/ltfs-info"),
    )
    parser.add_argument(
        "--share-broker-socket",
        type=Path,
        default=Path("/run/lto-archiver-share-broker/control.sock"),
    )
    parser.add_argument(
        "--share-broker-capability-file",
        type=Path,
        default=Path("/run/credentials/lto-archiverd.service/share-broker-capability"),
    )
    parser.add_argument(
        "--share-broker-proof-key-file",
        type=Path,
        default=Path("/run/credentials/lto-archiverd.service/share-broker-proof-key"),
    )
    parser.add_argument(
        "--share-request-key-file",
        type=Path,
        default=Path("/run/credentials/lto-archiverd.service/share-request-key"),
    )
    parser.add_argument(
        "--log-reader-socket",
        type=Path,
        default=Path("/run/lto-archiver-log-reader/control.sock"),
    )
    parser.add_argument(
        "--webui-user",
        default="lto-web",
        help="local account allowed to forward authenticated WebUI principals",
    )
    parser.add_argument(
        "--shutdown-timeout-seconds",
        type=_shutdown_timeout_seconds,
        default=30.0,
        help="seconds to drain operation workers before durable recovery fencing",
    )
    return parser


def load_share_runtime(
    args: argparse.Namespace,
    *,
    credential_loader=load_systemd_credential,
    client_factory=ShareBrokerClient,
) -> tuple[ShareBrokerClient, bytes]:
    capability = credential_loader(args.share_broker_capability_file)
    proof_key = credential_loader(args.share_broker_proof_key_file)
    request_key = credential_loader(args.share_request_key_file)
    if len({capability, proof_key, request_key}) != 3:
        raise RuntimeError("share broker runtime unavailable")
    client = client_factory(
        args.share_broker_socket,
        capability=capability,
        proof_key=proof_key,
    )
    client.assert_ready()
    return client, request_key


def main(argv: list[str] | None = None) -> int:
    if not sys.platform.startswith("linux"):
        raise SystemExit("lto-archiverd requires Linux")
    args = build_parser().parse_args(argv)
    settings = load_linux_settings(args.config)
    settings.validate()
    paths = LinuxPaths.from_settings(settings)
    paths.socket_path.parent.mkdir(parents=True, exist_ok=True)
    socket_gid = grp.getgrnam(settings.socket_group).gr_gid
    activated_socket = activated_unix_listener(
        3,
        os.environ,
        socket_type=socket.SOCK_STREAM,
        fd_name="daemon",
        expected_uid=os.geteuid(),
        expected_gid=socket_gid,
        expected_mode=0o660,
        expected_path=paths.socket_path,
    )
    principals = TrustedPrincipalResolver(webui_user=args.webui_user)
    principals.resolve_webui_uid()

    def catalog_factory() -> Catalog:
        return Catalog(paths.catalog_file)

    backups = BackupManager(paths.catalog_file, paths.backup_dir)
    capability = load_broker_capability(args.broker_capability_file)
    broker_api = UnixBrokeredCgroupScopeApi(args.broker_socket, capability)
    share_broker, share_request_key = load_share_runtime(args)
    scope_manager = BrokeredCgroupExecutionScopeManager(broker_api, capability)
    privilege_boundary = ReadOnlyCgroupPrivilegeBoundary()
    operational_events = JournalOperationalEventSink(
        syslog_identifier="lto-archiverd",
        on_error=lambda code: service.record_log("warning", code),
    )
    # The callback closes over the service only when a worker actually runs;
    # shutdown then stops an in-flight media wait before recovery fencing.
    service: DaemonService
    archive_resume = ProductionArchiveResume(
        paths=paths,
        settings=settings,
        backups=backups,
        telemetry_sink=lambda: service.archive_telemetry_sink,
        stop_requested=lambda: service.shutdown_requested,
        scope_manager=scope_manager,
        ltfs_sessions=broker_api,
        privilege_boundary=privilege_boundary,
        ltfs_info_binary=args.ltfs_info_binary,
        broker_ready=broker_api.assert_ready,
        managed_source_admission=lambda job_id, operation_id, generation: (
            service.admit_job_managed_sources(job_id, operation_id, generation)
        ),
        managed_source_release=lambda leases, generation: (
            service.release_job_managed_sources(leases, generation)
        ),
        event_sink=operational_events,
    )
    archive_resume.validate_readiness()
    native_archive = ProductionNativeArchive(
        paths=paths,
        settings=settings,
        backups=backups,
        telemetry_sink=lambda: service.archive_telemetry_sink,
        stop_requested=lambda: service.shutdown_requested,
        scope_manager=scope_manager,
        ltfs_sessions=broker_api,
        privilege_boundary=privilege_boundary,
        ltfs_info_binary=args.ltfs_info_binary,
        managed_source_admission=lambda job_id, operation_id, generation: (
            service.admit_job_managed_sources(job_id, operation_id, generation)
        ),
        managed_source_release=lambda leases, generation: (
            service.release_job_managed_sources(leases, generation)
        ),
        event_sink=operational_events,
    )
    restore_runtime = ProductionRestoreRuntime(archive_resume)

    def recovery_coordinator_factory(operations):
        archive_recovery = ProductionRecoveryRuntime(
            archive_resume,
            operations,
            native_archive,
            replacement_admission_factory=service.prepare_replacement_admission,
        )
        restore_recovery = ProductionRestoreRuntime(archive_resume, operations)

        class RecoveryRuntimeRouter:
            def __init__(self):
                self._native_archive = archive_recovery._native_archive
                self.retry_current_cassette = (
                    archive_recovery.retry_current_cassette
                )
                self.prove_incomplete = archive_recovery.prove_incomplete

            def inspect(self, operation, fence, catalog):
                runtime = (
                    restore_recovery
                    if operation.kind == "restore.cassette"
                    else archive_recovery
                )
                return runtime.inspect(operation, fence, catalog)

        decision_source = ProductionRecoveryDecisionSource(
            catalog_factory,
            operations.daemon_fence,
            RecoveryRuntimeRouter(),
        )
        executor = ProductionRecoveryExecutor(
            catalog_factory,
            observe_command=archive_recovery.observe_command,
            reconcile_commit=archive_recovery.reconcile_commit,
            retry_identification=archive_recovery.retry_identification,
            retry_current_cassette=archive_recovery.retry_current_cassette,
            prove_incomplete=archive_recovery.prove_incomplete,
            retry_unload=archive_recovery.retry_unload,
            safe_release=archive_recovery.safe_release,
            prepare_restore_retry=restore_recovery.prepare_restore_retry,
            reconcile_restore_commit=restore_recovery.reconcile_restore_commit,
            finalize_restore_control=restore_recovery.finalize_restore_control,
        )
        return AutomaticRecoveryCoordinator(
            catalog_factory,
            operations.daemon_fence,
            decision_source,
            executor,
        )

    def sequence_coordinator_factory(operations):
        boundary = service.boundary_dispatcher(operations.daemon_fence.generation)
        return SequenceCoordinatorGroup(
            NativeSequenceCoordinator(
                catalog_factory,
                daemon_generation=operations.daemon_fence.generation,
                reconcile_boundary=boundary.reconcile_once,
                admit=lambda candidate: service._admit_sequence_candidate(candidate),  # noqa: SLF001 - lifecycle-owned admission seam
                check_sources=NativeSourceCheckpoint(
                    catalog_factory,
                    daemon_generation=operations.daemon_fence.generation,
                    verify_library=lambda candidate, library: service.verify_cassette_source_library(candidate, library),
                ),
                on_error=lambda _error: service.record_log(
                    "warning", "sequence.coordinator.error"
                ),
            ),
            RestoreSequenceCoordinator(
                catalog_factory,
                operations=operations,
                runner=restore_runtime,
                hardware_target=restore_runtime.hardware_target,
                prepare_replacement_admission=(
                    service.prepare_restore_replacement_admission
                ),
                on_error=lambda _error: service.record_log(
                    "warning", "sequence.coordinator.error"
                ),
            ),
        )

    service = DaemonService(
        paths,
        settings,
        backups,
        None,
        EventBus(catalog_factory),
        principals=principals,
        operation_callbacks={
            "archive.resume": archive_resume,
            "archive.native": native_archive,
        },
        archive_resume_admission=archive_resume.admit,
        native_archive_admission=native_archive.admit,
        critical_replacement_callback=native_archive.run_frozen_recovery,
        cutover_environment=archive_resume.cutover_environment,
        startup_reconciler=archive_resume.reconcile_pending_ltfs_startup,
        recovery_coordinator_factory=recovery_coordinator_factory,
        pre_media_reset_reconciler=lambda operation, fence: ProductionRecoveryRuntime(
            archive_resume, service._require_operations(), native_archive,
        ).reconcile_pre_media_commands(operation, fence),
        sequence_coordinator_factory=sequence_coordinator_factory,
        shutdown_timeout_seconds=args.shutdown_timeout_seconds,
        share_broker=share_broker,
        share_credential_request_key=share_request_key,
        journal_reader=UnixJournalReaderClient(args.log_reader_socket),
        operational_event_sink=operational_events,
    )
    config = uvicorn.Config(
        create_app(service),
        uds=str(paths.socket_path),
        http=PeerCredentialH11Protocol,
    )
    try:
        SocketOwnershipServer(config, paths.socket_path, socket_gid).run(
            sockets=[activated_socket]
        )
    finally:
        activated_socket.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
