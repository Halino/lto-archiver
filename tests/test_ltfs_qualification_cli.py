import io
import os
import sqlite3
import stat
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from ltobackup.broker.client import BrokerUnavailable
from ltobackup.catalog import Catalog
from ltobackup.daemon.models import expected_media_scope_sha256
from ltobackup.errors import CatalogError
from ltobackup.linux_settings import LinuxSettings
from ltobackup.qualification.broker_models import (
    BrokerQualificationDispatch,
    BrokerQualificationInspection,
    BrokerQualificationInspectionRequest,
    qualification_request_operation_token,
)
from ltobackup.qualification.plan import (
    QualificationOperation,
    QualificationPlan,
    QualificationRefused,
)
from ltobackup.tape.linux_ltfs import (
    BackendUnavailable,
    StableDeviceIdentity,
    SysfsDeviceIdentityProvider,
)

NOW = 1_787_500_000_000_000_000
RUN_ID = "11111111-1111-4111-8111-111111111111"
CREDENTIAL = b"qualification-test-credential!".ljust(32, b"!")
TOOL_SHA256 = {
    name: character * 64
    for name, character in zip(
        ("ltfs", "mkltfs", "ltfsck", "ltfs-info", "fusermount", "mt"),
        "123456",
        strict=True,
    )
}
SUPPORTED_OPERATIONS = (
    QualificationOperation.READ_ONLY,
    QualificationOperation.FORMAT,
    QualificationOperation.ADDITIVE_WRITE,
    QualificationOperation.OVERWRITE,
    QualificationOperation.REPAIR,
    QualificationOperation.WIPE,
    QualificationOperation.UNLOAD,
    QualificationOperation.LOAD,
    QualificationOperation.EJECT,
)


class _Broker:
    def __init__(self) -> None:
        self.requests = []

    def execute_ltfs_qualification_stage(self, request):
        self.requests.append(request)
        child_exit_code = 1 if request.operation is QualificationOperation.WIPE else 0
        return BrokerQualificationDispatch(
            1,
            request.run_id,
            request.stage_ordinal,
            request.operation,
            request.request_sha256,
            "terminal",
            "1" * 64,
            child_exit_code,
            "2" * 64,
            b"n" * 32,
            b"p" * 32,
        )


class _InspectionBroker:
    def __init__(self, inspection) -> None:
        self.inspection = inspection
        self.inspections = []

    def inspect_ltfs_qualification_stage(self, request):
        self.inspections.append(request)
        return self.inspection

    def execute_ltfs_qualification_stage(self, _request):
        raise AssertionError("reconciliation dispatched a physical operation")


class QualificationCliTests(unittest.TestCase):
    def test_setup_system_exit_closes_qualification_lifecycle(self) -> None:
        from ltobackup.qualification import cli

        events = []
        sink = Mock()
        sink.emit.side_effect = events.append
        with (
            patch.object(cli, "JournalOperationalEventSink", return_value=sink),
            self.assertRaises(SystemExit),
        ):
            cli.main(["plan", "--not-a-real-option"])

        self.assertEqual(
            ["qualification.started", "qualification.failed"],
            [event.code for event in events],
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.catalog_path = self.root / "catalog.sqlite3"
        source = self.root / "source"
        source.mkdir()
        with Catalog(self.catalog_path) as catalog:
            catalog.initialize()
            catalog.add_library("LIB1", "Library", str(source))
            catalog.create_automatic_job(
                "JOB1",
                "LIB1",
                "drive",
                "/synthetic/mount",
                [
                    ("PROT01", "SERIAL1", 0, 0),
                    ("PROT02", "SERIAL2", 0, 0),
                    ("PROT03", "SERIAL3", 0, 0),
                    (r"CURRENT/LABEL\EXACT", "CURRENT-SERIAL", 0, 0),
                ],
                force_format=True,
            )

    def test_long_wipe_is_absent_from_every_operator_dispatch_boundary(self):
        from ltobackup.qualification import cli

        common_identity = [
            "--catalog",
            str(self.catalog_path),
            "--job-id",
            "JOB1",
            "--cassette-sequence",
            "4",
            "--expected-label",
            r"CURRENT/LABEL\EXACT",
            "--drive-serial",
            "DRIVE-SERIAL",
            "--drive-wwid",
            "0x5000000000000001",
            "--linux-tree-sha256",
            "a" * 64,
            "--ltfs-tree-sha256",
            "b" * 64,
            "--ltfs-rpm-sha256",
            "c" * 64,
        ]
        cases = (
            ["plan", *common_identity, "--operation", "long_wipe"],
            [
                "authorize",
                "--plan",
                str(self.root / "plan.json"),
                "--operation",
                "long_wipe",
                "--credential",
                str(self.root / "credential"),
            ],
            [
                "execute-stage",
                "--catalog",
                str(self.catalog_path),
                "--plan",
                str(self.root / "plan.json"),
                "--operation",
                "long_wipe",
                "--token",
                "0" * 64,
                "--credential",
                str(self.root / "credential"),
            ],
        )
        for arguments in cases:
            with (
                self.subTest(action=arguments[0]),
                patch("sys.stderr", io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                cli._parser().parse_args(arguments)

    def _catalog_sidecar_snapshot(
        self, catalog_path: Path | None = None
    ) -> dict[str, object]:
        catalog_path = self.catalog_path if catalog_path is None else catalog_path
        snapshot: dict[str, object] = {}
        for suffix in ("", "-wal", "-shm", "-journal"):
            candidate = Path(f"{catalog_path}{suffix}")
            try:
                details = candidate.lstat()
            except FileNotFoundError:
                snapshot[suffix] = None
                continue
            payload = None
            if stat.S_ISREG(details.st_mode):
                descriptor = os.open(
                    candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                )
                try:
                    payload = os.read(descriptor, details.st_size + 1)
                finally:
                    os.close(descriptor)
            snapshot[suffix] = (
                details.st_dev,
                details.st_ino,
                details.st_mode,
                details.st_nlink,
                details.st_uid,
                details.st_gid,
                details.st_size,
                details.st_mtime_ns,
                details.st_ctime_ns,
                payload,
            )
        return snapshot

    def _open_uncheckpointed_catalog_writer(self) -> sqlite3.Connection:
        writer = sqlite3.connect(self.catalog_path)
        self.addCleanup(writer.close)
        self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone(), ("wal",))
        writer.execute("PRAGMA wal_autocheckpoint=0")
        self.assertEqual(
            writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone(),
            (0, 0, 0),
        )
        writer.execute(
            "UPDATE automatic_cassettes SET physical_label=?,tape_serial=? "
            "WHERE job_id=? AND sequence=?",
            ("WAL-LABEL", "WAL-SERIAL", "JOB1", 4),
        )
        writer.commit()
        wal = Path(f"{self.catalog_path}-wal")
        self.assertTrue(wal.is_file())
        self.assertGreater(wal.stat().st_size, 0)
        return writer

    def test_default_action_emits_canonical_plan_and_never_connects_to_broker(self):
        from ltobackup.qualification import cli

        output = io.StringIO()
        operational_events = []
        operational_sink = Mock()
        operational_sink.emit.side_effect = operational_events.append
        with (
            patch.object(
                cli, "_connect_broker", side_effect=AssertionError("broker dispatch")
            ),
            patch.object(
                cli,
                "JournalOperationalEventSink",
                return_value=operational_sink,
            ) as journal_sink_type,
        ):
            result = cli.main(
                [
                    "--catalog",
                    str(self.catalog_path),
                    "--job-id",
                    "JOB1",
                    "--cassette-sequence",
                    "4",
                    "--expected-label",
                    r"CURRENT/LABEL\EXACT",
                    "--expected-mam-medium-serial",
                    "CURRENT-SERIAL",
                    "--drive-serial",
                    "DRIVE-SERIAL",
                    "--drive-wwid",
                    "0x5000000000000001",
                    "--linux-tree-sha256",
                    "a" * 64,
                    "--ltfs-tree-sha256",
                    "b" * 64,
                    "--ltfs-rpm-sha256",
                    "c" * 64,
                    "--operation",
                    "read_only",
                    "--operation",
                    "format",
                ],
                stdout=output,
                now_ns=lambda: NOW,
                run_id_factory=lambda: RUN_ID,
            )
        self.assertEqual(result, 0)
        journal_sink_type.assert_called_once_with(
            syslog_identifier="lto-archiver-ltfs-qualification"
        )
        self.assertEqual(
            ["qualification.started", "qualification.succeeded"],
            [event.code for event in operational_events],
        )
        plan = QualificationPlan.from_bytes(output.getvalue().rstrip("\n").encode())
        self.assertEqual(plan.physical_label, r"CURRENT/LABEL\EXACT")
        self.assertEqual(plan.tape_serial, "CURRENT-SERIAL")
        self.assertEqual(
            plan.operations,
            (QualificationOperation.FORMAT, QualificationOperation.READ_ONLY),
        )

    def test_probe_is_root_read_only_redacted_and_classifies_media(self):
        from ltobackup.qualification import cli

        self.root.chmod(0o750)
        self.catalog_path.chmod(0o600)
        staging_root = self.root / "probe-staging"
        staging_root.mkdir(mode=0o700)
        arguments = [
            "probe",
            "--catalog",
            str(self.catalog_path),
            "--job-id",
            "JOB1",
            "--cassette-sequence",
            "4",
            "--expected-label",
            r"CURRENT/LABEL\EXACT",
            "--drive-serial",
            "DRIVE-SERIAL",
            "--drive-wwid",
            "0x5000000000000001",
            "--linux-tree-sha256",
            "a" * 64,
            "--ltfs-tree-sha256",
            "b" * 64,
            "--ltfs-rpm-sha256",
            "c" * 64,
        ]
        for media_state, initial_operation, volume_uuid, generation in (
            (
                "ltfs",
                "read_only",
                "22222222-2222-4222-8222-222222222222",
                7,
            ),
            ("unidentified", "format", None, None),
        ):
            with self.subTest(media_state=media_state):
                output = io.StringIO()
                before_files = self._catalog_sidecar_snapshot()
                evidence = cli.QualificationEnvironmentEvidence(
                    physical_label=r"CURRENT/LABEL\EXACT",
                    tape_serial="CURRENT-SERIAL",
                    drive_serial="DRIVE-SERIAL",
                    drive_wwid="0x5000000000000001",
                    linux_tree_sha256="a" * 64,
                    ltfs_tree_sha256="b" * 64,
                    ltfs_rpm_sha256="c" * 64,
                    tape_device_identity_sha256="d" * 64,
                    scsi_device_identity_sha256="e" * 64,
                    expected_media_scope_sha256="f" * 64,
                    observed_media_identity_sha256="0" * 64,
                    volume_uuid=volume_uuid,
                    generation=generation,
                )
                with (
                    patch.object(cli, "_ACTIVE_CATALOG", self.catalog_path),
                    patch.object(cli, "_PROBE_SNAPSHOT_ROOT", staging_root),
                    patch.object(cli, "_effective_ids", return_value=(0, 0)),
                    patch.object(
                        cli.pwd,
                        "getpwnam",
                        return_value=Mock(pw_uid=os.getuid(), pw_gid=os.getgid()),
                    ),
                    patch.object(
                        cli, "_prepare_environment", return_value=evidence
                    ) as prepare,
                    patch.object(
                        cli,
                        "_connect_broker",
                        side_effect=AssertionError("probe connected to broker"),
                    ),
                ):
                    result = cli.main(
                        arguments,
                        stdout=output,
                        now_ns=lambda: NOW,
                        run_id_factory=lambda: RUN_ID,
                    )
                self.assertEqual(result, 0)
                self.assertEqual(
                    output.getvalue(),
                    '{"initial_operation":"'
                    + initial_operation
                    + '","media_state":"'
                    + media_state
                    + '","schema":2}\n',
                )
                plan, operation, catalog_path = prepare.call_args.args
                self.assertEqual(operation, QualificationOperation.FORMAT)
                self.assertEqual(catalog_path, self.catalog_path)
                self.assertEqual(plan.physical_label, r"CURRENT/LABEL\EXACT")
                for secret in (
                    plan.physical_label,
                    plan.tape_serial,
                    plan.drive_serial,
                    plan.drive_wwid,
                    str(volume_uuid),
                ):
                    self.assertNotIn(secret, output.getvalue())
                self.assertEqual(self._catalog_sidecar_snapshot(), before_files)
                with closing(
                    sqlite3.connect(
                        f"file:{self.catalog_path}?mode=ro&immutable=1", uri=True
                    )
                ) as connection:
                    runs = connection.execute(
                        "SELECT COUNT(*) FROM ltfs_qualification_runs"
                    ).fetchone()[0]
                self.assertEqual(runs, 0)
                self.assertEqual(self._catalog_sidecar_snapshot(), before_files)

        fixture_identities = (
            "MAM-VOLUME-IDENTIFIER",
            "UNEXPECTED-BARCODE",
            "22222222-2222-4222-8222-222222222222",
        )
        redacted_output = io.StringIO()
        errors = io.StringIO()
        with (
            patch.object(cli, "_ACTIVE_CATALOG", self.catalog_path),
            patch.object(cli, "_PROBE_SNAPSHOT_ROOT", staging_root),
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            patch.object(
                cli.pwd,
                "getpwnam",
                return_value=Mock(pw_uid=os.getuid(), pw_gid=os.getgid()),
            ),
            patch.object(
                cli,
                "_prepare_environment",
                side_effect=QualificationRefused(" ".join(fixture_identities)),
            ),
        ):
            result = cli.main(arguments, stdout=redacted_output, stderr=errors)
        self.assertEqual(result, 2)
        self.assertEqual(redacted_output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "LTFS qualification refused\n")
        for identity in fixture_identities:
            self.assertNotIn(identity, redacted_output.getvalue())
            self.assertNotIn(identity, errors.getvalue())

        errors = io.StringIO()
        with (
            patch.object(cli, "_ACTIVE_CATALOG", self.catalog_path),
            patch.object(cli, "_effective_ids", return_value=(1000, 1000)),
            patch.object(
                cli,
                "_prepare_environment",
                side_effect=AssertionError("non-root probe touched media"),
            ),
        ):
            result = cli.main(arguments, stderr=errors)
        self.assertEqual(result, 2)
        self.assertEqual(errors.getvalue(), "LTFS qualification refused\n")

    def test_probe_reads_committed_wal_without_mutating_live_catalog_sidecars(self):
        from ltobackup.qualification import cli

        self.root.chmod(0o750)
        self.catalog_path.chmod(0o600)
        self._open_uncheckpointed_catalog_writer()
        staging_root = self.root / "probe-staging"
        staging_root.mkdir(mode=0o700)
        before = self._catalog_sidecar_snapshot()
        self.assertIsNotNone(before["-shm"])

        with (
            patch.object(
                cli.pwd,
                "getpwnam",
                return_value=Mock(pw_uid=os.getuid(), pw_gid=os.getgid()),
            ),
            patch.object(cli, "_PROBE_SNAPSHOT_ROOT", staging_root, create=True),
        ):
            cassette = cli._read_probe_catalog_cassette(
                self.catalog_path,
                job_id="JOB1",
                cassette_sequence=4,
            )

        self.assertEqual(cassette["physical_label"], "WAL-LABEL")
        self.assertEqual(cassette["tape_serial"], "WAL-SERIAL")
        self.assertEqual(self._catalog_sidecar_snapshot(), before)
        self.assertEqual(tuple(staging_root.iterdir()), ())

    def test_probe_does_not_create_missing_shm_for_committed_wal(self):
        from ltobackup.qualification import cli

        self.root.chmod(0o750)
        self.catalog_path.chmod(0o600)
        self._open_uncheckpointed_catalog_writer()
        source_wal = Path(f"{self.catalog_path}-wal")
        target_root = self.root / "crash-snapshot"
        target_root.mkdir(mode=0o750)
        target_catalog = target_root / self.catalog_path.name
        target_catalog.write_bytes(self.catalog_path.read_bytes())
        target_catalog.chmod(0o600)
        target_wal = Path(f"{target_catalog}-wal")
        target_wal.write_bytes(source_wal.read_bytes())
        target_wal.chmod(0o600)
        staging_root = self.root / "probe-staging"
        staging_root.mkdir(mode=0o700)
        before = self._catalog_sidecar_snapshot(target_catalog)
        self.assertIsNone(before["-shm"])

        with (
            patch.object(
                cli.pwd,
                "getpwnam",
                return_value=Mock(pw_uid=os.getuid(), pw_gid=os.getgid()),
            ),
            patch.object(cli, "_PROBE_SNAPSHOT_ROOT", staging_root, create=True),
        ):
            cassette = cli._read_probe_catalog_cassette(
                target_catalog,
                job_id="JOB1",
                cassette_sequence=4,
            )

        self.assertEqual(cassette["physical_label"], "WAL-LABEL")
        self.assertEqual(cassette["tape_serial"], "WAL-SERIAL")
        self.assertEqual(self._catalog_sidecar_snapshot(target_catalog), before)
        self.assertEqual(tuple(staging_root.iterdir()), ())

    def test_probe_preserves_live_zero_length_wal_and_existing_shm(self):
        from ltobackup.qualification import cli

        self.root.chmod(0o750)
        self.catalog_path.chmod(0o600)
        writer = sqlite3.connect(self.catalog_path)
        self.addCleanup(writer.close)
        self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone(), ("wal",))
        writer.execute("PRAGMA wal_autocheckpoint=0")
        self.assertEqual(
            writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone(),
            (0, 0, 0),
        )
        wal = Path(f"{self.catalog_path}-wal")
        shm = Path(f"{self.catalog_path}-shm")
        self.assertEqual(wal.stat().st_size, 0)
        self.assertEqual(shm.stat().st_size, 32_768)
        staging_root = self.root / "probe-staging"
        staging_root.mkdir(mode=0o700)
        before = self._catalog_sidecar_snapshot()

        with (
            patch.object(
                cli.pwd,
                "getpwnam",
                return_value=Mock(pw_uid=os.getuid(), pw_gid=os.getgid()),
            ),
            patch.object(cli, "_PROBE_SNAPSHOT_ROOT", staging_root),
        ):
            cassette = cli._read_probe_catalog_cassette(
                self.catalog_path,
                job_id="JOB1",
                cassette_sequence=4,
            )

        self.assertEqual(cassette["physical_label"], r"CURRENT/LABEL\EXACT")
        self.assertEqual(cassette["tape_serial"], "CURRENT-SERIAL")
        self.assertEqual(self._catalog_sidecar_snapshot(), before)
        self.assertEqual(tuple(staging_root.iterdir()), ())

    def test_probe_rejects_hostile_catalog_sidecars_without_mutation(self):
        from ltobackup.qualification import cli

        cases = (
            "journal",
            "wal_symlink",
            "wal_hardlink",
            "wal_mode",
            "wal_malformed",
            "wal_oversize",
            "shm_oversize",
            "wrong_owner",
        )
        for case in cases:
            with self.subTest(case=case):
                target_root = self.root / f"hostile-{case}"
                target_root.mkdir(mode=0o750)
                target_catalog = target_root / self.catalog_path.name
                target_catalog.write_bytes(self.catalog_path.read_bytes())
                target_catalog.chmod(0o600)
                staging_root = target_root / "staging"
                staging_root.mkdir(mode=0o700)
                wal = Path(f"{target_catalog}-wal")
                shm = Path(f"{target_catalog}-shm")
                if case == "journal":
                    journal = Path(f"{target_catalog}-journal")
                    journal.write_bytes(b"journal")
                    journal.chmod(0o600)
                elif case == "wal_symlink":
                    wal.symlink_to(target_catalog.name)
                elif case == "wal_hardlink":
                    os.link(target_catalog, wal)
                elif case == "wal_mode":
                    wal.touch(mode=0o644)
                elif case == "wal_malformed":
                    wal.write_bytes(b"x" * 31)
                    wal.chmod(0o600)
                elif case == "wal_oversize":
                    wal.write_bytes(b"x" * 129)
                    wal.chmod(0o600)
                elif case == "shm_oversize":
                    shm.write_bytes(b"x" * 129)
                    shm.chmod(0o600)
                before = self._catalog_sidecar_snapshot(target_catalog)
                expected_uid = os.getuid() + (1 if case == "wrong_owner" else 0)

                with (
                    patch.object(
                        cli.pwd,
                        "getpwnam",
                        return_value=Mock(
                            pw_uid=expected_uid,
                            pw_gid=os.getgid(),
                        ),
                    ),
                    patch.object(cli, "_PROBE_SNAPSHOT_ROOT", staging_root),
                    patch.object(cli, "_MAX_PROBE_WAL_BYTES", 128),
                    patch.object(cli, "_MAX_PROBE_SHM_BYTES", 128),
                    self.assertRaises(QualificationRefused),
                ):
                    cli._read_probe_catalog_cassette(
                        target_catalog,
                        job_id="JOB1",
                        cassette_sequence=4,
                    )

                self.assertEqual(self._catalog_sidecar_snapshot(target_catalog), before)
                self.assertEqual(tuple(staging_root.iterdir()), ())

    def test_probe_rejects_catalog_path_swap_after_snapshot_copy(self):
        from ltobackup.qualification import cli

        self.root.chmod(0o750)
        self.catalog_path.chmod(0o600)
        staging_root = self.root / "probe-staging"
        staging_root.mkdir(mode=0o700)
        real_copy = cli._copy_probe_catalog_file

        def copy_then_swap(source, destination_fd, name):
            copied = real_copy(source, destination_fd, name)
            replacement = self.root / "replacement.db"
            replacement.write_bytes(self.catalog_path.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, self.catalog_path)
            return copied

        with (
            patch.object(
                cli.pwd,
                "getpwnam",
                return_value=Mock(pw_uid=os.getuid(), pw_gid=os.getgid()),
            ),
            patch.object(cli, "_PROBE_SNAPSHOT_ROOT", staging_root),
            patch.object(cli, "_copy_probe_catalog_file", copy_then_swap),
            self.assertRaises(QualificationRefused),
        ):
            cli._read_probe_catalog_cassette(
                self.catalog_path,
                job_id="JOB1",
                cassette_sequence=4,
            )
        self.assertEqual(tuple(staging_root.iterdir()), ())

    def test_probe_rejects_new_source_sidecar_during_snapshot_query(self):
        from ltobackup.qualification import cli

        self.root.chmod(0o750)
        self.catalog_path.chmod(0o600)
        staging_root = self.root / "probe-staging"
        staging_root.mkdir(mode=0o700)
        real_connect = sqlite3.connect

        def connect_after_source_change(*args, **kwargs):
            journal = Path(f"{self.catalog_path}-journal")
            journal.write_bytes(b"concurrent source change")
            journal.chmod(0o600)
            return real_connect(*args, **kwargs)

        with (
            patch.object(
                cli.pwd,
                "getpwnam",
                return_value=Mock(pw_uid=os.getuid(), pw_gid=os.getgid()),
            ),
            patch.object(cli, "_PROBE_SNAPSHOT_ROOT", staging_root),
            patch.object(cli.sqlite3, "connect", connect_after_source_change),
            self.assertRaises(QualificationRefused),
        ):
            cli._read_probe_catalog_cassette(
                self.catalog_path,
                job_id="JOB1",
                cassette_sequence=4,
            )
        self.assertEqual(tuple(staging_root.iterdir()), ())

    def test_probe_accepts_private_wal_ctime_only_change(self):
        from ltobackup.qualification import cli

        self.root.chmod(0o750)
        self.catalog_path.chmod(0o600)
        self._open_uncheckpointed_catalog_writer()
        staging_root = self.root / "probe-staging"
        staging_root.mkdir(mode=0o700)
        source_before = self._catalog_sidecar_snapshot()
        real_connect = sqlite3.connect

        def connect_after_private_wal_ctime_change(*args, **kwargs):
            workspace = next(staging_root.iterdir())
            private_wal = workspace / f"{self.catalog_path.name}-wal"
            before = private_wal.stat()
            os.chmod(private_wal, 0o600)
            after = private_wal.stat()
            self.assertEqual(after.st_mode, before.st_mode)
            self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
            self.assertNotEqual(after.st_ctime_ns, before.st_ctime_ns)
            return real_connect(*args, **kwargs)

        with (
            patch.object(
                cli.pwd,
                "getpwnam",
                return_value=Mock(pw_uid=os.getuid(), pw_gid=os.getgid()),
            ),
            patch.object(cli, "_PROBE_SNAPSHOT_ROOT", staging_root),
            patch.object(
                cli.sqlite3,
                "connect",
                connect_after_private_wal_ctime_change,
            ),
        ):
            cassette = cli._read_probe_catalog_cassette(
                self.catalog_path,
                job_id="JOB1",
                cassette_sequence=4,
            )

        self.assertEqual(cassette["physical_label"], "WAL-LABEL")
        self.assertEqual(cassette["tape_serial"], "WAL-SERIAL")
        self.assertEqual(self._catalog_sidecar_snapshot(), source_before)
        self.assertEqual(tuple(staging_root.iterdir()), ())

    def test_authorize_outputs_only_operation_specific_token(self):
        from ltobackup.qualification import cli

        plan = QualificationPlan(
            2,
            RUN_ID,
            "JOB1",
            4,
            r"CURRENT/LABEL\EXACT",
            "CURRENT-SERIAL",
            "DRIVE-SERIAL",
            "0x5000000000000001",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            NOW,
            NOW + 1_000_000_000,
            (QualificationOperation.FORMAT, QualificationOperation.WIPE),
            expected_mam_medium_serial="CURRENT-SERIAL",
        )
        plan_path = self.root / "plan.json"
        plan_path.write_bytes(plan.canonical_bytes())
        plan_path.chmod(0o600)
        credential_path = self.root / "credential"
        credential_path.write_bytes(CREDENTIAL)
        output = io.StringIO()
        with (
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            patch.object(cli, "_read_root_credential", return_value=CREDENTIAL),
        ):
            result = cli.main(
                [
                    "authorize",
                    "--plan",
                    str(plan_path),
                    "--operation",
                    "format",
                    "--credential",
                    str(credential_path),
                ],
                stdout=output,
            )
        self.assertEqual(result, 0)
        token = output.getvalue()
        self.assertEqual(
            token, plan.authorize(QualificationOperation.FORMAT, CREDENTIAL)
        )
        self.assertEqual(len(token.encode("ascii")), 64)
        self.assertRegex(token, r"\A[0-9a-f]{64}\Z")
        self.assertNotIn("\n", token)
        self.assertNotIn(CREDENTIAL.decode("ascii"), output.getvalue())

    def test_authorize_rejects_plan_that_is_not_exact_owner_mode_0600(self):
        from ltobackup.qualification import cli

        plan = QualificationPlan(
            1,
            RUN_ID,
            "JOB1",
            4,
            r"CURRENT/LABEL\EXACT",
            "CURRENT-SERIAL",
            "DRIVE-SERIAL",
            "0x5000000000000001",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            NOW,
            NOW + 1_000_000_000,
            (QualificationOperation.FORMAT,),
        )
        plan_path = self.root / "world-readable-plan.json"
        plan_path.write_bytes(plan.canonical_bytes())
        plan_path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "plan file is invalid"):
            cli._read_plan(plan_path)

    def test_authority_json_rejects_duplicate_keys(self):
        from ltobackup.qualification import cli

        authority = self.root / "authority.json"
        authority.write_text('{"schema":1,"schema":1}\n', encoding="utf-8")
        original_fstat = os.fstat

        def root_owned(descriptor):
            fields = list(original_fstat(descriptor))
            fields[4] = 0
            fields[5] = 0
            return os.stat_result(fields)

        with (
            patch.object(cli.os, "fstat", side_effect=root_owned),
            self.assertRaises(ValueError),
        ):
            cli._read_closed_json(authority, frozenset({"schema"}))

    def test_artifact_authority_is_exact_mode_0400_and_canonical_before_io(self):
        from ltobackup.qualification import cli

        authority = self.root / "qualification-artifacts.json"
        original_fstat = os.fstat

        def root_owned(descriptor):
            fields = list(original_fstat(descriptor))
            fields[4] = 0
            fields[5] = 0
            return os.stat_result(fields)

        def read() -> dict[str, object]:
            with patch.object(cli.os, "fstat", side_effect=root_owned):
                return cli._read_closed_json(
                    authority,
                    frozenset({"schema"}),
                    expected_mode=0o400,
                    require_canonical=True,
                )

        authority.write_bytes(b'{"schema":2}\n')
        authority.chmod(0o400)
        self.assertEqual({"schema": 2}, read())

        for payload, mode in (
            (b'{"schema":2}\n', 0o600),
            (b'{ "schema": 2 }\n', 0o400),
            (b'{"schema":2}', 0o400),
        ):
            with self.subTest(payload=payload, mode=oct(mode)):
                authority.chmod(0o600)
                authority.write_bytes(payload)
                authority.chmod(mode)
                with self.assertRaises(ValueError):
                    read()

    def test_device_authority_is_exact_root_lto_admin_0640(self):
        from ltobackup.qualification import cli

        authority = self.root / "device.json"
        authority.write_text('{"schema":2}\n', encoding="ascii")
        real_fstat = os.fstat
        metadata = {"uid": 0, "gid": 4242, "mode": 0o640}

        def trusted_fstat(descriptor):
            status = real_fstat(descriptor)
            fields = list(status)
            fields[0] = stat.S_IFREG | metadata["mode"]
            fields[4] = metadata["uid"]
            fields[5] = metadata["gid"]
            return type(status)(fields)

        with (
            patch.object(cli.os, "fstat", side_effect=trusted_fstat),
            patch.object(cli.grp, "getgrnam", return_value=Mock(gr_gid=4242)),
        ):
            self.assertEqual(
                {"schema": 2},
                cli._read_closed_json(
                    authority,
                    frozenset({"schema"}),
                    expected_mode=0o640,
                    expected_group="lto-admin",
                ),
            )
            for mutation in (
                {"mode": 0o600},
                {"mode": 0o660},
                {"uid": 1},
                {"gid": 0},
            ):
                with self.subTest(mutation=mutation):
                    metadata.update({"uid": 0, "gid": 4242, "mode": 0o640})
                    metadata.update(mutation)
                    with self.assertRaisesRegex(
                        QualificationRefused, "authority is unavailable"
                    ):
                        cli._read_closed_json(
                            authority,
                            frozenset({"schema"}),
                            expected_mode=0o640,
                            expected_group="lto-admin",
                        )

    def test_environment_uses_observed_mam_and_excludes_catalog_serial_from_scope(self):
        from ltobackup.qualification import cli

        plan = QualificationPlan(
            2,
            RUN_ID,
            "JOB1",
            4,
            r"CURRENT/LABEL\EXACT",
            "CURRENT-SERIAL",
            "DRIVE-SERIAL",
            "0x5000000000000001",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            NOW,
            NOW + 1_000_000_000,
            (QualificationOperation.FORMAT, QualificationOperation.READ_ONLY),
            expected_mam_medium_serial="MAM-VOLUME-IDENTIFIER",
        )
        settings = LinuxSettings(
            tape_device_path=Path("/dev/tape/by-id/current-nst"),
            scsi_device_path=Path("/dev/lto-archiver-scsi-current"),
        )
        device = {
            "nst_path": str(settings.tape_device_path),
            "sg_path": str(settings.scsi_device_path),
            "serial": plan.drive_serial,
            "wwid": plan.drive_wwid,
        }
        artifacts = {
            "schema": 2,
            "linux_tree_sha256": plan.linux_tree_sha256,
            "ltfs_tree_sha256": plan.ltfs_tree_sha256,
            "ltfs_rpm_sha256": plan.ltfs_rpm_sha256,
            "tool_sha256": TOOL_SHA256,
        }
        payload = {
            "tape_by_id": str(settings.tape_device_path),
            "scsi_by_id": str(settings.scsi_device_path),
            "drive_serial": plan.drive_serial,
            "mam_barcode": plan.physical_label,
            "schema": 2,
            "media_state": "ltfs",
            "mam_volume_serial": "MAM-VOLUME-IDENTIFIER",
            "ltfs_volume_label": plan.physical_label,
            "ltfs_volume_uuid": "22222222-2222-4222-8222-222222222222",
            "index_generation": 7,
        }
        provider = Mock()
        provider.resolve.side_effect = (
            StableDeviceIdentity("current-nst", plan.drive_serial, "same-unit"),
            StableDeviceIdentity("scsi-current", plan.drive_serial, "same-unit"),
        )
        authority_reader = Mock(side_effect=(device, artifacts))
        with (
            patch.object(cli, "load_linux_settings", return_value=settings),
            patch.object(cli, "_read_closed_json", authority_reader),
            patch.object(cli, "_run_ltfs_info", return_value=payload),
            patch.object(cli, "SysfsDeviceIdentityProvider", return_value=provider),
        ):
            evidence = cli._prepare_environment(plan, QualificationOperation.READ_ONLY)
        self.assertEqual(evidence.physical_label, plan.physical_label)
        self.assertEqual(evidence.tape_serial, plan.tape_serial)
        self.assertNotEqual(payload["mam_volume_serial"], plan.tape_serial)
        self.assertEqual(
            evidence.observed_media_identity_sha256,
            "24cb23d61189e5fa9aedfce4b881f1215c2262675d973be7865503eec622d351",
        )
        self.assertEqual(
            evidence.expected_media_scope_sha256,
            expected_media_scope_sha256(
                (
                    "qualification.read_only",
                    plan.job_id,
                    str(plan.cassette_sequence),
                    plan.physical_label,
                    "",
                    payload["ltfs_volume_uuid"],
                )
            ),
        )
        self.assertEqual(
            authority_reader.call_args_list[0].kwargs,
            {"expected_mode": 0o640, "expected_group": "lto-admin"},
        )
        self.assertEqual(
            authority_reader.call_args_list[1].kwargs,
            {"expected_mode": 0o400, "require_canonical": True},
        )
        self.assertNotEqual(
            evidence.tape_device_identity_sha256,
            evidence.scsi_device_identity_sha256,
        )

        for field, substituted in (
            ("mam_barcode", "CURRENT/LABEL/OTHER"),
            ("mam_volume_serial", "WRONG-MAM"),
            ("ltfs_volume_label", "current/LABEL\\EXACT"),
            ("drive_serial", "OTHER-DRIVE"),
        ):
            with self.subTest(field=field):
                changed = dict(payload)
                changed[field] = substituted
                local_provider = Mock()
                local_provider.resolve.side_effect = (
                    StableDeviceIdentity("current-nst", plan.drive_serial, "same-unit"),
                    StableDeviceIdentity(
                        "scsi-current", plan.drive_serial, "same-unit"
                    ),
                )
                with (
                    patch.object(cli, "load_linux_settings", return_value=settings),
                    patch.object(
                        cli, "_read_closed_json", side_effect=(device, artifacts)
                    ),
                    patch.object(cli, "_run_ltfs_info", return_value=changed),
                    patch.object(
                        cli,
                        "SysfsDeviceIdentityProvider",
                        return_value=local_provider,
                    ),
                    self.assertRaises(ValueError),
                ):
                    cli._prepare_environment(plan, QualificationOperation.READ_ONLY)

        invalid_payloads = {
            "missing_mam_volume_identifier": (
                {**payload, "mam_volume_serial": None},
                QualificationOperation.READ_ONLY,
            ),
            "contradictory_unidentified_state": (
                {**payload, "media_state": "unidentified"},
                QualificationOperation.FORMAT,
            ),
            "unidentified_state_requires_format": (
                {
                    **payload,
                    "media_state": "unidentified",
                    "mam_barcode": None,
                    "ltfs_volume_label": None,
                    "ltfs_volume_uuid": None,
                    "index_generation": None,
                },
                QualificationOperation.READ_ONLY,
            ),
            "unidentified_barcode_is_neither_null_nor_catalog_label": (
                {
                    **payload,
                    "media_state": "unidentified",
                    "mam_barcode": "UNEXPECTED-BARCODE",
                    "ltfs_volume_label": None,
                    "ltfs_volume_uuid": None,
                    "index_generation": None,
                },
                QualificationOperation.FORMAT,
            ),
            "partial_ltfs_tuple": (
                {**payload, "ltfs_volume_uuid": None},
                QualificationOperation.READ_ONLY,
            ),
            "empty_ltfs_uuid": (
                {**payload, "ltfs_volume_uuid": ""},
                QualificationOperation.READ_ONLY,
            ),
            "malformed_ltfs_uuid": (
                {**payload, "ltfs_volume_uuid": "not-a-uuid"},
                QualificationOperation.READ_ONLY,
            ),
            "noncanonical_ltfs_uuid": (
                {
                    **payload,
                    "ltfs_volume_uuid": "00000000-0000-0000-0000-000000000000",
                },
                QualificationOperation.READ_ONLY,
            ),
            "missing_schema_key": (
                {key: value for key, value in payload.items() if key != "schema"},
                QualificationOperation.READ_ONLY,
            ),
            "extra_key": (
                {**payload, "unexpected": True},
                QualificationOperation.READ_ONLY,
            ),
            "unsupported_schema": (
                {**payload, "schema": 1},
                QualificationOperation.READ_ONLY,
            ),
        }
        for reason, (invalid_payload, operation) in invalid_payloads.items():
            with self.subTest(reason=reason):
                local_provider = Mock()
                local_provider.resolve.side_effect = (
                    StableDeviceIdentity("current-nst", plan.drive_serial, "same-unit"),
                    StableDeviceIdentity(
                        "scsi-current", plan.drive_serial, "same-unit"
                    ),
                )
                with (
                    patch.object(cli, "load_linux_settings", return_value=settings),
                    patch.object(
                        cli,
                        "_read_closed_json",
                        side_effect=(device, artifacts),
                    ),
                    patch.object(cli, "_run_ltfs_info", return_value=invalid_payload),
                    patch.object(
                        cli,
                        "SysfsDeviceIdentityProvider",
                        return_value=local_provider,
                    ),
                    self.assertRaises(QualificationRefused),
                ):
                    cli._prepare_environment(plan, operation)

    def test_prepare_environment_accepts_real_flat_scsi_identity_only(self):
        from ltobackup.qualification import cli

        root = self.root / "identity"
        device_root = root / "dev"
        sys_class = root / "sys" / "class"
        tape_namespace = device_root / "tape" / "by-id"
        tape_namespace.mkdir(parents=True)
        (device_root / "nst0").write_bytes(b"")
        (device_root / "sg0").write_bytes(b"")
        tape_alias = tape_namespace / "current-nst"
        tape_alias.symlink_to(device_root / "nst0")
        scsi_alias = device_root / "lto-archiver-scsi-current"
        scsi_alias.symlink_to(device_root / "sg0")

        unit = root / "sys" / "devices" / "unit-a"
        unit.mkdir(parents=True)
        (unit / "vpd_pg80").write_bytes(b"\x00\x80\x00\x07DRIVE-A")
        for class_name, device_name in (
            ("scsi_tape", "nst0"),
            ("scsi_generic", "sg0"),
        ):
            class_device = sys_class / class_name / device_name
            class_device.mkdir(parents=True)
            (class_device / "device").symlink_to(unit, target_is_directory=True)

        plan = QualificationPlan(
            1,
            RUN_ID,
            "JOB1",
            4,
            r"CURRENT/LABEL\EXACT",
            "CURRENT-SERIAL",
            "DRIVE-A",
            "0x5000000000000001",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            NOW,
            NOW + 1_000_000_000,
            (QualificationOperation.READ_ONLY,),
        )
        settings = LinuxSettings(
            tape_device_path=tape_alias,
            scsi_device_path=scsi_alias,
        )
        device = {
            "nst_path": str(tape_alias),
            "sg_path": str(scsi_alias),
            "serial": plan.drive_serial,
            "wwid": plan.drive_wwid,
        }
        artifacts = {
            "schema": 2,
            "linux_tree_sha256": plan.linux_tree_sha256,
            "ltfs_tree_sha256": plan.ltfs_tree_sha256,
            "ltfs_rpm_sha256": plan.ltfs_rpm_sha256,
            "tool_sha256": TOOL_SHA256,
        }
        payload = {
            "schema": 2,
            "media_state": "ltfs",
            "tape_by_id": str(tape_alias),
            "scsi_by_id": str(scsi_alias),
            "drive_serial": plan.drive_serial,
            "mam_barcode": plan.physical_label,
            "mam_volume_serial": "MAM-VOLUME-IDENTIFIER",
            "ltfs_volume_label": plan.physical_label,
            "ltfs_volume_uuid": "22222222-2222-4222-8222-222222222222",
            "index_generation": 7,
        }
        provider_factory = lambda: SysfsDeviceIdentityProvider(
            sys_class=sys_class, device_root=device_root
        )
        with (
            patch.object(cli, "load_linux_settings", return_value=settings),
            patch.object(cli, "_read_closed_json", side_effect=(device, artifacts)),
            patch.object(cli, "_run_ltfs_info", return_value=payload),
            patch.object(
                cli,
                "SysfsDeviceIdentityProvider",
                side_effect=provider_factory,
            ),
        ):
            evidence = cli._prepare_environment(plan, QualificationOperation.READ_ONLY)
        self.assertEqual(plan.drive_serial, evidence.drive_serial)

        near_miss = device_root / "disk" / "by-id" / "lto-archiver-scsi-current"
        near_miss.parent.mkdir(parents=True)
        near_miss.symlink_to(device_root / "sg0")
        near_settings = replace(settings, scsi_device_path=near_miss)
        near_device = dict(device, sg_path=str(near_miss))
        near_payload = dict(payload, scsi_by_id=str(near_miss))
        with (
            patch.object(cli, "load_linux_settings", return_value=near_settings),
            patch.object(
                cli,
                "_read_closed_json",
                side_effect=(near_device, artifacts),
            ),
            patch.object(cli, "_run_ltfs_info", return_value=near_payload),
            patch.object(
                cli,
                "SysfsDeviceIdentityProvider",
                side_effect=provider_factory,
            ),
            self.assertRaises(BackendUnavailable),
        ):
            cli._prepare_environment(plan, QualificationOperation.READ_ONLY)

    def test_format_preprobe_accepts_mam_bound_unidentified_media_without_ltfs_index(
        self,
    ):
        from ltobackup.qualification import cli

        plan = QualificationPlan(
            1,
            RUN_ID,
            "JOB1",
            4,
            r"CURRENT/LABEL\EXACT",
            "CURRENT-SERIAL",
            "DRIVE-SERIAL",
            "0x5000000000000001",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            NOW,
            NOW + 1_000_000_000,
            (QualificationOperation.FORMAT,),
        )
        settings = LinuxSettings(
            tape_device_path=Path("/dev/tape/by-id/current-nst"),
            scsi_device_path=Path("/dev/lto-archiver-scsi-current"),
        )
        device = {
            "nst_path": str(settings.tape_device_path),
            "sg_path": str(settings.scsi_device_path),
            "serial": plan.drive_serial,
            "wwid": plan.drive_wwid,
        }
        artifacts = {
            "schema": 2,
            "linux_tree_sha256": plan.linux_tree_sha256,
            "ltfs_tree_sha256": plan.ltfs_tree_sha256,
            "ltfs_rpm_sha256": plan.ltfs_rpm_sha256,
            "tool_sha256": TOOL_SHA256,
        }
        payload = {
            "schema": 2,
            "media_state": "unidentified",
            "tape_by_id": str(settings.tape_device_path),
            "scsi_by_id": str(settings.scsi_device_path),
            "drive_serial": plan.drive_serial,
            "mam_barcode": None,
            "mam_volume_serial": "MAM-VOLUME-IDENTIFIER",
            "ltfs_volume_label": None,
            "ltfs_volume_uuid": None,
            "index_generation": None,
        }
        provider = Mock()
        provider.resolve.side_effect = (
            StableDeviceIdentity("current-nst", plan.drive_serial, "same-unit"),
            StableDeviceIdentity("scsi-current", plan.drive_serial, "same-unit"),
        )
        probe = Mock(return_value=payload)
        with (
            patch.object(cli, "load_linux_settings", return_value=settings),
            patch.object(cli, "_read_closed_json", side_effect=(device, artifacts)),
            patch.object(cli, "_run_ltfs_info", probe),
            patch.object(cli, "SysfsDeviceIdentityProvider", return_value=provider),
        ):
            evidence = cli._prepare_environment(plan, QualificationOperation.FORMAT)
        self.assertIsNone(evidence.volume_uuid)
        self.assertIsNone(evidence.generation)
        self.assertEqual(
            evidence.observed_media_identity_sha256,
            "f729dd30054d767095c338d4dca03eb9c8a109cb87726b456531711df0f5faa5",
        )
        probe.assert_called_once_with(TOOL_SHA256["ltfs-info"], mode="pre-format")

        labeled = {**payload, "mam_barcode": plan.physical_label}
        labeled_provider = Mock()
        labeled_provider.resolve.side_effect = (
            StableDeviceIdentity("current-nst", plan.drive_serial, "same-unit"),
            StableDeviceIdentity("scsi-current", plan.drive_serial, "same-unit"),
        )
        with (
            patch.object(cli, "load_linux_settings", return_value=settings),
            patch.object(cli, "_read_closed_json", side_effect=(device, artifacts)),
            patch.object(cli, "_run_ltfs_info", return_value=labeled),
            patch.object(
                cli,
                "SysfsDeviceIdentityProvider",
                return_value=labeled_provider,
            ),
        ):
            labeled_evidence = cli._prepare_environment(
                plan, QualificationOperation.FORMAT
            )
        self.assertIsNone(labeled_evidence.volume_uuid)
        self.assertIsNone(labeled_evidence.generation)
        self.assertEqual(
            labeled_evidence.observed_media_identity_sha256,
            "f9d9a310f78e2cdc293469933404af489c191f6d57da1eefb7689a182b4afe7e",
        )

        for changed in (
            {**payload, "ltfs_volume_label": plan.physical_label},
            {
                **payload,
                "ltfs_volume_uuid": "22222222-2222-4222-8222-222222222222",
                "index_generation": 7,
            },
        ):
            with self.subTest(changed=changed):
                local_provider = Mock()
                local_provider.resolve.side_effect = (
                    StableDeviceIdentity("current-nst", plan.drive_serial, "same-unit"),
                    StableDeviceIdentity(
                        "scsi-current", plan.drive_serial, "same-unit"
                    ),
                )
                with (
                    patch.object(cli, "load_linux_settings", return_value=settings),
                    patch.object(
                        cli, "_read_closed_json", side_effect=(device, artifacts)
                    ),
                    patch.object(cli, "_run_ltfs_info", return_value=changed),
                    patch.object(
                        cli,
                        "SysfsDeviceIdentityProvider",
                        return_value=local_provider,
                    ),
                    self.assertRaises(ValueError),
                ):
                    cli._prepare_environment(plan, QualificationOperation.FORMAT)

    def test_load_uses_only_completed_unload_identity_until_post_load_probe(self):
        from ltobackup.qualification import cli

        plan = QualificationPlan(
            1,
            RUN_ID,
            "JOB1",
            4,
            r"CURRENT/LABEL\EXACT",
            "CURRENT-SERIAL",
            "DRIVE-SERIAL",
            "0x5000000000000001",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            NOW,
            NOW + 1_000_000_000,
            (QualificationOperation.UNLOAD, QualificationOperation.LOAD),
        )
        volume_uuid = "22222222-2222-4222-8222-222222222222"
        with Catalog(self.catalog_path) as catalog:
            catalog.create_ltfs_qualification_run(plan)
            for ordinal, verdict, terminal in (
                (1, "dispatch_started", None),
                (2, "pass", "d" * 64),
            ):
                catalog.record_ltfs_qualification_stage(
                    run_id=plan.run_id,
                    ordinal=ordinal,
                    operation=QualificationOperation.UNLOAD,
                    request_sha256="e" * 64,
                    dispatched=True,
                    terminal_receipt_sha256=terminal,
                    child_exit_code=None if terminal is None else 0,
                    before_volume_uuid=volume_uuid,
                    before_generation=7,
                    after_volume_uuid=None,
                    after_generation=None,
                    content_manifest_sha256=None,
                    verdict=verdict,
                )
        settings = LinuxSettings(
            tape_device_path=Path("/dev/tape/by-id/current-nst"),
            scsi_device_path=Path("/dev/lto-archiver-scsi-current"),
        )
        device = {
            "nst_path": str(settings.tape_device_path),
            "sg_path": str(settings.scsi_device_path),
            "serial": plan.drive_serial,
            "wwid": plan.drive_wwid,
        }
        artifacts = {
            "schema": 2,
            "linux_tree_sha256": plan.linux_tree_sha256,
            "ltfs_tree_sha256": plan.ltfs_tree_sha256,
            "ltfs_rpm_sha256": plan.ltfs_rpm_sha256,
            "tool_sha256": TOOL_SHA256,
        }
        provider = Mock()
        provider.resolve.side_effect = (
            StableDeviceIdentity("current-nst", plan.drive_serial, "same-unit"),
            StableDeviceIdentity("scsi-current", plan.drive_serial, "same-unit"),
        )
        broker_ordinal = cli._EXECUTION_ORDER.index(QualificationOperation.UNLOAD) + 1
        observed_media_identity_sha256 = "6" * 64
        snapshot = {
            "run_id": plan.run_id,
            "stage_ordinal": broker_ordinal,
            "state": "TERMINAL",
            "boot_id": "44444444-4444-4444-8444-444444444444",
            "request_sha256": "e" * 64,
            "immutable_sha256": "1" * 64,
            "plan_sha256": plan.plan_sha256,
            "operation": QualificationOperation.UNLOAD.value,
            "operation_token_sha256": "2" * 64,
            "tape_device_identity_sha256": "3" * 64,
            "scsi_device_identity_sha256": "4" * 64,
            "expected_media_scope_sha256": "5" * 64,
            "observed_media_identity_sha256": observed_media_identity_sha256,
            "expected_physical_label": plan.physical_label,
            "expected_tape_serial": plan.tape_serial,
            "expected_drive_serial": plan.drive_serial,
            "expected_drive_wwid": plan.drive_wwid,
            "expected_volume_uuid": volume_uuid,
            "expected_generation": 7,
            "request_nonce": b"n" * 32,
            "created_at": "2026-08-23T00:00:00+00:00",
            "dispatched_at": "2026-08-23T00:00:01+00:00",
            "terminal_at": "2026-08-23T00:00:02+00:00",
        }
        dispatch = BrokerQualificationDispatch(
            1,
            plan.run_id,
            broker_ordinal,
            QualificationOperation.UNLOAD,
            "e" * 64,
            "terminal",
            "d" * 64,
            0,
            "8" * 64,
            b"b" * 32,
            b"p" * 32,
        )
        broker = _InspectionBroker(
            BrokerQualificationInspection(
                "terminal", snapshot, dispatch, b"o" * 32, b"i" * 32
            )
        )
        with (
            patch.object(cli, "load_linux_settings", return_value=settings),
            patch.object(cli, "_read_closed_json", side_effect=(device, artifacts)),
            patch.object(
                cli,
                "_run_ltfs_info",
                side_effect=AssertionError(
                    "load pre-dispatch opened the unloaded tape"
                ),
            ),
            patch.object(cli, "SysfsDeviceIdentityProvider", return_value=provider),
            patch.object(cli, "_connect_broker", return_value=broker),
        ):
            evidence = cli._prepare_environment(
                plan, QualificationOperation.LOAD, self.catalog_path
            )
        self.assertEqual(evidence.volume_uuid, volume_uuid)
        self.assertEqual(evidence.generation, 7)
        self.assertEqual(evidence.physical_label, plan.physical_label)
        self.assertEqual(evidence.tape_serial, plan.tape_serial)
        self.assertEqual(
            evidence.observed_media_identity_sha256,
            observed_media_identity_sha256,
        )
        self.assertEqual(
            evidence.expected_media_scope_sha256,
            expected_media_scope_sha256(
                (
                    "qualification.load",
                    plan.job_id,
                    str(plan.cassette_sequence),
                    plan.physical_label,
                    "",
                    volume_uuid,
                )
            ),
        )
        self.assertEqual(len(broker.inspections), 1)

        substituted_snapshot = {
            **snapshot,
            "expected_tape_serial": "SUBSTITUTED-LEGACY-SERIAL",
        }
        substituted = _InspectionBroker(
            BrokerQualificationInspection(
                "terminal",
                substituted_snapshot,
                dispatch,
                b"q" * 32,
                b"r" * 32,
            )
        )
        substituted_provider = Mock()
        substituted_provider.resolve.side_effect = (
            StableDeviceIdentity("current-nst", plan.drive_serial, "same-unit"),
            StableDeviceIdentity("scsi-current", plan.drive_serial, "same-unit"),
        )
        with (
            patch.object(cli, "load_linux_settings", return_value=settings),
            patch.object(cli, "_read_closed_json", side_effect=(device, artifacts)),
            patch.object(
                cli,
                "_run_ltfs_info",
                side_effect=AssertionError(
                    "load pre-dispatch opened the unloaded tape"
                ),
            ),
            patch.object(
                cli,
                "SysfsDeviceIdentityProvider",
                return_value=substituted_provider,
            ),
            patch.object(cli, "_connect_broker", return_value=substituted),
            self.assertRaises(QualificationRefused),
        ):
            cli._prepare_environment(
                plan, QualificationOperation.LOAD, self.catalog_path
            )

    def test_load_without_exact_completed_unload_is_rejected_before_device_io(self):
        from ltobackup.qualification import cli

        plan = QualificationPlan(
            1,
            RUN_ID,
            "JOB1",
            4,
            r"CURRENT/LABEL\EXACT",
            "CURRENT-SERIAL",
            "DRIVE-SERIAL",
            "0x5000000000000001",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            NOW,
            NOW + 1_000_000_000,
            (QualificationOperation.LOAD,),
        )
        artifacts = {
            "schema": 2,
            "linux_tree_sha256": plan.linux_tree_sha256,
            "ltfs_tree_sha256": plan.ltfs_tree_sha256,
            "ltfs_rpm_sha256": plan.ltfs_rpm_sha256,
            "tool_sha256": TOOL_SHA256,
        }
        settings = LinuxSettings(
            tape_device_path=Path("/dev/tape/by-id/current-nst"),
            scsi_device_path=Path("/dev/lto-archiver-scsi-current"),
        )
        device = {
            "nst_path": str(settings.tape_device_path),
            "sg_path": str(settings.scsi_device_path),
            "serial": plan.drive_serial,
            "wwid": plan.drive_wwid,
        }
        with (
            patch.object(cli, "load_linux_settings", return_value=settings),
            patch.object(cli, "_read_closed_json", side_effect=(device, artifacts)),
            patch.object(
                cli,
                "SysfsDeviceIdentityProvider",
                side_effect=AssertionError("orphan load touched the device"),
            ),
            self.assertRaisesRegex(ValueError, "load evidence is unavailable"),
        ):
            cli._prepare_environment(
                plan, QualificationOperation.LOAD, self.catalog_path
            )

    def test_post_operation_identity_transition_matrix_is_fail_closed(self):
        from ltobackup.qualification import cli

        before = cli.QualificationEnvironmentEvidence(
            physical_label=r"CURRENT/LABEL\EXACT",
            tape_serial="CURRENT-SERIAL",
            drive_serial="DRIVE-SERIAL",
            drive_wwid="0x5000000000000001",
            linux_tree_sha256="a" * 64,
            ltfs_tree_sha256="b" * 64,
            ltfs_rpm_sha256="c" * 64,
            tape_device_identity_sha256="d" * 64,
            scsi_device_identity_sha256="e" * 64,
            expected_media_scope_sha256="f" * 64,
            observed_media_identity_sha256="0" * 64,
            volume_uuid="22222222-2222-4222-8222-222222222222",
            generation=7,
        )

        def changed(**updates):
            values = {name: getattr(before, name) for name in before.__slots__}
            values.update(updates)
            return cli.QualificationEnvironmentEvidence(**values)

        accepted = {
            QualificationOperation.READ_ONLY: changed(),
            QualificationOperation.LOAD: changed(),
            QualificationOperation.ADDITIVE_WRITE: changed(generation=8),
            QualificationOperation.OVERWRITE: changed(generation=8),
            QualificationOperation.REPAIR: changed(generation=7),
            QualificationOperation.FORMAT: changed(
                volume_uuid="33333333-3333-4333-8333-333333333333",
                generation=1,
                observed_media_identity_sha256="1" * 64,
            ),
        }
        for operation, after in accepted.items():
            with self.subTest(operation=operation, accepted=True):
                cli._validate_post_operation_identity(operation, before, after)

        rejected = (
            (QualificationOperation.READ_ONLY, changed(generation=8)),
            (QualificationOperation.LOAD, changed(volume_uuid="3" * 36)),
            (QualificationOperation.ADDITIVE_WRITE, changed(generation=7)),
            (QualificationOperation.OVERWRITE, changed(generation=6)),
            (
                QualificationOperation.REPAIR,
                changed(observed_media_identity_sha256="1" * 64),
            ),
            (
                QualificationOperation.FORMAT,
                changed(volume_uuid=None, generation=None),
            ),
            (
                QualificationOperation.READ_ONLY,
                changed(tape_device_identity_sha256="1" * 64),
            ),
            (
                QualificationOperation.READ_ONLY,
                changed(scsi_device_identity_sha256="2" * 64),
            ),
        )
        for operation, after in rejected:
            with (
                self.subTest(operation=operation, accepted=False),
                self.assertRaises(ValueError),
            ):
                cli._validate_post_operation_identity(operation, before, after)

    def test_execute_stage_revalidates_exact_environment_before_broker_dispatch(self):
        from ltobackup.qualification import cli

        plan = QualificationPlan(
            2,
            RUN_ID,
            "JOB1",
            4,
            r"CURRENT/LABEL\EXACT",
            "CURRENT-SERIAL",
            "DRIVE-SERIAL",
            "0x5000000000000001",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            NOW,
            NOW + 1_000_000_000,
            (QualificationOperation.FORMAT,),
            expected_mam_medium_serial="CURRENT-SERIAL",
        )
        plan_path = self.root / "plan.json"
        plan_path.write_bytes(plan.canonical_bytes())
        plan_path.chmod(0o600)
        credential_path = self.root / "credential"
        credential_path.write_bytes(CREDENTIAL)
        token = plan.authorize(QualificationOperation.FORMAT, CREDENTIAL)
        evidence = cli.QualificationEnvironmentEvidence(
            physical_label=plan.physical_label,
            tape_serial=plan.tape_serial,
            drive_serial=plan.drive_serial,
            drive_wwid=plan.drive_wwid,
            linux_tree_sha256=plan.linux_tree_sha256,
            ltfs_tree_sha256=plan.ltfs_tree_sha256,
            ltfs_rpm_sha256=plan.ltfs_rpm_sha256,
            tape_device_identity_sha256="d" * 64,
            scsi_device_identity_sha256="e" * 64,
            expected_media_scope_sha256="f" * 64,
            observed_media_identity_sha256="0" * 64,
            volume_uuid="22222222-2222-4222-8222-222222222222",
            generation=7,
        )
        after_format_values = {
            name: getattr(evidence, name) for name in evidence.__slots__
        }
        after_format_values.update(
            volume_uuid="33333333-3333-4333-8333-333333333333",
            generation=1,
            observed_media_identity_sha256="1" * 64,
        )
        after_format = cli.QualificationEnvironmentEvidence(**after_format_values)
        broker = _Broker()
        output = io.StringIO()
        with (
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            patch.object(cli, "_read_root_credential", return_value=CREDENTIAL),
            patch.object(
                cli, "_prepare_environment", side_effect=(evidence, after_format)
            ),
            patch.object(cli, "_connect_broker", return_value=broker),
        ):
            result = cli.main(
                [
                    "execute-stage",
                    "--catalog",
                    str(self.catalog_path),
                    "--plan",
                    str(plan_path),
                    "--operation",
                    "format",
                    "--token",
                    token,
                    "--credential",
                    str(credential_path),
                ],
                stdout=output,
                now_ns=lambda: NOW + 1,
            )
        self.assertEqual(result, 0)
        self.assertEqual(len(broker.requests), 1)
        request = broker.requests[0]
        self.assertEqual(request.expected_physical_label, plan.physical_label)
        self.assertEqual(request.expected_tape_serial, plan.tape_serial)
        self.assertEqual(request.stage_ordinal, 2)
        self.assertEqual(request.issued_at_ns, plan.issued_at_ns)
        self.assertEqual(request.expires_at_ns, plan.expires_at_ns)
        self.assertEqual(
            request.operation_token,
            qualification_request_operation_token(request, CREDENTIAL),
        )
        self.assertNotEqual(request.operation_token, token)
        self.assertEqual(output.getvalue().count("\n"), 1)
        self.assertNotIn(plan.physical_label, output.getvalue())
        with Catalog(self.catalog_path) as catalog:
            run = catalog.connection.execute(
                "SELECT status FROM ltfs_qualification_runs WHERE run_id=?",
                (plan.run_id,),
            ).fetchone()
            stages = catalog.connection.execute(
                "SELECT operation,dispatched,verdict FROM ltfs_qualification_stages "
                "WHERE run_id=? ORDER BY ordinal",
                (plan.run_id,),
            ).fetchall()
        self.assertIsNotNone(run)
        self.assertEqual(run["status"], "completed")
        self.assertEqual(
            [
                ("format", 1, "dispatch_started"),
                ("format", 1, "pass"),
            ],
            [tuple(row) for row in stages],
        )

        changed = cli.QualificationEnvironmentEvidence(
            physical_label="SUBSTITUTED",
            tape_serial=plan.tape_serial,
            drive_serial=plan.drive_serial,
            drive_wwid=plan.drive_wwid,
            linux_tree_sha256=plan.linux_tree_sha256,
            ltfs_tree_sha256=plan.ltfs_tree_sha256,
            ltfs_rpm_sha256=plan.ltfs_rpm_sha256,
            tape_device_identity_sha256="d" * 64,
            scsi_device_identity_sha256="e" * 64,
            expected_media_scope_sha256="f" * 64,
            observed_media_identity_sha256="0" * 64,
            volume_uuid=None,
            generation=None,
        )
        with (
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            patch.object(cli, "_read_root_credential", return_value=CREDENTIAL),
            patch.object(cli, "_prepare_environment", return_value=changed),
            patch.object(
                cli, "_connect_broker", side_effect=AssertionError("broker dispatch")
            ),
        ):
            refused = cli.main(
                [
                    "execute-stage",
                    "--catalog",
                    str(self.catalog_path),
                    "--plan",
                    str(plan_path),
                    "--operation",
                    "format",
                    "--token",
                    token,
                    "--credential",
                    str(credential_path),
                ],
                stdout=io.StringIO(),
                stderr=io.StringIO(),
                now_ns=lambda: NOW + 1,
            )
        self.assertEqual(refused, 2)

    def test_execute_stage_cannot_skip_an_earlier_planned_operation(self):
        from ltobackup.qualification import cli

        plan = QualificationPlan(
            2,
            RUN_ID,
            "JOB1",
            4,
            r"CURRENT/LABEL\EXACT",
            "CURRENT-SERIAL",
            "DRIVE-SERIAL",
            "0x5000000000000001",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            NOW,
            NOW + 1_000_000_000,
            (
                QualificationOperation.READ_ONLY,
                QualificationOperation.FORMAT,
            ),
            expected_mam_medium_serial="CURRENT-SERIAL",
        )
        plan_path = self.root / "ordered-plan.json"
        plan_path.write_bytes(plan.canonical_bytes())
        plan_path.chmod(0o600)
        token = plan.authorize(QualificationOperation.FORMAT, CREDENTIAL)
        evidence = cli.QualificationEnvironmentEvidence(
            physical_label=plan.physical_label,
            tape_serial=plan.tape_serial,
            drive_serial=plan.drive_serial,
            drive_wwid=plan.drive_wwid,
            linux_tree_sha256=plan.linux_tree_sha256,
            ltfs_tree_sha256=plan.ltfs_tree_sha256,
            ltfs_rpm_sha256=plan.ltfs_rpm_sha256,
            tape_device_identity_sha256="d" * 64,
            scsi_device_identity_sha256="e" * 64,
            expected_media_scope_sha256="f" * 64,
            observed_media_identity_sha256="0" * 64,
            volume_uuid="22222222-2222-4222-8222-222222222222",
            generation=7,
        )
        broker = _Broker()
        with (
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            patch.object(cli, "_read_root_credential", return_value=CREDENTIAL),
            patch.object(cli, "_prepare_environment", return_value=evidence),
            patch.object(cli, "_connect_broker", return_value=broker),
        ):
            result = cli.main(
                [
                    "execute-stage",
                    "--catalog",
                    str(self.catalog_path),
                    "--plan",
                    str(plan_path),
                    "--operation",
                    "format",
                    "--token",
                    token,
                    "--credential",
                    str(self.root / "credential"),
                ],
                stdout=io.StringIO(),
                stderr=io.StringIO(),
                now_ns=lambda: NOW + 1,
            )
        self.assertEqual(result, 2)
        self.assertEqual(broker.requests, [])

    def test_ambiguous_broker_dispatch_is_durably_fenced_and_redacted(self):
        from ltobackup.qualification import cli

        plan = QualificationPlan(
            2,
            RUN_ID,
            "JOB1",
            4,
            r"CURRENT/LABEL\EXACT",
            "CURRENT-SERIAL",
            "DRIVE-SERIAL",
            "0x5000000000000001",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            NOW,
            NOW + 1_000_000_000,
            (QualificationOperation.FORMAT,),
            expected_mam_medium_serial="CURRENT-SERIAL",
        )
        plan_path = self.root / "ambiguous-plan.json"
        plan_path.write_bytes(plan.canonical_bytes())
        plan_path.chmod(0o600)
        evidence = cli.QualificationEnvironmentEvidence(
            physical_label=plan.physical_label,
            tape_serial=plan.tape_serial,
            drive_serial=plan.drive_serial,
            drive_wwid=plan.drive_wwid,
            linux_tree_sha256=plan.linux_tree_sha256,
            ltfs_tree_sha256=plan.ltfs_tree_sha256,
            ltfs_rpm_sha256=plan.ltfs_rpm_sha256,
            tape_device_identity_sha256="d" * 64,
            scsi_device_identity_sha256="e" * 64,
            expected_media_scope_sha256="f" * 64,
            observed_media_identity_sha256="0" * 64,
            volume_uuid="22222222-2222-4222-8222-222222222222",
            generation=7,
        )
        errors = io.StringIO()
        with (
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            patch.object(cli, "_read_root_credential", return_value=CREDENTIAL),
            patch.object(cli, "_prepare_environment", return_value=evidence),
            patch.object(
                cli,
                "_connect_broker",
                side_effect=BrokerUnavailable(),
            ),
        ):
            result = cli.main(
                [
                    "execute-stage",
                    "--catalog",
                    str(self.catalog_path),
                    "--plan",
                    str(plan_path),
                    "--operation",
                    "format",
                    "--token",
                    plan.authorize(QualificationOperation.FORMAT, CREDENTIAL),
                    "--credential",
                    str(self.root / "credential"),
                ],
                stdout=io.StringIO(),
                stderr=errors,
                now_ns=lambda: NOW + 1,
            )
        self.assertEqual(result, 2)
        self.assertEqual(errors.getvalue(), "LTFS qualification refused\n")
        with Catalog(self.catalog_path) as catalog:
            run = catalog.connection.execute(
                "SELECT status,fence_reason FROM ltfs_qualification_runs "
                "WHERE run_id=?",
                (plan.run_id,),
            ).fetchone()
            stages = catalog.connection.execute(
                "SELECT dispatched,verdict FROM ltfs_qualification_stages "
                "WHERE run_id=?",
                (plan.run_id,),
            ).fetchall()
        self.assertEqual(run["status"], "fenced")
        self.assertEqual(run["fence_reason"], "ambiguous_or_invalid_terminal_evidence")
        self.assertEqual([(1, "dispatch_started")], [tuple(row) for row in stages])

    def test_every_ltfs_operation_crosses_cli_broker_and_catalog_once(self):
        from ltobackup.qualification import cli

        for ordinal, operation in enumerate(SUPPORTED_OPERATIONS, 1):
            with self.subTest(operation=operation):
                plan = QualificationPlan(
                    2,
                    f"11111111-1111-4111-8111-{ordinal:012d}",
                    "JOB1",
                    4,
                    r"CURRENT/LABEL\EXACT",
                    "CURRENT-SERIAL",
                    "DRIVE-SERIAL",
                    "0x5000000000000001",
                    "a" * 64,
                    "b" * 64,
                    "c" * 64,
                    NOW,
                    NOW + 1_000_000_000,
                    (operation,),
                    expected_mam_medium_serial="CURRENT-SERIAL",
                )
                plan_path = self.root / f"{operation.value}.json"
                plan_path.write_bytes(plan.canonical_bytes())
                plan_path.chmod(0o600)
                evidence = cli.QualificationEnvironmentEvidence(
                    physical_label=plan.physical_label,
                    tape_serial=plan.tape_serial,
                    drive_serial=plan.drive_serial,
                    drive_wwid=plan.drive_wwid,
                    linux_tree_sha256=plan.linux_tree_sha256,
                    ltfs_tree_sha256=plan.ltfs_tree_sha256,
                    ltfs_rpm_sha256=plan.ltfs_rpm_sha256,
                    tape_device_identity_sha256="d" * 64,
                    scsi_device_identity_sha256="e" * 64,
                    expected_media_scope_sha256="f" * 64,
                    observed_media_identity_sha256="0" * 64,
                    volume_uuid="22222222-2222-4222-8222-222222222222",
                    generation=7,
                )
                broker = _Broker()
                environment_calls = 0

                def prepare_environment(*_args, op=operation, ev=evidence):
                    nonlocal environment_calls
                    environment_calls += 1
                    if environment_calls == 2 and op in {
                        QualificationOperation.ADDITIVE_WRITE,
                        QualificationOperation.OVERWRITE,
                    }:
                        values = {name: getattr(ev, name) for name in ev.__slots__}
                        values["generation"] = ev.generation + 1
                        return cli.QualificationEnvironmentEvidence(**values)
                    if environment_calls == 2 and op is QualificationOperation.FORMAT:
                        values = {name: getattr(ev, name) for name in ev.__slots__}
                        values.update(
                            volume_uuid="33333333-3333-4333-8333-333333333333",
                            generation=1,
                            observed_media_identity_sha256="1" * 64,
                        )
                        return cli.QualificationEnvironmentEvidence(**values)
                    return ev

                with (
                    patch.object(cli, "_effective_ids", return_value=(0, 0)),
                    patch.object(cli, "_read_root_credential", return_value=CREDENTIAL),
                    patch.object(
                        cli, "_prepare_environment", side_effect=prepare_environment
                    ),
                    patch.object(cli, "_connect_broker", return_value=broker),
                ):
                    result = cli.main(
                        [
                            "execute-stage",
                            "--catalog",
                            str(self.catalog_path),
                            "--plan",
                            str(plan_path),
                            "--operation",
                            operation.value,
                            "--token",
                            plan.authorize(operation, CREDENTIAL),
                            "--credential",
                            str(self.root / "credential"),
                        ],
                        stdout=io.StringIO(),
                        stderr=io.StringIO(),
                        now_ns=lambda: NOW + 1,
                    )
                self.assertEqual(result, 0)
                self.assertEqual(
                    [request.operation for request in broker.requests], [operation]
                )
                with Catalog(self.catalog_path) as catalog:
                    run = catalog.connection.execute(
                        "SELECT status FROM ltfs_qualification_runs WHERE run_id=?",
                        (plan.run_id,),
                    ).fetchone()
                self.assertEqual(run["status"], "completed")

    def test_manual_service_action_uses_only_fixed_paths_and_next_operation(self):
        from ltobackup.qualification import cli

        fixed_plan = self.root / "active-plan.json"
        fixed_catalog = self.catalog_path
        qualification_credential = self.root / "qualification-credential"
        operation_token = self.root / "operation-token"
        plan = QualificationPlan(
            1,
            RUN_ID,
            "JOB1",
            4,
            r"CURRENT/LABEL\EXACT",
            "CURRENT-SERIAL",
            "DRIVE-SERIAL",
            "0x5000000000000001",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            NOW,
            NOW + 1_000_000_000,
            (QualificationOperation.READ_ONLY, QualificationOperation.FORMAT),
        )
        fixed_plan.write_bytes(plan.canonical_bytes())
        fixed_plan.chmod(0o600)
        operation_token.write_text(
            plan.authorize(QualificationOperation.READ_ONLY, CREDENTIAL),
            encoding="ascii",
        )
        captured = []
        with (
            patch.object(cli, "_ACTIVE_PLAN", fixed_plan),
            patch.object(cli, "_ACTIVE_CATALOG", fixed_catalog),
            patch.object(cli, "_QUALIFICATION_CREDENTIAL", qualification_credential),
            patch.object(cli, "_OPERATION_TOKEN", operation_token),
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            patch.object(cli, "_read_operation_token", return_value="f" * 64),
            patch.object(
                cli,
                "_execute_stage",
                side_effect=lambda arguments, output, current_time_ns: (
                    captured.append((arguments, output, current_time_ns)) or 0
                ),
            ),
        ):
            result = cli.main(
                ["execute-approved-stage"],
                stdout=io.StringIO(),
                now_ns=lambda: NOW + 1,
            )
        self.assertEqual(result, 0)
        self.assertEqual(len(captured), 1)
        arguments, _output, timestamp = captured[0]
        self.assertEqual(arguments.catalog, fixed_catalog)
        self.assertEqual(arguments.plan, fixed_plan)
        self.assertEqual(arguments.operation, QualificationOperation.READ_ONLY.value)
        self.assertEqual(arguments.token, "f" * 64)
        self.assertEqual(arguments.credential, qualification_credential)
        self.assertEqual(timestamp, NOW + 1)


class QualificationReconcileCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.catalog_path = self.root / "catalog.sqlite3"
        source = self.root / "source"
        source.mkdir()
        with Catalog(self.catalog_path) as catalog:
            catalog.initialize()
            catalog.add_library("LIB1", "Library", str(source))
            catalog.create_automatic_job(
                "JOB1",
                "LIB1",
                "drive",
                "/synthetic/mount",
                [
                    ("PROT01", "SERIAL1", 0, 0),
                    ("PROT02", "SERIAL2", 0, 0),
                    ("PROT03", "SERIAL3", 0, 0),
                    (r"CURRENT/LABEL\EXACT", "CURRENT-SERIAL", 0, 0),
                ],
                force_format=True,
            )
        self.credential_path = self.root / "broker-credential"
        self.credential_path.write_bytes(CREDENTIAL)
        self.credential_path.chmod(0o400)

    def _plan(self, operation, *, run_id=RUN_ID, operations=None):
        return QualificationPlan(
            1,
            run_id,
            "JOB1",
            4,
            r"CURRENT/LABEL\EXACT",
            "CURRENT-SERIAL",
            "DRIVE-SERIAL",
            "0x5000000000000001",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            NOW,
            NOW + 1_000_000_000,
            (operation,) if operations is None else operations,
        )

    def test_terminal_reconciliation_validates_authorities_before_probe(self):
        from ltobackup.qualification import cli

        plan = self._plan(QualificationOperation.WIPE)
        settings = LinuxSettings(
            tape_device_path=Path("/dev/tape/by-id/current-nst"),
            scsi_device_path=Path("/dev/lto-archiver-scsi-current"),
        )
        device = {
            "nst_path": str(settings.tape_device_path),
            "sg_path": str(settings.scsi_device_path),
            "serial": plan.drive_serial,
            "wwid": plan.drive_wwid,
        }
        artifacts = {
            "schema": 2,
            "linux_tree_sha256": plan.linux_tree_sha256,
            "ltfs_tree_sha256": plan.ltfs_tree_sha256,
            "ltfs_rpm_sha256": plan.ltfs_rpm_sha256,
            "tool_sha256": TOOL_SHA256,
        }
        authority_reader = Mock(side_effect=(device, artifacts))
        provider = Mock()
        provider.resolve.side_effect = (
            StableDeviceIdentity("current-nst", plan.drive_serial, "same-unit"),
            StableDeviceIdentity("scsi-current", plan.drive_serial, "same-unit"),
        )
        snapshot = {
            "expected_volume_uuid": "22222222-2222-4222-8222-222222222222",
            "observed_media_identity_sha256": "6" * 64,
        }
        with (
            patch.object(cli, "load_linux_settings", return_value=settings),
            patch.object(cli, "_read_closed_json", authority_reader),
            patch.object(cli, "_run_ltfs_terminal_state") as terminal_probe,
            patch.object(cli, "SysfsDeviceIdentityProvider", return_value=provider),
        ):
            evidence = cli._prepare_reconciliation_environment(
                plan,
                QualificationOperation.WIPE,
                snapshot,
                self.catalog_path,
            )

        self.assertEqual(
            authority_reader.call_args_list[0].kwargs,
            {"expected_mode": 0o640, "expected_group": "lto-admin"},
        )
        self.assertEqual(
            authority_reader.call_args_list[1].kwargs,
            {"expected_mode": 0o400, "require_canonical": True},
        )
        terminal_probe.assert_called_once_with(
            TOOL_SHA256["ltfs-info"], QualificationOperation.WIPE
        )
        self.assertEqual(
            evidence.expected_media_scope_sha256,
            expected_media_scope_sha256(
                (
                    "qualification.wipe",
                    plan.job_id,
                    str(plan.cassette_sequence),
                    plan.physical_label,
                    "",
                    snapshot["expected_volume_uuid"],
                )
            ),
        )

    def _plan_path(self, plan):
        path = self.root / f"{plan.run_id}.json"
        path.write_bytes(plan.canonical_bytes())
        path.chmod(0o600)
        return path

    @staticmethod
    def _evidence(cli, plan, *, volume_uuid, generation, observed="6" * 64):
        return cli.QualificationEnvironmentEvidence(
            physical_label=plan.physical_label,
            tape_serial=plan.tape_serial,
            drive_serial=plan.drive_serial,
            drive_wwid=plan.drive_wwid,
            linux_tree_sha256=plan.linux_tree_sha256,
            ltfs_tree_sha256=plan.ltfs_tree_sha256,
            ltfs_rpm_sha256=plan.ltfs_rpm_sha256,
            tape_device_identity_sha256="3" * 64,
            scsi_device_identity_sha256="4" * 64,
            expected_media_scope_sha256="5" * 64,
            observed_media_identity_sha256=observed,
            volume_uuid=volume_uuid,
            generation=generation,
        )

    def _fenced_terminal(self, operation, *, run_id=RUN_ID, operations=None):
        plan = self._plan(operation, run_id=run_id, operations=operations)
        before_uuid = (
            None
            if operation is QualificationOperation.FORMAT
            else "22222222-2222-4222-8222-222222222222"
        )
        before_generation = None if before_uuid is None else 7
        request_sha256 = "d" * 64
        with Catalog(self.catalog_path) as catalog:
            catalog.create_ltfs_qualification_run(plan)
            catalog.record_ltfs_qualification_stage(
                run_id=plan.run_id,
                ordinal=1,
                operation=operation,
                request_sha256=request_sha256,
                dispatched=True,
                terminal_receipt_sha256=None,
                child_exit_code=None,
                before_volume_uuid=before_uuid,
                before_generation=before_generation,
                after_volume_uuid=None,
                after_generation=None,
                content_manifest_sha256=None,
                verdict="dispatch_started",
            )
            catalog.fence_ltfs_qualification_run(plan.run_id, "ambiguous_dispatch")
        broker_ordinal = (
            __import__(
                "ltobackup.qualification.cli", fromlist=["_EXECUTION_ORDER"]
            )._EXECUTION_ORDER.index(operation)
            + 1
        )
        snapshot = {
            "run_id": plan.run_id,
            "stage_ordinal": broker_ordinal,
            "state": "TERMINAL",
            "boot_id": "44444444-4444-4444-8444-444444444444",
            "request_sha256": request_sha256,
            "immutable_sha256": "1" * 64,
            "plan_sha256": plan.plan_sha256,
            "operation": operation.value,
            "operation_token_sha256": "2" * 64,
            "tape_device_identity_sha256": "3" * 64,
            "scsi_device_identity_sha256": "4" * 64,
            "expected_media_scope_sha256": "5" * 64,
            "observed_media_identity_sha256": "6" * 64,
            "expected_physical_label": plan.physical_label,
            "expected_tape_serial": plan.tape_serial,
            "expected_drive_serial": plan.drive_serial,
            "expected_drive_wwid": plan.drive_wwid,
            "expected_volume_uuid": before_uuid,
            "expected_generation": before_generation,
            "request_nonce": b"n" * 32,
            "created_at": "2026-08-23T00:00:00+00:00",
            "dispatched_at": "2026-08-23T00:00:01+00:00",
            "terminal_at": "2026-08-23T00:00:02+00:00",
        }
        child_exit_code = 1 if operation is QualificationOperation.WIPE else 0
        dispatch = BrokerQualificationDispatch(
            1,
            plan.run_id,
            broker_ordinal,
            operation,
            request_sha256,
            "terminal",
            "7" * 64,
            child_exit_code,
            "8" * 64,
            b"b" * 32,
            b"p" * 32,
        )
        inspection = BrokerQualificationInspection(
            "terminal", snapshot, dispatch, b"o" * 32, b"i" * 32
        )
        return plan, inspection, before_uuid, before_generation

    def test_reconcile_parser_has_only_three_absolute_path_inputs(self):
        from ltobackup.qualification import cli

        parsed = cli._parser().parse_args(
            [
                "reconcile-stage",
                "--catalog",
                str(self.catalog_path),
                "--plan",
                str(self.root / "plan.json"),
                "--credential",
                str(self.credential_path),
            ]
        )
        self.assertEqual(
            vars(parsed),
            {
                "action": "reconcile-stage",
                "catalog": self.catalog_path,
                "plan": self.root / "plan.json",
                "credential": self.credential_path,
            },
        )
        with patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
            cli._parser().parse_args(
                [
                    "reconcile-stage",
                    "--catalog",
                    str(self.catalog_path),
                    "--plan",
                    str(self.root / "plan.json"),
                    "--credential",
                    str(self.credential_path),
                    "--token",
                    "f" * 64,
                ]
            )

    def test_reconcile_requires_root_and_absolute_paths_before_broker_access(self):
        from ltobackup.qualification import cli

        broker = Mock(side_effect=AssertionError("broker reached"))
        cases = (
            (
                (1000, 1000),
                str(self.catalog_path),
                str(self.root / "p"),
                str(self.credential_path),
            ),
            ((0, 0), "catalog.db", str(self.root / "p"), str(self.credential_path)),
            ((0, 0), str(self.catalog_path), "plan.json", str(self.credential_path)),
            ((0, 0), str(self.catalog_path), str(self.root / "p"), "credential"),
        )
        for ids, catalog, plan, credential in cases:
            with (
                self.subTest(
                    ids=ids, catalog=catalog, plan=plan, credential=credential
                ),
                patch.object(cli, "_effective_ids", return_value=ids),
                patch.object(cli, "_connect_broker", broker),
            ):
                result = cli.main(
                    [
                        "reconcile-stage",
                        "--catalog",
                        catalog,
                        "--plan",
                        plan,
                        "--credential",
                        credential,
                    ],
                    stdout=io.StringIO(),
                    stderr=io.StringIO(),
                    now_ns=lambda: NOW + 1,
                )
            self.assertEqual(result, 2)
        broker.assert_not_called()

    def test_reconciliation_postcondition_oracle_covers_every_operation(self):
        from ltobackup.qualification import cli

        prior_uuid = "22222222-2222-4222-8222-222222222222"
        new_uuid = "33333333-3333-4333-8333-333333333333"
        for ordinal, operation in enumerate(SUPPORTED_OPERATIONS, 1):
            with self.subTest(operation=operation):
                plan, inspection, _before_uuid, _before_generation = (
                    self._fenced_terminal(
                        operation,
                        run_id=f"11111111-1111-4111-8111-{ordinal:012d}",
                    )
                )
                if operation is QualificationOperation.FORMAT:
                    evidence = self._evidence(
                        cli, plan, volume_uuid=new_uuid, generation=1, observed="9" * 64
                    )
                elif operation in {
                    QualificationOperation.WIPE,
                    QualificationOperation.UNLOAD,
                    QualificationOperation.EJECT,
                }:
                    evidence = self._evidence(
                        cli, plan, volume_uuid=None, generation=None
                    )
                else:
                    generation = (
                        8
                        if operation
                        in {
                            QualificationOperation.ADDITIVE_WRITE,
                            QualificationOperation.OVERWRITE,
                        }
                        else 7
                    )
                    evidence = self._evidence(
                        cli, plan, volume_uuid=prior_uuid, generation=generation
                    )
                cli._validate_reconciliation_postcondition(
                    operation, inspection.stage_snapshot, evidence
                )

        plan, inspection, _, _ = self._fenced_terminal(
            QualificationOperation.FORMAT,
            run_id="21111111-1111-4111-8111-111111111111",
        )
        invalid = (
            self._evidence(cli, plan, volume_uuid="not-a-uuid", generation=1),
            self._evidence(cli, plan, volume_uuid=None, generation=None),
            self._evidence(
                cli,
                plan,
                volume_uuid="33333333-3333-4333-8333-333333333333",
                generation=0,
            ),
        )
        for evidence in invalid:
            with self.assertRaises(ValueError):
                cli._validate_reconciliation_postcondition(
                    QualificationOperation.FORMAT,
                    inspection.stage_snapshot,
                    evidence,
                )

    def test_terminal_inspection_reconciles_once_without_execute_or_driver(self):
        from ltobackup.qualification import cli

        operation = QualificationOperation.ADDITIVE_WRITE
        plan, inspection, before_uuid, _ = self._fenced_terminal(operation)
        plan_path = self._plan_path(plan)
        evidence = self._evidence(cli, plan, volume_uuid=before_uuid, generation=8)
        broker = _InspectionBroker(inspection)
        output = io.StringIO()
        real_reconcile = Catalog.reconcile_ltfs_qualification_stage
        reconcile_calls = 0

        def reconcile_once(catalog, **kwargs):
            nonlocal reconcile_calls
            reconcile_calls += 1
            return real_reconcile(catalog, **kwargs)

        with (
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            patch.object(cli, "_connect_broker", return_value=broker),
            patch.object(
                cli, "_prepare_reconciliation_environment", return_value=evidence
            ) as prepare,
            patch.object(
                Catalog,
                "reconcile_ltfs_qualification_stage",
                new=reconcile_once,
            ),
            patch(
                "ltobackup.qualification.physical_driver.PhysicalLtfsQualificationDriver",
                side_effect=AssertionError("physical driver reached"),
            ),
        ):
            result = cli.main(
                [
                    "reconcile-stage",
                    "--catalog",
                    str(self.catalog_path),
                    "--plan",
                    str(plan_path),
                    "--credential",
                    str(self.credential_path),
                ],
                stdout=output,
                stderr=io.StringIO(),
                now_ns=lambda: NOW + 1,
            )
        self.assertEqual(result, 0)
        self.assertEqual(len(broker.inspections), 1)
        self.assertIsInstance(
            broker.inspections[0], BrokerQualificationInspectionRequest
        )
        self.assertEqual(reconcile_calls, 1)
        prepare.assert_called_once()
        self.assertEqual(
            output.getvalue(),
            '{"operation":"additive_write","reconciled":true,'
            f'"run_id":"{RUN_ID}","stage_ordinal":3}}\n',
        )
        with Catalog(self.catalog_path) as catalog:
            run = catalog.connection.execute(
                "SELECT status FROM ltfs_qualification_runs WHERE run_id=?",
                (plan.run_id,),
            ).fetchone()
            rows = catalog.connection.execute(
                "SELECT COUNT(*) FROM ltfs_qualification_reconciliations "
                "WHERE run_id=?",
                (plan.run_id,),
            ).fetchone()[0]
        self.assertEqual(run["status"], "completed")
        self.assertEqual(rows, 1)

    def test_response_loss_recovery_for_every_operation_uses_inspection_only(self):
        from ltobackup.qualification import cli

        prior_uuid = "22222222-2222-4222-8222-222222222222"
        new_uuid = "33333333-3333-4333-8333-333333333333"
        for ordinal, operation in enumerate(SUPPORTED_OPERATIONS, 1):
            with self.subTest(operation=operation):
                run_id = f"31111111-1111-4111-8111-{ordinal:012d}"
                plan, inspection, before_uuid, _ = self._fenced_terminal(
                    operation, run_id=run_id
                )
                plan_path = self._plan_path(plan)
                if operation is QualificationOperation.FORMAT:
                    self.assertEqual(plan.schema, 1)
                    self.assertIsNone(plan.expected_mam_medium_serial)
                    evidence = self._evidence(
                        cli,
                        plan,
                        volume_uuid=new_uuid,
                        generation=1,
                        observed="9" * 64,
                    )
                elif operation in {
                    QualificationOperation.WIPE,
                    QualificationOperation.UNLOAD,
                    QualificationOperation.EJECT,
                }:
                    evidence = self._evidence(
                        cli, plan, volume_uuid=None, generation=None
                    )
                else:
                    evidence = self._evidence(
                        cli,
                        plan,
                        volume_uuid=prior_uuid,
                        generation=(
                            8
                            if operation
                            in {
                                QualificationOperation.ADDITIVE_WRITE,
                                QualificationOperation.OVERWRITE,
                            }
                            else 7
                        ),
                    )
                self.assertEqual(
                    before_uuid, inspection.stage_snapshot["expected_volume_uuid"]
                )
                broker = _InspectionBroker(inspection)
                with (
                    patch.object(cli, "_effective_ids", return_value=(0, 0)),
                    patch.object(
                        QualificationPlan,
                        "authorize",
                        side_effect=AssertionError(
                            "historical reconciliation minted a new token"
                        ),
                    ),
                    patch.object(cli, "_connect_broker", return_value=broker),
                    patch.object(
                        cli,
                        "_prepare_reconciliation_environment",
                        return_value=evidence,
                    ),
                ):
                    result = cli.main(
                        [
                            "reconcile-stage",
                            "--catalog",
                            str(self.catalog_path),
                            "--plan",
                            str(plan_path),
                            "--credential",
                            str(self.credential_path),
                        ],
                        stdout=io.StringIO(),
                        stderr=io.StringIO(),
                        now_ns=lambda: NOW + 1,
                    )
                self.assertEqual(result, 0)
                self.assertEqual(len(broker.inspections), 1)

    def test_schema_two_format_response_loss_reconciles_without_reauthorization(self):
        from ltobackup.qualification import cli

        pinned = replace(
            self._plan(QualificationOperation.FORMAT),
            schema=2,
            expected_mam_medium_serial="V210531095",
        )
        with patch.object(self, "_plan", return_value=pinned):
            plan, inspection, _, _ = self._fenced_terminal(
                QualificationOperation.FORMAT
            )
        path = self._plan_path(plan)
        broker = _InspectionBroker(inspection)
        evidence = self._evidence(
            cli,
            plan,
            volume_uuid="33333333-3333-4333-8333-333333333333",
            generation=1,
            observed="9" * 64,
        )
        with (
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            patch.object(cli, "_connect_broker", return_value=broker),
            patch.object(
                cli, "_prepare_reconciliation_environment", return_value=evidence
            ),
            patch.object(
                QualificationPlan,
                "authorize",
                side_effect=AssertionError("new token minted"),
            ),
        ):
            result = cli.main(
                [
                    "reconcile-stage",
                    "--catalog",
                    str(self.catalog_path),
                    "--plan",
                    str(path),
                    "--credential",
                    str(self.credential_path),
                ],
                stdout=io.StringIO(),
                stderr=io.StringIO(),
                now_ns=lambda: NOW + 1,
            )
        self.assertEqual(result, 0)
        self.assertEqual(len(broker.inspections), 1)
        with Catalog(self.catalog_path) as catalog:
            row = catalog.connection.execute(
                "SELECT plan_json,plan_sha256,status FROM ltfs_qualification_runs WHERE run_id=?",
                (plan.run_id,),
            ).fetchone()
            self.assertEqual(row["plan_json"], plan.canonical_bytes().decode())
            self.assertEqual(row["plan_sha256"], plan.plan_sha256)
            self.assertEqual(row["status"], "completed")

    def test_reconciliation_oracle_rejects_identity_and_generation_substitution(self):
        from ltobackup.qualification import cli

        prior_uuid = "22222222-2222-4222-8222-222222222222"
        new_uuid = "33333333-3333-4333-8333-333333333333"
        cases = (
            (QualificationOperation.READ_ONLY, prior_uuid, 8),
            (QualificationOperation.LOAD, new_uuid, 7),
            (QualificationOperation.ADDITIVE_WRITE, prior_uuid, 7),
            (QualificationOperation.OVERWRITE, new_uuid, 8),
            (QualificationOperation.REPAIR, prior_uuid, 6),
            (QualificationOperation.WIPE, prior_uuid, 7),
            (QualificationOperation.UNLOAD, prior_uuid, 7),
            (QualificationOperation.EJECT, prior_uuid, 7),
        )
        for ordinal, (operation, volume_uuid, generation) in enumerate(cases, 1):
            with self.subTest(operation=operation):
                plan, inspection, _, _ = self._fenced_terminal(
                    operation,
                    run_id=f"41111111-1111-4111-8111-{ordinal:012d}",
                )
                evidence = self._evidence(
                    cli, plan, volume_uuid=volume_uuid, generation=generation
                )
                with self.assertRaises(ValueError):
                    cli._validate_reconciliation_postcondition(
                        operation, inspection.stage_snapshot, evidence
                    )

        plan, inspection, _, _ = self._fenced_terminal(
            QualificationOperation.READ_ONLY,
            run_id="51111111-1111-4111-8111-111111111111",
        )
        for field, value in (
            ("physical_label", "current/LABEL\\EXACT"),
            ("tape_serial", "current-serial"),
            ("drive_serial", "OTHER-DRIVE"),
            ("drive_wwid", "0x5000000000000002"),
            ("tape_device_identity_sha256", "0" * 64),
            ("scsi_device_identity_sha256", "1" * 64),
        ):
            with self.subTest(field=field):
                evidence = self._evidence(
                    cli, plan, volume_uuid=prior_uuid, generation=7
                )
                setattr(evidence, field, value)
                with self.assertRaises(ValueError):
                    cli._validate_reconciliation_postcondition(
                        QualificationOperation.READ_ONLY,
                        inspection.stage_snapshot,
                        evidence,
                    )

    def test_nonterminal_inspection_stays_fenced_without_media_or_catalog_write(self):
        from ltobackup.qualification import cli

        plan, terminal, _, _ = self._fenced_terminal(QualificationOperation.REPAIR)
        plan_path = self._plan_path(plan)
        nonterminal = BrokerQualificationInspection(
            "dispatched",
            {
                **terminal.stage_snapshot,
                "state": "DISPATCHED",
                "terminal_at": None,
            },
            None,
            b"o" * 32,
            b"i" * 32,
        )
        broker = _InspectionBroker(nonterminal)
        with (
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            patch.object(cli, "_connect_broker", return_value=broker),
            patch.object(
                cli,
                "_prepare_reconciliation_environment",
                side_effect=AssertionError("media probe reached"),
            ),
            patch.object(
                Catalog,
                "reconcile_ltfs_qualification_stage",
                side_effect=AssertionError("catalog reconciliation reached"),
            ),
        ):
            result = cli.main(
                [
                    "reconcile-stage",
                    "--catalog",
                    str(self.catalog_path),
                    "--plan",
                    str(plan_path),
                    "--credential",
                    str(self.credential_path),
                ],
                stdout=io.StringIO(),
                stderr=io.StringIO(),
                now_ns=lambda: NOW + 1,
            )
        self.assertEqual(result, 2)
        self.assertEqual(len(broker.inspections), 1)
        with Catalog(self.catalog_path) as catalog:
            self.assertEqual(
                catalog.connection.execute(
                    "SELECT status FROM ltfs_qualification_runs WHERE run_id=?",
                    (plan.run_id,),
                ).fetchone()[0],
                "fenced",
            )
            self.assertEqual(
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM ltfs_qualification_reconciliations"
                ).fetchone()[0],
                0,
            )

    def test_stale_plan_and_substituted_inspection_stay_fenced(self):
        from ltobackup.qualification import cli

        plan, inspection, before_uuid, _ = self._fenced_terminal(
            QualificationOperation.READ_ONLY
        )
        plan_path = self._plan_path(plan)
        broker = _InspectionBroker(inspection)
        with (
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            patch.object(cli, "_connect_broker", return_value=broker),
        ):
            stale = cli.main(
                [
                    "reconcile-stage",
                    "--catalog",
                    str(self.catalog_path),
                    "--plan",
                    str(plan_path),
                    "--credential",
                    str(self.credential_path),
                ],
                stdout=io.StringIO(),
                stderr=io.StringIO(),
                now_ns=lambda: plan.expires_at_ns,
            )
        self.assertEqual(stale, 2)
        self.assertEqual(broker.inspections, [])

        substituted = replace(
            inspection.dispatch,
            request_sha256="e" * 64,
        )
        substituted_snapshot = dict(inspection.stage_snapshot)
        substituted_snapshot["request_sha256"] = "e" * 64
        substituted_inspection = BrokerQualificationInspection(
            "terminal",
            substituted_snapshot,
            substituted,
            inspection.observation_nonce,
            inspection.proof,
        )
        broker = _InspectionBroker(substituted_inspection)
        with (
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            patch.object(cli, "_connect_broker", return_value=broker),
            patch.object(
                cli,
                "_prepare_reconciliation_environment",
                return_value=self._evidence(
                    cli, plan, volume_uuid=before_uuid, generation=7
                ),
            ),
        ):
            refused = cli.main(
                [
                    "reconcile-stage",
                    "--catalog",
                    str(self.catalog_path),
                    "--plan",
                    str(plan_path),
                    "--credential",
                    str(self.credential_path),
                ],
                stdout=io.StringIO(),
                stderr=io.StringIO(),
                now_ns=lambda: NOW + 1,
            )
        self.assertEqual(refused, 2)

    def test_hmac_failure_and_catalog_rollback_leave_original_fence(self):
        from ltobackup.qualification import cli

        plan, inspection, before_uuid, _ = self._fenced_terminal(
            QualificationOperation.REPAIR
        )
        plan_path = self._plan_path(plan)
        evidence = self._evidence(cli, plan, volume_uuid=before_uuid, generation=7)
        for failure in (
            BrokerUnavailable(),
            CatalogError("injected reconciliation rollback"),
        ):
            with self.subTest(failure=type(failure).__name__):
                broker = _InspectionBroker(inspection)
                connect = (
                    Mock(side_effect=failure)
                    if isinstance(failure, BrokerUnavailable)
                    else Mock(return_value=broker)
                )
                reconcile = (
                    Mock(
                        side_effect=AssertionError("catalog reached after HMAC failure")
                    )
                    if isinstance(failure, BrokerUnavailable)
                    else Mock(side_effect=failure)
                )
                with (
                    patch.object(cli, "_effective_ids", return_value=(0, 0)),
                    patch.object(cli, "_connect_broker", connect),
                    patch.object(
                        cli,
                        "_prepare_reconciliation_environment",
                        return_value=evidence,
                    ),
                    patch.object(
                        Catalog,
                        "reconcile_ltfs_qualification_stage",
                        reconcile,
                    ),
                ):
                    result = cli.main(
                        [
                            "reconcile-stage",
                            "--catalog",
                            str(self.catalog_path),
                            "--plan",
                            str(plan_path),
                            "--credential",
                            str(self.credential_path),
                        ],
                        stdout=io.StringIO(),
                        stderr=io.StringIO(),
                        now_ns=lambda: NOW + 1,
                    )
                self.assertEqual(result, 2)
                with Catalog(self.catalog_path) as catalog:
                    run = catalog.connection.execute(
                        "SELECT status,fence_reason FROM ltfs_qualification_runs "
                        "WHERE run_id=?",
                        (plan.run_id,),
                    ).fetchone()
                    self.assertEqual(tuple(run), ("fenced", "ambiguous_dispatch"))
                    self.assertEqual(
                        catalog.connection.execute(
                            "SELECT COUNT(*) FROM ltfs_qualification_reconciliations"
                        ).fetchone()[0],
                        0,
                    )

    def test_reconciled_nonfinal_stage_requires_fresh_next_operation_token(self):
        from ltobackup.qualification import cli

        operations = (
            QualificationOperation.READ_ONLY,
            QualificationOperation.FORMAT,
        )
        plan, inspection, before_uuid, _ = self._fenced_terminal(
            QualificationOperation.READ_ONLY, operations=operations
        )
        plan_path = self._plan_path(plan)
        broker = _InspectionBroker(inspection)
        evidence = self._evidence(cli, plan, volume_uuid=before_uuid, generation=7)
        output = io.StringIO()
        with (
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            patch.object(cli, "_connect_broker", return_value=broker),
            patch.object(
                cli, "_prepare_reconciliation_environment", return_value=evidence
            ),
        ):
            result = cli.main(
                [
                    "reconcile-stage",
                    "--catalog",
                    str(self.catalog_path),
                    "--plan",
                    str(plan_path),
                    "--credential",
                    str(self.credential_path),
                ],
                stdout=output,
                stderr=io.StringIO(),
                now_ns=lambda: NOW + 1,
            )
        self.assertEqual(result, 0)
        self.assertNotIn("token", output.getvalue())
        self.assertIs(
            cli._next_operation(plan, self.catalog_path), QualificationOperation.FORMAT
        )
        previous_token = plan.authorize(QualificationOperation.READ_ONLY, CREDENTIAL)
        with self.assertRaises(ValueError):
            plan.verify_token(
                QualificationOperation.FORMAT,
                previous_token,
                CREDENTIAL,
                now_ns=NOW + 1,
            )

    def test_plan_reader_rejects_changed_descriptor_snapshot(self):
        from ltobackup.qualification import cli

        plan = self._plan(QualificationOperation.READ_ONLY)
        path = self._plan_path(plan)
        real_fstat = os.fstat
        calls = 0

        def changed(descriptor):
            nonlocal calls
            status = real_fstat(descriptor)
            calls += 1
            if calls == 2:
                fields = list(status)
                fields[8] += 1
                return os.stat_result(fields)
            return status

        with (
            patch.object(cli.os, "fstat", side_effect=changed),
            self.assertRaisesRegex(ValueError, "plan file changed"),
        ):
            cli._read_plan(path)

    def test_plan_reader_rejects_owner_hardlink_and_symlink_substitution(self):
        from ltobackup.qualification import cli

        plan = self._plan(QualificationOperation.READ_ONLY)
        path = self._plan_path(plan)
        real_fstat = os.fstat

        def wrong_owner(descriptor):
            fields = list(real_fstat(descriptor))
            fields[4] += 1
            return os.stat_result(fields)

        with (
            patch.object(cli.os, "fstat", side_effect=wrong_owner),
            self.assertRaisesRegex(ValueError, "plan file is invalid"),
        ):
            cli._read_plan(path)

        hardlink = self.root / "plan-hardlink.json"
        os.link(path, hardlink)
        with self.assertRaisesRegex(ValueError, "plan file is invalid"):
            cli._read_plan(path)
        hardlink.unlink()

        symlink = self.root / "plan-symlink.json"
        symlink.symlink_to(path)
        with self.assertRaisesRegex(ValueError, "plan is unavailable"):
            cli._read_plan(symlink)

    def test_credential_and_catalog_are_regular_no_follow_pinned_files(self):
        from ltobackup.qualification import cli

        real_fstat = os.fstat

        def root_owned(descriptor):
            fields = list(real_fstat(descriptor))
            fields[4] = 0
            fields[5] = 0
            return os.stat_result(fields)

        with (
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            patch.object(cli.os, "fstat", side_effect=root_owned),
        ):
            self.assertEqual(
                cli._read_root_credential(self.credential_path), CREDENTIAL
            )

        self.credential_path.chmod(0o600)
        with (
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            patch.object(cli.os, "fstat", side_effect=root_owned),
            self.assertRaisesRegex(ValueError, "credential is unavailable"),
        ):
            cli._read_root_credential(self.credential_path)
        self.credential_path.chmod(0o400)

        credential_link = self.root / "credential-link"
        credential_link.symlink_to(self.credential_path)
        with (
            patch.object(cli, "_effective_ids", return_value=(0, 0)),
            self.assertRaisesRegex(ValueError, "credential is unavailable"),
        ):
            cli._read_root_credential(credential_link)

        catalog_link = self.root / "catalog-link.sqlite3"
        catalog_link.symlink_to(self.catalog_path)
        with (
            self.assertRaisesRegex(ValueError, "catalog is unavailable"),
            cli._open_pinned_catalog(catalog_link),
        ):
            self.fail("symlink catalog was opened")

        catalog_hardlink = self.root / "catalog-hardlink.sqlite3"
        os.link(self.catalog_path, catalog_hardlink)
        with (
            self.assertRaisesRegex(ValueError, "catalog file is invalid"),
            cli._open_pinned_catalog(self.catalog_path),
        ):
            self.fail("hard-linked catalog was opened")


if __name__ == "__main__":
    unittest.main()
