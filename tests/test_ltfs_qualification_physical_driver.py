import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ltobackup.broker.ltfs_session import LtfsPinningError, LtfsStandaloneReceiptRoot
from ltobackup.daemon.models import HardwareTargetBinding, media_identity_sha256
from ltobackup.linux_settings import LinuxSettings
from ltobackup.qualification.broker_models import BrokerQualificationExecution
from ltobackup.qualification.physical_driver import PhysicalLtfsQualificationDriver
from ltobackup.qualification.physical_runtime import (
    PhysicalLtfsStageCommands,
    SystemPhysicalLtfsQualificationRuntime,
    _load_tool_attestation,
    _SystemCommands,
)
from ltobackup.qualification.plan import QualificationOperation, QualificationRefused
from ltobackup.tape.command_supervisor import LtfsReadyReceipt, LtfsStandaloneReceipt
from ltobackup.tape.linux_ltfs import StableDeviceIdentity
from ltobackup.tape.models import MediaIdentity
from tests.test_broker_ltfs_qualification import request_model

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


class _Runtime:
    def __init__(self):
        self.calls = []

    def execute(self, operation, request):
        self.calls.append((operation, request))
        exit_code = 1 if operation is QualificationOperation.WIPE else 0
        return BrokerQualificationExecution(
            terminal_receipt_sha256=operation.value.encode().hex().ljust(64, "0"),
            child_exit_code=exit_code,
            evidence_sha256="e" * 64,
        )


class PhysicalLtfsQualificationDriverTests(unittest.TestCase):
    def test_every_operation_has_one_closed_runtime_entrypoint(self):
        runtime = _Runtime()
        driver = PhysicalLtfsQualificationDriver(runtime=runtime)
        for ordinal, operation in enumerate(SUPPORTED_OPERATIONS, 1):
            request = request_model(
                stage_ordinal=ordinal,
                operation=operation,
                request_nonce=bytes([ordinal]) * 32,
            )
            result = getattr(driver, operation.value)(request)
            self.assertIsInstance(result, BrokerQualificationExecution)
        self.assertEqual(
            [operation for operation, _request in runtime.calls],
            list(SUPPORTED_OPERATIONS),
        )

    def test_stage_workspace_is_uuid_derived_and_never_label_derived(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = PhysicalLtfsQualificationDriver.stage_workspace(
                root,
                request_model(
                    expected_physical_label=r"CURRENT/LABEL\EXACT",
                    expected_tape_serial="SERIAL/WITH\\SEPARATORS",
                ),
            )
        self.assertEqual(
            path,
            root / "11111111-1111-4111-8111-111111111111" / "0003-wipe",
        )
        self.assertNotIn("CURRENT", str(path))
        self.assertNotIn("SERIAL", str(path))

    def test_runtime_failure_is_returned_once_without_driver_retry(self):
        class FailingRuntime:
            def __init__(self):
                self.calls = 0

            def execute(self, operation, request):
                del operation, request
                self.calls += 1
                raise RuntimeError("ambiguous physical result")

        runtime = FailingRuntime()
        driver = PhysicalLtfsQualificationDriver(runtime=runtime)
        with self.assertRaises(RuntimeError):
            driver.format(request_model(operation=QualificationOperation.FORMAT))
        self.assertEqual(runtime.calls, 1)


class PhysicalLtfsStageCommandsTests(unittest.TestCase):
    def test_historical_long_wipe_is_rejected_before_command_construction(self):
        request = request_model(operation=QualificationOperation.WIPE)
        object.__setattr__(request, "operation", QualificationOperation.LONG_WIPE)
        with self.assertRaisesRegex(QualificationRefused, "unsupported"):
            PhysicalLtfsStageCommands().for_operation(
                QualificationOperation.LONG_WIPE, request
            )

    def test_all_supported_operations_have_fixed_closed_command_shapes(self):
        commands = PhysicalLtfsStageCommands()
        plans = {
            operation: commands.for_operation(
                operation, request_model(operation=operation)
            )
            for operation in SUPPORTED_OPERATIONS
        }
        request = request_model(operation=QualificationOperation.FORMAT)
        self.assertEqual(set(plans), set(SUPPORTED_OPERATIONS))
        self.assertEqual(
            plans[QualificationOperation.FORMAT][0],
            (
                "mkltfs",
                "--config",
                "/etc/ltfs.conf",
                "--device",
                "/dev/lto-archiver-scsi-configured",
                "--volume-name",
                request.expected_physical_label,
                "--no-compression",
                "--force",
                "--quiet",
            ),
        )
        self.assertIn("--wipe", plans[QualificationOperation.WIPE][0])
        self.assertEqual(
            plans[QualificationOperation.REPAIR],
            (
                (
                    "ltfsck",
                    "--config",
                    "/etc/ltfs.conf",
                    "/dev/lto-archiver-scsi-configured",
                ),
                (
                    "ltfsck",
                    "--config",
                    "/etc/ltfs.conf",
                    "--full-recovery",
                    "/dev/lto-archiver-scsi-configured",
                ),
            ),
        )
        self.assertIn("eject", plans[QualificationOperation.UNLOAD][0][-1])
        for operation in (
            QualificationOperation.READ_ONLY,
            QualificationOperation.ADDITIVE_WRITE,
            QualificationOperation.OVERWRITE,
            QualificationOperation.UNLOAD,
        ):
            self.assertIn("-f", plans[operation][0])
        self.assertEqual(
            plans[QualificationOperation.LOAD][0],
            ("mt", "-f", "/dev/tape/by-id/configured-nst", "load"),
        )
        self.assertEqual(
            plans[QualificationOperation.EJECT][0],
            ("mt", "-f", "/dev/tape/by-id/configured-nst", "eject"),
        )

    def test_mkltfs_ansi_barcode_uses_only_eligible_physical_label(self):
        commands = PhysicalLtfsStageCommands()
        current = request_model(
            operation=QualificationOperation.FORMAT,
            expected_physical_label="ZX91Q4",
            expected_tape_serial="MAM-VOLUME-SERIAL-DIFFERENT",
        )
        argv = commands.for_operation(QualificationOperation.FORMAT, current)[0]
        self.assertEqual("ZX91Q4", argv[argv.index("--tape-serial") + 1])
        self.assertNotIn(current.expected_tape_serial, argv)

        separator_label = request_model(
            operation=QualificationOperation.FORMAT,
            expected_physical_label=r"CURRENT/LABEL\EXACT",
        )
        argv = commands.for_operation(QualificationOperation.FORMAT, separator_label)[0]
        self.assertNotIn("--tape-serial", argv)

    def test_label_and_serial_are_values_never_path_components(self):
        request = request_model(
            expected_physical_label=r"CURRENT/LABEL\EXACT",
            expected_tape_serial=r"SERIAL/WITH\SEPARATORS",
        )
        commands = PhysicalLtfsStageCommands()
        for operation in SUPPORTED_OPERATIONS:
            with self.subTest(operation=operation):
                exact_request = replace(request, operation=operation)
                for argv in commands.for_operation(operation, exact_request):
                    self.assertNotIn(request.expected_physical_label, argv[0])
                    self.assertNotIn(request.expected_tape_serial, argv[0])
                    self.assertFalse(
                        any(
                            request.expected_physical_label in item
                            for item in argv
                            if item.startswith(("/var/", "/mnt/"))
                        )
                    )

    def test_system_tools_are_descriptor_pinned_and_closed(self):
        from ltobackup.qualification import physical_runtime

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool_paths = {}
            for name in (
                "ltfs",
                "mkltfs",
                "ltfsck",
                "ltfs-info",
                "fusermount",
                "mt",
            ):
                path = root / name
                path.write_text("#!/bin/sh\nexit 0\n")
                path.chmod(
                    0o4755
                    if name == "fusermount"
                    else 0o750
                    if name == "mkltfs"
                    else 0o755
                )
                tool_paths[name] = path
            real_fstat = os.fstat
            real_path_stat = Path.stat
            mkltfs_inode = real_path_stat(tool_paths["mkltfs"]).st_ino

            def root_owned(status):
                fields = list(status)
                fields[4] = 0
                fields[5] = 4242 if status.st_ino == mkltfs_inode else 0
                return type(status)(fields)

            def pinned_path_stat(path, *, follow_symlinks=True):
                return root_owned(real_path_stat(path, follow_symlinks=follow_symlinks))

            with (
                patch.object(physical_runtime, "_TOOL_PATHS", tool_paths),
                patch.object(
                    physical_runtime.os,
                    "fstat",
                    side_effect=lambda descriptor: root_owned(real_fstat(descriptor)),
                ),
                patch.object(Path, "stat", pinned_path_stat),
                patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=4242)),
            ):
                commands = _SystemCommands(
                    {
                        name: hashlib.sha256(path.read_bytes()).hexdigest()
                        for name, path in tool_paths.items()
                    }
                )
                descriptors = tuple(item[0] for item in commands._pins.values())
                with patch.object(
                    physical_runtime.subprocess,
                    "run",
                    return_value=SimpleNamespace(
                        returncode=0, stdout=b"{}", stderr=None
                    ),
                ) as run:
                    commands.run(("ltfs-info", "--json"), timeout=1.0)
                executed = run.call_args.args[0]
                self.assertRegex(executed[0], r"^/proc/self/fd/[0-9]+$")
                self.assertEqual(run.call_args.kwargs["pass_fds"], (descriptors[3],))

                child = SimpleNamespace()
                mount_command = PhysicalLtfsStageCommands().for_operation(
                    QualificationOperation.READ_ONLY,
                    request_model(operation=QualificationOperation.READ_ONLY),
                )[0]
                with patch.object(
                    physical_runtime.subprocess, "Popen", return_value=child
                ) as popen:
                    self.assertIs(commands.start(mount_command), child)
                self.assertEqual(child.ltfs_event_diagnostic(), "invalid")
                mount_argv = popen.call_args.args[0]
                self.assertRegex(mount_argv[0], r"^/proc/self/fd/[0-9]+$")
                self.assertEqual(mount_argv[1], "-f")
                self.assertRegex(mount_argv[2], r"^--event-fd=[0-9]+$")
                self.assertEqual(mount_argv[3], "--event-schema=1")
                self.assertEqual(
                    mount_argv[4],
                    "--operation-id=a081a350-376c-5f9a-a0a3-7d490a25a053",
                )
                self.assertEqual(mount_argv[5], "/mnt/lto-archiver/tape")
                event_descriptor = int(mount_argv[2].split("=", 1)[1])
                self.assertEqual(
                    popen.call_args.kwargs["pass_fds"],
                    (descriptors[0], event_descriptor),
                )
                self.assertIsNone(popen.call_args.kwargs["stderr"])
                with self.assertRaises(OSError):
                    real_fstat(event_descriptor)

                tool_paths["ltfs-info"].write_text("#!/bin/sh\nexit 100\n")
                with self.assertRaisesRegex(ValueError, "tool changed"):
                    commands.run(("ltfs-info", "--json"), timeout=1.0)
                commands.close()
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        real_fstat(descriptor)

    def test_event_stream_collector_is_bounded_closed_and_redacted(self):
        from ltobackup.qualification import physical_runtime

        collect = getattr(physical_runtime, "_collect_redacted_event_stream", None)
        self.assertIsNotNone(collect, "LTFS event collector is unavailable")
        operation_id = "a081a350-376c-5f9a-a0a3-7d490a25a053"
        valid = (
            json.dumps(
                {
                    "code": "device.identity.mismatch",
                    "detail": "SECRET-DRIVE-SERIAL-MUST-NOT-ESCAPE",
                    "operation_id": operation_id,
                    "schema": 1,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
        wrong_operation = valid.replace(
            operation_id.encode("ascii"),
            b"00000000-0000-4000-8000-000000000001",
        )
        unknown_code = valid.replace(
            b"device.identity.mismatch", b"private.secret.event.code"
        )
        wrong_schema = valid.replace(b'"schema":1', b'"schema":2')
        cases = (
            (valid, "device.identity.mismatch"),
            (b"{not-json}\n", "invalid"),
            (b"[" * 2_000 + b"0" + b"]" * 2_000 + b"\n", "invalid"),
            (b"x" * (64 * 1024 + 1), "invalid"),
            (wrong_operation, "invalid"),
            (wrong_schema, "invalid"),
            (unknown_code, "invalid"),
        )
        for payload, expected in cases:
            with self.subTest(expected=expected, size=len(payload)):
                with tempfile.TemporaryFile() as stream:
                    stream.write(payload)
                    stream.seek(0)
                    descriptor = os.dup(stream.fileno())
                    self.assertEqual(
                        collect(descriptor, expected_operation_id=operation_id),
                        expected,
                    )
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

    def test_system_tool_metadata_contract_rejects_role_substitution(self):
        from ltobackup.qualification import physical_runtime

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool_paths = {}
            for name in (
                "ltfs",
                "mkltfs",
                "ltfsck",
                "ltfs-info",
                "fusermount",
                "mt",
            ):
                path = root / name
                path.write_text("#!/bin/sh\nexit 0\n")
                path.chmod(
                    0o4755
                    if name == "fusermount"
                    else 0o750
                    if name == "mkltfs"
                    else 0o755
                )
                tool_paths[name] = path
            real_fstat = os.fstat
            real_path_stat = Path.stat
            name_by_inode = {
                real_path_stat(path).st_ino: name for name, path in tool_paths.items()
            }
            mutation = {}

            def packaged_status(status):
                fields = list(status)
                name = name_by_inode[status.st_ino]
                fields[4] = 0
                fields[5] = 4242 if name == "mkltfs" else 0
                if name == mutation.get("name"):
                    for field, index in (("mode", 0), ("nlink", 3), ("gid", 5)):
                        if field in mutation:
                            fields[index] = mutation[field]
                return type(status)(fields)

            def pinned_path_stat(path, *, follow_symlinks=True):
                return packaged_status(
                    real_path_stat(path, follow_symlinks=follow_symlinks)
                )

            expected = {
                name: hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in tool_paths.items()
            }
            cases = (
                {"name": "mkltfs", "gid": 0},
                {"name": "mkltfs", "mode": stat.S_IFREG | 0o755},
                {"name": "mkltfs", "mode": stat.S_IFREG | 0o770},
                {"name": "fusermount", "mode": stat.S_IFREG | 0o755},
                {"name": "ltfs", "gid": 4242},
                {"name": "ltfsck", "nlink": 2},
            )
            with (
                patch.object(physical_runtime, "_TOOL_PATHS", tool_paths),
                patch.object(
                    physical_runtime.os,
                    "fstat",
                    side_effect=lambda descriptor: packaged_status(
                        real_fstat(descriptor)
                    ),
                ),
                patch.object(Path, "stat", pinned_path_stat),
                patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=4242)),
            ):
                for case in cases:
                    with self.subTest(case=case):
                        mutation.clear()
                        mutation.update(case)
                        with self.assertRaisesRegex(ValueError, "tool is not trusted"):
                            _SystemCommands(expected)

    def test_artifact_attestation_is_canonical_closed_and_root_owned(self):
        from ltobackup.qualification import physical_runtime

        with tempfile.TemporaryDirectory() as temporary:
            authority = Path(temporary) / "qualification-artifacts.json"
            payload = {
                "linux_tree_sha256": "a" * 64,
                "ltfs_rpm_sha256": "b" * 64,
                "ltfs_tree_sha256": "c" * 64,
                "schema": 2,
                "tool_sha256": {
                    name: character * 64
                    for name, character in zip(
                        (
                            "fusermount",
                            "ltfs",
                            "ltfs-info",
                            "ltfsck",
                            "mkltfs",
                            "mt",
                        ),
                        "123456",
                        strict=True,
                    )
                },
            }
            canonical = (
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("ascii")
            authority.write_bytes(canonical)
            authority.chmod(0o400)
            real_fstat = os.fstat

            def root_owned_fstat(descriptor):
                status = real_fstat(descriptor)
                fields = list(status)
                fields[4] = 0
                fields[5] = 0
                return type(status)(fields)

            with (
                patch.object(physical_runtime, "_ARTIFACT_ATTESTATION", authority),
                patch.object(
                    physical_runtime.os, "fstat", side_effect=root_owned_fstat
                ),
            ):
                self.assertEqual(_load_tool_attestation(), payload["tool_sha256"])
                authority.chmod(0o600)
                authority.write_bytes(canonical.rstrip(b"\n"))
                authority.chmod(0o400)
                with self.assertRaisesRegex(ValueError, "authority is invalid"):
                    _load_tool_attestation()


class _Commands:
    def __init__(self, payload):
        self.payload = payload
        self.argv = []
        self.processes = []

    def run(self, argv, *, timeout):
        self.argv.append((argv, timeout))
        if argv[0] == "ltfs-info":
            import json

            payload = (
                self.payload.pop(0) if isinstance(self.payload, list) else self.payload
            )
            return SimpleNamespace(
                returncode=0,
                stdout=(json.dumps(payload, separators=(",", ":")) + "\n").encode(),
                stderr=b"",
            )
        return SimpleNamespace(
            returncode=(
                1
                if argv[0] == "mkltfs"
                and "--wipe" in argv
                else 0
            ),
            stdout=b"",
            stderr=b"",
        )

    def start(self, argv):
        self.argv.append((argv, None))
        process = SimpleNamespace(wait=lambda: 0)
        self.processes.append(process)
        return process


class _PostStateCommands(_Commands):
    def __init__(self, payload, *, terminal_probe_returncode):
        super().__init__(payload)
        self.terminal_probe_returncode = terminal_probe_returncode

    def run(self, argv, *, timeout):
        if argv[0] == "ltfs-info" and any(
            recorded[0][0] in {"mkltfs", "mt"}
            or (
                recorded[0][0] == "ltfs"
                and "-o" in recorded[0]
                and any("eject" in argument for argument in recorded[0])
            )
            for recorded in self.argv
        ):
            self.argv.append((argv, timeout))
            return SimpleNamespace(
                returncode=self.terminal_probe_returncode,
                stdout=b"",
                stderr=b"",
            )
        return super().run(argv, timeout=timeout)


class _NeverSignalCommands(_Commands):
    def __init__(self, payload):
        super().__init__(payload)
        self.terminate_calls = 0
        self.kill_calls = 0
        self.wait_started = threading.Event()
        self.wait_release = threading.Event()
        self.reaped = threading.Event()

    def start(self, argv):
        self.argv.append((argv, None))

        def wait():
            self.wait_started.set()
            self.wait_release.wait()
            self.reaped.set()
            return 0

        process = SimpleNamespace(
            wait=wait,
            terminate=lambda: setattr(
                self, "terminate_calls", self.terminate_calls + 1
            ),
            kill=lambda: setattr(self, "kill_calls", self.kill_calls + 1),
        )
        self.processes.append(process)
        return process


class _ExitedBeforeReadyCommands(_Commands):
    def __init__(self, payload):
        super().__init__(payload)
        self.poll_calls = 0
        self.wait_calls = 0
        self.reaped = threading.Event()
        self.child_pid = -1

    def start(self, argv):
        self.argv.append((argv, None))
        process = subprocess.Popen(
            (sys.executable, "-c", "raise SystemExit(74)"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.child_pid = process.pid
        wait_process = process.wait

        def poll():
            self.poll_calls += 1
            return None

        def wait():
            self.wait_calls += 1
            result = wait_process()
            self.reaped.set()
            return result

        process.poll = poll
        process.wait = wait
        self.processes.append(process)
        return process


class _ExitedWithEventDiagnosticCommands(_Commands):
    def start(self, argv):
        self.argv.append((argv, None))
        process = SimpleNamespace(
            wait=lambda: 74,
            ltfs_event_diagnostic=lambda: "device.identity.mismatch",
        )
        self.processes.append(process)
        return process


class _PendingThenExitedCommands(_Commands):
    def __init__(self, payload):
        super().__init__(payload)
        self.child_pid = -1
        self.release_writer = -1
        self.reaped = threading.Event()
        self.wait_arguments = []

    def start(self, argv):
        self.argv.append((argv, None))
        reader, self.release_writer = os.pipe()
        process = subprocess.Popen(
            (
                sys.executable,
                "-c",
                "import os,sys; os.read(int(sys.argv[1]), 1)",
                str(reader),
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            pass_fds=(reader,),
        )
        os.close(reader)
        self.child_pid = process.pid
        wait_process = process.wait

        def wait(*args, **kwargs):
            self.wait_arguments.append((args, kwargs))
            result = wait_process(*args, **kwargs)
            self.reaped.set()
            return result

        process.wait = wait
        self.processes.append(process)
        return process

    def release(self):
        os.write(self.release_writer, b"x")
        os.close(self.release_writer)
        self.release_writer = -1


class _UnmountFailureCommands(_Commands):
    def __init__(
        self,
        payload,
        *,
        unmount_returncode=0,
        unmount_error=None,
        wait_returncode=0,
        wait_error=None,
    ):
        super().__init__(payload)
        self.unmount_returncode = unmount_returncode
        self.unmount_error = unmount_error
        self.wait_returncode = wait_returncode
        self.wait_error = wait_error
        self.wait_calls = 0

    def run(self, argv, *, timeout):
        if argv[0] == "fusermount":
            self.argv.append((argv, timeout))
            if self.unmount_error is not None:
                raise self.unmount_error
            return SimpleNamespace(
                returncode=self.unmount_returncode,
                stdout=b"",
                stderr=b"",
            )
        return super().run(argv, timeout=timeout)

    def start(self, argv):
        self.argv.append((argv, None))

        def wait():
            self.wait_calls += 1
            if self.wait_error is not None:
                raise self.wait_error
            return self.wait_returncode

        process = SimpleNamespace(wait=wait)
        self.processes.append(process)
        return process


class SystemPhysicalLtfsQualificationRuntimeTests(unittest.TestCase):
    def test_device_authority_requires_exact_root_lto_admin_0640(self):
        from ltobackup.qualification import physical_runtime

        with tempfile.TemporaryDirectory() as temporary:
            authority = Path(temporary) / "device.json"
            authority.write_text(
                '{"nst_path":"/dev/nst0","serial":"DRIVE",'
                '"sg_path":"/dev/sg0","wwid":"0x5000"}\n',
                encoding="ascii",
            )
            real_fstat = os.fstat
            metadata = {"uid": 0, "gid": 4242, "mode": 0o640}

            def trusted_fstat(descriptor):
                status = real_fstat(descriptor)
                fields = list(status)
                fields[0] = stat.S_IFREG | metadata["mode"]
                fields[4] = metadata["uid"]
                fields[5] = metadata["gid"]
                return type(status)(fields)

            runtime = object.__new__(SystemPhysicalLtfsQualificationRuntime)
            with (
                patch.object(physical_runtime, "_DEVICE_CONFIG", authority),
                patch.object(physical_runtime.os, "fstat", side_effect=trusted_fstat),
                patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=4242)),
            ):
                self.assertEqual(runtime._device_authority()["serial"], "DRIVE")
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
                            QualificationRefused, "device authority is invalid"
                        ):
                            runtime._device_authority()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.receipts = self.root / "receipts"
        self.mount = self.root / "mount"
        for directory in (self.workspace, self.receipts, self.mount):
            directory.mkdir(mode=0o700)
        self.settings = LinuxSettings(
            state_dir=self.root / "state",
            socket_path=self.root / "daemon.sock",
            tape_device_path=Path("/dev/tape/by-id/configured-nst"),
            scsi_device_path=Path("/dev/lto-archiver-scsi-configured"),
            mount_path=self.mount,
        )
        self.tape = StableDeviceIdentity("configured-nst", "DRIVE-SERIAL", "unit")
        self.scsi = StableDeviceIdentity("scsi-configured", "DRIVE-SERIAL", "unit")
        self.payload = {
            "schema": 2,
            "media_state": "ltfs",
            "tape_by_id": str(self.settings.tape_device_path),
            "scsi_by_id": str(self.settings.scsi_device_path),
            "drive_serial": "DRIVE-SERIAL",
            "mam_barcode": r"CURRENT/LABEL\EXACT",
            "mam_volume_serial": "CURRENT-SERIAL",
            "ltfs_volume_label": r"CURRENT/LABEL\EXACT",
            "ltfs_volume_uuid": "22222222-2222-4222-8222-222222222222",
            "index_generation": 7,
        }
        with (
            patch(
                "ltobackup.broker.ltfs_session._fstat",
                side_effect=self._root_status_from_fd,
            ),
            patch(
                "ltobackup.broker.ltfs_session._stat_path",
                side_effect=self._root_status_from_path,
            ),
        ):
            self.receipt_root = LtfsStandaloneReceiptRoot.open(self.receipts)
        self.addCleanup(self.receipt_root.close)

    @staticmethod
    def _root_status(status):
        fields = list(status)
        fields[4] = 0
        fields[5] = 0
        return type(status)(fields)

    def _root_status_from_fd(self, descriptor):
        import os

        return self._root_status(os.fstat(descriptor))

    def _root_status_from_path(self, path):
        return self._root_status(Path(path).stat(follow_symlinks=False))

    def _request(self, operation, ordinal):
        binding = HardwareTargetBinding.from_verified_inputs(
            self.mount,
            self.tape.canonical_json(),
            self.scsi.canonical_json(),
            ("qualification", "qualification", "1", "label", "serial", ""),
        )
        observed = MediaIdentity(
            drive_serial=self.payload["drive_serial"],
            mam_barcode=self.payload["mam_barcode"],
            mam_volume_serial=self.payload["mam_volume_serial"],
            ltfs_volume_label=self.payload["ltfs_volume_label"],
            ltfs_volume_uuid=self.payload["ltfs_volume_uuid"],
        )
        return request_model(
            operation=operation,
            stage_ordinal=ordinal,
            request_nonce=bytes([ordinal]) * 32,
            tape_device_identity_sha256=binding.tape_device_identity_sha256,
            scsi_device_identity_sha256=binding.scsi_device_identity_sha256,
            observed_media_identity_sha256=media_identity_sha256(
                observed.canonical_fields()
            ),
        )

    def _runtime(self, commands):
        provider = SimpleNamespace(
            resolve=lambda path: (
                self.tape if path == self.settings.tape_device_path else self.scsi
            )
        )
        with patch.object(self.receipt_root, "_assert_anchor", return_value=None):
            runtime = SystemPhysicalLtfsQualificationRuntime(
                settings=self.settings,
                receipt_root=self.receipt_root,
                workspace_root=self.workspace,
                commands=commands,
                device_provider=provider,
            )
        runtime._device_authority = lambda: {
            "nst_path": str(self.settings.tape_device_path),
            "sg_path": str(self.settings.scsi_device_path),
            "serial": "DRIVE-SERIAL",
            "wwid": "0x5000000000000001",
        }
        return runtime

    def test_ltfs_tools_use_scsi_path_while_mt_keeps_nst_path(self):
        runtime = self._runtime(_Commands(self.payload))

        read_only = self._request(QualificationOperation.READ_ONLY, 1)
        mount_argv = runtime._grammar.for_operation(
            QualificationOperation.READ_ONLY, read_only
        )[0]
        mount_options = mount_argv[mount_argv.index("-o") + 1].split(",")
        self.assertIn(
            f"devname={self.settings.scsi_device_path}", mount_options
        )
        self.assertNotIn(
            f"devname={self.settings.tape_device_path}", mount_options
        )

        for ordinal, operation in enumerate(
            (
                QualificationOperation.FORMAT,
                QualificationOperation.WIPE,
            ),
            2,
        ):
            with self.subTest(operation=operation):
                mkltfs_argv = runtime._grammar.for_operation(
                    operation, self._request(operation, ordinal)
                )[0]
                self.assertEqual(
                    str(self.settings.scsi_device_path),
                    mkltfs_argv[mkltfs_argv.index("--device") + 1],
                )

        repair_request = self._request(QualificationOperation.REPAIR, 5)
        repair_argv = runtime._grammar.for_operation(
            QualificationOperation.REPAIR, repair_request
        )
        self.assertTrue(
            all(argv[-1] == str(self.settings.scsi_device_path) for argv in repair_argv)
        )

        for ordinal, operation in enumerate(
            (QualificationOperation.LOAD, QualificationOperation.EJECT), 6
        ):
            with self.subTest(operation=operation):
                motion_argv = runtime._grammar.for_operation(
                    operation, self._request(operation, ordinal)
                )[0]
                self.assertEqual(str(self.settings.tape_device_path), motion_argv[2])

    def test_command_only_destructive_stages_execute_once_and_persist_evidence(self):
        for ordinal, operation in enumerate(
            (
                QualificationOperation.FORMAT,
                QualificationOperation.REPAIR,
                QualificationOperation.WIPE,
            ),
            1,
        ):
            with self.subTest(operation=operation):
                post_format = dict(self.payload)
                post_format["ltfs_volume_uuid"] = "33333333-3333-4333-8333-333333333333"
                post_format["index_generation"] = 1
                commands = (
                    _PostStateCommands(self.payload, terminal_probe_returncode=5)
                    if operation is QualificationOperation.WIPE
                    else _Commands(
                        [self.payload, post_format]
                        if operation is QualificationOperation.FORMAT
                        else self.payload
                    )
                )
                request = self._request(operation, ordinal)
                result = self._runtime(commands).execute(operation, request)
                self.assertIsInstance(result, BrokerQualificationExecution)
                if operation is QualificationOperation.FORMAT:
                    self.assertEqual(
                        ("ltfs-info", "--json", "--mode", "pre-format"),
                        commands.argv[0][0],
                    )
                dispatched = [
                    argv for argv, _timeout in commands.argv if argv[0] != "ltfs-info"
                ]
                self.assertEqual(
                    len(dispatched),
                    2 if operation is QualificationOperation.REPAIR else 1,
                )
                evidence = (
                    self.workspace
                    / request.run_id
                    / f"{ordinal:04d}-{operation.value}"
                    / "evidence.json"
                )
                self.assertTrue(evidence.is_file())

    def test_manifest_records_bounded_selinux_and_user_xattrs(self):
        target = Path("/synthetic")
        values = {
            "security.selinux": b"system_u:object_r:lto_archiver_mount_t:s0\0",
            "user.lto_qualification": b"proof",
        }
        with (
            patch.object(os, "listxattr", return_value=list(values)),
            patch.object(
                os, "getxattr", side_effect=lambda _path, name, **_kw: values[name]
            ),
        ):
            records = SystemPhysicalLtfsQualificationRuntime._xattrs(target)
        self.assertEqual(
            [record["name"] for record in records],
            ["security.selinux", "user.lto_qualification"],
        )
        with (
            patch.object(os, "listxattr", return_value=["user.bad\nname"]),
            self.assertRaisesRegex(ValueError, "xattr is unsupported"),
        ):
            SystemPhysicalLtfsQualificationRuntime._xattrs(target)

    def test_wipe_requires_exact_unformatted_post_probe(self):
        operation = QualificationOperation.WIPE
        request = self._request(operation, 40)
        commands = _PostStateCommands(self.payload, terminal_probe_returncode=5)
        result = self._runtime(commands).execute(operation, request)
        self.assertEqual(result.child_exit_code, 1)
        self.assertEqual(
            [argv[0] for argv, _timeout in commands.argv],
            ["ltfs-info", "mkltfs", "ltfs-info"],
        )

        wrong = _PostStateCommands(self.payload, terminal_probe_returncode=0)
        with self.assertRaisesRegex(ValueError, "remains formatted"):
            self._runtime(wrong).execute(
                operation, self._request(operation, 60)
            )

    def test_eject_requires_exact_no_media_post_probe(self):
        request = self._request(QualificationOperation.EJECT, 50)
        commands = _PostStateCommands(self.payload, terminal_probe_returncode=3)
        result = self._runtime(commands).execute(QualificationOperation.EJECT, request)
        self.assertEqual(result.child_exit_code, 0)
        self.assertEqual(
            [argv[0] for argv, _timeout in commands.argv],
            ["ltfs-info", "mt", "ltfs-info"],
        )

        read_failure = _PostStateCommands(self.payload, terminal_probe_returncode=7)
        with self.assertRaisesRegex(ValueError, "eject state is ambiguous"):
            self._runtime(read_failure).execute(
                QualificationOperation.EJECT,
                self._request(QualificationOperation.EJECT, 51),
            )

    def test_wipe_zero_exit_and_repair_unknown_exit_are_not_success(self):
        class ExitCommands(_Commands):
            def __init__(self, payload, *, command_returncode, check_returncode=0):
                super().__init__(payload)
                self.command_returncode = command_returncode
                self.check_returncode = check_returncode

            def run(self, argv, *, timeout):
                if argv[0] in {"mkltfs", "ltfsck"}:
                    self.argv.append((argv, timeout))
                    return SimpleNamespace(
                        returncode=(
                            self.check_returncode
                            if argv[0] == "ltfsck" and "--full-recovery" not in argv
                            else self.command_returncode
                        ),
                        stdout=b"",
                        stderr=b"",
                    )
                return super().run(argv, timeout=timeout)

        zero_wipe = ExitCommands(self.payload, command_returncode=0)
        with self.assertRaisesRegex(ValueError, "command failed"):
            self._runtime(zero_wipe).execute(
                QualificationOperation.WIPE,
                self._request(QualificationOperation.WIPE, 52),
            )
        self.assertEqual(
            [argv[0] for argv, _timeout in zero_wipe.argv], ["ltfs-info", "mkltfs"]
        )

        corrected = ExitCommands(
            self.payload,
            command_returncode=1,
            check_returncode=1,
        )
        repaired = self._runtime(corrected).execute(
            QualificationOperation.REPAIR,
            self._request(QualificationOperation.REPAIR, 53),
        )
        self.assertEqual(repaired.child_exit_code, 1)

        failed_check = ExitCommands(
            self.payload,
            command_returncode=0,
            check_returncode=2,
        )
        with self.assertRaisesRegex(ValueError, "read-only check failed"):
            self._runtime(failed_check).execute(
                QualificationOperation.REPAIR,
                self._request(QualificationOperation.REPAIR, 54),
            )
        self.assertEqual(
            [argv for argv, _timeout in failed_check.argv if argv[0] == "ltfsck"],
            [
                (
                    "ltfsck",
                    "--config",
                    "/etc/ltfs.conf",
                    "/dev/lto-archiver-scsi-configured",
                )
            ],
        )

        unknown = ExitCommands(self.payload, command_returncode=2)
        with self.assertRaisesRegex(ValueError, "command failed"):
            self._runtime(unknown).execute(
                QualificationOperation.REPAIR,
                self._request(QualificationOperation.REPAIR, 55),
            )

    def test_failed_fixed_commands_emit_only_allowlisted_tool_phase_and_exit(self):
        class FailingCommands(_Commands):
            def __init__(self, payload, *, failed_tool, returncode):
                super().__init__(payload)
                self.failed_tool = failed_tool
                self.returncode = returncode

            def run(self, argv, *, timeout):
                if argv[0] == self.failed_tool:
                    self.argv.append((argv, timeout))
                    return SimpleNamespace(
                        returncode=self.returncode,
                        stdout=b"SECRET-PROBE-PAYLOAD",
                        stderr=b"SECRET-TOOL-ERROR",
                    )
                return super().run(argv, timeout=timeout)

        cases = (
            (QualificationOperation.FORMAT, "ltfs-info", 17, "pre_format_probe"),
            (QualificationOperation.FORMAT, "mkltfs", 18, "format_command"),
            (QualificationOperation.REPAIR, "ltfsck", 19, "repair_precheck"),
        )
        for ordinal, (operation, tool, returncode, phase) in enumerate(cases, 60):
            with self.subTest(tool=tool, phase=phase):
                diagnostics = io.StringIO()
                with (
                    patch("sys.stderr", diagnostics),
                    self.assertRaises(QualificationRefused),
                ):
                    self._runtime(
                        FailingCommands(
                            self.payload,
                            failed_tool=tool,
                            returncode=returncode,
                        )
                    ).execute(operation, self._request(operation, ordinal))
                self.assertEqual(
                    diagnostics.getvalue(),
                    f"LTFS command failed: tool={tool} phase={phase} "
                    f"exit={returncode} reason=exit_status\n",
                )
                self.assertNotIn("SECRET", diagnostics.getvalue())
                self.assertNotIn(
                    self.payload["ltfs_volume_label"], diagnostics.getvalue()
                )

    def test_rc0_probe_rejections_emit_only_closed_redacted_diagnostics(self):
        class ProbeCommands(_Commands):
            def __init__(self, payload, *, probe_stdout, terminal=False):
                super().__init__(payload)
                self.probe_stdout = probe_stdout
                self.terminal = terminal
                self.probe_calls = 0

            def run(self, argv, *, timeout):
                if argv[0] == "ltfs-info":
                    self.probe_calls += 1
                    if not self.terminal or self.probe_calls > 1:
                        self.argv.append((argv, timeout))
                        return SimpleNamespace(
                            returncode=3 if self.terminal else 0,
                            stdout=self.probe_stdout,
                            stderr=b"SECRET-TOOL-ERROR",
                        )
                return super().run(argv, timeout=timeout)

        schema_invalid = dict(self.payload)
        schema_invalid["schema"] = 1
        identity_mismatch = dict(self.payload)
        identity_mismatch["drive_serial"] = "SECRET-OTHER-DRIVE"
        cases = (
            (b"x" * 4097, "output_oversized"),
            (b"SECRET-NOT-JSON", "output_malformed"),
            (
                (json.dumps(schema_invalid, separators=(",", ":")) + "\n").encode(),
                "schema_invalid",
            ),
            (
                (json.dumps(identity_mismatch, separators=(",", ":")) + "\n").encode(),
                "identity_mismatch",
            ),
        )
        for ordinal, (probe_stdout, reason) in enumerate(cases, 70):
            with self.subTest(reason=reason):
                diagnostics = io.StringIO()
                with (
                    patch("sys.stderr", diagnostics),
                    self.assertRaises(QualificationRefused),
                ):
                    self._runtime(
                        ProbeCommands(self.payload, probe_stdout=probe_stdout)
                    ).execute(
                        QualificationOperation.FORMAT,
                        self._request(QualificationOperation.FORMAT, ordinal),
                    )
                self.assertEqual(
                    diagnostics.getvalue(),
                    "LTFS command failed: tool=ltfs-info "
                    f"phase=pre_format_probe exit=0 reason={reason}\n",
                )
                self.assertNotIn("SECRET", diagnostics.getvalue())

        diagnostics = io.StringIO()
        with (
            patch("sys.stderr", diagnostics),
            self.assertRaises(QualificationRefused),
        ):
            self._runtime(
                ProbeCommands(
                    self.payload,
                    probe_stdout=b"SECRET-UNEXPECTED-TERMINAL-OUTPUT",
                    terminal=True,
                )
            ).execute(
                QualificationOperation.EJECT,
                self._request(QualificationOperation.EJECT, 74),
            )
        self.assertEqual(
            diagnostics.getvalue(),
            "LTFS command failed: tool=ltfs-info "
            "phase=eject_terminal_probe exit=3 reason=output_unexpected\n",
        )
        self.assertNotIn("SECRET", diagnostics.getvalue())

    def test_virgin_format_rebinds_only_after_exact_post_format_labels(self):
        blank = dict(self.payload)
        blank["media_state"] = "unidentified"
        blank["mam_barcode"] = None
        blank["ltfs_volume_label"] = None
        blank["ltfs_volume_uuid"] = None
        blank["index_generation"] = None
        observed = MediaIdentity(
            drive_serial=blank["drive_serial"],
            mam_barcode=blank["mam_barcode"],
            mam_volume_serial=blank["mam_volume_serial"],
            ltfs_volume_label=None,
            ltfs_volume_uuid=None,
        )
        request = replace(
            self._request(QualificationOperation.FORMAT, 8),
            expected_volume_uuid=None,
            expected_generation=None,
            observed_media_identity_sha256=media_identity_sha256(
                observed.canonical_fields()
            ),
        )
        commands = _Commands([blank, self.payload])
        result = self._runtime(commands).execute(QualificationOperation.FORMAT, request)
        self.assertEqual(result.child_exit_code, 0)
        self.assertEqual(
            [argv[0] for argv, _timeout in commands.argv],
            ["ltfs-info", "mkltfs", "ltfs-info"],
        )

    def test_format_rejects_preprobe_mam_change_before_dispatch(self):
        prior = dict(self.payload)
        prior["media_state"] = "unidentified"
        prior["mam_barcode"] = None
        prior["ltfs_volume_label"] = None
        prior["ltfs_volume_uuid"] = None
        prior["index_generation"] = None
        observed = MediaIdentity(
            drive_serial=prior["drive_serial"],
            mam_barcode=prior["mam_barcode"],
            mam_volume_serial=prior["mam_volume_serial"],
            ltfs_volume_label=prior["ltfs_volume_label"],
            ltfs_volume_uuid=prior["ltfs_volume_uuid"],
        )
        request = replace(
            self._request(QualificationOperation.FORMAT, 56),
            expected_volume_uuid=None,
            expected_generation=None,
            observed_media_identity_sha256=media_identity_sha256(
                observed.canonical_fields()
            ),
        )
        changed = dict(prior)
        changed["mam_volume_serial"] = "OTHER-PHYSICAL-MAM-SERIAL"
        commands = _Commands(changed)

        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            self._runtime(commands).execute(QualificationOperation.FORMAT, request)

        self.assertEqual(
            [argv[0] for argv, _timeout in commands.argv],
            ["ltfs-info"],
        )

    def test_format_rejects_wrong_approved_mam_even_with_matching_latest_observation(
        self,
    ):
        request = self._request(QualificationOperation.FORMAT, 57)
        changed = dict(self.payload, mam_volume_serial="SUBSTITUTED-MAM")
        observed = MediaIdentity(
            drive_serial=changed["drive_serial"],
            mam_barcode=changed["mam_barcode"],
            mam_volume_serial=changed["mam_volume_serial"],
            ltfs_volume_label=changed["ltfs_volume_label"],
            ltfs_volume_uuid=changed["ltfs_volume_uuid"],
        )
        request = replace(
            request,
            observed_media_identity_sha256=media_identity_sha256(
                observed.canonical_fields()
            ),
        )
        commands = _Commands(changed)
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            self._runtime(commands).execute(QualificationOperation.FORMAT, request)
        self.assertEqual([argv[0] for argv, _timeout in commands.argv], ["ltfs-info"])
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_labeled_unidentified_format_binds_observed_barcode_and_succeeds(self):
        prior = dict(self.payload)
        prior["media_state"] = "unidentified"
        prior["ltfs_volume_label"] = None
        prior["ltfs_volume_uuid"] = None
        prior["index_generation"] = None
        observed = MediaIdentity(
            drive_serial=prior["drive_serial"],
            mam_barcode=prior["mam_barcode"],
            mam_volume_serial=prior["mam_volume_serial"],
            ltfs_volume_label=None,
            ltfs_volume_uuid=None,
        )
        request = replace(
            self._request(QualificationOperation.FORMAT, 57),
            expected_volume_uuid=None,
            expected_generation=None,
            observed_media_identity_sha256=media_identity_sha256(
                observed.canonical_fields()
            ),
        )
        post = dict(self.payload)
        post["ltfs_volume_uuid"] = "33333333-3333-4333-8333-333333333333"
        post["index_generation"] = 1
        commands = _Commands([prior, post])

        result = self._runtime(commands).execute(
            QualificationOperation.FORMAT, request
        )

        self.assertEqual(result.child_exit_code, 0)
        self.assertEqual(
            [argv[0] for argv, _timeout in commands.argv],
            ["ltfs-info", "mkltfs", "ltfs-info"],
        )

    def test_unidentified_format_rejects_wrong_barcode_before_dispatch(self):
        prior = dict(self.payload)
        prior["media_state"] = "unidentified"
        prior["mam_barcode"] = "OTHER-LABEL"
        prior["ltfs_volume_label"] = None
        prior["ltfs_volume_uuid"] = None
        prior["index_generation"] = None
        observed = MediaIdentity(
            drive_serial=prior["drive_serial"],
            mam_barcode=prior["mam_barcode"],
            mam_volume_serial=prior["mam_volume_serial"],
            ltfs_volume_label=None,
            ltfs_volume_uuid=None,
        )
        request = replace(
            self._request(QualificationOperation.FORMAT, 58),
            expected_volume_uuid=None,
            expected_generation=None,
            observed_media_identity_sha256=media_identity_sha256(
                observed.canonical_fields()
            ),
        )
        commands = _Commands(prior)

        with self.assertRaises(ValueError):
            self._runtime(commands).execute(QualificationOperation.FORMAT, request)

        self.assertEqual(
            [argv[0] for argv, _timeout in commands.argv],
            ["ltfs-info"],
        )

    def test_format_rejects_incomplete_or_changed_post_format_identity(self):
        prior = dict(self.payload)
        prior["media_state"] = "unidentified"
        prior["mam_barcode"] = None
        prior["ltfs_volume_label"] = None
        prior["ltfs_volume_uuid"] = None
        prior["index_generation"] = None
        observed = MediaIdentity(
            drive_serial=prior["drive_serial"],
            mam_barcode=None,
            mam_volume_serial=prior["mam_volume_serial"],
            ltfs_volume_label=None,
            ltfs_volume_uuid=None,
        )
        post = dict(self.payload)
        post["ltfs_volume_uuid"] = "33333333-3333-4333-8333-333333333333"
        post["index_generation"] = 1
        mutations = (
            ("mam_barcode", None),
            ("mam_barcode", "OTHER-LABEL"),
            ("ltfs_volume_label", None),
            ("ltfs_volume_label", "OTHER-LABEL"),
            ("mam_volume_serial", None),
            ("mam_volume_serial", "OTHER-PHYSICAL-MAM-SERIAL"),
            ("ltfs_volume_uuid", None),
            ("ltfs_volume_uuid", "not-a-uuid"),
            ("index_generation", None),
            ("index_generation", 0),
        )
        for offset, (field, value) in enumerate(mutations):
            with self.subTest(field=field, value=value):
                request = replace(
                    self._request(QualificationOperation.FORMAT, 60 + offset),
                    expected_volume_uuid=None,
                    expected_generation=None,
                    observed_media_identity_sha256=media_identity_sha256(
                        observed.canonical_fields()
                    ),
                )
                changed = dict(post)
                changed[field] = value
                commands = _Commands([dict(prior), changed])
                with self.assertRaises(ValueError):
                    self._runtime(commands).execute(
                        QualificationOperation.FORMAT, request
                    )
                self.assertEqual(
                    [argv[0] for argv, _timeout in commands.argv],
                    ["ltfs-info", "mkltfs", "ltfs-info"],
                )

    def test_unidentified_state_is_rejected_before_non_format_dispatch_except_load(
        self,
    ):
        unidentified = dict(self.payload)
        unidentified["media_state"] = "unidentified"
        unidentified["mam_barcode"] = None
        unidentified["ltfs_volume_label"] = None
        unidentified["ltfs_volume_uuid"] = None
        unidentified["index_generation"] = None
        for ordinal, operation in enumerate(
            (
                candidate
                for candidate in SUPPORTED_OPERATIONS
                if candidate
                not in {QualificationOperation.FORMAT, QualificationOperation.LOAD}
            ),
            80,
        ):
            with self.subTest(operation=operation):
                commands = _Commands(unidentified)
                runtime = self._runtime(commands)
                with self.assertRaises(ValueError):
                    runtime.execute(operation, self._request(operation, ordinal))
                self.assertEqual(
                    [argv[0] for argv, _timeout in commands.argv],
                    ["ltfs-info"],
                )

    def test_load_unidentified_postprobe_fences_after_only_mechanical_load(self):
        unidentified = dict(self.payload)
        unidentified["media_state"] = "unidentified"
        unidentified["mam_barcode"] = None
        unidentified["ltfs_volume_label"] = None
        unidentified["ltfs_volume_uuid"] = None
        unidentified["index_generation"] = None
        # LOAD is the one mechanical transition whose media cannot be probed
        # until after the load command.  Exactly that command may cross the
        # boundary before unidentified post-load evidence fences the stage.
        request = self._request(QualificationOperation.LOAD, 90)
        load_commands = _Commands(unidentified)
        load_runtime = self._runtime(load_commands)
        with self.assertRaises(ValueError):
            load_runtime.execute(
                QualificationOperation.LOAD,
                request,
            )
        self.assertEqual(
            [argv[0] for argv, _timeout in load_commands.argv],
            ["mt", "ltfs-info"],
        )
        self.assertFalse(
            (
                self.workspace
                / request.run_id
                / "0090-load"
                / "evidence.json"
            ).exists()
        )

    def test_existing_format_rejects_unchanged_volume_uuid(self):
        request = self._request(QualificationOperation.FORMAT, 55)
        commands = _Commands([self.payload, self.payload])
        with self.assertRaisesRegex(ValueError, "did not replace UUID"):
            self._runtime(commands).execute(QualificationOperation.FORMAT, request)
        self.assertEqual(
            [argv[0] for argv, _timeout in commands.argv],
            ["ltfs-info", "mkltfs", "ltfs-info"],
        )

    def test_every_identity_substitution_is_rejected_before_destructive_dispatch(self):
        base = self._request(QualificationOperation.WIPE, 9)
        mutations = (
            ("payload", "schema", 1),
            ("payload", "media_state", "blank"),
            ("payload", "mam_barcode", "OTHER-LABEL"),
            ("payload", "mam_volume_serial", "OTHER-SERIAL"),
            ("payload", "drive_serial", "OTHER-DRIVE"),
            ("authority", "wwid", "0x5000000000000002"),
            ("request", "tape_device_identity_sha256", "0" * 64),
            ("request", "scsi_device_identity_sha256", "1" * 64),
            ("request", "observed_media_identity_sha256", "2" * 64),
        )
        for scope, field, value in mutations:
            with self.subTest(scope=scope, field=field):
                payload = dict(self.payload)
                authority = {
                    "nst_path": str(self.settings.tape_device_path),
                    "sg_path": str(self.settings.scsi_device_path),
                    "serial": "DRIVE-SERIAL",
                    "wwid": "0x5000000000000001",
                }
                request = base
                if scope == "payload":
                    payload[field] = value
                elif scope == "authority":
                    authority[field] = value
                else:
                    request = replace(request, **{field: value})
                commands = _Commands(payload)
                runtime = self._runtime(commands)
                runtime._device_authority = lambda authority=authority: authority
                with self.assertRaises(ValueError):
                    runtime.execute(QualificationOperation.WIPE, request)
                self.assertEqual(
                    [argv[0] for argv, _timeout in commands.argv], ["ltfs-info"]
                )

    def test_load_and_eject_are_distinct_token_bound_motion_stages(self):
        load_request = self._request(QualificationOperation.LOAD, 17)
        load_commands = _Commands(self.payload)
        load_result = self._runtime(load_commands).execute(
            QualificationOperation.LOAD, load_request
        )
        self.assertEqual(load_result.child_exit_code, 0)
        self.assertEqual(
            [argv[0] for argv, _timeout in load_commands.argv], ["mt", "ltfs-info"]
        )
        self.assertEqual(load_commands.argv[0][0][-1], "load")

        eject_request = self._request(QualificationOperation.EJECT, 18)
        eject_commands = _PostStateCommands(self.payload, terminal_probe_returncode=3)
        eject_result = self._runtime(eject_commands).execute(
            QualificationOperation.EJECT, eject_request
        )
        self.assertEqual(eject_result.child_exit_code, 0)
        self.assertEqual(
            [argv[0] for argv, _timeout in eject_commands.argv],
            ["ltfs-info", "mt", "ltfs-info"],
        )
        self.assertEqual(eject_commands.argv[-2][0][-1], "eject")

    def test_mounted_read_write_overwrite_and_eject_have_terminal_receipts(self):
        ready = LtfsReadyReceipt(
            1,
            "ready",
            "11111111-1111-4111-8111-111111111111",
            self.payload["ltfs_volume_uuid"],
            self.payload["index_generation"],
            False,
            self.payload["drive_serial"],
            self.payload["mam_barcode"],
            self.payload["mam_volume_serial"],
            self.payload["ltfs_volume_label"],
        )
        terminal = LtfsStandaloneReceipt(
            1,
            "terminal",
            ready.operation_id,
            ready.volume_uuid,
            7,
            8,
            True,
            1,
            True,
            1,
            (0,) * 11,
            0,
            0,
            True,
            0,
            0,
            True,
            True,
            False,
            0,
            "9" * 64,
        )
        operations = (
            QualificationOperation.ADDITIVE_WRITE,
            QualificationOperation.OVERWRITE,
            QualificationOperation.READ_ONLY,
            QualificationOperation.UNLOAD,
        )
        for ordinal, operation in enumerate(operations, 10):
            with self.subTest(operation=operation):
                commands = (
                    _PostStateCommands(self.payload, terminal_probe_returncode=3)
                    if operation is QualificationOperation.UNLOAD
                    else _Commands(self.payload)
                )
                request = self._request(operation, ordinal)
                runtime = self._runtime(commands)
                operation_id = runtime._grammar._operation_id(request, phase="primary")
                primary_ready = replace(
                    ready,
                    operation_id=operation_id,
                    read_only=operation
                    in {
                        QualificationOperation.READ_ONLY,
                        QualificationOperation.UNLOAD,
                    },
                )
                primary_terminal = replace(
                    terminal,
                    operation_id=operation_id,
                    new_generation=(
                        8
                        if operation
                        in {
                            QualificationOperation.ADDITIVE_WRITE,
                            QualificationOperation.OVERWRITE,
                        }
                        else 7
                    ),
                    terminal_sha256="8" * 64,
                )
                ready_receipts = [primary_ready]
                terminal_receipts = [primary_terminal]
                if operation in {
                    QualificationOperation.ADDITIVE_WRITE,
                    QualificationOperation.OVERWRITE,
                }:
                    verify_operation_id = runtime._grammar._operation_id(
                        request, phase="verify"
                    )
                    ready_receipts.append(
                        replace(
                            ready,
                            operation_id=verify_operation_id,
                            prior_generation=8,
                            read_only=True,
                        )
                    )
                    terminal_receipts.append(
                        replace(
                            terminal,
                            operation_id=verify_operation_id,
                            prior_generation=8,
                            new_generation=8,
                            terminal_sha256="9" * 64,
                        )
                    )
                else:
                    terminal_receipts[0] = replace(
                        terminal_receipts[0], terminal_sha256="9" * 64
                    )
                with (
                    patch.object(
                        self.receipt_root,
                        "_assert_anchor",
                        return_value=None,
                    ),
                    patch.object(
                        self.receipt_root,
                        "wait_ready",
                        side_effect=ready_receipts,
                    ),
                    patch.object(
                        self.receipt_root,
                        "read_terminal",
                        side_effect=terminal_receipts,
                    ),
                ):
                    result = runtime.execute(operation, request)
                self.assertEqual(result.terminal_receipt_sha256, "9" * 64)
                self.assertEqual(
                    len(commands.processes),
                    2
                    if operation
                    in {
                        QualificationOperation.ADDITIVE_WRITE,
                        QualificationOperation.OVERWRITE,
                    }
                    else 1,
                )
                owned = self.mount / ".lto-qualification" / request.run_id
                if operation is QualificationOperation.ADDITIVE_WRITE:
                    self.assertEqual(
                        os.getxattr(owned / "qualified.bin", "user.lto_qualification"),
                        request.request_sha256.encode("ascii"),
                    )
                    self.assertEqual(
                        (owned / "sparse.bin").stat().st_size,
                        1024 * 1024 + len(b"SPARSE-END"),
                    )
                    self.assertEqual(
                        (owned / "directory" / "nested.bin").read_bytes(),
                        b"nested-content",
                    )
                    self.assertFalse((owned / "delete.bin").exists())

    def test_mounted_ready_receipt_requires_preprobe_mam_not_catalog_serial(self):
        request = self._request(QualificationOperation.READ_ONLY, 14)
        commands = _Commands(self.payload)
        runtime = self._runtime(commands)
        operation_id = runtime._grammar._operation_id(request, phase="primary")
        substituted = LtfsReadyReceipt(
            1,
            "ready",
            operation_id,
            self.payload["ltfs_volume_uuid"],
            self.payload["index_generation"],
            True,
            self.payload["drive_serial"],
            self.payload["mam_barcode"],
            request.expected_tape_serial,
            self.payload["ltfs_volume_label"],
        )
        self.assertNotEqual(
            request.expected_tape_serial,
            self.payload["mam_volume_serial"],
        )
        diagnostics = io.StringIO()
        with (
            patch.object(self.receipt_root, "_assert_anchor", return_value=None),
            patch.object(
                self.receipt_root,
                "wait_ready",
                return_value=substituted,
            ),
            patch("sys.stderr", diagnostics),
            self.assertRaisesRegex(ValueError, "mounted identity mismatch"),
        ):
            runtime.execute(QualificationOperation.READ_ONLY, request)
        self.assertEqual(
            [argv[0] for argv, _timeout in commands.argv],
            ["ltfs-info", "ltfs", "fusermount"],
        )
        self.assertEqual(
            diagnostics.getvalue(),
            "LTFS mount cycle failed: phase=mounted_identity\n",
        )

    def test_finalization_timeout_is_fenced_without_signalling_the_child(self):
        request = self._request(QualificationOperation.READ_ONLY, 15)
        commands = _NeverSignalCommands(self.payload)
        runtime = self._runtime(commands)
        operation_id = runtime._grammar._operation_id(request, phase="primary")
        ready = LtfsReadyReceipt(
            1,
            "ready",
            operation_id,
            self.payload["ltfs_volume_uuid"],
            self.payload["index_generation"],
            True,
            self.payload["drive_serial"],
            self.payload["mam_barcode"],
            self.payload["mam_volume_serial"],
            self.payload["ltfs_volume_label"],
        )
        with (
            patch.object(self.receipt_root, "_assert_anchor", return_value=None),
            patch.object(self.receipt_root, "wait_ready", return_value=ready),
            patch(
                "ltobackup.qualification.physical_runtime._TERMINAL_TIMEOUT",
                0.05,
            ),
            self.assertRaisesRegex(ValueError, "finalization remains ambiguous"),
        ):
            runtime.execute(QualificationOperation.READ_ONLY, request)
        self.assertTrue(commands.wait_started.is_set())
        self.assertEqual(commands.terminate_calls, 0)
        self.assertEqual(commands.kill_calls, 0)
        self.assertFalse(
            (
                self.workspace / request.run_id / "0015-read_only" / "evidence.json"
            ).exists()
        )
        commands.wait_release.set()
        self.assertTrue(commands.reaped.wait(1.0))

    def test_real_child_exit_is_reaped_by_waiter_without_polling_or_receipt_timeout(
        self,
    ):
        request = self._request(QualificationOperation.READ_ONLY, 25)
        commands = _ExitedBeforeReadyCommands(self.payload)
        runtime = self._runtime(commands)
        wait_ready = self.receipt_root.wait_ready

        def bounded_wait_ready(**kwargs):
            kwargs["timeout"] = 1.0
            return wait_ready(**kwargs)

        with (
            patch.object(self.receipt_root, "_assert_anchor", return_value=None),
            patch.object(
                self.receipt_root,
                "wait_ready",
                side_effect=bounded_wait_ready,
            ),
            self.assertRaisesRegex(ValueError, "finalization failed"),
        ):
            runtime.execute(QualificationOperation.READ_ONLY, request)
        self.assertEqual(commands.poll_calls, 0)
        self.assertEqual(commands.wait_calls, 1)
        self.assertTrue(commands.reaped.is_set())
        with self.assertRaises(ChildProcessError):
            os.waitpid(commands.child_pid, os.WNOHANG)
        self.assertEqual(
            [argv[0] for argv, _timeout in commands.argv],
            ["ltfs-info", "ltfs", "fusermount"],
        )

    def test_pending_real_child_is_naturally_reaped_by_blocking_waiter(self):
        request = self._request(QualificationOperation.READ_ONLY, 27)
        commands = _PendingThenExitedCommands(self.payload)
        runtime = self._runtime(commands)
        wait_ready = self.receipt_root.wait_ready

        def release_pending_child(**kwargs):
            self.assertEqual(os.waitpid(commands.child_pid, os.WNOHANG), (0, 0))
            commands.release()
            kwargs["timeout"] = 1.0
            return wait_ready(**kwargs)

        with (
            patch.object(self.receipt_root, "_assert_anchor", return_value=None),
            patch.object(
                self.receipt_root,
                "wait_ready",
                side_effect=release_pending_child,
            ),
            self.assertRaises(LtfsPinningError),
        ):
            runtime.execute(QualificationOperation.READ_ONLY, request)
        self.assertEqual(commands.wait_arguments, [((), {})])
        self.assertTrue(commands.reaped.is_set())
        with self.assertRaises(ChildProcessError):
            os.waitpid(commands.child_pid, os.WNOHANG)

    def test_child_exit_before_ready_reports_only_redacted_event_without_retry(self):
        request = self._request(QualificationOperation.READ_ONLY, 26)
        commands = _ExitedWithEventDiagnosticCommands(self.payload)
        runtime = self._runtime(commands)
        diagnostics = io.StringIO()
        with (
            patch.object(self.receipt_root, "_assert_anchor", return_value=None),
            patch("sys.stderr", diagnostics),
            self.assertRaisesRegex(ValueError, "finalization failed"),
        ):
            runtime.execute(QualificationOperation.READ_ONLY, request)
        self.assertEqual(
            diagnostics.getvalue(),
            "LTFS mount cycle failed: phase=ready_receipt\n"
            "LTFS mount child failed: event=device.identity.mismatch exit=74\n",
        )
        self.assertNotIn("SECRET", diagnostics.getvalue())
        self.assertEqual(len(commands.processes), 1)
        self.assertEqual(
            [argv[0] for argv, _timeout in commands.argv],
            ["ltfs-info", "ltfs", "fusermount"],
        )

    def test_unmount_nonzero_still_waits_for_started_process(self):
        request = self._request(QualificationOperation.READ_ONLY, 22)
        commands = _UnmountFailureCommands(self.payload, unmount_returncode=1)
        runtime = self._runtime(commands)
        operation_id = runtime._grammar._operation_id(request, phase="primary")
        ready = LtfsReadyReceipt(
            1,
            "ready",
            operation_id,
            self.payload["ltfs_volume_uuid"],
            self.payload["index_generation"],
            True,
            self.payload["drive_serial"],
            self.payload["mam_barcode"],
            self.payload["mam_volume_serial"],
            self.payload["ltfs_volume_label"],
        )
        with (
            patch.object(self.receipt_root, "_assert_anchor", return_value=None),
            patch.object(self.receipt_root, "wait_ready", return_value=ready),
            self.assertRaisesRegex(ValueError, "physical LTFS unmount failed"),
        ):
            runtime.execute(QualificationOperation.READ_ONLY, request)
        self.assertEqual(commands.wait_calls, 1)

    def test_unmount_exception_still_waits_for_started_process(self):
        request = self._request(QualificationOperation.READ_ONLY, 23)
        commands = _UnmountFailureCommands(
            self.payload,
            unmount_error=QualificationRefused(
                "physical LTFS command is unavailable"
            ),
        )
        runtime = self._runtime(commands)
        operation_id = runtime._grammar._operation_id(request, phase="primary")
        ready = LtfsReadyReceipt(
            1,
            "ready",
            operation_id,
            self.payload["ltfs_volume_uuid"],
            self.payload["index_generation"],
            True,
            self.payload["drive_serial"],
            self.payload["mam_barcode"],
            self.payload["mam_volume_serial"],
            self.payload["ltfs_volume_label"],
        )
        with (
            patch.object(self.receipt_root, "_assert_anchor", return_value=None),
            patch.object(self.receipt_root, "wait_ready", return_value=ready),
            self.assertRaisesRegex(ValueError, "physical LTFS command is unavailable"),
        ):
            runtime.execute(QualificationOperation.READ_ONLY, request)
        self.assertEqual(commands.wait_calls, 1)

    def test_unmount_failure_does_not_mask_ambiguous_child_finalization(self):
        request = self._request(QualificationOperation.READ_ONLY, 24)
        commands = _UnmountFailureCommands(
            self.payload,
            unmount_returncode=1,
            wait_error=subprocess.TimeoutExpired(("ltfs",), 86_400.0),
        )
        runtime = self._runtime(commands)
        operation_id = runtime._grammar._operation_id(request, phase="primary")
        ready = LtfsReadyReceipt(
            1,
            "ready",
            operation_id,
            self.payload["ltfs_volume_uuid"],
            self.payload["index_generation"],
            True,
            self.payload["drive_serial"],
            self.payload["mam_barcode"],
            self.payload["mam_volume_serial"],
            self.payload["ltfs_volume_label"],
        )
        with (
            patch.object(self.receipt_root, "_assert_anchor", return_value=None),
            patch.object(self.receipt_root, "wait_ready", return_value=ready),
            self.assertRaisesRegex(ValueError, "finalization remains ambiguous"),
        ):
            runtime.execute(QualificationOperation.READ_ONLY, request)
        self.assertEqual(commands.wait_calls, 1)

    def test_content_oserror_is_redacted_and_mount_is_finalized(self):
        request = self._request(QualificationOperation.ADDITIVE_WRITE, 19)
        commands = _Commands(self.payload)
        runtime = self._runtime(commands)
        operation_id = runtime._grammar._operation_id(request, phase="primary")
        ready = LtfsReadyReceipt(
            1,
            "ready",
            operation_id,
            self.payload["ltfs_volume_uuid"],
            self.payload["index_generation"],
            False,
            self.payload["drive_serial"],
            self.payload["mam_barcode"],
            self.payload["mam_volume_serial"],
            self.payload["ltfs_volume_label"],
        )
        diagnostics = io.StringIO()
        with (
            patch.object(self.receipt_root, "_assert_anchor", return_value=None),
            patch.object(self.receipt_root, "wait_ready", return_value=ready),
            patch.object(
                runtime,
                "_content_action",
                side_effect=PermissionError(13, "private detail", "/private/path"),
            ),
            patch("sys.stderr", diagnostics),
            self.assertRaisesRegex(ValueError, "content action failed"),
        ):
            runtime.execute(QualificationOperation.ADDITIVE_WRITE, request)
        self.assertEqual(
            [argv[0] for argv, _timeout in commands.argv],
            ["ltfs-info", "ltfs", "fusermount"],
        )
        self.assertEqual(diagnostics.getvalue(), "LTFS content action failed: errno=13\n")
        self.assertNotIn("private", diagnostics.getvalue())

    def test_content_refusal_also_finalizes_mount_before_propagation(self):
        request = self._request(QualificationOperation.READ_ONLY, 20)
        commands = _Commands(self.payload)
        runtime = self._runtime(commands)
        operation_id = runtime._grammar._operation_id(request, phase="primary")
        ready = LtfsReadyReceipt(
            1,
            "ready",
            operation_id,
            self.payload["ltfs_volume_uuid"],
            self.payload["index_generation"],
            True,
            self.payload["drive_serial"],
            self.payload["mam_barcode"],
            self.payload["mam_volume_serial"],
            self.payload["ltfs_volume_label"],
        )
        with (
            patch.object(self.receipt_root, "_assert_anchor", return_value=None),
            patch.object(self.receipt_root, "wait_ready", return_value=ready),
            patch.object(
                runtime,
                "_content_action",
                side_effect=QualificationRefused("content proof is invalid"),
            ),
            self.assertRaisesRegex(ValueError, "content proof is invalid"),
        ):
            runtime.execute(QualificationOperation.READ_ONLY, request)
        self.assertEqual(
            [argv[0] for argv, _timeout in commands.argv],
            ["ltfs-info", "ltfs", "fusermount"],
        )

    def test_ready_receipt_refusal_finalizes_mount_and_reports_phase(self):
        request = self._request(QualificationOperation.READ_ONLY, 21)
        commands = _Commands(self.payload)
        runtime = self._runtime(commands)
        diagnostics = io.StringIO()
        with (
            patch.object(self.receipt_root, "_assert_anchor", return_value=None),
            patch.object(
                self.receipt_root,
                "wait_ready",
                side_effect=QualificationRefused("ready receipt rejected"),
            ),
            patch("sys.stderr", diagnostics),
            self.assertRaisesRegex(ValueError, "ready receipt rejected"),
        ):
            runtime.execute(QualificationOperation.READ_ONLY, request)
        self.assertEqual(
            [argv[0] for argv, _timeout in commands.argv],
            ["ltfs-info", "ltfs", "fusermount"],
        )
        self.assertEqual(
            diagnostics.getvalue(),
            "LTFS mount cycle failed: phase=ready_receipt\n",
        )

    def test_write_stage_rejects_independent_read_only_readback_mismatch(self):
        request = self._request(QualificationOperation.ADDITIVE_WRITE, 16)
        commands = _Commands(self.payload)
        runtime = self._runtime(commands)
        primary_id = runtime._grammar._operation_id(request, phase="primary")
        verify_id = runtime._grammar._operation_id(request, phase="verify")
        ready = LtfsReadyReceipt(
            1,
            "ready",
            primary_id,
            self.payload["ltfs_volume_uuid"],
            7,
            False,
            self.payload["drive_serial"],
            self.payload["mam_barcode"],
            self.payload["mam_volume_serial"],
            self.payload["ltfs_volume_label"],
        )
        terminal = LtfsStandaloneReceipt(
            1,
            "terminal",
            primary_id,
            self.payload["ltfs_volume_uuid"],
            7,
            8,
            True,
            1,
            True,
            1,
            (0,) * 11,
            0,
            0,
            True,
            0,
            0,
            True,
            True,
            False,
            0,
            "8" * 64,
        )
        with (
            patch.object(self.receipt_root, "_assert_anchor", return_value=None),
            patch.object(
                self.receipt_root,
                "wait_ready",
                side_effect=(
                    ready,
                    replace(
                        ready,
                        operation_id=verify_id,
                        prior_generation=8,
                        read_only=True,
                    ),
                ),
            ),
            patch.object(
                self.receipt_root,
                "read_terminal",
                side_effect=(
                    terminal,
                    replace(
                        terminal,
                        operation_id=verify_id,
                        prior_generation=8,
                        new_generation=8,
                        terminal_sha256="9" * 64,
                    ),
                ),
            ),
            patch.object(
                runtime,
                "_content_action",
                side_effect=("a" * 64, "b" * 64),
            ),
            self.assertRaisesRegex(ValueError, "readback digest mismatch"),
        ):
            runtime.execute(QualificationOperation.ADDITIVE_WRITE, request)
        self.assertEqual(len(commands.processes), 2)
        self.assertFalse(
            (
                self.workspace
                / request.run_id
                / "0016-additive_write"
                / "evidence.json"
            ).exists()
        )


if __name__ == "__main__":
    unittest.main()
