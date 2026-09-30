from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict, replace
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging" / "scripts" / "deploy-rhel9.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("deploy_rhel9", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load deployment runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FakeDeploymentHost:
    def __init__(self, module, root: Path) -> None:
        self.module = module
        self.root = root
        self.root_user = True
        self.artifacts_verified = True
        self.artifact_source_commit = "a" * 40
        self.app_signed = True
        self.runtime_signed = True
        self.driver_verified = True
        self.admission = module.AdmissionObservation(
            daemon_idle=True,
            daemon_reconciled=True,
            broker_idle=True,
            qualification_idle=True,
            no_ltfs_process=True,
            no_tape_mount=True,
            no_unmanaged_share_mount=True,
            no_failed_unit=True,
            no_priority_error=True,
            web_tls_firewall_ok=True,
        )
        self.rollback_ready = True
        self.remaining_capacity = True
        self.tls_verified = True
        self.custom_hash = "c" * 64
        self.driver_unchanged = True
        self.live_ok = True
        self.rollback_status = "restored"
        self.rollback_raises = False
        self.fail_at: str | None = None
        self.calls: list[str] = []
        self.masks_kept = False
        self.source_validations = [True, True]
        self.resume_ok = True
        self.prepared_backup = self.root / "prepared-source-v35.sqlite3"
        self.artifact_lease_active = False

    def is_root(self) -> bool:
        return self.root_user

    def verify_release_artifacts(self, request):
        self.calls.append("verify-artifacts")
        if self.fail_at == "verify-artifacts":
            raise RuntimeError("injected")
        return self.module.ArtifactEvidence(
            verified=self.artifacts_verified,
            source_commit=self.artifact_source_commit,
            application_rpm_sha256=_sha(request.application_rpm),
            runtime_rpm_sha256=_sha(request.runtime_rpm),
            application_manifest_sha256=_sha(request.application_manifest),
            runtime_manifest_sha256=_sha(request.runtime_manifest),
            application_signed=self.app_signed,
            runtime_signed=self.runtime_signed,
        )

    def verify_driver_input(self, request) -> bool:
        self.calls.append("verify-driver-input")
        return self.driver_verified

    def observe_admission(self, request):
        self.calls.append("observe-admission")
        return self.admission

    def verify_rollback_preflight(self, request) -> bool:
        self.calls.append("rollback-preflight")
        return self.rollback_ready

    def validate_predecessor_source(self, request) -> bool:
        self.calls.append("validate-predecessor-source")
        return self.source_validations.pop(0)

    def verify_remaining_capacity(self, rollback) -> bool:
        self.calls.append("remaining-capacity")
        if self.fail_at == "remaining-capacity":
            raise RuntimeError("injected capacity observation failure")
        return self.remaining_capacity and rollback.bundle_id == "bundle-id"

    def verify_tls_candidates(self, request) -> bool:
        self.calls.append("verify-tls-candidates")
        return self.tls_verified

    def stop_stack(self, units) -> None:
        self.calls.append("stop:" + ",".join(units))

    def prepare_predecessor_recovery(self, request):
        self.calls.append("prepare-predecessor-recovery")
        if self.fail_at == "prepare-recovery":
            raise RuntimeError("injected")
        self.prepared_backup.write_bytes(b"protected schema 35")
        return self.prepared_backup

    def create_verified_rollback(self, request, prepared_backup):
        self.calls.append("create-verified-rollback")
        if prepared_backup != self.prepared_backup:
            raise RuntimeError("unbound prepared backup")
        if self.fail_at == "bundle":
            raise RuntimeError("injected")
        manifest = self.root / "rollback-manifest.json"
        manifest.write_bytes(b"rollback\n")
        return self.module.RollbackEvidence(
            bundle_dir=request.bundle_dir,
            bundle_id="bundle-id",
            manifest_sha256=_sha(manifest),
        )

    def resume_unchanged_predecessor(self, request, prepared_backup) -> bool:
        self.calls.append("resume-unchanged-predecessor")
        return self.resume_ok and prepared_backup == self.prepared_backup

    def register_rollback_artifact(self, rollback) -> None:
        self.calls.append("register-rollback-artifact")
        if self.fail_at == "artifact-registration":
            raise RuntimeError("registration failed")

    @contextmanager
    def rollback_artifact_lease(self, rollback):
        if self.fail_at == "artifact-lease":
            raise RuntimeError("bundle lease unavailable")
        self.calls.append("artifact-lease-enter")
        self.artifact_lease_active = True
        try:
            yield
        finally:
            self.artifact_lease_active = False
            self.calls.append("artifact-lease-exit")

    def finalize_rollback_artifacts(self, rollback, evidence_hash):
        self.calls.append("finalize-rollback-artifacts")
        if self.artifact_lease_active:
            raise RuntimeError("exclusive promotion attempted under shared lease")
        if self.fail_at == "artifact-promotion":
            raise RuntimeError("private /sensitive/registry/path failed")
        return {"status": "promoted", "pruned": [], "deferred": [], "error": ""}

    def migrate_custom_web_unit(self, expected_hash: str) -> None:
        self.calls.append("migrate-custom-unit:" + expected_hash)
        if self.fail_at == "migrate":
            raise RuntimeError("injected")

    def install_web_candidate(self, candidate: Path) -> None:
        self.calls.append("install-web-candidate")
        if self.fail_at == "web":
            raise RuntimeError("injected")

    def install_tls_candidates(self, certificate: Path, private_key: Path) -> None:
        self.calls.append("install-tls-candidates")
        if self.fail_at == "tls":
            raise RuntimeError("injected")

    def install_release_packages(self, runtime: Path, application: Path, driver=None) -> None:
        self.calls.append("install-release-packages")
        for rpm in (runtime, application, *((driver,) if driver is not None else ())):
            self.calls.append("install:" + rpm.name)
            if self.fail_at == rpm.name:
                raise RuntimeError("injected package transaction failure")

    def verify_installed_driver(self, request) -> bool:
        self.calls.append("verify-installed-driver")
        return self.driver_unchanged

    def authenticated_preflight(self) -> None:
        self.calls.append("authenticated-preflight")
        if self.fail_at == "authenticated-preflight":
            raise RuntimeError("injected")

    def install_qualification_attestation(self, request) -> None:
        self.calls.append("install-qualification-attestation")

    def activate_complete_stack(self) -> None:
        self.calls.append("activate-complete-stack")
        if self.fail_at == "activate":
            raise self.module.ActivationDeploymentError(
                "unit_start", cleanup_failed=True
            )

    def verify_live(self, request):
        self.calls.append("verify-live")
        if self.fail_at == "live":
            raise RuntimeError("injected")
        return self.module.LiveEvidence(
            status="verified" if self.live_ok else "failed",
            report_sha256="d" * 64,
        )

    def restore_verified_rollback(self, rollback):
        self.calls.append("restore-verified-rollback")
        if self.rollback_raises:
            raise RuntimeError("rollback leaked /secret/path")
        return self.module.RollbackOutcome(
            status=self.rollback_status,
            old_health_verified=self.rollback_status == "restored",
        )

    def keep_stack_masked(self) -> None:
        self.calls.append("keep-stack-masked")
        self.masks_kept = True

    def write_deployment_evidence(self, evidence) -> str:
        self.calls.append("write-deployment-evidence")
        if self.fail_at == "evidence":
            raise RuntimeError("durable deployment evidence failed")
        return hashlib.sha256(evidence).hexdigest()


class Rhel9DeploymentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = _load_module()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.files = {}
        for name, data in {
            "app.rpm": b"app",
            "runtime.rpm": b"runtime",
            "driver.rpm": b"candidate driver",
            "predecessor-driver.json": b"predecessor driver contract",
            "app-SHA256SUMS": b"app manifest",
            "app-SHA256SUMS.asc": b"app manifest signature",
            "runtime-SHA256SUMS": b"runtime manifest",
            "runtime-SHA256SUMS.asc": b"runtime manifest signature",
            "driver.json": b"driver contract",
            "web.toml": b"web candidate",
            "signing.json": b"signing policy",
            "server.crt": b"certificate",
            "server.key": b"private key",
        }.items():
            path = self.root / name
            path.write_bytes(data)
            self.files[name] = path
        self.host = FakeDeploymentHost(self.module, self.root)

        self.request = self.module.DeploymentRequest(
            repository_commit="a" * 40,
            deployment_commit="a" * 40,
            application_rpm=self.files["app.rpm"],
            runtime_rpm=self.files["runtime.rpm"],
            driver_rpm=self.files["driver.rpm"],
            application_manifest=self.files["app-SHA256SUMS"],
            application_manifest_signature=self.files["app-SHA256SUMS.asc"],
            runtime_manifest=self.files["runtime-SHA256SUMS"],
            runtime_manifest_signature=self.files["runtime-SHA256SUMS.asc"],
            app_runtime_signing_policy=self.files["signing.json"],
            driver_input_contract=self.files["driver.json"],
            expected_driver_input_sha256=_sha(self.files["driver.json"]),
            rollback_request=self.module.RollbackRequest(
                bundle_dir=self.root / "rollback",
                rollback_rpm_dir=self.root / "old-rpms",
                expected_custom_web_unit_sha256=self.host.custom_hash,
                driver_input_contract=self.files["predecessor-driver.json"],
                expected_driver_input_sha256=_sha(self.files["predecessor-driver.json"]),
                candidate_driver_input_contract=self.files["driver.json"],
                expected_candidate_driver_input_sha256=_sha(self.files["driver.json"]),
                predecessor_web_probe={
                    "url": "https://console.example.invalid:8443/login",
                    "ca_certificate": str(self.files["server.crt"]),
                },
            ),
            web_config_candidate=self.files["web.toml"],
            expected_web_config_sha256=_sha(self.files["web.toml"]),
            tls_certificate_candidate=self.files["server.crt"],
            tls_private_key_candidate=self.files["server.key"],
            expected_tls_certificate_sha256=_sha(self.files["server.crt"]),
            expected_tls_private_key_sha256=_sha(self.files["server.key"]),
            maintenance_started_at="2026-08-29T12:00:00Z",
        )

    def test_dnf_authority_uses_regular_rhel9_entrypoint(self) -> None:
        self.assertEqual(Path("/usr/bin/dnf-3"), self.module._DNF)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_bootstrap_manifest_is_canonical_by_path_not_digest(self) -> None:
        manifest = Path("/release/SHA256SUMS")
        first = manifest.parent / "a"
        second = manifest.parent / "b"
        first_content = b"a"
        second_content = b"b"
        first_digest = hashlib.sha256(first_content).hexdigest()
        second_digest = hashlib.sha256(second_content).hexdigest()
        self.assertGreater(first_digest, second_digest)
        raw = f"{first_digest}  a\n{second_digest}  b\n".encode("ascii")
        authorities = {
            manifest: raw,
            first: first_content,
            second: second_content,
        }

        with mock.patch.object(
            self.module,
            "_bootstrap_read",
            side_effect=lambda path, maximum=4 * 1024 * 1024: authorities[path],
        ):
            rows, observed = self.module._bootstrap_manifest(manifest)

        self.assertEqual(raw, observed)
        self.assertEqual(
            {first.resolve(): first_digest, second.resolve(): second_digest},
            rows,
        )

    def test_bootstrap_manifest_uses_a_bounded_release_member_limit(self) -> None:
        manifest = Path("/release/SHA256SUMS")
        member = manifest.parent / "runtime.rpm"
        content = b"r" * (4 * 1024 * 1024 + 1)
        member_digest = hashlib.sha256(content).hexdigest()
        raw = f"{member_digest}  runtime.rpm\n".encode("ascii")
        authorities = {manifest: raw, member: content}
        observed_limits: list[int] = []

        def bounded_read(path, maximum=4 * 1024 * 1024):
            data = authorities[path]
            observed_limits.append(maximum)
            if len(data) > maximum:
                raise self.module.DeploymentError("bootstrap input exceeded its bound")
            return data

        with mock.patch.object(
            self.module,
            "_bootstrap_read",
            side_effect=bounded_read,
        ):
            rows, observed = self.module._bootstrap_manifest(manifest)

        self.assertEqual(raw, observed)
        self.assertEqual({member.resolve(): member_digest}, rows)
        self.assertEqual(4 * 1024 * 1024, observed_limits[0])
        self.assertEqual(self.module._BOOTSTRAP_MEMBER_MAX, observed_limits[1])
        self.assertGreaterEqual(observed_limits[1], len(content))

    def test_release_manifest_validation_orders_rows_by_path(self) -> None:
        first = self.root / "a"
        second = self.root / "b"
        first.write_bytes(b"a")
        second.write_bytes(b"b")
        first_digest = hashlib.sha256(first.read_bytes()).hexdigest()
        second_digest = hashlib.sha256(second.read_bytes()).hexdigest()
        self.assertGreater(first_digest, second_digest)
        manifest = self.root / "SHA256SUMS"
        manifest.write_text(
            f"{first_digest}  a\n{second_digest}  b\n",
            encoding="ascii",
        )

        self.assertTrue(
            self.module.SystemDeploymentHost._manifest_ok(manifest, first)
        )
        manifest.write_text(
            f"{second_digest}  b\n{first_digest}  a\n",
            encoding="ascii",
        )
        self.assertFalse(
            self.module.SystemDeploymentHost._manifest_ok(manifest, first)
        )

    def test_signed_release_authorities_accept_root_owned_immutable_files(self) -> None:
        class Authority:
            def __init__(self, mode: int) -> None:
                self.mode = mode

            def stat(self, *, follow_symlinks: bool):
                self.assert_no_follow = follow_symlinks is False
                return SimpleNamespace(st_mode=stat.S_IFREG | self.mode, st_uid=0)

            def is_absolute(self) -> bool:
                return True

            def is_symlink(self) -> bool:
                return False

        immutable = Authority(0o444)
        group_writable = Authority(0o664)

        self.assertTrue(
            self.module.SystemDeploymentHost._secure_file(
                immutable, self.module._RELEASE_AUTHORITY_MODES
            )
        )
        self.assertTrue(immutable.assert_no_follow)
        self.assertFalse(
            self.module.SystemDeploymentHost._secure_file(
                group_writable, self.module._RELEASE_AUTHORITY_MODES
            )
        )

    def test_ltfs_admission_matches_executable_tokens_not_info_arguments(self):
        self.assertTrue(hasattr(self.module, "_is_active_ltfs_commandline"))
        active = self.module._is_active_ltfs_commandline

        self.assertFalse(
            active(
                b"/usr/bin/lto-archiverd\0--ltfs-info-binary\0"
                b"/usr/bin/ltfs-info\0",
                "/usr/bin/lto-archiverd",
            )
        )
        self.assertFalse(
            active(b"/usr/bin/ltfs-info\0--version\0", "/usr/bin/ltfs-info")
        )
        self.assertFalse(
            active(b"/usr/bin/ltfs-helper\0", "/usr/bin/ltfs-helper")
        )
        for commandline, executable in (
            (
                b"/usr/bin/ltfs\0/mnt/lto-archiver/tape\0",
                "/usr/bin/ltfs",
            ),
            (b"/usr/bin/mkltfs\0-d\0/dev/nst0\0", "/usr/bin/mkltfs"),
            (b"/usr/bin/ltfsck\0/dev/nst0\0", "/usr/bin/ltfsck"),
            (
                b"/usr/bin/unltfs\0/mnt/lto-archiver/tape\0",
                "/usr/bin/unltfs",
            ),
            (
                b"/usr/bin/fusermount3\0-u\0/mnt/lto-archiver/tape\0",
                "/usr/bin/fusermount3",
            ),
            (b"/proc/self/fd/9\0/mnt/lto-archiver/tape\0", "/usr/bin/ltfs"),
            (
                b"/usr/bin/lto-archiver-qualify-ltfs\0--execute\0",
                "/usr/bin/python3.11",
            ),
            (
                b"/usr/bin/python3.11\0/usr/bin/"
                b"lto-archiver-qualify-archive-runner\0",
                "/usr/bin/python3.11",
            ),
        ):
            with self.subTest(commandline=commandline, executable=executable):
                self.assertTrue(active(commandline, executable))

    def _tls_pair(self, name: str) -> tuple[Path, Path]:
        certificate = self.root / f"{name}.crt"
        private_key = self.root / f"{name}.key"
        subprocess.run(
            [
                "/usr/bin/openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                f"/CN={name}.example.invalid",
                "-keyout",
                str(private_key),
                "-out",
                str(certificate),
            ],
            check=True,
            capture_output=True,
        )
        certificate.chmod(0o644)
        private_key.chmod(0o600)
        return certificate, private_key

    def test_concrete_tls_preflight_requires_matching_cryptographic_keys(self):
        certificate, private_key = self._tls_pair("matching")
        _other_certificate, other_key = self._tls_pair("other")
        malformed = self.root / "malformed.pem"
        malformed.write_text("not a PEM object\n")
        host = object.__new__(self.module.SystemDeploymentHost)
        commands: list[tuple[str, ...]] = []

        def trusted_run(argv, *, accepted=(0,)):
            command = tuple(str(value) for value in argv)
            commands.append(command)
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/usr/sbin"},
            )
            if result.returncode not in accepted:
                raise self.module.DeploymentError("test command failed")
            return result

        with (
            mock.patch.object(host, "_secure_file", return_value=True),
            mock.patch.object(host, "_run", side_effect=trusted_run),
        ):
            self.assertTrue(
                host.verify_tls_candidates(
                    replace(
                        self.request,
                        tls_certificate_candidate=certificate,
                        tls_private_key_candidate=private_key,
                    )
                )
            )
            self.assertFalse(
                host.verify_tls_candidates(
                    replace(
                        self.request,
                        tls_certificate_candidate=certificate,
                        tls_private_key_candidate=other_key,
                    )
                )
            )
            for bad_certificate, bad_key in (
                (malformed, private_key),
                (certificate, malformed),
            ):
                with self.subTest(bad_certificate=bad_certificate, bad_key=bad_key):
                    self.assertFalse(
                        host.verify_tls_candidates(
                            replace(
                                self.request,
                                tls_certificate_candidate=bad_certificate,
                                tls_private_key_candidate=bad_key,
                            )
                        )
                    )

        self.assertTrue(commands)
        self.assertTrue(all(command[0] == "/usr/bin/openssl" for command in commands))
        self.assertTrue(
            any(command[:2] == ("/usr/bin/openssl", "x509") for command in commands)
        )
        self.assertTrue(
            any(command[:2] == ("/usr/bin/openssl", "pkey") for command in commands)
        )
        self.assertTrue(any("pass:" in command for command in commands))

    def test_concrete_activation_unmasks_stopped_stack_immediately_before_activator(self):
        host = object.__new__(self.module.SystemDeploymentHost)
        host._config = SimpleNamespace(
            activation_script=Path("/usr/libexec/lto-archiver/activate-rhel9.py"),
            activation_config=Path("/etc/lto-archiver/config.toml"),
        )
        host._live = SimpleNamespace(
            ContractError=RuntimeError,
            _healthy_api_v1=lambda value: value
            == {"api_version": 1, "status": "ok"},
        )
        host._live_host = SimpleNamespace(
            _daemon_get=lambda _endpoint, **_kwargs: {
                "api_version": 1,
                "status": "ok",
            }
        )
        masked = set(self.module.STOP_UNITS)
        active: set[str] = set()
        commands: list[tuple[str, ...]] = []

        def observe_run(argv, *, accepted=(0,), activation_diagnostics=False):
            command = tuple(str(value) for value in argv)
            commands.append(command)
            if command[:3] == ("/usr/bin/systemctl", "unmask", "--runtime"):
                self.assertEqual(set(self.module.STOP_UNITS), set(command[3:]))
                self.assertFalse(active)
                masked.difference_update(command[3:])
            elif command[0] == "/usr/bin/python3.11":
                self.assertTrue(activation_diagnostics)
                self.assertFalse(masked, "activator observed runtime-masked units")
                self.assertFalse(active, "stack started before the activator")
            else:
                self.fail(f"unexpected activation command: {command!r}")
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch.object(host, "_run", side_effect=observe_run):
            host.activate_complete_stack()

        self.assertEqual(2, len(commands))
        self.assertEqual(
            ("/usr/bin/systemctl", "unmask", "--runtime", *self.module.STOP_UNITS),
            commands[0],
        )

    def test_concrete_activation_waits_for_daemon_api_readiness(self):
        host = object.__new__(self.module.SystemDeploymentHost)
        host._config = SimpleNamespace(
            activation_script=Path("/usr/libexec/lto-archiver/activate-rhel9.py"),
            activation_config=Path("/etc/lto-archiver/config.toml"),
        )
        events: list[str] = []

        class ProbeError(RuntimeError):
            pass

        class LiveHost:
            attempts = 0

            def _daemon_get(self, endpoint, **_kwargs):
                self.attempts += 1
                events.append(f"probe:{endpoint}")
                if self.attempts == 1:
                    raise ProbeError("not ready")
                return {"api_version": 1, "status": "ok"}

        host._live = SimpleNamespace(
            ContractError=ProbeError,
            _healthy_api_v1=lambda value: value
            == {"api_version": 1, "status": "ok"},
        )
        host._live_host = LiveHost()

        def run(_argv, *, accepted=(0,), activation_diagnostics=False):
            events.append("activate")
            return subprocess.CompletedProcess((), 0, "", "")

        with (
            mock.patch.object(host, "_run", side_effect=run),
            mock.patch.object(self.module.time, "monotonic", side_effect=(0.0, 1.0)),
            mock.patch.object(self.module.time, "sleep") as sleep,
        ):
            host.activate_complete_stack()

        self.assertEqual(
            ["activate", "activate", "probe:/api/v1/health", "probe:/api/v1/health"],
            events,
        )
        sleep.assert_called_once_with(1)

    def test_concrete_activation_fails_closed_when_daemon_never_becomes_ready(self):
        host = object.__new__(self.module.SystemDeploymentHost)
        host._config = SimpleNamespace(
            activation_script=Path("/usr/libexec/lto-archiver/activate-rhel9.py"),
            activation_config=Path("/etc/lto-archiver/config.toml"),
        )

        class ProbeError(RuntimeError):
            pass

        host._live = SimpleNamespace(
            ContractError=ProbeError,
            _healthy_api_v1=lambda _value: False,
        )
        host._live_host = SimpleNamespace(
            _daemon_get=mock.Mock(side_effect=ProbeError("not ready"))
        )

        with (
            mock.patch.object(
                host,
                "_run",
                return_value=subprocess.CompletedProcess((), 0, "", ""),
            ),
            mock.patch.object(
                self.module.time, "monotonic", side_effect=(0.0, 121.0)
            ),
            mock.patch.object(self.module.time, "sleep") as sleep,
            self.assertRaisesRegex(
                self.module.DeploymentError, "daemon readiness timed out"
            ),
        ):
            host.activate_complete_stack()

        sleep.assert_not_called()

    def test_concrete_activation_bounds_near_deadline_probe_to_total_timeout(self):
        host = object.__new__(self.module.SystemDeploymentHost)
        host._config = SimpleNamespace(
            activation_script=Path("/usr/libexec/lto-archiver/activate-rhel9.py"),
            activation_config=Path("/etc/lto-archiver/config.toml"),
        )

        class ProbeError(RuntimeError):
            pass

        clock = [0.0]
        attempts = [0]

        def daemon_get(_endpoint, *, deadline=None):
            attempts[0] += 1
            if attempts[0] == 1:
                clock[0] += 119.5
            else:
                fixed_probe_timeout = 10.0
                remaining = (
                    fixed_probe_timeout
                    if deadline is None
                    else max(0.0, deadline - clock[0])
                )
                clock[0] += min(fixed_probe_timeout, remaining)
            raise ProbeError("not ready")

        host._live = SimpleNamespace(
            ContractError=ProbeError,
            _healthy_api_v1=lambda _value: False,
        )
        host._live_host = SimpleNamespace(_daemon_get=daemon_get)

        def sleep(seconds):
            clock[0] += seconds

        with (
            mock.patch.object(
                host,
                "_run",
                return_value=subprocess.CompletedProcess((), 0, "", ""),
            ),
            mock.patch.object(
                self.module.time, "monotonic", side_effect=lambda: clock[0]
            ),
            mock.patch.object(self.module.time, "sleep", side_effect=sleep),
            self.assertRaisesRegex(
                self.module.DeploymentError, "daemon readiness timed out"
            ),
        ):
            host.activate_complete_stack()

        self.assertEqual(2, attempts[0])
        self.assertLessEqual(
            clock[0], self.module._DAEMON_READINESS_TIMEOUT_SECONDS
        )

    def test_concrete_runner_accepts_only_closed_activation_diagnostic(self):
        result = subprocess.CompletedProcess(
            ("/usr/bin/python3.11",),
            2,
            stdout="secret stdout",
            stderr="RHEL activation failed stage=unit_start cleanup=failed\n",
        )
        trusted_tool = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        with (
            mock.patch.object(self.module.Path, "stat", return_value=trusted_tool),
            mock.patch.object(self.module.subprocess, "run", return_value=result),
        ):
            with self.assertRaises(self.module.ActivationDeploymentError) as raised:
                self.module.SystemDeploymentHost._run(
                    (Path("/usr/bin/python3.11"),),
                    activation_diagnostics=True,
                )
        self.assertEqual("unit_start", raised.exception.stage)
        self.assertTrue(raised.exception.cleanup_failed)
        self.assertNotIn("stdout", str(raised.exception))

        tampered = subprocess.CompletedProcess(
            ("/usr/bin/python3.11",),
            2,
            stdout="secret stdout",
            stderr=(
                "RHEL activation failed stage=unit_start cleanup=failed\n"
                "/secret/path password=leaked\n"
            ),
        )
        with (
            mock.patch.object(self.module.Path, "stat", return_value=trusted_tool),
            mock.patch.object(self.module.subprocess, "run", return_value=tampered),
        ):
            with self.assertRaises(self.module.DeploymentError) as rejected:
                self.module.SystemDeploymentHost._run(
                    (Path("/usr/bin/python3.11"),),
                    activation_diagnostics=True,
                )
        self.assertNotIsInstance(
            rejected.exception, self.module.ActivationDeploymentError
        )
        self.assertEqual("deployment command failed", str(rejected.exception))

    def test_deploy_refuses_mismatched_commit_binding_or_unverified_artifact_and_driver_inputs(self):
        for scenario in (
            "commit",
            "artifact",
            "source",
            "app-sign",
            "runtime-sign",
            "driver",
            "rollback-driver",
            "tls-hash",
        ):
            with self.subTest(scenario=scenario):
                host = FakeDeploymentHost(self.module, self.root)
                request = self.request
                if scenario == "commit":
                    request = replace(request, deployment_commit="b" * 40)
                elif scenario == "artifact":
                    host.artifacts_verified = False
                elif scenario == "source":
                    host.artifact_source_commit = "b" * 40
                elif scenario == "app-sign":
                    host.app_signed = False
                elif scenario == "runtime-sign":
                    host.runtime_signed = False
                elif scenario == "driver":
                    host.driver_verified = False
                elif scenario == "rollback-driver":
                    request = replace(
                        request,
                        rollback_request=replace(
                            request.rollback_request,
                            expected_driver_input_sha256="b" * 64,
                        ),
                    )
                else:
                    request = replace(
                        request, expected_tls_private_key_sha256="b" * 64
                    )
                result = self.module.deploy(request, host)
                self.assertEqual("refused", result.status)
                self.assertNotIn("create-verified-rollback", host.calls)

        policy = {
            "primary_fingerprint": "A" * 40,
            "signing_subkey_fingerprint": "B" * 40,
        }
        valid = (
            "[GNUPG:] VALIDSIG "
            + "B" * 40
            + " 20260829 123 0 4 0 1 8 00 "
            + "A" * 40
        )
        self.assertTrue(self.module._validsig_authorized(valid, policy))
        self.assertFalse(
            self.module._validsig_authorized(
                valid.replace("B" * 40, "C" * 40), policy
            )
        )
        self.assertFalse(
            self.module._validsig_authorized(
                valid.replace(" 1 8 00 ", " 1 2 00 "), policy
            )
        )
        self.assertFalse(
            self.module._validsig_authorized(
                valid.replace(" 1 8 00 ", " 17 8 00 "), policy
            )
        )
        self.assertFalse(self.module._validsig_authorized("", policy))
        for failure in (
            "EXPKEYSIG",
            "REVKEYSIG",
            "BADSIG",
            "ERRSIG",
            "SIGEXPIRED",
        ):
            self.assertFalse(
                self.module._validsig_authorized(
                    valid + f"\n[GNUPG:] {failure} {'B' * 16}", policy
                )
            )
        self.assertFalse(
            self.module._validsig_authorized(
                valid + f"\n[GNUPG:] KEY_CONSIDERED {'C' * 40} 0",
                policy,
            )
        )

    def test_deploy_requires_idle_reconciled_daemon_and_zero_broker_or_qualification_work(self):
        fields = tuple(self.host.admission.__dataclass_fields__)
        for field in fields:
            with self.subTest(field=field):
                host = FakeDeploymentHost(self.module, self.root)
                host.admission = replace(host.admission, **{field: False})
                result = self.module.deploy(self.request, host)
                self.assertEqual("refused", result.status)
                self.assertNotIn("create-verified-rollback", host.calls)

    def test_deployment_daemon_quiescence_accepts_only_safe_persisted_job_states(self):
        for state in ("waiting_media", "paused"):
            with self.subTest(state=state):
                self.assertTrue(
                    self.module._daemon_quiescent_for_deployment(
                        {
                            "job": {"state": state},
                            "operation": None,
                            "admission_blocker": None,
                        }
                    )
                )
        self.assertTrue(
            self.module._daemon_quiescent_for_deployment(
                {"job": None, "operation": None, "admission_blocker": None}
            )
        )
        for status in (
            {
                "job": {"state": "waiting_media"},
                "operation": {"state": "running"},
                "admission_blocker": None,
            },
            {
                "job": {"state": "paused"},
                "operation": None,
                "admission_blocker": {"state": "recovery_required"},
            },
            {"job": {"state": "writing"}, "operation": None, "admission_blocker": None},
            {"job": {"state": "planned"}, "operation": None, "admission_blocker": None},
            {"job": {}, "operation": None, "admission_blocker": None},
            {"job": "waiting_media", "operation": None, "admission_blocker": None},
            {"job": None, "operation": None},
            {},
        ):
            with self.subTest(status=status):
                self.assertFalse(
                    self.module._daemon_quiescent_for_deployment(status)
                )

    def test_deploy_verifies_capacity_stops_in_order_and_creates_bundle_before_first_mutation(self):
        result = self.module.deploy(self.request, self.host)
        self.assertEqual("deployed", result.status)
        expected_stop = "stop:" + ",".join(self.module.STOP_UNITS)
        validations = [
            index
            for index, call in enumerate(self.host.calls)
            if call == "validate-predecessor-source"
        ]
        self.assertEqual(2, len(validations))
        self.assertLess(validations[0], self.host.calls.index(expected_stop))
        prepared = self.host.calls.index("prepare-predecessor-recovery")
        self.assertLess(self.host.calls.index(expected_stop), prepared)
        self.assertLess(prepared, validations[1])
        self.assertLess(validations[1], self.host.calls.index("create-verified-rollback"))
        self.assertLess(self.host.calls.index("rollback-preflight"), self.host.calls.index(expected_stop))
        self.assertLess(self.host.calls.index(expected_stop), self.host.calls.index("create-verified-rollback"))
        self.assertLess(self.host.calls.index("create-verified-rollback"), self.host.calls.index("migrate-custom-unit:" + self.host.custom_hash))

    def test_insufficient_capacity_refuses_before_allocating_validation_snapshot(self):
        self.host.rollback_ready = False

        result = self.module.deploy(self.request, self.host)

        self.assertEqual("refused", result.status)
        self.assertNotIn("validate-predecessor-source", self.host.calls)
        self.assertNotIn("prepare-predecessor-recovery", self.host.calls)
        self.assertFalse(any(call.startswith("stop:") for call in self.host.calls))

    def test_post_bundle_capacity_is_checked_before_first_configuration_mutation(self):
        result = self.module.deploy(self.request, self.host)
        self.assertEqual("deployed", result.status)
        self.assertIn("remaining-capacity", self.host.calls)
        self.assertLess(self.host.calls.index("create-verified-rollback"), self.host.calls.index("remaining-capacity"))
        self.assertLess(self.host.calls.index("remaining-capacity"),
                        self.host.calls.index("migrate-custom-unit:" + self.host.custom_hash))

    def test_post_bundle_capacity_refusal_resumes_unchanged_predecessor_without_install(self):
        self.host.remaining_capacity = False
        result = self.module.deploy(self.request, self.host)
        self.assertEqual("refused", result.status)
        self.assertIn("create-verified-rollback", self.host.calls)
        self.assertIn("resume-unchanged-predecessor", self.host.calls)
        self.assertNotIn("install-release-packages", self.host.calls)
        self.assertNotIn("install-web-candidate", self.host.calls)
        self.assertNotIn("restore-verified-rollback", self.host.calls)
        self.assertFalse(any(call.startswith("migrate-custom-unit:") for call in self.host.calls))
        self.assertFalse(self.host.masks_kept)

    def test_post_bundle_capacity_observation_failure_does_not_start_mutation(self):
        self.host.fail_at = "remaining-capacity"
        result = self.module.deploy(self.request, self.host)
        self.assertEqual("refused", result.status)
        self.assertIn("resume-unchanged-predecessor", self.host.calls)
        self.assertNotIn("install-release-packages", self.host.calls)
        self.assertNotIn("restore-verified-rollback", self.host.calls)

    def test_post_bundle_capacity_refusal_keeps_masks_if_unchanged_resume_fails(self):
        self.host.remaining_capacity = False
        self.host.resume_ok = False
        result = self.module.deploy(self.request, self.host)
        self.assertEqual("blocked", result.status)
        self.assertTrue(self.host.masks_kept)
        self.assertNotIn("install-release-packages", self.host.calls)

    def test_retention_registers_verified_bundle_and_leases_until_durable_success(self):
        result = self.module.deploy(self.request, self.host)
        self.assertEqual("deployed", result.status)
        expected = ["create-verified-rollback", "register-rollback-artifact", "artifact-lease-enter",
                    "remaining-capacity", "install-release-packages", "write-deployment-evidence",
                    "artifact-lease-exit", "finalize-rollback-artifacts"]
        self.assertEqual(expected, [call for call in self.host.calls if call in expected])
        self.assertEqual("promoted", getattr(result, "retention", {}).get("status"))

    def test_retention_registration_or_lease_failure_never_installs_release(self):
        for failure in ("artifact-registration", "artifact-lease"):
            host = FakeDeploymentHost(self.module, self.root)
            host.fail_at = failure
            with self.subTest(failure=failure):
                result = self.module.deploy(self.request, host)
                self.assertEqual("refused", result.status)
                self.assertIn("resume-unchanged-predecessor", host.calls)
                self.assertNotIn("install-release-packages", host.calls)
                self.assertNotIn("finalize-rollback-artifacts", host.calls)

    def test_failed_deployment_keeps_lease_through_restore_and_never_promotes(self):
        self.host.fail_at = "web"
        result = self.module.deploy(self.request, self.host)
        self.assertEqual("rolled_back", result.status)
        self.assertIn("artifact-lease-enter", self.host.calls)
        self.assertLess(self.host.calls.index("artifact-lease-enter"), self.host.calls.index("restore-verified-rollback"))
        self.assertLess(self.host.calls.index("restore-verified-rollback"), self.host.calls.index("artifact-lease-exit"))
        self.assertNotIn("finalize-rollback-artifacts", self.host.calls)

    def test_undurable_success_evidence_never_promotes_bundle(self):
        self.host.fail_at = "evidence"
        result = self.module.deploy(self.request, self.host)
        self.assertEqual("rolled_back", result.status)
        self.assertNotIn("finalize-rollback-artifacts", self.host.calls)
        self.assertIn("artifact-lease-exit", self.host.calls)

    def test_post_success_retention_error_is_observable_without_rollback(self):
        self.host.fail_at = "artifact-promotion"
        result = self.module.deploy(self.request, self.host)
        self.assertEqual("deployed", result.status)
        self.assertIn("finalize-rollback-artifacts", self.host.calls)
        self.assertNotIn("restore-verified-rollback", self.host.calls)
        self.assertFalse(self.host.masks_kept)
        self.assertEqual("refused", getattr(result, "retention", {}).get("status"))
        self.assertNotIn("sensitive", json.dumps(asdict(result)))

    def test_concrete_retention_adapter_promotes_real_registry_using_recovery_verification(self):
        path = ROOT / "packaging/scripts/deployment_artifacts.py"
        spec = importlib.util.spec_from_file_location("deployment_artifacts_integration", path)
        artifacts = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(artifacts)
        registry = artifacts.DeploymentArtifactRegistry(self.root / "artifact-registry")
        bundle = self.root / "rollback-bundles" / "predecessor141"
        bundle.mkdir(parents=True, mode=0o700)
        manifest = bundle / "bundle-manifest.json"
        manifest.write_bytes(b'{"bundle_id":"predecessor141"}\n')
        manifest.chmod(0o600)
        rollback = self.module.RollbackEvidence(bundle, "predecessor141", _sha(manifest))
        evidence = self.root / "success-evidence.json"
        evidence.write_text(json.dumps({
            "schema": 1, "status": "deployed", "rollback_manifest_sha256": rollback.manifest_sha256,
            "repository_commit": "a" * 40, "application_manifest_sha256": "b" * 64,
            "application_rpm_sha256": "c" * 64, "driver_input_sha256": "d" * 64,
            "live_report_sha256": "e" * 64, "runtime_manifest_sha256": "f" * 64,
            "runtime_rpm_sha256": "0" * 64,
        }))
        evidence.chmod(0o600)
        verification = []

        def full_verify(selected, _host, *, require_predeploy_state=True):
            self.assertEqual(bundle, selected)
            self.assertEqual(rollback.manifest_sha256, _sha(selected / "bundle-manifest.json"))
            verification.append(require_predeploy_state)
            return SimpleNamespace(bundle_id="predecessor141")

        host = object.__new__(self.module.SystemDeploymentHost)
        host._artifact_registry = registry
        host._rollback = SimpleNamespace(verify_bundle=full_verify, _verify_bundle=full_verify)
        host._rollback_host = SimpleNamespace(prove_artifact_prunable=lambda _path: None)
        host._config = SimpleNamespace(deployment_evidence_output=evidence)
        self.assertTrue(hasattr(host, "register_rollback_artifact"), "registry adapter is missing")
        with mock.patch.object(artifacts, "_ROOT_UID", os.getuid()), mock.patch.object(artifacts, "_ROOT_GID", os.getgid()):
            host.register_rollback_artifact(rollback)
            report = host.finalize_rollback_artifacts(rollback, _sha(evidence))
        self.assertEqual("promoted", report["status"])
        self.assertEqual([True, False], verification)
        state = json.loads((registry.path / "registry.json").read_text())
        self.assertEqual(str(bundle), state["current"])
        self.assertEqual("current", state["bundles"][str(bundle)]["state"])

    def test_prepared_backup_failure_cannot_resume_without_exact_evidence(self):
        self.host.fail_at = "prepare-recovery"

        result = self.module.deploy(self.request, self.host)

        self.assertEqual("blocked", result.status)
        self.assertIn("prepare-predecessor-recovery", self.host.calls)
        self.assertNotIn("resume-unchanged-predecessor", self.host.calls)
        self.assertTrue(self.host.masks_kept)

    def test_post_stop_source_drift_resumes_the_unchanged_predecessor(self):
        self.host.source_validations = [True, False]

        result = self.module.deploy(self.request, self.host)

        self.assertEqual("refused", result.status)
        self.assertEqual(2, self.host.calls.count("validate-predecessor-source"))
        self.assertIn("resume-unchanged-predecessor", self.host.calls)
        self.assertNotIn("create-verified-rollback", self.host.calls)
        self.assertFalse(self.host.masks_kept)

    def test_failed_safe_resume_leaves_the_stopped_stack_masked(self):
        self.host.source_validations = [True, False]
        self.host.resume_ok = False

        result = self.module.deploy(self.request, self.host)

        self.assertEqual("blocked", result.status)
        self.assertTrue(self.host.masks_kept)

    def test_bundle_creation_failure_resumes_before_any_configuration_mutation(self):
        self.host.fail_at = "bundle"

        result = self.module.deploy(self.request, self.host)

        self.assertEqual("refused", result.status)
        self.assertIn("resume-unchanged-predecessor", self.host.calls)
        self.assertFalse(
            any(call.startswith("migrate-custom-unit:") for call in self.host.calls)
        )
        self.assertFalse(self.host.masks_kept)

    def test_concrete_predecessor_gate_requires_app126_runtime3_driver16_schema39(self):
        # Historical 126 -> 127 migration contract; keep separate from current admission.
        host = object.__new__(self.module.SystemDeploymentHost)
        observed: list[tuple[Path, dict[str, object]]] = []
        expected = {
            "lto-archiver": "lto-archiver-0.11.27-126.el9.noarch",
            "lto-archiver-python-runtime": (
                "lto-archiver-python-runtime-0.11.27-3.el9.x86_64"
            ),
            "lto-ltfs": "lto-ltfs-0.1.0-16.el9.x86_64",
        }
        host._rollback = SimpleNamespace(
            _PREDECESSOR_NEVRAS=expected,
            _PREDECESSOR_CATALOG_SCHEMA="39",
        )
        host._rollback_host = SimpleNamespace(
            installed_nevras=lambda: expected,
            _sqlite_check=lambda path, **kwargs: (
                observed.append((path, kwargs)) or True
            ),
        )

        self.assertTrue(host.validate_predecessor_source(self.request.rollback_request))
        self.assertEqual(
            [
                (
                    Path("/var/lib/lto-archiver/catalog.db"),
                    {
                        "catalog": True,
                        "catalog_schema": "39",
                        "deployment_quiescent": True,
                    },
                )
            ],
            observed,
        )

        host._rollback_host.installed_nevras = lambda: {
            **expected,
            "lto-archiver": "lto-archiver-0.11.27-100.el9.noarch",
        }
        self.assertFalse(host.validate_predecessor_source(self.request.rollback_request))

    def test_release144_admits_only_app141_driver21_schema40_before_mutation(self):
        from tests.test_rhel9_rollback import _load_module as load_rollback

        rollback = load_rollback()
        host = object.__new__(self.module.SystemDeploymentHost)
        host._rollback = rollback
        expected = {
            "lto-archiver": "lto-archiver-0.11.27-141.el9.noarch",
            "lto-archiver-python-runtime": (
                "lto-archiver-python-runtime-0.11.27-3.el9.x86_64"
            ),
            "lto-ltfs": "lto-ltfs-0.1.0-21.el9.x86_64",
        }
        checked = mock.Mock(return_value=True)
        host._rollback_host = SimpleNamespace(
            installed_nevras=lambda: expected, _sqlite_check=checked,
        )

        self.assertTrue(host.validate_predecessor_source(self.request.rollback_request))
        checked.assert_called_once_with(
            Path("/var/lib/lto-archiver/catalog.db"), catalog=True,
            catalog_schema="40", deployment_quiescent=True,
        )
        checked.reset_mock()
        host._rollback_host.installed_nevras = lambda: {
            **expected, "lto-archiver": "lto-archiver-0.11.27-126.el9.noarch",
        }
        self.assertFalse(host.validate_predecessor_source(self.request.rollback_request))
        checked.assert_not_called()

    def test_deployment_request_schema2_remains_closed(self):
        def json_value(value):
            if isinstance(value, Path):
                return str(value)
            if isinstance(value, dict):
                return {key: json_value(item) for key, item in value.items()}
            if isinstance(value, (list, tuple)):
                return [json_value(item) for item in value]
            return value

        value = {**json_value(asdict(self.request)), "schema": 2}
        path = self.root / "closed-deployment-request.json"
        path.write_bytes(self.module._canonical(value))
        self.assertEqual(self.request, self.module._deployment_request_from_file(path))
        for schema in (1, 3, 4, 2.0, True):
            with self.subTest(schema=schema):
                path.write_bytes(self.module._canonical({**value, "schema": schema}))
                with self.assertRaises(self.module.DeploymentError):
                    self.module._deployment_request_from_file(path)

    def test_deploy_migrates_only_hash_approved_custom_web_unit_and_preserves_tls(self):
        result = self.module.deploy(self.request, self.host)
        self.assertEqual("deployed", result.status)
        self.assertIn("migrate-custom-unit:" + self.host.custom_hash, self.host.calls)
        self.assertIn("install-web-candidate", self.host.calls)
        self.assertIn("install-tls-candidates", self.host.calls)
        self.assertFalse(any("parse-command-line" in call or "old-tls" in call for call in self.host.calls))

    def test_deploy_installs_runtime_then_app_keeps_exact_driver_and_activates_complete_stack(self):
        result = self.module.deploy(self.request, self.host)
        self.assertEqual("deployed", result.status)
        self.assertEqual(1, self.host.calls.count("install-release-packages"))
        self.assertIn("install:driver.rpm", self.host.calls)
        runtime = self.host.calls.index("install:runtime.rpm")
        app = self.host.calls.index("install:app.rpm")
        driver = self.host.calls.index("verify-installed-driver")
        activate = self.host.calls.index("activate-complete-stack")
        self.assertLess(runtime, app)
        self.assertLess(app, driver)
        self.assertLess(driver, activate)
        self.assertFalse(any(call.startswith("install:lto-ltfs") for call in self.host.calls))

    def test_concrete_release_install_groups_explicit_artifacts_in_one_offline_transaction(self):
        host = object.__new__(self.module.SystemDeploymentHost)
        install = getattr(host, "install_release_packages", None)
        self.assertTrue(callable(install), "release closure must be an explicit transaction")
        driver = self.root / "driver.rpm"
        driver.write_bytes(b"driver")
        calls = []
        host._run = lambda argv: calls.append(argv)
        for selected in (None, driver):
            with self.subTest(driver=selected):
                calls.clear()
                install(self.files["runtime.rpm"], self.files["app.rpm"], selected)
                self.assertEqual([
                    (Path("/usr/bin/dnf-3"), "--disablerepo=*",
                     "--setopt=install_weak_deps=False", "--assumeyes", "install",
                     self.files["runtime.rpm"], self.files["app.rpm"],
                     *((driver,) if selected is not None else ())),
                ], calls)

    def test_concrete_release_install_rejects_nonlocal_or_duplicate_artifacts(self):
        host = object.__new__(self.module.SystemDeploymentHost)
        install = getattr(host, "install_release_packages", None)
        self.assertTrue(callable(install), "release closure must be an explicit transaction")
        calls = []
        host._run = lambda argv: calls.append(argv)
        link = self.root / "linked.rpm"
        link.symlink_to(self.files["app.rpm"])
        for invalid in (Path("relative.rpm"), self.root / "absent.rpm", link,
                        self.files["runtime.rpm"], self.files["web.toml"]):
            with self.subTest(invalid=invalid), self.assertRaises(self.module.DeploymentError):
                install(self.files["runtime.rpm"], invalid)
        self.assertEqual([], calls)

    def test_concrete_release_gate_uses_exact_app144_runtime3_driver21_closure(self):
        expected = {
            "lto-archiver": "lto-archiver-0.11.27-144.el9.noarch",
            "lto-archiver-python-runtime": (
                "lto-archiver-python-runtime-0.11.27-3.el9.x86_64"
            ),
            "lto-ltfs": "lto-ltfs-0.1.0-21.el9.x86_64",
        }
        captured: list[object] = []

        class LiveModule:
            @staticmethod
            def VerifyDeploymentRequest(**values):
                request = SimpleNamespace(**values)
                captured.append(request)
                return request

            @staticmethod
            def verify_deployment(request, _host):
                self.assertEqual(expected, request.expected_nevras)
                return SimpleNamespace(status="green", to_json=lambda: "{}\n")

            @staticmethod
            def _publish_report(_path, _data):
                return None

        host = object.__new__(self.module.SystemDeploymentHost)
        host._live = LiveModule
        host._config = SimpleNamespace(
            rpm_verify_policy=self.root / "rpm-policy.json",
            journal_policy=self.root / "journal-policy.json",
            live_report_output=self.root / "live-report.json",
        )
        host._live_host = SimpleNamespace(
            _driver_ok=lambda _request: (True, True),
            _driver_artifact_ok=lambda _request: True,
            _config=SimpleNamespace(driver_rpm=self.request.driver_rpm),
        )
        host._rollback_host = SimpleNamespace(installed_nevras=lambda: expected)
        rollback_dir = self.request.rollback_request.bundle_dir
        rollback_dir.mkdir()
        (rollback_dir / "bundle-manifest.json").write_bytes(b"rollback\n")

        self.assertTrue(host.verify_driver_input(self.request))
        host.authenticated_preflight()
        live = host.verify_live(self.request)

        self.assertEqual("verified", live.status)
        self.assertEqual(2, len(captured))
        self.assertTrue(
            all(request.expected_nevras == expected for request in captured)
        )

    def test_each_post_mutation_failure_invokes_verified_restore_and_old_health_gate(self):
        for failure in ("migrate", "web", "tls", "runtime.rpm", "app.rpm", "driver.rpm", "authenticated-preflight", "activate", "live"):
            with self.subTest(failure=failure):
                host = FakeDeploymentHost(self.module, self.root)
                host.fail_at = failure
                result = self.module.deploy(self.request, host)
                self.assertEqual("rolled_back", result.status)
                self.assertEqual(1, host.calls.count("restore-verified-rollback"))
                self.assertFalse(host.masks_kept)

    def test_swapped_driver_contracts_are_refused_before_service_stop(self):
        rollback = self.request.rollback_request
        swapped = replace(rollback,
            candidate_driver_input_contract=rollback.driver_input_contract,
            expected_candidate_driver_input_sha256=rollback.expected_driver_input_sha256)
        same = replace(rollback, driver_input_contract=self.request.driver_input_contract,
                       expected_driver_input_sha256=self.request.expected_driver_input_sha256)
        for invalid in (swapped, same, replace(rollback, expected_driver_input_sha256="f" * 64)):
            host = FakeDeploymentHost(self.module, self.root)
            result = self.module.deploy(replace(self.request, rollback_request=invalid), host)
            self.assertEqual("refused", result.status)
            self.assertEqual([], host.calls)

    def test_failed_installed_driver_verification_never_activates_candidate(self):
        self.host.driver_unchanged = False
        result = self.module.deploy(self.request, self.host)
        self.assertEqual("rolled_back", result.status)
        self.assertNotIn("activate-complete-stack", self.host.calls)
        self.assertIn("restore-verified-rollback", self.host.calls)

    def test_rollback_failure_keeps_stack_stopped_masked_and_reports_blocked(self):
        self.host.fail_at = "live"
        self.host.rollback_status = "blocked"
        result = self.module.deploy(self.request, self.host)
        self.assertEqual("blocked", result.status)
        self.assertTrue(self.host.masks_kept)
        self.assertIn("keep-stack-masked", self.host.calls)

    def test_rollback_exception_preserves_bounded_primary_activation_stage(self):
        self.host.fail_at = "activate"
        self.host.rollback_raises = True

        result = self.module.deploy(self.request, self.host)

        self.assertEqual("blocked", result.status)
        self.assertEqual(
            "activation_stage=unit_start cleanup=failed; rollback=failed",
            result.detail,
        )
        self.assertLessEqual(len(result.detail), 96)
        self.assertNotIn("/secret/path", result.detail)
        self.assertTrue(self.host.masks_kept)

    def test_deploy_success_report_binds_commit_artifact_manifest_bundle_and_live_report_hashes(self):
        result = self.module.deploy(self.request, self.host)
        self.assertEqual("deployed", result.status)
        self.assertEqual("a" * 40, result.repository_commit)
        self.assertEqual(_sha(self.files["app-SHA256SUMS"]), result.application_manifest_sha256)
        self.assertEqual(_sha(self.files["driver.json"]), result.driver_input_sha256)
        self.assertEqual("d" * 64, result.live_report_sha256)
        self.assertRegex(result.evidence_sha256, r"^[0-9a-f]{64}$")

        request_value = {
            "app_runtime_signing_policy": str(self.request.app_runtime_signing_policy),
            "application_manifest": str(self.request.application_manifest),
            "application_manifest_signature": str(
                self.request.application_manifest_signature
            ),
            "application_rpm": str(self.request.application_rpm),
            "deployment_commit": self.request.deployment_commit,
            "driver_input_contract": str(self.request.driver_input_contract),
            "driver_rpm": str(self.request.driver_rpm),
            "expected_driver_input_sha256": self.request.expected_driver_input_sha256,
            "expected_tls_certificate_sha256": self.request.expected_tls_certificate_sha256,
            "expected_tls_private_key_sha256": self.request.expected_tls_private_key_sha256,
            "expected_web_config_sha256": self.request.expected_web_config_sha256,
            "maintenance_started_at": self.request.maintenance_started_at,
            "repository_commit": self.request.repository_commit,
            "rollback_request": {
                "candidate_driver_input_contract": str(self.request.rollback_request.candidate_driver_input_contract),
                "expected_candidate_driver_input_sha256": self.request.rollback_request.expected_candidate_driver_input_sha256,
                "bundle_dir": str(self.request.rollback_request.bundle_dir),
                "driver_input_contract": str(
                    self.request.rollback_request.driver_input_contract
                ),
                "expected_custom_web_unit_sha256": (
                    self.request.rollback_request.expected_custom_web_unit_sha256
                ),
                "expected_driver_input_sha256": (
                    self.request.rollback_request.expected_driver_input_sha256
                ),
                "predecessor_web_probe": dict(
                    self.request.rollback_request.predecessor_web_probe
                ),
                "rollback_rpm_dir": str(
                    self.request.rollback_request.rollback_rpm_dir
                ),
            },
            "runtime_manifest": str(self.request.runtime_manifest),
            "runtime_manifest_signature": str(
                self.request.runtime_manifest_signature
            ),
            "runtime_rpm": str(self.request.runtime_rpm),
            "schema": 2,
            "tls_certificate_candidate": str(
                self.request.tls_certificate_candidate
            ),
            "tls_private_key_candidate": str(
                self.request.tls_private_key_candidate
            ),
            "web_config_candidate": str(self.request.web_config_candidate),
        }
        request_file = self.root / "deployment-request.json"
        request_file.write_bytes(self.module._canonical(request_value))
        config_file = self.root / "deployment-host.json"
        config_file.write_text(
            json.dumps(
                {
                    "activation_config": str(self.root / "activation.toml"),
                    "activation_script": str(self.root / "activate.py"),
                    "artifact_source_commit_file": str(self.root / "commit"),
                    "clean_source_root": str(self.root / "source"),
                    "deployment_evidence_output": str(self.root / "deployment-evidence.json"),
                    "journal_policy": str(self.root / "journal.json"),
                    "live_private_config": str(self.root / "live-private.json"),
                    "live_report_output": str(self.root / "live-report.json"),
                    "main_rpm_contract": str(self.root / "main-contract.json"),
                    "main_rpm_verifier": str(self.root / "verify-main.py"),
                    "rpm_verify_policy": str(self.root / "rpm-policy.json"),
                    "schema": 1,
                }
            ),
            encoding="utf-8",
        )
        cli_output = self.root / "deployment-result.json"
        cli_host = FakeDeploymentHost(self.module, self.root)
        with mock.patch.object(
            self.module, "_bootstrap_authorities", return_value={}
        ), mock.patch.object(
            self.module, "SystemDeploymentHost", return_value=cli_host
        ):
            return_code = self.module.main(
                [
                    "--request",
                    str(request_file),
                    "--host-config",
                    str(config_file),
                    "--json-output",
                    str(cli_output),
                ]
            )
        self.assertEqual(0, return_code)
        self.assertEqual("deployed", json.loads(cli_output.read_text())["status"])

        imported = False

        def untrusted_import(*_args, **_kwargs):
            nonlocal imported
            imported = True
            raise AssertionError("untrusted top-level code executed")

        rejected_output = self.root / "rejected-result.json"
        with mock.patch.object(
            self.module,
            "_bootstrap_authorities",
            side_effect=self.module.DeploymentError("invalid detached signature"),
        ), mock.patch.object(self.module, "_load_sibling", side_effect=untrusted_import):
            rejected = self.module.main(
                [
                    "--request",
                    str(request_file),
                    "--host-config",
                    str(config_file),
                    "--json-output",
                    str(rejected_output),
                ]
            )
        self.assertEqual(2, rejected)
        self.assertFalse(imported)
        self.assertFalse(rejected_output.exists())

        bootstrap_root = self.root / "bootstrap"
        bootstrap_root.mkdir()
        bootstrap_script = bootstrap_root / "deploy-rhel9.py"
        bootstrap_script.write_text("# bootstrap\n")
        side_effect = bootstrap_root / "side-effect"
        (bootstrap_root / "rollback-rhel9.py").write_text(
            f"from pathlib import Path\nPath({str(side_effect)!r}).write_text('ran')\n"
        )
        with mock.patch.object(
            self.module, "__file__", str(bootstrap_script)
        ), self.assertRaises(self.module.DeploymentError):
            self.module._load_sibling("untrusted_rollback", "rollback-rhel9.py", {})
        self.assertFalse(side_effect.exists())


if __name__ == "__main__":
    unittest.main()
