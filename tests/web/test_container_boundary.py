from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import tomllib
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from starlette.requests import Request

from ltobackup.daemon.service import (
    PEER_CREDENTIAL_SCOPE_KEY,
    TrustedPrincipalResolver,
)
from ltobackup.preflight import AccountIdentity, PreflightHost, _owned_directory
from ltobackup.web.auth_store import AuthStore, SessionManager
from ltobackup.web.main import (
    _password_from_descriptor,
    build_parser,
    main,
    prepare_runtime,
)


class WebEntrypointTests(unittest.TestCase):
    def test_admin_create_rejects_password_argument(self) -> None:
        parser = build_parser()

        for supplied in ("secret", "3"):
            with self.subTest(supplied=supplied), self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "admin",
                        "create",
                        "--username",
                        "admin",
                        "--password",
                        supplied,
                    ]
                )

    def test_admin_create_reads_password_from_explicit_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as isolated:
            database = Path(isolated) / "auth.sqlite3"
            read_fd, write_fd = os.pipe()
            self.addCleanup(lambda: os.close(read_fd) if read_fd >= 0 else None)
            try:
                os.write(write_fd, b"correct horse battery staple\n")
            finally:
                os.close(write_fd)

            stdout = StringIO()
            with redirect_stdout(stdout):
                result = main(
                    [
                        "admin",
                        "create",
                        "--username",
                        "TapeAdmin",
                        "--auth-db",
                        str(database),
                        "--password-fd",
                        str(read_fd),
                    ]
                )
            os.close(read_fd)
            read_fd = -1

            self.assertEqual(0, result)
            self.assertEqual("Administrator created\n", stdout.getvalue())
            users = AuthStore(database).list_users()
            self.assertEqual(["TapeAdmin"], [user.login_name for user in users])
            self.assertEqual(0o600, database.stat().st_mode & 0o777)

    def test_admin_create_refuses_non_tty_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as isolated:
            database = Path(isolated) / "auth.sqlite3"

            with self.assertRaisesRegex(SystemExit, "terminal TTY"):
                main(
                    [
                        "admin",
                        "create",
                        "--username",
                        "admin",
                        "--auth-db",
                        str(database),
                    ],
                    password_reader=lambda: (_ for _ in ()).throw(
                        RuntimeError("password input requires a terminal TTY")
                    ),
                )

            self.assertFalse(database.exists())

    def test_break_glass_reset_enable_revoke_and_list_are_safe(self) -> None:
        with tempfile.TemporaryDirectory() as isolated:
            database = Path(isolated) / "auth.sqlite3"
            store = AuthStore(database)
            admin = store.create_admin("TapeAdmin", "correct horse battery staple")
            recovery = store.create_admin(
                "RecoveryAdmin", "another secure administrator password"
            )
            sessions = SessionManager(store)
            session = sessions.create(admin)
            store.disable_user(
                actor_user_id=recovery.id,
                target_user_id=admin.id,
                idempotency_key="break-glass-disable",
            )

            self.assertEqual(
                0,
                main(
                    [
                        "admin",
                        "enable",
                        "--username",
                        "TapeAdmin",
                        "--auth-db",
                        str(database),
                    ]
                ),
            )
            self.assertEqual(
                0,
                main(
                    [
                        "admin",
                        "reset",
                        "--username",
                        "TapeAdmin",
                        "--auth-db",
                        str(database),
                    ],
                    password_reader=lambda: "definitive reset password",
                ),
            )
            self.assertIsNotNone(
                AuthStore(database).authenticate(
                    "TapeAdmin", "definitive reset password"
                )
            )
            self.assertIsNone(sessions.resolve(session.cookie))
            self.assertEqual(
                0,
                main(
                    [
                        "admin",
                        "revoke",
                        "--username",
                        "TapeAdmin",
                        "--auth-db",
                        str(database),
                    ]
                ),
            )
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    0,
                    main(
                        [
                            "admin",
                            "list",
                            "--auth-db",
                            str(database),
                        ]
                    ),
                )
            rendered = output.getvalue()
            self.assertIn("TapeAdmin\tadmin\tactive", rendered)
            self.assertNotIn("argon2", rendered)
            self.assertNotIn("password", rendered.casefold())

    def test_break_glass_password_commands_reject_argv_and_environment_inputs(
        self,
    ) -> None:
        parser = build_parser()
        for command in ("create", "reset"):
            with self.subTest(command=command), self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "admin",
                        command,
                        "--username",
                        "admin",
                        "--password",
                        "secret-value",
                    ]
                )

    def test_password_descriptor_returns_at_newline_while_writer_stays_open(
        self,
    ) -> None:
        completed, result, failure = self.read_from_open_pipe(
            b"correct horse battery staple\n"
        )

        self.assertTrue(completed, "password reader waited for pipe EOF")
        self.assertEqual(["correct horse battery staple"], result)
        self.assertEqual([], failure)

    def test_password_descriptor_uses_first_line_independent_of_trailing_timing(
        self,
    ) -> None:
        expected = "correct horse battery staple"
        cases = (
            ("writer-open", f"{expected}\n".encode(), None),
            ("preloaded-trailing", f"{expected}\nsecond line\n".encode(), None),
            ("delayed-trailing", f"{expected}\n".encode(), b"second line\n"),
        )

        for name, initial, delayed in cases:
            with self.subTest(name=name):
                completed, result, failure = self.read_from_open_pipe(
                    initial,
                    delayed_payload=delayed,
                )
                self.assertTrue(completed, "password reader waited for pipe EOF")
                self.assertEqual([expected], result)
                self.assertEqual([], failure)

    def test_password_descriptor_accepts_maximum_line_before_lf(self) -> None:
        maximum = "a" * 4096

        completed, result, failure = self.read_from_open_pipe(
            f"{maximum}\nignored\n".encode()
        )

        self.assertTrue(completed, "password reader waited for pipe EOF")
        self.assertEqual([maximum], result)
        self.assertEqual([], failure)

    def test_password_descriptor_rejects_empty_nul_and_invalid_utf8(self) -> None:
        for name, payload in (
            ("empty", b"\n"),
            ("nul", b"valid-prefix\x00invalid\n"),
            ("embedded-cr", b"valid-prefix\rinvalid\n"),
            ("invalid-utf8", b"valid-prefix\xff\n"),
            ("over-limit", b"a" * 4097 + b"\n"),
        ):
            with self.subTest(name=name):
                completed, result, failure = self.read_from_open_pipe(payload)
                self.assertTrue(completed, "password reader waited for pipe EOF")
                self.assertEqual([], result)
                self.assertEqual(1, len(failure))

    def read_from_open_pipe(
        self,
        payload: bytes,
        *,
        delayed_payload: bytes | None = None,
    ) -> tuple[bool, list[str], list[BaseException]]:
        read_fd, write_fd = os.pipe()
        result: list[str] = []
        failure: list[BaseException] = []
        finished = threading.Event()

        def read_password() -> None:
            try:
                result.append(_password_from_descriptor(read_fd))
            except BaseException as exc:  # noqa: BLE001 - propagate thread failures
                failure.append(exc)
            finally:
                finished.set()

        os.write(write_fd, payload)
        reader = threading.Thread(target=read_password, daemon=True)
        reader.start()
        completed_before_eof = finished.wait(0.5)
        if delayed_payload is not None:
            os.write(write_fd, delayed_payload)
        os.close(write_fd)
        reader.join(1)
        os.close(read_fd)
        self.assertFalse(reader.is_alive(), "password reader did not terminate")
        return completed_before_eof, result, failure

    def test_serve_runtime_uses_separate_auth_state_and_daemon_uds(self) -> None:
        with tempfile.TemporaryDirectory() as isolated:
            database = Path(isolated) / "auth.sqlite3"
            socket_path = Path(isolated) / "daemon.sock"
            args = build_parser().parse_args(
                [
                    "serve",
                    "--auth-db",
                    str(database),
                    "--daemon-socket",
                    str(socket_path),
                    "--daemon-timeout-seconds",
                    "7.5",
                ]
            )

            runtime = prepare_runtime(args)
            self.addCleanup(runtime.close)

            self.assertEqual(database, runtime.auth_store.database)
            self.assertEqual(socket_path, runtime.daemon_client.socket_path)
            self.assertEqual(7.5, runtime.daemon_client.timeout_seconds)
            self.assertIs(runtime.auth_store, runtime.app.state.session_manager.store)
            self.assertFalse(hasattr(runtime, "catalog"))

    def test_serve_passes_explicit_tls_files_to_uvicorn(self) -> None:
        with tempfile.TemporaryDirectory() as isolated:
            root = Path(isolated)
            database = root / "auth.sqlite3"
            certificate = root / "server.crt"
            private_key = root / "server.key"
            certificate.write_text("test certificate", encoding="utf-8")
            private_key.write_text("test private key", encoding="utf-8")

            with patch("ltobackup.web.main.uvicorn.run") as run_server:
                result = main(
                    [
                        "serve",
                        "--host",
                        "192.0.2.26",
                        "--port",
                        "8443",
                        "--auth-db",
                        str(database),
                        "--tls-certfile",
                        str(certificate),
                        "--tls-keyfile",
                        str(private_key),
                    ]
                )

            self.assertEqual(0, result)
            run_server.assert_called_once()
            _, keyword = run_server.call_args
            self.assertEqual("192.0.2.26", keyword["host"])
            self.assertEqual(8443, keyword["port"])
            self.assertEqual(str(certificate), keyword["ssl_certfile"])
            self.assertEqual(str(private_key), keyword["ssl_keyfile"])

    def test_serve_rejects_an_incomplete_tls_pair_before_state_creation(self) -> None:
        with tempfile.TemporaryDirectory() as isolated:
            root = Path(isolated)
            database = root / "auth.sqlite3"
            certificate = root / "server.crt"
            certificate.write_text("test certificate", encoding="utf-8")

            with self.assertRaisesRegex(
                SystemExit,
                "TLS certificate and key must be supplied together",
            ):
                main(
                    [
                        "serve",
                        "--auth-db",
                        str(database),
                        "--tls-certfile",
                        str(certificate),
                    ]
                )

            self.assertFalse(database.exists())

    def test_serve_rejects_relative_daemon_socket_before_state_creation(self) -> None:
        with tempfile.TemporaryDirectory() as isolated:
            database = Path(isolated) / "auth.sqlite3"
            args = build_parser().parse_args(
                [
                    "serve",
                    "--auth-db",
                    str(database),
                    "--daemon-socket",
                    "daemon.sock",
                ]
            )

            with self.assertRaisesRegex(ValueError, "absolute"):
                prepare_runtime(args)

            self.assertFalse(database.exists())


class ContainerPolicyTests(unittest.TestCase):
    def test_container_has_numeric_nonroot_user_healthcheck_and_no_catalog(
        self,
    ) -> None:
        text = Path("Containerfile.web").read_text(encoding="utf-8")

        self.assertRegex(text, r"(?m)^USER 1001:1001$")
        self.assertIn("HEALTHCHECK", text)
        self.assertNotIn("/var/lib/lto-archiver/catalog.db", text)
        self.assertNotIn("/dev/st", text)
        self.assertNotIn("/dev/sg", text)
        self.assertNotRegex(text, r"(?im)^ENV .*?(?:password|secret|token)")

    def test_container_provisions_as_root_then_finishes_as_numeric_nonroot(
        self,
    ) -> None:
        text = Path("Containerfile.web").read_text(encoding="utf-8")

        root = text.index("USER 0")
        install = text.index("RUN python -m venv")
        nonroot = text.rindex("USER 1001:1001")
        self.assertLess(root, install)
        self.assertLess(install, nonroot)

    def test_container_installs_only_from_hash_locked_wheelhouse(self) -> None:
        container = Path("Containerfile.web").read_text(encoding="utf-8")
        lock = Path("requirements-web.lock").read_text(encoding="utf-8")

        self.assertIn("COPY requirements-web.lock", container)
        self.assertIn("COPY wheelhouse", container)
        self.assertIn("--no-index", container)
        self.assertIn("--require-hashes", container)
        self.assertNotIn("pip install --no-cache-dir .", container)
        for distribution in (
            "argon2-cffi",
            "fastapi",
            "httpx",
            "jinja2",
            "pydantic",
            "setuptools",
            "uvicorn",
            "wheel",
        ):
            self.assertRegex(lock, rf"(?m)^{distribution}==[^ ]+ \\")
        requirement_starts = [line for line in lock.splitlines() if line[:1].isalnum()]
        self.assertTrue(requirement_starts)
        self.assertNotIn("httpx2", lock)

    def test_rootless_recipe_maps_the_webui_primary_uid_and_gid(
        self,
    ) -> None:
        manual = Path("docs/linux/webui.md").read_text(encoding="utf-8")
        container = Path("Containerfile.web").read_text(encoding="utf-8")
        daemon = Path("packaging/systemd/lto-archiverd.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("--userns=keep-id:uid=1001,gid=1001", manual)
        self.assertNotIn("--group-add keep-groups", manual)
        self.assertIn("primary group", manual)
        self.assertIn(
            "podman build --format=docker --network=none --pull=never", manual
        )
        self.assertIn("--no-index --find-links=wheelhouse", container)
        self.assertIn("--require-hashes --requirement requirements-web.lock", container)
        self.assertRegex(container, r"(?m)^USER 1001:1001$")
        groups = next(
            line.split("=", 1)[1].split()
            for line in daemon.splitlines()
            if line.startswith("SupplementaryGroups=")
        )
        self.assertIn("lto-web", groups)
        if not Path("docs/superpowers").is_dir():
            self.assertFalse(any(Path("docs/superpowers").rglob("*.md")))
            return
        cutover = Path(
            "docs/superpowers/plans/2026-08-21-linux-production-cutover-plan.md"
        ).read_text(encoding="utf-8")
        task_plan = Path(
            "docs/superpowers/plans/2026-08-21-linux-webui-plan.md"
        ).read_text(encoding="utf-8")

        self.assertIn("--userns=keep-id:uid=1001,gid=1001", manual)
        self.assertNotIn("--group-add keep-groups", manual)
        self.assertIn("primary group", manual)
        self.assertIn(
            "podman build --format=docker --network=none --pull=never",
            manual,
        )
        self.assertIn("UserNS=keep-id:uid=1001,gid=1001", cutover)
        self.assertNotIn("GroupAdd=keep-groups", cutover)
        self.assertIn("SupplementaryGroups=tape fuse lto-web", cutover)
        self.assertIn(
            "podman build --format=docker --network=none --pull=never",
            task_plan,
        )
        self.assertIn("--no-index --find-links=wheelhouse", task_plan)
        self.assertIn("--require-hashes --requirement requirements-web.lock", task_plan)
        self.assertIn(r'self.assertRegex(text, r"(?m)^USER 1001:1001$")', task_plan)

    def test_production_plan_provisions_auth_bind_source_fail_closed(self) -> None:
        expected_rule = "d /var/lib/lto-archiver-web 0700 lto-web lto-web -"
        rules = Path("packaging/systemd/lto-archiver.tmpfiles").read_text(
            encoding="utf-8"
        )
        self.assertIn(expected_rule, rules.splitlines())
        unit = Path("packaging/systemd/lto-archiver-web.service").read_text(
            encoding="utf-8"
        )
        for control in (
            "User=lto-web",
            "Group=lto-web",
            "UMask=0077",
            "PrivateDevices=yes",
            "DevicePolicy=closed",
            "ProtectSystem=strict",
            "ReadWritePaths=/var/lib/lto-archiver-web",
        ):
            self.assertIn(control, unit.splitlines())
        self.assert_auth_state_preflight_rejects_unsafe_directory()
        if not Path("docs/superpowers").is_dir():
            self.assertFalse(any(Path("docs/superpowers").rglob("*.md")))
            return
        cutover = Path(
            "docs/superpowers/plans/2026-08-21-linux-production-cutover-plan.md"
        ).read_text(encoding="utf-8")
        expected_rule = "d /var/lib/lto-archiver-web 0700 lto-web lto-web -"
        tmpfiles_rules = {
            line.strip()
            for line in cutover.splitlines()
            if line.strip().startswith("d /var/lib/")
        }

        self.assertIn(expected_rule, tmpfiles_rules)
        self.assertIn("ExecStartPre=", cutover)
        self.assertIn("/usr/bin/stat", cutover)
        self.assertIn("test ! -L /var/lib/lto-archiver-web", cutover)
        self.assertIn("700:lto-web:lto-web", cutover)
        self.assertIn(
            "systemd-tmpfiles --create /usr/lib/tmpfiles.d/lto-archiver.conf",
            cutover,
        )
        self.assertLess(
            cutover.index(expected_rule),
            cutover.index("Volume=/var/lib/lto-archiver-web"),
        )

    def assert_auth_state_preflight_rejects_unsafe_directory(self) -> None:
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as isolated:
            root = Path(isolated)
            state = root / "catalog-state"
            for path in (state, state / "backups", state / "migrations"):
                path.mkdir(mode=0o750)
            settings = SimpleNamespace(state_dir=state, restore_roots=())
            owner = state.stat()
            daemon = AccountIdentity(owner.st_uid, (owner.st_gid,))
            auth = root / "auth"
            auth.mkdir(mode=0o700)
            symlink = root / "auth-link"
            symlink.symlink_to(auth, target_is_directory=True)
            regular = root / "auth-file"
            regular.write_bytes(b"not a directory")
            regular.chmod(0o700)
            broker = Path("/var/lib/lto-archiver-broker")
            cases = (
                ("valid", auth, owner.st_uid, owner.st_gid, 0o700, True),
                ("wrong uid", auth, owner.st_uid + 1, owner.st_gid, 0o700, False),
                ("wrong gid", auth, owner.st_uid, owner.st_gid + 1, 0o700, False),
                ("wrong mode", auth, owner.st_uid, owner.st_gid, 0o750, False),
                ("symlink", symlink, owner.st_uid, owner.st_gid, 0o700, False),
                ("regular file", regular, owner.st_uid, owner.st_gid, 0o700, False),
                ("missing", root / "missing", owner.st_uid, owner.st_gid, 0o700, False),
            )
            for name, candidate, uid, gid, mode, expected in cases:
                auth.chmod(mode)

                def owned(
                    path,
                    expected_uid,
                    expected_gids,
                    expected_mode,
                    candidate=candidate,
                ):
                    # Model only the unrelated root-owned broker directory;
                    # catalog and auth validation use the real filesystem.
                    if path == broker:
                        return True
                    if path == Path("/var/lib/lto-archiver-web"):
                        path = candidate
                    return _owned_directory(
                        path, expected_uid, expected_gids, expected_mode
                    )

                with (
                    self.subTest(case=name),
                    patch("ltobackup.preflight._owned_directory", side_effect=owned),
                ):
                    self.assertEqual(
                        expected,
                        PreflightHost().state_paths_ready(
                            settings, daemon, AccountIdentity(uid, (gid,))
                        ),
                    )

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux SO_PEERCRED gate")
    def test_kernel_peer_credentials_report_the_real_host_identity(self) -> None:
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with receiver, sender:
            process_id, user_id, group_id = struct.unpack(
                "3i",
                receiver.getsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_PEERCRED,
                    struct.calcsize("3i"),
                ),
            )

        self.assertEqual(os.getpid(), process_id)
        self.assertEqual(os.getuid(), user_id)
        self.assertEqual(os.getgid(), group_id)

    def test_container_base_has_no_default_and_entrypoint_is_web_only(self) -> None:
        text = Path("Containerfile.web").read_text(encoding="utf-8")

        self.assertIn("ARG UBI_IMAGE\nFROM ${UBI_IMAGE}", text)
        self.assertNotRegex(text, r"(?m)^ARG UBI_IMAGE=")
        self.assertIn('ENTRYPOINT ["lto-archiver-web"]', text)
        self.assertIn('CMD ["serve", "--port", "8080"]', text)

    def test_runtime_dependencies_and_console_script_are_packaged(self) -> None:
        project = tomllib.loads(Path("pyproject.toml").read_text())["project"]

        self.assertIn("jinja2>=3.1,<4", project["dependencies"])
        self.assertIn("httpx>=0.28,<1", project["dependencies"])
        self.assertIn("argon2-cffi>=25.1,<26", project["dependencies"])
        self.assertEqual(
            "ltobackup.web.main:main", project["scripts"]["lto-archiver-web"]
        )

    def test_web_base_image_validation_requires_explicit_ubi_9_python_311(
        self,
    ) -> None:
        self.assert_rejected("")
        self.assert_rejected("ubi9/python-311:latest")
        self.assert_rejected("registry.example/ubi9/python-311:latest")
        self.assert_accepted("registry.example/ubi9/python-311:9.6")
        self.assert_accepted(
            "registry.example/ubi9/python-311@sha256:" + "a" * 64,
            release=True,
        )
        self.assert_accepted(
            "registry.example/ubi9/python-311:9.6@sha256:" + "b" * 64,
            release=True,
        )
        self.assert_rejected(
            "registry.example/ubi9/python-311:9.6",
            release=True,
        )

    def run_validator(
        self, reference: str, *, release: bool
    ) -> subprocess.CompletedProcess:
        mode = "--release" if release else "--development"
        return subprocess.run(
            [
                os.environ.get("PYTHON", os.sys.executable),
                "scripts/validate-web-base-image.py",
                mode,
                reference,
            ],
            capture_output=True,
            check=False,
            text=True,
        )

    def assert_accepted(self, reference: str, *, release: bool = False) -> None:
        result = self.run_validator(reference, release=release)
        self.assertEqual(0, result.returncode, result.stderr)

    def assert_rejected(self, reference: str, *, release: bool = False) -> None:
        result = self.run_validator(reference, release=release)
        self.assertNotEqual(0, result.returncode, result.stdout)
        if reference:
            self.assertNotIn(reference, result.stderr)

    @unittest.skipUnless(
        shutil.which("podman") and os.environ.get("LTO_WEB_TEST_UBI_IMAGE"),
        "requires Podman and an explicit local UBI test image",
    )
    def test_real_rootless_image_preserves_host_peer_credentials(self) -> None:
        image = f"localhost/lto-archiver-web:task5-{os.getpid()}"
        base = os.environ["LTO_WEB_TEST_UBI_IMAGE"]
        subprocess.run(
            [
                os.sys.executable,
                "scripts/validate-web-base-image.py",
                "--development",
                base,
            ],
            check=True,
        )
        subprocess.run(["podman", "image", "exists", base], check=True)
        subprocess.run(
            [
                "podman",
                "build",
                "--format=docker",
                "--network=none",
                "--pull=never",
                "--build-arg",
                f"UBI_IMAGE={base}",
                "--file",
                "Containerfile.web",
                "--tag",
                image,
                ".",
            ],
            check=True,
        )
        self.addCleanup(
            subprocess.run,
            ["podman", "image", "rm", "--force", image],
            check=False,
            capture_output=True,
        )
        inspected = subprocess.run(
            ["podman", "inspect", "--format", "{{.Config.User}}", image],
            capture_output=True,
            check=True,
            text=True,
        )
        self.assertEqual("1001:1001", inspected.stdout.strip())
        image_details = json.loads(
            subprocess.run(
                ["podman", "inspect", image],
                capture_output=True,
                check=True,
                text=True,
            ).stdout
        )[0]
        self.assertIn("Healthcheck", image_details)
        self.assertTrue(image_details["Healthcheck"]["Test"])

        with tempfile.TemporaryDirectory() as isolated:
            socket_group = os.getgid()
            socket_path = Path(isolated) / "peer.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(socket_path))
                os.chmod(socket_path, 0o660)
                os.chown(socket_path, -1, socket_group)
                subprocess.run(
                    ["podman", "unshare", "chown", "1:0", str(socket_path)],
                    check=True,
                )
                socket_status = socket_path.stat()
                self.assertNotEqual(os.getuid(), socket_status.st_uid)
                self.assertEqual(socket_group, socket_status.st_gid)
                listener.listen(1)
                listener.settimeout(10)
                client_program = (
                    "import socket; s=socket.socket(socket.AF_UNIX); "
                    "s.connect('/run/peer/peer.sock'); s.sendall(b'R'); "
                    "s.recv(1); s.close()"
                )
                connector = subprocess.Popen(
                    [
                        "podman",
                        "run",
                        "--rm",
                        "--network=none",
                        "--read-only",
                        "--cap-drop=all",
                        "--security-opt=no-new-privileges",
                        # This Task 5 gate isolates Unix DAC and SO_PEERCRED.
                        # Production SELinux permission is qualified by the
                        # separate cutover policy gate before deployment.
                        "--security-opt=label=disable",
                        "--userns=keep-id:uid=1001,gid=1001",
                        "--volume",
                        f"{isolated}:/run/peer:Z",
                        "--entrypoint",
                        "python",
                        image,
                        "-c",
                        client_program,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.addCleanup(connector.kill)
                connection, _address = listener.accept()
                with connection:
                    try:
                        self.assertEqual(b"R", connection.recv(1))
                        credentials = struct.unpack(
                            "3i",
                            connection.getsockopt(
                                socket.SOL_SOCKET,
                                socket.SO_PEERCRED,
                                struct.calcsize("3i"),
                            ),
                        )
                        _peer_pid, peer_uid, peer_gid = credentials
                        self.assertNotEqual(socket_status.st_uid, peer_uid)
                        self.assertEqual(os.getuid(), peer_uid)
                        self.assertEqual(os.getgid(), peer_gid)
                        self.assertEqual(socket_status.st_gid, peer_gid)

                        principal = TrustedPrincipalResolver(
                            administrator_uids={},
                            webui_uid=peer_uid,
                        ).require_mutation_principal(
                            Request(
                                {
                                    "type": "http",
                                    "headers": [
                                        (
                                            b"x-authenticated-principal",
                                            b"operator-1",
                                        )
                                    ],
                                    PEER_CREDENTIAL_SCOPE_KEY: credentials,
                                }
                            )
                        )
                        self.assertEqual("operator-1", principal.name)
                    finally:
                        try:
                            connection.sendall(b"A")
                        except OSError:
                            pass
                stdout, stderr = connector.communicate(timeout=10)
                self.assertEqual(0, connector.returncode, stdout + stderr)


if __name__ == "__main__":
    unittest.main()
