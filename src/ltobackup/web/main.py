from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys
import warnings
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import uvicorn

from ltobackup.client import UnixDaemonClient
from ltobackup.errors import ValidationError

from .app import WebSettings, create_web_app
from .auth_store import AuthStore, User

_DEFAULT_AUTH_DATABASE = Path("/var/lib/lto-archiver-web/auth.sqlite3")
_DEFAULT_DAEMON_SOCKET = Path("/run/lto-archiver/daemon.sock")
_MAX_PASSWORD_BYTES = 4096


def _port(value: str) -> int:
    try:
        port = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _positive_seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not 0 < seconds <= 300:
        raise argparse.ArgumentTypeError("timeout must be between 0 and 300 seconds")
    return seconds


def _file_descriptor(value: str) -> int:
    try:
        descriptor = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "password descriptor must be an integer"
        ) from exc
    if descriptor < 0:
        raise argparse.ArgumentTypeError("password descriptor must be non-negative")
    return descriptor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lto-archiver-web", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser(
        "serve",
        help="serve the unprivileged WebUI",
        allow_abbrev=False,
    )
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=_port, default=8080)
    serve.add_argument("--auth-db", type=Path, default=_DEFAULT_AUTH_DATABASE)
    serve.add_argument(
        "--daemon-socket",
        type=Path,
        default=_DEFAULT_DAEMON_SOCKET,
    )
    serve.add_argument(
        "--daemon-timeout-seconds",
        type=_positive_seconds,
        default=10.0,
    )
    serve.add_argument("--tls-certfile", type=Path)
    serve.add_argument("--tls-keyfile", type=Path)

    admin = commands.add_parser(
        "admin",
        help="manage WebUI-only administrators",
        allow_abbrev=False,
    )
    admin_commands = admin.add_subparsers(dest="admin_command", required=True)
    create = admin_commands.add_parser(
        "create",
        help="create a WebUI administrator",
        allow_abbrev=False,
    )
    create.add_argument("--username", required=True)
    create.add_argument("--auth-db", type=Path, default=_DEFAULT_AUTH_DATABASE)
    create.add_argument(
        "--password-fd",
        type=_file_descriptor,
        help="read one UTF-8 password line from this inherited file descriptor",
    )
    reset = admin_commands.add_parser(
        "reset",
        help="reset a WebUI account password",
        allow_abbrev=False,
    )
    reset.add_argument("--username", required=True)
    reset.add_argument("--auth-db", type=Path, default=_DEFAULT_AUTH_DATABASE)
    reset.add_argument(
        "--password-fd",
        type=_file_descriptor,
        help="read one UTF-8 password line from this inherited file descriptor",
    )
    for command, help_text in (
        ("enable", "enable a disabled WebUI account"),
        ("revoke", "revoke every session for a WebUI account"),
    ):
        action = admin_commands.add_parser(
            command,
            help=help_text,
            allow_abbrev=False,
        )
        action.add_argument("--username", required=True)
        action.add_argument("--auth-db", type=Path, default=_DEFAULT_AUTH_DATABASE)
    listing = admin_commands.add_parser(
        "list",
        help="list WebUI accounts without credential material",
        allow_abbrev=False,
    )
    listing.add_argument("--auth-db", type=Path, default=_DEFAULT_AUTH_DATABASE)
    return parser


@dataclass(frozen=True)
class WebRuntime:
    app: object
    auth_store: AuthStore
    daemon_client: UnixDaemonClient

    def close(self) -> None:
        self.daemon_client.close()


def prepare_runtime(args: argparse.Namespace) -> WebRuntime:
    """Construct only WebUI authentication state and the daemon UDS client."""

    daemon_client = UnixDaemonClient(
        args.daemon_socket,
        timeout_seconds=args.daemon_timeout_seconds,
    )
    try:
        auth_store = AuthStore(args.auth_db)
        app = create_web_app(WebSettings(), auth_store, daemon_client)
    except BaseException:
        daemon_client.close()
        raise
    return WebRuntime(app=app, auth_store=auth_store, daemon_client=daemon_client)


def _password_from_tty() -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass("Password: ")
    except (EOFError, getpass.GetPassWarning) as exc:
        raise RuntimeError("password input requires a terminal TTY") from exc


def _password_from_descriptor(descriptor: int) -> str:
    payload = bytearray()
    while True:
        chunk = os.read(descriptor, 1)
        if not chunk or chunk == b"\n":
            break
        payload.extend(chunk)
        if len(payload) > _MAX_PASSWORD_BYTES:
            raise RuntimeError("password input exceeds the supported limit")
    if payload.endswith(b"\r"):
        del payload[-1:]
    if not payload:
        raise RuntimeError("password descriptor must not be empty")
    if b"\x00" in payload or b"\n" in payload or b"\r" in payload:
        raise RuntimeError("password descriptor must contain exactly one line")
    try:
        return bytes(payload).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RuntimeError("password descriptor must contain UTF-8") from exc


def _create_admin(
    args: argparse.Namespace,
    password_reader: Callable[[], str],
) -> int:
    try:
        password = (
            password_reader()
            if args.password_fd is None
            else _password_from_descriptor(args.password_fd)
        )
        AuthStore(args.auth_db).create_admin(args.username, password)
    except (OSError, RuntimeError, ValidationError) as exc:
        raise SystemExit(str(exc)) from exc
    finally:
        if "password" in locals():
            password = ""
    print("Administrator created")
    return 0


def _read_password(args: argparse.Namespace, password_reader: Callable[[], str]) -> str:
    return (
        password_reader()
        if args.password_fd is None
        else _password_from_descriptor(args.password_fd)
    )


def _require_cli_user(store: AuthStore, username: str) -> User:
    try:
        user = store.get_user_by_login(username)
    except ValidationError as exc:
        raise SystemExit(str(exc)) from exc
    if user is None:
        raise SystemExit("WebUI account not found")
    return user


def _reset_account(
    args: argparse.Namespace,
    password_reader: Callable[[], str],
) -> int:
    try:
        password = _read_password(args, password_reader)
        store = AuthStore(args.auth_db)
        user = _require_cli_user(store, args.username)
        store.reset_password_break_glass(
            target_user_id=user.id,
            new_password=password,
            idempotency_key=secrets.token_hex(24),
        )
    except (OSError, RuntimeError, ValidationError) as exc:
        raise SystemExit(str(exc)) from exc
    finally:
        if "password" in locals():
            password = ""
    print("Password reset")
    return 0


def _enable_account(args: argparse.Namespace) -> int:
    try:
        store = AuthStore(args.auth_db)
        user = _require_cli_user(store, args.username)
        store.enable_user(
            actor_user_id=None,
            target_user_id=user.id,
            idempotency_key=secrets.token_hex(24),
            allow_break_glass=True,
        )
    except ValidationError as exc:
        raise SystemExit(str(exc)) from exc
    print("Account enabled")
    return 0


def _revoke_account_sessions(args: argparse.Namespace) -> int:
    try:
        store = AuthStore(args.auth_db)
        user = _require_cli_user(store, args.username)
        store.revoke_user_sessions(
            actor_user_id=None,
            target_user_id=user.id,
            idempotency_key=secrets.token_hex(24),
            allow_break_glass=True,
        )
    except ValidationError as exc:
        raise SystemExit(str(exc)) from exc
    print("Sessions revoked")
    return 0


def _list_accounts(args: argparse.Namespace) -> int:
    for user in AuthStore(args.auth_db).list_users():
        print(f"{user.login_name}\t{user.role}\t{user.state}")
    return 0


def _serve(args: argparse.Namespace) -> int:
    if (args.tls_certfile is None) != (args.tls_keyfile is None):
        raise SystemExit("TLS certificate and key must be supplied together")
    runtime = prepare_runtime(args)
    try:
        uvicorn.run(
            runtime.app,
            host=args.host,
            port=args.port,
            proxy_headers=False,
            server_header=False,
            ssl_certfile=(
                None if args.tls_certfile is None else str(args.tls_certfile)
            ),
            ssl_keyfile=(None if args.tls_keyfile is None else str(args.tls_keyfile)),
        )
    finally:
        runtime.close()
    return 0


def main(
    argv: Sequence[str] | None = None,
    *,
    password_reader: Callable[[], str] = _password_from_tty,
) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        return _serve(args)
    if args.command == "admin" and args.admin_command == "create":
        return _create_admin(args, password_reader)
    if args.command == "admin" and args.admin_command == "reset":
        return _reset_account(args, password_reader)
    if args.command == "admin" and args.admin_command == "enable":
        return _enable_account(args)
    if args.command == "admin" and args.admin_command == "revoke":
        return _revoke_account_sessions(args)
    if args.command == "admin" and args.admin_command == "list":
        return _list_accounts(args)
    raise SystemExit("unsupported WebUI command")


if __name__ == "__main__":
    sys.exit(main())
