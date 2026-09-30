from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from ltobackup.daemon.models import (
    CommandExitEvidence,
    OperationFence,
    RecoveryCommandFence,
)

from .command_supervisor import (
    CompletedCommand,
    ExecutionScopeIdentity,
    LaunchGate,
    RunningCommand,
)
from .models import (
    ExpectedMedia,
    MediaIdentity,
    MountedTape,
    TapeTelemetry,
    UnmountResult,
)


class CommandLauncher(Protocol):
    def launch_blocked(
        self,
        argv: tuple[str, ...],
        scope_identity: ExecutionScopeIdentity,
        pass_fds: tuple[int, ...] = (),
    ) -> LaunchGate: ...


class UnmountObserver(Protocol):
    def finalization_started(self) -> None: ...

    def mount_release_started(self) -> None: ...


class TapeBackend(Protocol):
    def wait_for_media(
        self, expected: ExpectedMedia, stop: Callable[[], bool]
    ) -> bool: ...

    def identify(self) -> MediaIdentity: ...

    def format(self, expected: ExpectedMedia) -> None: ...

    def mount(self, *, read_only: bool) -> MountedTape: ...

    def unmount(
        self, mounted: MountedTape, observer: UnmountObserver
    ) -> UnmountResult: ...

    def unload(self) -> None: ...

    def telemetry(self) -> TapeTelemetry: ...


class CommandSupervisor(Protocol):
    def start(
        self,
        fence: OperationFence | RecoveryCommandFence,
        kind: str,
        argv: tuple[str, ...],
        pass_fds: tuple[int, ...] = (),
    ) -> RunningCommand: ...

    def assert_running(self, command: RunningCommand) -> None: ...

    def terminate_and_await(self, command_id: str) -> CommandExitEvidence: ...

    def run(
        self,
        fence: OperationFence | RecoveryCommandFence,
        kind: str,
        argv: tuple[str, ...],
        timeout: float,
        pass_fds: tuple[int, ...] = (),
    ) -> CompletedCommand: ...
