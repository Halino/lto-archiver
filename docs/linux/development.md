# Linux daemon foundation development

The foundation daemon can be exercised without a tape drive, SCSI generic
device, LTFS mount, or remote server. Its drive status remains `unavailable`;
the device paths below are stable-path-shaped placeholders that are validated
but never opened by this phase.

Run all commands from the repository root as a non-root development user.
Python 3.11 and the test extra must already be installed.

## Temporary development configuration

Create isolated state, runtime, source, restore, and synthetic mount
directories:

```bash
export LTO_DEV_ROOT="$(mktemp -d /tmp/lto-archiver-dev.XXXXXX)"
export LTO_DEV_CONFIG="$LTO_DEV_ROOT/config.toml"
export LTO_DEV_SOCKET="$LTO_DEV_ROOT/run/daemon.sock"
mkdir -p \
  "$LTO_DEV_ROOT/state" \
  "$LTO_DEV_ROOT/run" \
  "$LTO_DEV_ROOT/source" \
  "$LTO_DEV_ROOT/restore" \
  "$LTO_DEV_ROOT/mount"
```

Write the configuration. The current user's primary group owns the
development socket:

```bash
cat >"$LTO_DEV_CONFIG" <<EOF
state_dir = "$LTO_DEV_ROOT/state"
socket_path = "$LTO_DEV_SOCKET"
socket_group = "$(id -gn)"
tape_device_path = "/dev/tape/by-id/development-drive"
scsi_device_path = "/dev/lto-archiver-scsi-development-generic"
mount_path = "$LTO_DEV_ROOT/mount"
source_roots = ["$LTO_DEV_ROOT/source"]
restore_roots = ["$LTO_DEV_ROOT/restore"]
buffer_bytes = 8388608
EOF
```

## Foreground daemon and health check

Start the daemon in the foreground in terminal 1:

```bash
PYTHONPATH=src python3.11 -m ltobackup.daemon.main \
  --config "$LTO_DEV_CONFIG" \
  --webui-user "$(id -un)" \
  --shutdown-timeout-seconds 30
```

Wait for the socket, then query the read-only health endpoint from terminal 2:

```bash
test -S "$LTO_DEV_SOCKET"
curl --fail --silent --show-error \
  --unix-socket "$LTO_DEV_SOCKET" \
  http://localhost/api/v1/health
```

The response is:

```json
{"status":"ok","api_version":1}
```

Stop the foreground daemon with `Ctrl-C` and wait for it to return to the
shell. For a scripted smoke run, send `SIGTERM` to the exact daemon PID and
wait for that process:

```bash
PYTHONPATH=src python3.11 -m ltobackup.daemon.main \
  --config "$LTO_DEV_CONFIG" \
  --webui-user "$(id -un)" \
  --shutdown-timeout-seconds 30 &
LTO_DAEMON_PID=$!
for _attempt in $(seq 1 100); do
  test -S "$LTO_DEV_SOCKET" && break
  sleep 0.1
done
test -S "$LTO_DEV_SOCKET"
kill -TERM "$LTO_DAEMON_PID"
wait "$LTO_DAEMON_PID"
```

Do not use `SIGKILL`: orderly shutdown closes mutation admission, waits for
workers up to `--shutdown-timeout-seconds` (30 seconds by default), and durably
changes timed-out operations to `recovery_required`. A command already released
by a worker is not declared stopped. Its command-ledger row remains
non-quiescent until the supervisor records exact exit evidence and physical
reconciliation. A timed-out Python callback is fenced and cannot keep process
exit waiting; shutdown does not claim that any already launched external
command has stopped.

## RHEL RPM source and package gates

Run the packaging pipeline suite from the clean Git worktree before invoking
the RPM builder:

```bash
PYTHONPATH=src python3.11 -m unittest tests.test_linux_packaging -v
```

This is a pre-build repository gate. It intentionally exercises Git-bound
Source0 creation, the four-argument signing builder, reproducibility, and
adversarial publication fixtures. The signed release gate must run from its
clean committed checkout; RPM `%check` must not recursively invoke that release
gate. RPM `%check` retains its Source0-safe functional checks for RHEL preflight,
private-runtime launchers and share-broker packaging.

The separate full Linux-export suite is invoked from the committed checkout:

```bash
/bin/bash packaging/scripts/test-linux-release.sh /absolute/python3.11
```

Supply the absolute prepared Python3.11 interpreter path. This wrapper tests
the committed Linux export, including WebUI tests. Export-aware inventory tests
check the actual exported files, while tests requiring Git create disposable
fixture repositories; this does not grant an extracted archive authority to
build or sign a release. The full Linux-export suite, signed repository gate
and RPM `%check` are distinct requirements; failure in any blocks release.

The private runtime supplies third-party dependencies only. Application
launchers prepend the RPM-owned global application site after adding the
private dependency site, which makes the application site the effective first
entry. The launcher test deliberately places a stale `ltobackup` package in the
private path and proves it cannot shadow the installed application.

The release entrypoint is `packaging/rpm/release-rhel9-rpm.sh`. Its four
arguments are the new output directory, explicit private `GNUPGHOME`, primary
fingerprint, and signing-subkey fingerprint. It runs the repository gate,
rechecks the same clean commit, signs a canonical gate report, and only then
calls the internal `build-rhel9-rpm.sh`. The internal builder refuses missing,
tampered, unsigned, wrong-commit, or wrong-builder evidence; do not invoke it
directly. The canonical gate report and its detached signature are retained
under `VERIFICATION/` and covered by the release `SHA256SUMS` and its signature.

## Hardware-free Foundation gate

Run the complete Foundation suite:

```bash
PYTHONPATH=src python3.11 -m unittest \
  tests.test_linux_settings \
  tests.test_catalog \
  tests.test_catalog_backups \
  tests.test_daemon_operations \
  tests.test_daemon_api \
  tests.test_linux_entrypoints \
  tests.test_linux_foundation_integration \
  -v
```

Run static and formatting gates:

```bash
ruff check \
  src/ltobackup/daemon/events.py \
  src/ltobackup/daemon/main.py \
  src/ltobackup/daemon/operations.py \
  src/ltobackup/daemon/service.py \
  tests/test_daemon_api.py \
  tests/test_linux_foundation_integration.py
ruff format --check \
  src/ltobackup/daemon/events.py \
  src/ltobackup/daemon/main.py \
  src/ltobackup/daemon/operations.py \
  src/ltobackup/daemon/service.py \
  tests/test_daemon_api.py \
  tests/test_linux_foundation_integration.py
git diff --check
```

These commands do not mount, format, unload, or probe tape hardware. Keep the
temporary state directory when investigating restart/recovery behavior; remove
it only after every daemon process using its socket and catalog has exited.
