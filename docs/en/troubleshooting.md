# Troubleshooting

## Current Linux operational logs

Use the **WebUI first**. The Operational log page keeps the last good page
visible while it is reconnecting and identifies any temporarily unavailable
source. If **cursor rotation** expires an immutable cursor, restart from the
newest available entry; do not guess a replacement cursor.

If every source is unavailable, an administrator may inspect the reader socket
and services without touching the tape:

```console
sudo systemctl status lto-archiver-log-reader.socket \
  lto-archiver-log-reader.service lto-archiverd.service \
  lto-archiver-web.service
sudo stat /run/lto-archiver-log-reader/control.sock
sudo ausearch -m AVC,USER_AVC -ts recent
```

The socket must be `root:lto-log-read` mode `0660`, the daemon is its only
application client, and SELinux must permit the expected transition. For
offline escalation, use bounded `journalctl --since` queries against only the
six documented units. Redact output before sharing it. Never weaken the socket,
SELinux, or unit allowlist to make diagnostics succeed.

## Safe observation and escalation

For **No cache samples**, retain the telemetry gap; it is not evidence of zero
speed or a reason to invent progress. For **Wrong tape**, preserve the identity
mismatch; never write to test it. For **Full tape**, preserve the capacity error
and plan another cassette, never delete tape files or catalog rows to make space.

**Forbidden concurrent actions:** do not start a second writer, force eject,
kill the LTFS provider, mount a tape for catalog search, or edit SQLite rows.
**Escalation:** retain redacted phase/error evidence and involve the administrator
while the recovery fence remains closed. Preserve verified backups before any
state-changing diagnostic; do not open the live catalog from another process.

For **Release verification**, follow the signed deployment gate; failure is not
permission to replace installed files or weaken policy. During a long LTFS
close or finalization, observe bounded service and journal state; do not start
a competing operation. For exclusive semaphore contention, wait for the owner
to release the device or escalate after a verified safe stop. Treat `Clean
requested` as a drive-maintenance indication, not permission to interrupt an
active write; follow the hardware vendor's procedure at a safe boundary.
