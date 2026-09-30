# LTFS operations and safe completion

## Native schema 41 cassette sequence

schema 41 preserves one cassette per fenced operation: each cassette receives
its own exact operation, expected-media scope, LTFS session, and recovery fence.
For a new job, an administrator must select **Authorize automatic formatting**
when saving the ordered plan. The authority binds the job, layout fingerprint,
cassette sequence, normalized physical label, format operation, and registered
reuse decision. For an existing job without exact current-layout authority,
use the one-time authorization action; the upgrade never infers destructive
authority.

Adding a format or reserve operation, or extending a layout while any format
row is `pending` or `waiting_media`, requires a fresh administrator grant in
that reserve or extension request.
Authority from an earlier layout never carries forward. Old immutable rows
remain audit history; admission consults only the current epoch and fingerprint.
An append-only extension may proceed without destructive authority only when no
existing format row is pending or waiting; it rebinds the sequence disabled at
the unloaded boundary without changing frozen file placement or reserve order.

Every new cassette continuation stores immutable provenance for the original
operation, job, sequence, layout epoch and fingerprint, deterministic key, and
hardware target. Format also requires exactly one matching authority and
confirmation; append requires neither. Replay after restart or a later layout
extension uses only those persisted rows. Missing or mismatched legacy
provenance fails closed and never dispatches another worker.

Insert cassettes in the displayed order. A standalone drive cannot validate a
printed label on blank media, so blank-media authority applies only to the exact
expected tuple. A recognized incompatible LTFS medium is never reformatted
automatically. Stop safely and use the expected-label, critical-recovery, or
imported-job confirmation workflow as appropriate.

After a confirmed eject, a nonfinal job waits in `waiting_media`; insertion of
the next expected cassette permits the coordinator to admit its separate
operation. A pause is applied only at this unloaded checkpoint. On restart, the
coordinator reconciles existing command, mount, finalization, and eject receipts
before continuation; ambiguity is a recovery gate, not permission to retry or
format.

## Linux ownership and completion

The packaged Linux runtime uses `sync_type=unmount`. The privileged broker starts
the FUSE process as root with `allow_other,default_permissions`; the mount is
reachable only below the group-restricted `/mnt/lto-archiver` parent. This lets
the unprivileged daemon use the mounted volume without granting the WebUI access.
Removing either option must fail the release gate.

Filesystem write/close return is not proof that physical tape and LTFS index
work have finished. A block becomes searchable only after successful finalization,
unmount and catalog commit. Do not power off, kill the provider, eject media or
claim completion while finalization remains pending. Normal backup does not
remount the completed tape for readback.

Use [troubleshooting](troubleshooting.md) for safe diagnostics. No
concurrent device probes are permitted while the provider owns the drive.
Physical qualification and sampled readback require a separately reviewed
procedure, exact authorization, the [public safety checklist](../qualification/physical-ltfs-runbook.md),
and the [release gate](release-process.md).
