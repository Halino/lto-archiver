# LTO Archiver operator manuals

These operator manuals describe public release **0.11.26** for Windows Server
2022 and append-only SMB archives on LTFS tape. HPE StoreOpen, HPE drivers, and
HPE support tools are external prerequisites; they are not bundled with LTO
Archiver.

## Choose a path

- [New installation](installation.md): prerequisites, checksum, installer, CFA,
  upgrade, and removal.
- [First backup](user-guide.md#first-backup): register, scan, plan, save, then
  explicitly start a first job.
- [Routine operations](user-guide.md): media changes, progress, stopping,
  catalog search, offline browsing, and restore.
- [Troubleshooting](../troubleshooting.md): non-destructive diagnosis of slow
  LTFS operations.
- [Development](../development.md) and [release management](../release-notes-0.11.26.md):
  local engineering and the 0.11.26 release record.

Read [administration](administration.md) before operating the shared state and
[LTFS operations](ltfs-operations.md) before diagnosing a mounted drive. The
same manuals are available in [Italiano](../it/index.md).

## Safety boundary

LTO tape writes are sequential. `NUOVA` formats a tape destructively, while
`APPEND` preserves committed data. A file is followed by the next file only
after `close.complete`; a tape is complete only after StoreOpen unmounts it and
the LTFS index is consolidated.
