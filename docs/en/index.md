# LTO Archiver Linux operator manuals

This source tree targets application **0.11.28-155**, Python runtime **3**,
external LTFS driver **22**, catalog **schema 41**, and RHEL 9. The exact
installed versions and release signatures must be verified on the host; a
source snapshot is not an installed or physically qualified release. The active
source branch is [`linux`](https://github.com/Halino/lto-archiver/tree/linux).
Linux RPM publication and qualification remain pending; see the
[current candidate notes](../release-notes-0.11.28-155.md).

## Choose a path

- [New installation](installation.md): prerequisites, signed RPM verification,
  activation and post-install smoke checks.
- [First backup](user-guide.md#first-backup): configure shares and libraries,
  scan, plan, save, then explicitly start.
- [Routine operations](user-guide.md): cassette changes, progress, catalog
  search, offline browsing and restore.
- [Administration](administration.md): backup, quiescence, upgrades and
  rollback.
- [LTFS operations](ltfs-operations.md): drive safety and troubleshooting.
- [Release process](release-process.md): source, test, signature and
  publication gates.
- [Legacy-capture import on Linux](../linux/migration.md): offline catalog and
  path compatibility, outside fresh-install qualification.
- [Windows archive](../windows-archive.md): historical source and releases,
  outside the active Linux installation path.

The [RHEL 9 installation guide](../linux/installation-rhel9.md),
[WebUI workflow](../linux/webui.md) and
[catalog search guide](../linux/catalog-search.md) provide detailed
operator steps.

## Safety boundary

LTO tape writes are sequential. Native format is destructive and requires
exact authorization. `APPEND` preserves committed data. A cassette is not
complete until its data, LTFS index, catalog state, unmount and eject have
been verified. An active operation or `waiting_media` alone is not a safe
installation boundary. Never manipulate tape to satisfy a software-release
gate.
