# LTO Archiver operator manuals

This source tree targets application **0.11.28-155**, Python runtime **3**,
external LTFS driver **22**, catalog **schema 41**, and RHEL 9. The exact
installed versions and release signatures must be verified on the host; a
source snapshot is not an installed or physically qualified release.

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
- [Windows-origin migration](../linux/migration.md): offline catalog and path
  migration; no Windows application is distributed.

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
