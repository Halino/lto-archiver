# Linux command-line boundaries

Release **0.11.28-155** uses the authenticated [Linux WebUI](../linux/webui.md)
as the operator surface. The legacy `lto-backup` job and catalog workflow is not
a supported Linux operator path. Do not use it to open the authoritative catalog
or bypass daemon ownership.

Use [RHEL installation](../linux/installation-rhel9.md) for packaged administrator
commands, [administration](administration.md) for protected state and recovery,
and [release process](release-process.md) for signed deployment tools.
Physical qualification requires a separately reviewed procedure and exact
authorization; see the [public safety checklist](../qualification/physical-ltfs-runbook.md).
It is not a normal backup or an implicit grant to use hardware.

For Windows-origin catalogs and paths, use only the documented
[offline migration](../linux/migration.md) process. Preserve the original state
and work on verified copies; migration support does not ship a Windows executable.
