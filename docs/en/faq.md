# Linux operator FAQ

Release **0.11.27-129** is Linux/WebUI-only. See the
[WebUI guide](../linux/webui.md) for the complete workflow.

**Does saving start a job?** No. Review the frozen plan and required authority,
then start explicitly.

**Can a file span tapes?** No. Planning keeps each file whole and accounts for
LTFS allocation and metadata, not just its payload bytes.

**Does a pending write prove physical completion?** No. Telemetry is not
completion evidence; finalization, unmount and the required receipts must succeed.

**Does normal backup read back a completed tape?** No. The separate
[release process](release-process.md) requires separately authorized
physical qualification and sampled readback; see the
[public safety checklist](../qualification/physical-ltfs-runbook.md). A sample does not prove every written byte.

**Can the catalog be searched without a tape?** Yes. Catalog discovery is
metadata-only. Restore execution needs the requested cassette and a read-only
LTFS mount. See [catalog search](../linux/catalog-search.md).

**Can Windows-origin state be migrated?** Yes, through the protected
[offline migration](../linux/migration.md) workflow. No Windows application is
distributed in this release.
