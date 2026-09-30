# Linux operator FAQ

The current source candidate **0.11.30-155** is Linux/WebUI-only, paired with
runtime **0.11.27-3**, driver **0.1.2-22**, and catalog **schema 41**. Linux RPM
publication and qualification are pending. See the
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

**Can existing legacy state be imported?** The Linux source includes protected
[offline import](../linux/migration.md) of an existing sealed capture. It is
outside the fresh-install smoke qualification profile. Windows application
guidance is in the [Windows archive](../windows-archive.md).
