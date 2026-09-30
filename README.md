# LTO Archiver

LTO Archiver is an open-source RHEL 9 service for sequential, append-only
backup to LTFS tapes. Its authenticated WebUI handles shares, libraries, jobs,
cassette changes, catalog search and restore. The WebUI has no direct tape,
source-share or catalog-database access: privileged operations are admitted
through the daemon and separate brokers.

## Source version and compatibility

This source tree targets application **0.11.28-155**, Python runtime **3**,
external LTFS driver **22** (`lto-ltfs 0.1.0-22.el9`), and catalog **schema 41**.
These are package/source identities, not a claim that public RPMs or a public
release already exist. Verify installed versions on the target host before an
installation; release 155 is a fresh disposable-host path, not a qualified
upgrade. The driver has its own repository, provenance, license and release
process; this application does not embed or rebuild it.

The application and driver are independent of Hewlett Packard Enterprise.
No HPE firmware, installer, diagnostic package, proprietary driver or vendor
support entitlement is distributed here. HPE and related marks belong to
their respective owners.

## Safety model

Saving a backup plan does not start it. Native formatting is destructive and
requires administrator authorization for an exact cassette and layout. An
active write, mount, finalization or unload is not an installation window.
`waiting_media` alone does not prove quiescence. Do not manually alter the
catalog or treat an RPM installation as permission to resume a job.

A completed cassette becomes searchable after durable catalog commit and
successful LTFS finalization. The catalog stores metadata, not tape bytes.
Restore is an explicit cassette-ordered, read-only LTFS operation to a safe
destination; conflicting files require separate authorization. Physical
driver and tape qualification is separate from hardware-free application
tests.

## Install and operate

Begin with the [RHEL 9 installation guide](docs/linux/installation-rhel9.md)
and [English operator index](docs/en/index.md). Verify signed RPMs and exact
application/runtime/driver dependencies before installation. Use the
[WebUI guide](docs/linux/webui.md) to configure shares and libraries, scan,
plan, then explicitly start a job. The [catalog search guide](docs/linux/catalog-search.md)
covers offline metadata lookup. The [release process](docs/en/release-process.md)
explains build, signatures and publication; GitHub Releases are direct asset
downloads, not a DNF repository.
The [GitHub-built RPM verification guide](docs/en/github-rpm-verification.md)
lists the two approval gates, signature and attestation checks, and exact
download/install order. No public RPM is implied by this source snapshot.

For source builds and contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).
For reports, use [SUPPORT.md](SUPPORT.md); for vulnerabilities, use
[SECURITY.md](SECURITY.md). Never attach credentials, raw catalogs, media
identifiers, unsanitized logs or private host details to a public report.

## Known limits

Normal backup does not read back every tape file. A changed version of a
path already completed on an earlier cassette is a separate semantic
limitation from unused-suffix replanning. Publication-content auditing and
physical-media qualification require their own evidence. Only the supported
RHEL 9/Linux distribution is described here; no Windows installer is shipped.
The public disposable-VM smoke covers installation, genuine WebUI login and
correct hardware-preflight refusal with no tape/SCSI device. It does not cover
daemon-mediated import, physical LTFS operations or backup/restore.

## License

LTO Archiver is licensed under [Apache-2.0](LICENSE), with additional
attributions in [NOTICE](NOTICE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The separately released
LTFS driver has its own license and source-provenance inventory.
