# LTO Archiver 0.11.28-155 — public release preparation

This distinct version is prepared for `Halino/lto-archiver` and tag
`v0.11.28`. It must not replace the existing `v0.11.27` release or its assets.
The separate driver destination is `Halino/lto-ltfs-driver`; private driver
history must not be made public by changing repository visibility.

The exact package tuple is application `0.11.28-155.el9`, Python runtime
`0.11.27-3.el9`, driver `0.1.0-22.el9`, and catalog schema 41. The application
version changes for the distinct public identity; the runtime, driver and
catalog compatibility requirements do not change. See the earlier
[155 feature notes](release-notes-0.11.27-155.md) for the source change-time
policy and historical-version limitations.

Public RPMs and SRPMs must be built from the reviewed source on GitHub,
compared across independent builds, signed, attested and verified before
publication. Local build success does not constitute GitHub provenance.

The supported qualification route is first install on a clean, restorable
disposable RHEL 9 VM. The smoke must prove a genuine WebUI login and correct
hardware-preflight refusal when tape/SCSI devices are absent, then observe
uninstall residue and prove snapshot restoration. Daemon-mediated import,
physical LTFS and backup/restore remain unverified in this profile. The
[smoke evidence contract](linux/public-fresh-install-smoke.md) records these
limits explicitly. No private-host upgrade, automatic Resume or tape
operation is authorized by this release preparation.

This source preparation does not assert that a GitHub build, signed asset
set, VM smoke or public Release has completed. Exact public source transfer
and final signed-asset publication remain separate approval gates.
