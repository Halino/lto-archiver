# LTO Archiver 0.11.29-155 — next source candidate

This is local preparation of the next Linux application identity, paired with
driver `0.1.1-22.el9` from [Halino/lto-ltfs-driver](https://github.com/Halino/lto-ltfs-driver).
The exact tuple is application `0.11.29-155.el9`, Python runtime
`0.11.27-3.el9`, driver `0.1.1-22.el9`, and catalog schema 41. The runtime and
schema do not change.

The candidate fixes the application build-container Git bootstrap order and
font-dependent dashboard/restore layout failures found in public CI. The
separate driver candidate prepares its full pinned upstream provenance fixture
and supplies the previously pinned pkg-config dependency closure for fresh RPM
installation. These fixes are source changes, not evidence of a completed
GitHub build, signing, attestation or install qualification.

The existing `v0.11.28` application and `v0.1.0` driver tags retain their
published source identities. This candidate must not move either tag or replace
historical releases or assets. Its new source, history, tag and final package
bytes need separate review before publication.

Linux RPM build and qualification remain pending; no signed Linux RPM release
is claimed. Follow the [release process](en/release-process.md) and
[RPM verification guide](en/github-rpm-verification.md) only with independently
approved source and final artifacts. The acceptance route remains first install
on a fresh, restorable disposable RHEL 9 VM with a genuine WebUI login,
expected no-tape hardware refusal and snapshot restoration.

No upgrade, catalog migration, daemon-mediated import, physical LTFS,
backup/restore or automatic Resume is qualified by this profile. Windows
source and immutable historical ZIP releases remain in the
[Windows archive](windows-archive.md). Earlier feature changes are recorded in
the [0.11.28 source notes](release-notes-0.11.28-155.md).
