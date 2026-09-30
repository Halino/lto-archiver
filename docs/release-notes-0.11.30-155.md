# LTO Archiver 0.11.30-155 — successor source candidate

This local source candidate pairs application `0.11.30-155.el9` with
driver `0.1.2-22.el9` from
[Halino/lto-ltfs-driver](https://github.com/Halino/lto-ltfs-driver).
Python runtime `0.11.27-3.el9` and catalog schema 41 remain unchanged.

Both application build-container jobs now trust only their exact checked-out
workspace before the existing exact tag, commit and clean-tree admission.
The driver successor aligns its native version regression with the compiled
project identity. These source corrections do not qualify RPM artifacts.

Published application `v0.11.29` and driver `v0.1.1` source tags remain
immutable. Successor source/history/tag approval, GitHub builds, signing,
attestation, disposable-host acceptance and RPM publication are pending.
No successor tag or signed Linux RPM availability is claimed.

The acceptance route remains first install on a fresh, restorable disposable
RHEL 9 VM with a genuine WebUI login, expected no-tape hardware refusal and
snapshot restoration. No upgrade, catalog migration, daemon-mediated import,
physical LTFS, backup/restore or automatic Resume is qualified here.

See the [release process](en/release-process.md),
[RPM verification guide](en/github-rpm-verification.md), and preserved
[0.11.29 source notes](release-notes-0.11.29-155.md).
Historical Windows releases remain in the [Windows archive](windows-archive.md).
