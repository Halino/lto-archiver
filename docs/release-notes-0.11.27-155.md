# LTO Archiver 0.11.27-155

Application-only release. Runtime remains
lto-archiver-python-runtime-0.11.27-3; public driver pairing is lto-ltfs-0.1.0-22.
Public build status: source preparation only. No GitHub-built RPM or public
Release is asserted by these notes. Publication requires the independently
reviewed public tag, GitHub build/sign/attestation evidence, a clean
snapshotted disposable RHEL 9 first-install/no-tape smoke and successful VM
snapshot restoration, and separate approval of the exact final assets.
The historical 144/driver-21 upgrade route is not qualified for 155/driver-22.
The publication workflow also requires two independent read-only checks of
the exact repository's immutable-release setting before draft creation and
before making the reviewed draft public; this source snapshot has not run
those gates on GitHub.


Schema 41 records positive source change-time for newly archived file versions.
New plans default to size, modification-time, and change-time comparison,
using existing filesystem metadata rather than reading terabytes of content.
The selected policy is frozen in each new plan and job; changing settings
later does not alter a frozen backup.

Historical versions retain unknown change-time. Matching size and modification
time keeps those files archived without mass recopy; analysis reports their
partial coverage. Existing plans and jobs retain their prior policy and
digest-bound snapshots, including deliberately paused cassette work.

Change-time is best effort, especially on SMB/NFS: metadata-only changes may
trigger extra copies, and unchanged metadata cannot prove content integrity.
Full content verification remains a separate opt-in with substantial read cost.
