# Installation on RHEL 9

The current source contract is application **0.11.29-155**, Python runtime
**3**, external LTFS driver **22**, and catalog **schema 41**. This identifies
the source and package dependencies; it does not assert that a public release
has been signed or installed on a particular host. The active source branch is
[`linux`](https://github.com/Halino/lto-archiver/tree/linux); the separate driver
project is [Halino/lto-ltfs-driver](https://github.com/Halino/lto-ltfs-driver).
Linux RPM publication and qualification are pending: these are conditional
installation instructions, not a ready package download.

Use the [RHEL 9 installation guide](../linux/installation-rhel9.md) for
host prerequisites, signature and checksum verification, compatible RPM
installation, TLS/SELinux configuration, activation and smoke checks. Obtain
the application, runtime and driver from their separately signed, matching
release assets only after the Linux signed release is published. Historical
Windows ZIP releases are not Linux packages; see the [Windows archive](../windows-archive.md).
GitHub Releases provide direct downloads, not a DNF
repository. Never substitute unsigned packages or bypass a failed gate.

The current release route is a fresh, restorable disposable RHEL 9 VM only.
No existing-host upgrade or catalog migration is qualified by this route.
An independently qualified upgrade would require a preserved catalog,
rollback packages, verified compatibility and capacity, and a genuinely
quiescent cassette boundary. `waiting_media` alone is insufficient; do not install during
identification, formatting, mounting, writing, finalization or unloading.
Installation does not authorize a tape operation or automatic job Resume.

Follow the [Linux WebUI guide](../linux/webui.md) to provision users, configure
shares and libraries, then plan and explicitly start jobs. For upgrades and
rollback consult [administration](administration.md) and the
[release process](release-process.md). Windows-origin catalog and path
migration compatibility is described in the [Linux import guide](../linux/migration.md).
Windows application installation and operations belong to the
[Windows archive](../windows-archive.md).
