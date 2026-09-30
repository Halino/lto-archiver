# Installation on RHEL 9

The current source contract is application **0.11.28-155**, Python runtime
**3**, external LTFS driver **22**, and catalog **schema 41**. This identifies
the source and package dependencies; it does not assert that a public release
has been signed or installed on a particular host.

Use the [RHEL 9 installation guide](../linux/installation-rhel9.md) for
host prerequisites, signature and checksum verification, compatible RPM
installation, TLS/SELinux configuration, activation and smoke checks. Obtain
the application, runtime and driver from their separately signed, matching
release assets. GitHub Releases provide direct downloads, not a DNF
repository. Never substitute unsigned packages or bypass a failed gate.

Before an upgrade, preserve the catalog and rollback package, verify
compatibility and capacity, and establish a genuinely quiescent cassette
boundary. `waiting_media` alone is insufficient; do not install during
identification, formatting, mounting, writing, finalization or unloading.
Installation does not authorize a tape operation or automatic job Resume.

Follow the [Linux WebUI guide](../linux/webui.md) to provision users, configure
shares and libraries, then plan and explicitly start jobs. For upgrades and
rollback consult [administration](administration.md) and the
[release process](release-process.md). Windows-origin catalog and path
migration is described in the [migration guide](../linux/migration.md); this
project does not distribute a Windows installer.
