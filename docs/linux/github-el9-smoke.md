# GitHub-hosted EL9 compatibility smoke

The manual `Smoke existing unsigned RPMs in disposable AlmaLinux 9 VM`
workflow reuses the already compared GitHub-built driver 0.1.2-22,
runtime 0.11.27-3 and application 0.11.31-155 RPMs. It performs no build,
full source suite, signing, release publication or production operation.
Artifact ZIP and individual RPM hashes and the official dated AlmaLinux 9.8
cloud-image hash are fixed in the controller. Expired or changed inputs fail.

A new VM runs only on a disposable GitHub-hosted Ubuntu runner. It uses KVM
when available, otherwise QEMU software emulation, with a 20-minute observation
bound inside a 30-minute workflow. GitHub does not officially support nested
VMs; failure remains failure, not an automatic retry or skipped check.
No host devices, production data, existing catalog or tape are attached.

The guest checks a fresh package/state inventory, installation order, exact
NEVRAs and payloads, service accounts, unit syntax, enforcing SELinux and
installed policy/labels. It invokes the installed WebUI launcher with
guest-only ephemeral TLS and credentials and observes CSRF, login redirect,
session cookie and authenticated account access. Package erase and remaining
generated state, owned executables and unit activity are then observed.

The production preflight intentionally accepts only RHEL 9. The AlmaLinux
identity is not spoofed: its real unsupported-platform and absent-device
refusal is recorded. This smoke does **not** certify daemon/tape operation on
AlmaLinux or RHEL, signed RPM acceptance, snapshot restoration, migration,
import or backup/restore. Its distinct report always has `qualified=false`;
`compatibility_passed=true` means only the listed EL9 checks actually passed.
It cannot satisfy the existing RHEL-specific publication report validator.

Unsigned local RPM admission is confined to this isolated compatibility test;
distribution dependencies retain normal repository signature verification.
No signing secrets, personal GitHub tokens or administrative tokens are provided
to this workflow. A short-lived official download URL for the exact driver ZIP
is supplied as `EL9_DRIVER_ARTIFACT_URL`; it is masked, never logged, and cannot
authorize other repository operations. The workflow token reads only the app
artifact in its own repository. An expired driver URL fails without fallback.
Remove the temporary repository secret after the approved test; no personal
credential is copied to create it, and its download capability expires.
Reports and serial diagnostics are retained as workflow artifacts for seven
days. The VM is terminated after the report or deadline, and the hosted runner
is discarded by GitHub. Existing immutable package tags and release gates
remain unchanged.
