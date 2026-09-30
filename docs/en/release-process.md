# Release process

LTO Archiver and the `lto-ltfs` runtime are separate source projects with
independent versions and release tags. The application package pins an exact
driver RPM version. Building the application must not rebuild, embed, or
relabel the driver.

## Source and test gate

Prepare each release from a reviewed, immutable source tag. The tag, RPM
Version/Release, source archive, and package metadata must agree. Run the
hardware-free test suite and packaging checks in a clean RHEL 9 build
environment with the project's pinned toolchain. Native driver tests,
sanitizers, per-file license/provenance checks, and the driver package's own
build gate belong to the separate driver project. Automated tests do not
establish physical tape qualification.

The public source snapshot contains only reviewed source, tests, build
recipes, licenses, notices, and manuals. Audit the snapshot and its new Git
history for credentials, private operational data, unexpected binaries,
unsafe links, and license omissions before publishing anything. Keep the
historical private repository and its commits out of the public history.

The public application source does not include one-off, host-bound catalog
compaction and retained-candidate recovery tools or their incident fixtures.
They were never installed by the application RPM and are not a supported
operator recovery interface. Catalog, backup, restore and WebUI product tests
remain in the public test set; omitting incident tooling is not evidence that
its recovery procedure has been generalized or qualified for other hosts.

## Build and sign

Build the RPM and matching SRPM twice from the same exact source. Compare the
outputs and verify package contents, dependency pins, service files, source
archive identity, SBOM, license inventory, and provenance. The driver release
must additionally establish its upstream and downstream source lineage; a
local-build identity alone is not proof of authenticated upstream provenance.

Signing keys are available only in the trusted release environment. Untrusted
pull requests may run keyless tests, but cannot sign or publish. Sign the RPMs
and checksums, and publish the public verification key and its reviewed
fingerprint. Verify signatures again from the downloaded assets.

The proposed GitHub Release asset allowlist is four application/runtime
RPM/SRPM files, `FINAL-RPM-SHA256SUMS` and its detached signature, the public
verification key and the GitHub attestation bundle. The manifest binds the
four RPM bytes; the manifest, signature, key file and bundle each have a
separately approved SHA-256. A draft Release is downloaded and reverified
before the one-way publication step. Separate protected, Administration-read
jobs require the exact repository's immutable-release API to return HTTP 200
with `enabled: true` before draft creation and again before publication;
neither release-write job receives that credential. Its notes record the exact source tag,
commit, build run, approved smoke-report digest and all eight asset hashes.
The last protected Administration-read job binds the draft's numeric ID and
eight asset hashes to a proof valid for at most 120 seconds. Its dependent
release-write finalizer has no second approval Environment and refuses a
changed or stale draft before `draft=false`, then independently verifies the
published bytes and `isImmutable: true`. These are separate GitHub API calls:
an administrator can still change the repository setting in the interval
between the final check and publication. The separate final approval must
explicitly acknowledge that residual race; the workflow does not claim an
atomic guarantee.
Source archives, licenses and notices remain bound to the protected source
tag and the SRPMs; the runtime SPDX inventory is included in its source and
binary package. Application SBOM and driver-license clearance remain
separate publication evidence gates, not claims established by this workflow.
GitHub Releases is a download channel, not a DNF repository. A DNF repository
would need separately signed repository metadata and an update policy.

## Installation and acceptance

On a disposable RHEL 9 host, verify the downloaded artifacts, install the
compatible driver and application packages, then exercise service health,
WebUI/API smoke behavior, and rollback. Production deployment has additional
backup, signature, compatibility, capacity, quiescence, and catalog gates.
Never infer a safe installation window merely from `waiting_media`, and never
operate a tape or resume a job as part of release publication.

Record the exact source tag, package hashes, dependency tuple, verification
results, and any limitations in the release notes. A failed test, content
audit, license gate, signature check, or disposable-host acceptance blocks
publication without changing an installed system. Public repositories and
assets are published only after the exact payload and destination receive
final approval. Follow the
[GitHub-built RPM verification guide](github-rpm-verification.md) for the
exact tag, run, checksum-signature and attestation checks.
