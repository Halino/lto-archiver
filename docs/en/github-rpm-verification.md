# GitHub-built RPM verification

The active application repository is
[Halino/lto-archiver, branch `linux`](https://github.com/Halino/lto-archiver/tree/linux);
the separate driver repository is
[Halino/lto-ltfs-driver](https://github.com/Halino/lto-ltfs-driver).
Published application source `v0.11.30` remains immutable: source CI passed but
its artifact comparison gate failed. Application `v0.11.31` source and tag
were approved and published at commit `4507cd23e96fef48dd3099d0da69bb7cda3a9a27`.
Its [hosted build run](https://github.com/Halino/lto-archiver/actions/runs/36776008356)
passed both builds and verified byte-identical unsigned application/runtime
RPMs and SRPMs. Driver `v0.1.2` at commit
`61f8b6acb547e715624856e85786e7676fa28c37` passed its
[hosted build, comparison and no-tape UBI container smoke gates](https://github.com/Halino/lto-ltfs-driver/actions/runs/36764908507).
Both runs await signing; signed-package verification and final release
acceptance remain pending. Signed Linux RPM releases are not yet available.
Historical Windows ZIPs are [archived](../windows-archive.md), not a Linux
download; do not use the repository's generic latest-release URL.
The application and Python runtime
are built from one reviewed public tag on GitHub. The LTFS driver is a
separate project and is not built, signed, or released by this workflow.

## Two approval boundaries

Before the first public push, review the exact owner/repository, source
commit and entire public history, licenses and third-party inventory,
workflow source, pinned runner image and action commits. Private source
history, host data, credentials, tape metadata and signing keys are excluded.
The separately derived LTFS driver must disclose its seven conditional,
unverified file origins under the owner's conservative LGPL-2.1-only policy
and receive approval for its exact source and history before any public push.

Before dispatching either release workflow, make sure its reviewed workflow
file is present on the new repository's default branch; GitHub accepts
`workflow_dispatch` only when the workflow is registered there. The protected
release tag must point to the same approved commit. Dispatch with that tag as
the workflow ref and supply the exact tag and commit inputs; a run started from
a moving branch is not a substitute. Configure the protected signing and
publication Environments before dispatch. See [GitHub's manual-workflow
requirement](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).

The protected build workflow can then produce a *candidate*, not a GitHub
Release. It builds unsigned application and runtime RPM/SRPM trees twice from
the same protected tag; the comparison step refuses unequal bytes. The
protected signing job alone can access the signing key. It signs four final
RPM/SRPM files and the flat `FINAL-RPM-SHA256SUMS`, publishes the public
verification key with the candidate, and requests GitHub build-provenance
attestations for the signed RPM bytes. Candidate artifact retention is short;
record the exact build run and independent evidence promptly.

Publication needs a second, separate approval for the exact tag/commit,
successful build run, final manifest digest, exact SHA-256 digests of its
detached signature, public key file and attestation bundle, full primary and
signing-subkey fingerprints, and the sanitized disposable RHEL 9
fresh-install/WebUI hardware-absent and snapshot-restoration report digest. Together with the four RPM rows in the
manifest, this binds all eight Release asset bytes. Configure the
`public-rpm-publication` Environment with required human review, administrator
bypass disabled, a protected selected-tag rule, matching approval variables and the reviewed
base64-encoded sanitized smoke report in
`PUBLIC_RPM_APPROVED_SMOKE_REPORT_BASE64`. The currently approved single-owner
policy permits the owner who initiated a run to review it; it is not a
two-person approval guarantee. Automated agents must not approve on the
human reviewer's behalf. The workflow decodes and validates
the report bytes, including real-login/expected hardware-refusal and snapshot-restoration claims,
before creating a draft. The Environment reviewer must separately inspect the
underlying VM transcript; JSON claims alone cannot establish execution. See
the [smoke evidence contract](../linux/public-fresh-install-smoke.md). Confirm
the exact repository's immutable-release setting through the separate
`public-rpm-admin-read` Environment. Its repository-scoped credential needs
only Administration read permission and must be unavailable to both
release-write jobs. The workflow requires a fresh HTTP 200 response with
`enabled: true` from `GET /repos/{owner}/{repo}/immutable-releases` before
creating a draft and again immediately before publication. A configured
boolean or a check made only after publication is insufficient; missing
access or a disabled setting leaves the release unpublished. The workflow
downloads and verifies the draft, then publishes it only after the second
preflight. The protected final read-only job emits a proof bound to the exact
repository, tag, commit, numeric draft ID, approved manifest and eight asset
hashes; the dependent release-write finalizer has no second approval
Environment and accepts the proof only for 0–120 seconds. It downloads and
checks the same draft again immediately before `draft=false`, then verifies
the published bytes and `isImmutable: true`. The Administration check and
publication are not one atomic GitHub operation: the separate final approval
must acknowledge the remaining administrator race. It never receives a
private signing key. Failed verification must not be bypassed by uploading
assets manually.

## Verify a published direct download

Only after an actual approved Linux release exists, use its exact tag (the
current source candidate is `v0.11.31`), reviewed 40-character commit and
independently approved fingerprints below. A public source tag alone is not
evidence that these downloadable assets exist:

```sh
gh release download v0.11.31 --repo Halino/lto-archiver --dir verified-rpms
cd verified-rpms
sha256sum FINAL-RPM-SHA256SUMS FINAL-RPM-SHA256SUMS.asc RPM-PUBLIC-KEY.asc ATTESTATION.json
# Compare all four digests with the separately approved exact-asset record.
gpg --batch --with-colons --show-keys RPM-PUBLIC-KEY.asc
# Compare the complete primary and signing-subkey fingerprints with the
# independently approved release record, not only the short key ID.
gpg_home="$(mktemp -d)"
gpg --homedir "$gpg_home" --batch --import RPM-PUBLIC-KEY.asc
gpg --homedir "$gpg_home" --batch --verify FINAL-RPM-SHA256SUMS.asc FINAL-RPM-SHA256SUMS
sha256sum -c FINAL-RPM-SHA256SUMS
rpmdb="$(mktemp -d)"
trap 'rm -rf -- "$gpg_home" "$rpmdb"' EXIT
rpmkeys --dbpath "$rpmdb" --import RPM-PUBLIC-KEY.asc
for package in ./*.rpm; do
  rpmkeys --dbpath "$rpmdb" --checksig --verbose "$package"
  rpm --dbpath "$rpmdb" -K "$package"
  gh attestation verify "$package" --repo Halino/lto-archiver \
    --signer-workflow Halino/lto-archiver/.github/workflows/build-release.yml \
    --source-ref refs/tags/v0.11.31 \
    --source-digest REVIEWED_PUBLIC_COMMIT \
    --signer-digest REVIEWED_PUBLIC_COMMIT \
    --deny-self-hosted-runners --bundle ATTESTATION.json
done
```

The publication job independently downloads every draft asset and
rechecks its exact byte identity, checksum signature, RPM signature and
GitHub attestation against the approved build run and public tag before publication. The
finalization job repeats the exact byte, signature and attestation checks
after the second read-only immutable-release preflight. The
application and runtime SRPM sources are also compared with the reviewed
public tag *before* publication. GitHub's automatically generated source
archive is not a substitute for checking the SRPM source members.

These are direct GitHub Release downloads, **not** a DNF repository.
Installing requires the compatible external `lto-ltfs 0.1.2-22.el9`
driver, then `lto-archiver-python-runtime 0.11.27-3.el9`, then
`lto-archiver 0.11.31-155.el9`. Verify exact NEVRAs and dependency
resolution on a clean, snapshotted disposable RHEL 9 VM with no tape first.
For this release only a fresh first install is being qualified. No private
144/21 upgrade, catalog migration, active-backup restart, media operation or
automatic Resume is authorized by publication or package verification.
