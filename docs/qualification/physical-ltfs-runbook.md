# Physical LTFS qualification

Physical qualification is a separate, manually authorized activity. It is
not part of normal backup, software installation, automated tests, or a
GitHub release. Format and write stages can erase or overwrite a cassette.
This document is a safety checklist, not an authorization or a command recipe.

## Before a physical trial

1. Identify the exact signed application, Python runtime and LTFS driver RPMs,
   their source archives, hashes, package signatures and compatible versions.
   Verify the installed versions and configuration against that authority.
2. Make and verify the protected catalog/configuration backup. Record a
   rollback plan with enough free space, and confirm the job and drive are
   quiescent. A `waiting_media` label alone does not prove quiescence.
3. Obtain explicit operator approval for the exact physical cassette and the
   destructive stage. Match the catalog physical label, MAM barcode/serial,
   observed LTFS label and drive identity through the supported preflight.
   Unidentified media is not proven blank.
4. Use a fresh, root-owned plan and one-shot authority produced by the
   installed qualification tools. Bind source, package, device and medium
   identities. Reject stale evidence, mismatches, missing serial pins or any
   concurrent drive owner. Never weaken these checks to make a trial proceed.

## During and after the trial

- Permit only the reviewed stage and its recorded owner to operate the drive.
  Do not run a second probe, mount, format, eject, Resume or recovery in
  parallel. Stop on an identity mismatch or uncertain device state.
- Treat an LTFS copy result as incomplete until unmount/finalization, index
  writes, catalog commit and physical unload/eject are separately verified.
  A failed close is not a successful qualification.
- A sampled readback is performed only after safe finalization and under a
  separate authorization. Sampling does not prove every byte on the tape.
- Preserve signed inputs, bounded redacted results, catalog backups and
  rollback evidence. Restore recorded service activation only after verified
  acceptance; do not automatically resume a backup job.

See [RHEL installation](../linux/installation-rhel9.md),
[LTFS operations](../en/ltfs-operations.md), and the
[release process](../en/release-process.md) for the non-destructive package
and application gates. Site-specific commands, device paths, credentials,
medium IDs and approval records belong in private operational procedures,
never in this public source tree.
