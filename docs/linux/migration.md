# Offline Windows-to-Linux migration

`lto-archiver-migrate` accepts the sealed Windows capture, verifies a canonical
bundle, and activates a frozen job in a new Linux state directory. It does not
start the daemon, scan source libraries, invoke LTFS, or inspect any tape.

## Safety boundary

Before starting:

1. Stop and disable the Windows archiver service. Confirm that its GUI, LTFS
   processes, and LTFS mounts are absent.
2. Keep the sealed capture and its independently recorded SHA-256 unchanged.
   Store both the capture and canonical bundle outside the source repository
   with administrator-only permissions.
3. Stop the Linux daemon. The target state directory must not exist; an existing
   empty directory is also rejected so no state can be overwritten.
4. Keep cassettes 1, 2, and 3 offline. Migration neither mounts nor verifies
   them. The first permitted production media operation is cassette 4 after an
   operator has accepted this offline report.

Every command writes one JSON object to standard output. Success exits `0`, a
deterministic input or policy rejection exits `2`, and an unexpected runtime
failure exits `3`. Standard error contains only a stable redacted status; it
never repeats paths, media labels, mapping values, or exception details.

## 1. Normalize the sealed capture

Use the SHA-256 recorded independently when the Windows capture was sealed:

```bash
install -d -m 0700 /var/lib/lto-migration-input
lto-archiver-migrate normalize \
  /var/lib/lto-migration-input/windows-capture.tar.gz \
  --expected-sha256 "$EXPECTED_CAPTURE_SHA256" \
  --output /var/lib/lto-migration-input/canonical.zip \
  --json > /var/lib/lto-migration-input/normalize-result.json
```

The output ZIP is created exclusively and is never overwritten. The source
capture is opened read-only without following symlinks, remains authoritative,
and is not extracted over or re-exported.

## 2. Inspect the canonical bundle

```bash
lto-archiver-migrate inspect \
  /var/lib/lto-migration-input/canonical.zip \
  --json > /var/lib/lto-migration-input/inspect-result.json
```

Do not continue unless the JSON reports all of the following:

- `accepted: true`;
- `completed_sequences: [1, 2, 3]`;
- `next_sequence: 4` and `total_cassettes: 20`;
- `media_accesses: []` and `error_codes: []`.

Inspection verifies the bundle hashes, SQLite integrity, the frozen assignment
digest, and the exact cassette boundary. It performs no source scan and cannot
add files that appeared after the Windows job was frozen.

## 3. Create the exact path mapping

Create an administrator-only JSON file. Its top-level keys and every source key
must match the canonical catalog exactly; extra fields or partial mappings are
rejected.

```json
{
  "device_names": {
    "TAPE0": "/dev/tape/by-id/configured-drive"
  },
  "library_roots": {
    "Z:\\Anime": "/srv/plex/Anime",
    "Z:\\Film": "/srv/plex/Film",
    "Z:\\Telefilm": "/srv/plex/Telefilm"
  },
  "mount_paths": {
    "L:": "/mnt/lto-archiver/tape"
  }
}
```

All Linux library targets must already exist and be readable. The CLI opens the
mapping as a bounded regular file without following symlinks. It rejects
duplicate JSON keys, unknown fields, control/format characters, relative target
paths, incomplete mappings, and duplicate resolved library targets.

## 4. Import into absent Linux state

Keep the daemon stopped and verify that `/var/lib/lto-archiver` does not exist.
Then run:

```bash
lto-archiver-migrate import \
  /var/lib/lto-migration-input/canonical.zip \
  --mapping-file /var/lib/lto-migration-input/path-mapping.json \
  --state-dir /var/lib/lto-archiver \
  --json > /var/lib/lto-migration-input/import-result.json
```

Import works on a cloned catalog, creates verified protected backups before any
schema migration or mapping change, and publishes the state atomically without
overwriting an existing target. The success JSON must report the installed
`activated_schema_version`, `authority_state: "pre_cutover"`,
`rollback_allowed: true`, `next_sequence: 4`, and
`acceptance_receipt_stored: true`.

The same safe JSON is retained at:

```text
/var/lib/lto-archiver/migrations/windows-import-acceptance.json
```

The catalog, protected backups, receipt directory, and mode-`0600` receipt are
fully written, identity-checked, and synchronized inside one sibling staging
tree before a single anchored rename publishes the target state. A failure
before that rename leaves the target absent and the unchanged command can be
retried. If publication completed but the final parent-directory sync returned
an ambiguous error, a retry succeeds only when the anchored state, catalog
receipt, external receipt, bundle, mapping digest, assignment digest, schema,
and pre-cutover policy all match exactly; any other existing state is rejected.

The receipt contains hashes and acceptance facts, not raw paths, credentials,
job IDs, or media labels. Preserve the sealed capture, canonical bundle,
mapping file, redirected command results, imported state, and protected backups
according to the site's backup policy. Do not place any of them in the source
repository.

## Authority, startup, and rollback

The CLI never starts a service. After reviewing the receipt, installation and
hardware acceptance must separately prove the configured drive and cassette 4
before the daemon is enabled.

Until cassette 4 is successfully finalized and committed, authority remains
`pre_cutover`: Windows remains resumable and Linux rollback is permitted. A
rollback must keep the daemon stopped, preserve the rejected or imported Linux
state for diagnosis, and restore service only from the unchanged Windows state.
Do not alter cassette assignments or rebuild the job.

The first successful cassette-4 commit makes Linux authoritative. From that
point, do not restore the pre-import catalog or resume Windows; use protected
backups and documented forward recovery. At no point should migration request,
mount, rescan, or verify cassettes 1 through 3. Files created in source
repositories after the sealed Windows allocation are not added to this job.
