# Security and privacy

## Current Linux log boundary

Operational logs cross a least-privilege boundary: the root reader socket is
`root:lto-log-read` mode `0660`, and only the daemon is a member of
`lto-log-read`. The reader has **no tape authority**. The WebUI receives only
typed, bounded, **redacted** application events through the daemon. Unix
permissions and SELinux both enforce the boundary; neither is a substitute for
the other. Keep the project and operational evidence private.

## Privileges and protected state

The daemon owns the catalog; the rootless WebUI receives neither that database
nor devices or source mounts. Separate brokers admit privileged operations.
Keep credentials, keys, catalogs, backups and logs private. Use least-privilege
share accounts and the documented Unix and SELinux boundaries; do not broaden
permissions to silence a denial.

Format requires exact administrator authority. APPEND preserves committed data.
Physical cassette label, LTFS volume label and cassette number remain separate
identities. Never bypass an identity or recovery fence to test a tape. Restore
writes only to configured safe roots and requires exact conflict authorization.

## Releases and reporting

Use the signed-artifact and clean-source gates in the
[release process](release-process.md); a checksum alone is not signer
provenance or deployment acceptance. Report vulnerabilities privately through
[SECURITY.md](../../SECURITY.md). Never publish credentials, private keys,
catalogs, unsanitized logs or operational identifiers.
