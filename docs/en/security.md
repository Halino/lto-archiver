# Security and privacy

LTO Archiver controls destructive tape and Windows/StoreOpen boundaries; it is
not a replacement for OS, SMB, retention, or physical-media security.

## Privileges and sensitive state

Installation/StoreOpen require Administrator privileges; backup operators need
the required SMB read and LTFS write rights. Keep
`C:\ProgramData\LtoBackupManager` restricted to SYSTEM/Administrators: config,
catalog, backups, checkpoints, logs, and `run.lock` are sensitive. Exports/logs
need the same handling. Use least-privilege SMB accounts; never put credentials
in arguments, config, scripts, issues, or shell history. Do not disable
Defender: CFA permits only installed GUI/CLI paths, including under GPO/Intune,
never broad folder/device/process exclusions.

## Destructive, identity, and path controls

`NUOVA` is destructive and requires explicit consent; `APPEND` preserves
committed data. The registered LTFS volume label is the media identity and a
label mismatch blocks use. The StoreOpen/FUSE Win32 serial is diagnostic and
may repeat across cartridges. Never bypass identity checks or write a wrong
cassette to diagnose them. `run.lock`
prevents concurrent catalog/drive mutation and is not permission to kill owner.
Treat SMB source, mount, restore destination, and export output as untrusted:
verify intended location/ACLs and do not follow surprising redirection.

## Releases and reporting

SHA-256 only matches a download to a published checksum; it does not prove
trust/provenance or replace endpoint policy. Treat unsigned binaries as a
warning and validate version, checksum, publisher/signature policy, and release
source. Authenticode is optional in the build process, not implied by checksum.
Redact public issues: never disclose credentials, keys/tokens, catalogs, full
logs, tickets, accounts, hosts/IPs, SMB paths, job IDs, labels/serials, registry
exports, or captures. Report vulnerabilities privately through
[`SECURITY.md`](../../SECURITY.md), not a public issue before coordinated triage.
