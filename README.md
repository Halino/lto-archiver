# LTO Archiver

[Italiano](README.it.md)

Current version: **0.11.26**.

## What it does

LTO Archiver is a Windows backup and catalog manager for append-only SMB
archives on LTFS tapes. It writes files directly to the LTFS filesystem, so
they remain normal LTFS files rather than TAR archives or proprietary
containers. The local SQLite catalog supports planning, search, offline
browsing, restore, and SHA-256 verification.

## Safety model

Tape writing is sequential: LTO Archiver writes one file at a time, and the
next file starts only after `close.complete`. New-tape (`NUOVA`) formatting is
destructive. `APPEND` never formats the tape and preserves previously committed
data. A tape is complete only after StoreOpen has successfully unmounted it;
until then, its LTFS index and newly written data are not treated as committed.
In the Italian UI this data-preserving mode is labelled `APPEND - conserva i dati`.

## Features

- Plans capacity across LTO-5 through LTO-10 media without splitting files.
- Creates saved jobs that require an explicit start, with one active job per
  drive and protected catalog state.
- Copies directly to LTFS with `CopyFileEx`, records SHA-256, and exposes
  `write.pending`, `close.complete`, and `unmount.progress` progress.
- Identifies LTFS cartridges by their volume label. The Win32 serial reported
  through StoreOpen/FUSE is retained for diagnostics and may be shared by
  different cartridges.
- Records a per-tape manifest and distinguishes "Media effettiva cassetta" from
  LTFS cache admission. The chart uses "campioni regolari di un secondo", and
  telemetry "non incrementa i byte" when no bytes have been confirmed.
- Catalogs completed blocks for offline search, restore planning, and logical
  deletion without deleting SMB source files or tape contents.

## Requirements

- Windows Server 2022 x64.
- HPE StoreOpen 3.5.0 and an HPE LTO driver version 1.0.9.4 or a later
  supported version, plus compatible drive and media.
- Administrator access for installation and StoreOpen operations; source-SMB
  read access and LTFS-volume write access for backup work.

HPE StoreOpen, drivers, firmware, Library and Tape Tools, and installers are
external prerequisites. They are not bundled with this project.

## Quick start

After verifying the release checksum, install as an administrator and confirm
the installed CLI version:

```powershell
Get-FileHash .\LTO-Archiver-0.11.26.zip -Algorithm SHA256
& '.\install-lto-backup-manager.ps1' -SourceDirectory '.'
& 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe' --version
```

Register a documentation-only SMB library, then use the user guide to plan and
start the first job:

```powershell
LtoBackupManagerCli.exe library add `
  --id MEDIA_01 `
  --name 'Media Library 01' `
  --source '\\files.example.test\archive'
```

Do not format, mount, unmount, or eject a tape from a procedure other than the
documented workflow.

## Documentation

Start with the [English documentation][en-index]. Long procedures live in the
[installation][en-installation], [user guide][en-user-guide],
[administration guide][en-administration], [LTFS operations guide][en-ltfs],
[CLI reference][en-cli], [troubleshooting guide][en-troubleshooting],
[security guide][en-security], [development guide][en-development],
[release process][en-release-process], and [FAQ][en-faq].

## Releases and verification

Current public release: **0.11.26**. See the [changelog](CHANGELOG.md) and the
[release process][en-release-process] for reproducible checks. Verify the ZIP
SHA-256 and the GUI/CLI version before distribution. No production server
operation is part of release preparation.

## Project status and limitations

Version 0.11.26 upgrades existing catalogs to schema 13. The migration removes
the old uniqueness constraint on the diagnostic Win32 serial and makes each
non-empty LTFS volume label unique; it does not alter completed tapes, blocks,
files, hashes, or checkpoints. LTFS, StoreOpen, the drive, and the operator
control physical media behavior. A tape copy is not by itself a redundancy
strategy, and recovery after an interrupted unmount may require the HPE tools
described in the [LTFS operations guide][en-ltfs].

## Contributing, support, and security

Read the future [contribution guide][contributing], [support policy][support],
and [security policy][security] before opening an issue. Never include
credentials, private keys, catalog databases, unsanitized logs, support tickets,
or operational identifiers in public reports.

## License and trademarks

Copyright 2026 Alessandro Gnagni. LTO Archiver is licensed under
[Apache-2.0](LICENSE). HPE, StoreOpen, StoreEver, and related names are
trademarks of their respective owners. LTO Archiver is independent and is not
affiliated with or endorsed by Hewlett Packard Enterprise.

[en-index]: docs/en/index.md
[en-installation]: docs/en/installation.md
[en-user-guide]: docs/en/user-guide.md
[en-administration]: docs/en/administration.md
[en-ltfs]: docs/en/ltfs-operations.md
[en-cli]: docs/en/cli-reference.md
[en-troubleshooting]: docs/en/troubleshooting.md
[en-security]: docs/en/security.md
[en-development]: docs/en/development.md
[en-release-process]: docs/en/release-process.md
[en-faq]: docs/en/faq.md
[contributing]: CONTRIBUTING.md
[support]: SUPPORT.md
[security]: SECURITY.md
