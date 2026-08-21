# Installation on Windows Server 2022

This procedure installs LTO Archiver **0.11.26**. It supports Windows Server
2022 x64, HPE StoreOpen 3.5.0, an HPE-supported LTO driver, and compatible HPE
LTO drive and media. Installation and StoreOpen operations require an
administrator; backup operators also need SMB source read access and
LTFS-volume write access.

## Obtain prerequisites and verify the release

Obtain StoreOpen 3.5.0, the supported driver, firmware information, and HPE
Library and Tape Tools directly from HPE for the installed hardware. The LTO
Archiver ZIP contains none of that HPE software, and does not redistribute it.
Download the published checksum with the release and compare it with:

```powershell
Get-FileHash .\LTO-Archiver-0.11.26.zip -Algorithm SHA256
```

Only extract a ZIP whose SHA-256 matches the published value, to a local
directory. Run PowerShell as Administrator and invoke the included installer:

```powershell
& '.\install-lto-backup-manager.ps1' -SourceDirectory '.'
& 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe' --version
```

The version command must report `0.11.26`. The installer verifies GUI and CLI
hashes, installs beneath `C:\Program Files\LtoBackupManager`, protects
`C:\ProgramData\LtoBackupManager` for SYSTEM and Administrators, and backs up
the existing catalog before replacing executables.

## Controlled Folder Access and state permissions

With Controlled Folder Access (CFA) enabled, the installer adds only these two
application paths to the application allow-list and verifies the saved rule:

- `C:\Program Files\LtoBackupManager\LtoBackupManager.exe`
- `C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe`

It does not disable Defender or create broad folder, process, or device
exclusions. If CFA is managed by GPO or Intune, use
`-SkipControlledFolderAccess` and authorize exactly those paths centrally.
Do not loosen the ACL on `C:\ProgramData\LtoBackupManager`: it contains the
catalog, checkpoints, configuration, backups, and job state.

After installation, also check the catalog using the same privileged state
directory:

```powershell
& 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe' `
  --state-dir 'C:\ProgramData\LtoBackupManager' catalog check
```

For 0.11.26 this reports catalog schema 13. The migration keeps the StoreOpen
Win32 serial as diagnostic information, permits different cartridges to share
that value, and makes each non-empty LTFS volume label unique. Before a live
job, confirm that the GUI can display `write.pending`, `close.pending`,
`close.complete`, and `timing.complete`; the next file must not start before
`close.complete`.

## Upgrade and uninstall

Upgrade only when no job is `formatting`, `mounting`, `writing`, or
`unmounting`. Stop at a safe boundary or let the cassette complete, wait for the
LTFS letter to disappear and for StoreOpen/FUSE to finish index work, close the
GUI, then re-run the installer. Do not manually replace files while the GUI is
open. The installer retains `config.json`, `catalog.db`, jobs, checkpoints, and
catalog backups.

To uninstall, first ensure there is no active job and no mounted LTFS volume;
retain a verified catalog backup if it is needed for future offline browsing or
restore planning. Remove the installed application through the Windows
uninstall mechanism. Removing the application or CFA allow-list does not by
itself delete catalog, job, or backup state; do not delete the state directory
unless its recovery value has been deliberately retired.
