# Administration

This guide applies to LTO Archiver **0.11.26** state in
`C:\ProgramData\LtoBackupManager`. Keep that directory accessible only to
SYSTEM and Administrators as installed. It contains `config.json`, `catalog.db`,
`logs`, `temp`, and `run.lock`; changing permissions or copying mutable files
during an active job can compromise recovery evidence.

## Catalogs, backups, and logs

The SQLite catalog is authoritative for libraries, files, versions, tapes,
blocks, and jobs. The default catalog backup is
`C:\ProgramData\LtoBackupManager\backups\catalog\catalog-latest.db`; an
administrator may configure an absolute local or UNC backup directory. Preserve
catalog backups independently and test access before relying on offline search
or restore planning.

Logs are in `C:\ProgramData\LtoBackupManager\logs`. Set retention according
to the organization’s incident and privacy policy, leaving enough history to
diagnose a whole tape cycle and unmount. Retention should rotate or archive old
logs rather than delete the current evidence during investigation. Treat both
logs and catalog backups as confidential operational data.

## Capacity and concurrency

Choose capacity profiles only for supported LTO-5 through LTO-10 media. The
plan includes each object’s LTFS allocation and metadata, and after mounting
uses the minimum of profile limit, Windows-reported free volume space, and
`ltfs.mediaDataPartitionAvailableSpace`; it does not treat Explorer’s generic
capacity as the data partition. The default application margin is zero. Do not
use a speculative reserve to conceal an incorrect capacity profile.

`run.lock` serializes operations that modify a catalog or drive. One drive has
one active job. Read-only telemetry may be unavailable while StoreOpen reserves
the device, but it must not be turned into a concurrent job or direct probe.

## Maintenance, upgrades, and recovery boundaries

Schedule maintenance windows outside `formatting`, `mounting`, `writing`, and
`unmounting`. Gate upgrades on no active job, no mounted LTFS letter, and
StoreOpen/FUSE having released index work. Before a change, validate a catalog
backup and record the installed 0.11.26 version; after it, run `catalog check`.

The application can recover from a controlled stop at a cassette checkpoint,
but it cannot declare a tape committed after an interrupted provider flush or
unmount. `NUOVA` recovery starts the new tape cycle from zero; `APPEND` keeps
previous committed blocks and discards only the provisional new block. Server,
application, StoreOpen, or power failure during finalization can require HPE
recovery tools after safe release of the drive. Never force ejection or delete
state merely to make a job appear complete.

## Public-data boundary

Never attach a catalog database or backup, unsanitized logs, support tickets,
credentials, private keys, account names, hostnames, private IP addresses, real
job IDs, real cassette labels, SMB paths, device serials, registry exports, or
diagnostic captures to a public issue. Provide only sanitized excerpts with
version, generic environment, reproduction, and safety state.
