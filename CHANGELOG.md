# Changelog

All notable changes to LTO Archiver are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases
use semantic versions.

## [0.11.26] - 2026-08-20

### Added

- Independent left and right 0%, 50%, and 100% chart scales for effective tape
  average and LTFS cache admission rate, with units on every tick.
- A diagnostic order for long LTFS close operations: StoreOpen/FUSE ownership,
  drive LED and TapeAlert, then an HPE Library and Tape Tools support ticket
  after StoreOpen releases the device.

### Changed

- The compact idle finalization panel is 64 pixels high and expands while
  unmount finalization is active.
- LTFS cartridge identity now uses the unique volume label; the Win32 serial
  exposed by StoreOpen/FUSE is diagnostic and may be shared by different media.
- Application and Windows file/product release metadata are 0.11.26. Existing
  catalogs migrate from schema 12 to schema 13 without changing completed
  tapes, blocks, files, hashes, or checkpoints.

### Documentation

- Added public-release preparation notes covering safe diagnostics, Windows
  Server 2022 and StoreOpen 3.5.0 compatibility, and verification boundaries.
- Added this cumulative release history for the first public GitHub release.

## [0.11.25] - 2026-08-20

### Changed

- Failed jobs continue to reserve their libraries until reset, completed, or
  deleted; saving a job still does not start it.
- Recorded separate data delivery, `CopyFileEx` return, close, and hash times;
  closes of at least 120 seconds are reported.
- Kept catalog schema 12 and avoided destructive changes to jobs, manifests,
  and already cataloged data.

### Documentation

- Clarified the effective tape average, one-second chart buckets, real cache
  gaps, non-interpolated traces, and `unmount.progress` finalization stages.

## [0.11.24] - 2026-08-20

### Changed

- Data files on Windows use `CopyFileEx`; SHA-256 is calculated in parallel
  from the SMB source, and each file closes before the next begins.
- GUI progress distinguishes `write.pending`, `close.pending`, and
  `close.complete`; a Windows copy error stops the job without a legacy-writer
  fallback.
- Saved jobs require explicit **Avvia / riprendi job selezionato** confirmation;
  only one job runs at a time and a library cannot join a concurrent unfinished
  job.

## [0.11.23] - 2026-08-20

### Added

- Persistent per-tape manifests preserve assigned library, path, size, and
  mtime across job resumption.
- Capacity planning covers LTO-5 through LTO-10 profiles, LTFS metadata, and
  protected registered tapes.

### Changed

- The required Windows data path was `windows_cached_sequential_pipeline`, with
  overlapping SMB reads and sequential LTFS writes.
- The GUI distinguished `read.pending`, `write.pending`, and
  `close_queue.pending` without attributing unconfirmed bytes.

[0.11.26]: ../../releases/tag/v0.11.26
[0.11.25]: ../../releases/tag/v0.11.25
[0.11.24]: ../../releases/tag/v0.11.24
[0.11.23]: ../../releases/tag/v0.11.23
