# User guide

LTO Archiver **0.11.26** has four operator stages: **Libraries**, **Cassette
plan**, **Automatic jobs**, and **Backup / catalog and restore**. The job is
saved before it uses a drive; that separation protects operators from an
unplanned tape action.

## Libraries, scan, and cassette planning

In **Libraries**, register each SMB library with its stable ID, display name,
and source path, then scan it. Review file count, total size, and last-scan
time before using **Cassette plan**. Select LTO-5 through LTO-10 capacity
profile and all intended libraries. Planning uses the LTFS data-partition
capacity plus object allocation and metadata; it keeps every file whole and
calculates a sequence of physical cassette labels. Enter labels in physical
order, one per line. Extra labels become future reserves and are not formatted
until needed.

## Save, validate, and explicitly start

The **Automatic jobs** stage saves the selected libraries, profile, cassette
sequence, and checkpoint. Saving is not a start. Select that saved job and use
**Start / resume selected job**; its confirmation identifies the job, drive,
and next cassette. Only one active job can use a drive, and a library cannot
belong to two unfinished jobs. Resolve a conflict by resuming, completing, or
deleting the existing job—there is no automatic FIFO start.

The operator must validate the displayed label before inserting media. The
runner waits without an application timeout for the requested cassette. For
`NUOVA`, it formats LTFS after the destructive confirmation; `NUOVA` is a
destructive operation. For `APPEND`, it does not format and checks the cassette
number and LTFS volume label against the catalog. The Win32 serial exposed by
StoreOpen/FUSE is retained for diagnostics and may match another cartridge;
the LTFS label is the media identity. `APPEND` preserves existing committed
blocks. A full APPEND tape moves to the next planned tape or leaves the job
saved while requesting labels.

## Progress and finalization

The runner writes one file at a time. It emits `write.pending`, confirms bytes
through `write.complete` and `file.progress`, then emits `close.pending` and
`close.complete` when `CopyFileEx` returns with the file handle closed. SHA-256
is read from the SMB source in parallel; only after close and hash completion
is the file recorded and the next one starts.

The job view reports job and cassette confirmed bytes, live write value,
**Effective tape average**, LTFS cache admission, elapsed time, cassette ETA,
job ETA, StoreOpen heartbeat, and LTFS activity. Confirmed bytes never advance
just because a provider call is pending. Effective tape average is confirmed
bytes from first write divided by elapsed time, including close, verification,
gaps, and unmount; cache admission is a separate filesystem-return value and
is not physical tape speed.

The five-minute chart uses exact one-second buckets and non-interpolated
traces. Its green left axis is **Effective tape average** and its amber right
axis is **LTFS cache admission**. Both independent axes show a rate unit at
their exact 100%, 50%, and 0% ticks (top, midpoint, and origin). Missing cache
samples leave a real amber gap; they do not prove a stopped drive. During a
pending StoreOpen call the elapsed time and effective average continue to
update, without invented bytes or provider progress percentages.

At cassette completion `unmount.progress` drives the finalization monitor:
cache/index synchronization, LTFS-letter release, then ejection. Only a
successful unmount makes the block visible to search and restore. A cassette is
not complete while its index remains uncommitted.

## Stop, completion, search, and restore

**Stop now** is observed between copy operations. If StoreOpen owns a pending
call, it takes effect when that call returns. The incomplete file is removed,
LTFS is unmounted, and the cassette is ejected. A stopped `NUOVA` cassette is
reformatted and restarted from zero; `APPEND` preserves earlier completed
blocks and retries only the new cycle without formatting. To stop at a cassette
boundary, wait for ejection, do not insert the next cassette, and stop while
the application is waiting for media.

Search and the backup tree are local SQLite-catalog operations: they work while
sources and tapes are offline. Results identify library, cassette, block, and
LTFS-relative path. Restore first creates a plan; insert the listed media and
choose the destination to execute it. Logical deletion of a job, library, or
block changes catalog references only; it does not delete SMB sources or LTFS
contents.

## First backup

1. Register a documentation-only SMB library and scan it.
2. Build the cassette plan, select media profile, enter validated labels, and
   explicitly confirm any `NUOVA` formatting.
3. Save the job, select it, and choose **Start / resume selected job**.
4. Insert only the requested cassette, observe `close.complete` and
   `unmount.progress`, and remove media only after ejection is requested.
