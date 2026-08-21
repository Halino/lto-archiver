# LTFS operations and safe completion

This guide covers LTO Archiver **0.11.27** with HPE StoreOpen 3.5.0. LTO is
sequential media: a filesystem write may be accepted by caches before physical
tape work and LTFS index work are complete. StoreOpen/FUSE owns formatting,
mount, LTFS filesystem service, unmount, and ejection; LTO Archiver writes to
the mounted filesystem rather than directly to the drive.

## Ownership and the completion chain

LTO Archiver uses `sync_type=unmount`: the principal LTFS index is synchronized
at unmount, not represented as a percentage that the application can infer.
For each file it starts Windows `CopyFileEx`, waits for its return, then records
`close.complete`. That return means the application’s file handle is closed.
The provider may still flush cached data and metadata; StoreOpen then updates
the LTFS index and unmounts the volume. `unmount.progress` reports the real
stages: cache/index synchronization, LTFS-letter release, and ejection.

The application cannot defer open handles for StoreOpen to close later. It owns
only the handle it opened, while StoreOpen/FUSE owns the filesystem provider,
provider flush, index update, unmount, and physical-media state. Deferring
handles would make completion ambiguous, prevent the one-file sequential
contract, and cannot transfer Windows-handle ownership to StoreOpen. Therefore
there are no concurrent closes or final batch of application handles; after
`close.complete` the application does not reopen or query the LTFS file. The
next file starts only then. An explicit `FlushFileBuffers` per file is not used.

A block becomes searchable and restorable only after provider flush, index
update, and successful unmount. Do not stop FUSE, power off the server, remove
media, reuse the LTFS letter, or claim completion while the volume remains
mounted or StoreOpen is still finalizing.

## Safe diagnostics

When a drive is slow or a close is long, first observe application heartbeat,
StoreOpen/FUSE events, and LTFS activity. A pending call with increasing elapsed
time is not a reason to invent progress or open the tape. Do not directly probe
`TAPE0`, issue SCSI/device commands, or open the LTFS drive letter with Explorer,
indexers, or antivirus while StoreOpen owns the drive; this can create exclusive
semaphore or provider contention.

After StoreOpen safely releases the device, use HPE Library and Tape Tools
(HPE L&TT) to create a support ticket and inspect health, margins, retries,
interface, and firmware. Differentiate media from drive problems with a known
good scratch cassette only after release; do not test a data cassette with a
destructive assessment.

Read TapeAlert and the drive Clean LED. Clean only when the Clean LED flashes or
TapeAlert/support guidance reports `Clean Now`, `Clean Periodic`, or `Clean
requested`. For an HPE Ultrium drive use only the universal cleaning cartridge
`C7978A`; never use swabs or preventative cleaning. If the LED continues to
flash after cleaning and loading known-good media, arrange drive service.
