# User guide

This source tree targets application **0.11.29-155**, runtime **3**,
external driver **22**, and catalog **schema 41**. Verify the installed
package identities before operating a host. The Linux WebUI is the normal
operator surface; no Windows application or installer is distributed.
Offline [Windows-origin migration](../linux/migration.md) remains supported.

## Current Linux WebUI workflow

1. Sign in with the provisioned administrator. Use **Users** for local accounts,
   roles, password resets, and session revocation. Use **Settings** for the
   application capacity reserve, source age, copy buffer, verification policy,
   default LTO profile, and tape root. Finite domains are guided selections and
   the profile choices are the daemon's supported LTO-5-through-LTO-10 values;
   host/device settings are read-only.
2. Under **Shares**, create an SMB or NFS share, choose its protocol settings,
   and install an SMB credential when needed. A new share is **Active**, so the
   daemon connects it automatically and reconnects it during reconciliation.
   To disconnect it manually, change its lifecycle to **Disabled**; the daemon
   performs the same safe, broker-managed disconnect and keeps it disconnected.
   Return it to **Active** to reconnect. **Test** and **Reconcile** remain
   verification and recovery actions. The WebUI has no separate auto-connect
   toggle. Mounts are read-only and passwords are never redisplayed.
3. Under **Libraries**, enter a recognizable name and choose exactly one guided
   source type: a local folder or a connected NFS/SMB share with an optional
   relative subdirectory. The technical ID is proposed automatically and can be
   changed under advanced options. Create the library, then select **Scan and
   verify** to review its file count, byte count, and state. Neither action uses
   tape. Managed-share-only hosts may use an empty local `source_roots` allowlist.
4. Under **Jobs**, select all intended libraries and an LTO-5 through LTO-10
   profile. Review native capacity, effective LTFS data space, payload,
   allocation/metadata overhead, utilization, and the cassette estimate. Enter
   exact physical cassette labels in physical order, one per line. The required
   cassette count is shown; additional labels are saved as future reserves and
   are not formatted until needed. Saving does not start the drive.
5. For a new native job containing format rows, an administrator must select
   **Authorize automatic formatting** while saving the ordered plan. Review the
   frozen labels and insert cassettes in the displayed order. Start or resume
   explicitly; after sequence authority is complete, the native WebUI has no
   label field at start or resume. APPEND does not format committed media.

## Automatic cassette sequence safety

Release131 introduced a pre-admission **Source check**
at automatic cassette boundaries and exclusive tape-catalog cleanup when deleting
a job. See the
[source-check and deletion workflow](../linux/webui.md#next-cassette-source-checks).
Deleting a job with this change removes only its exclusively owned tape catalogs
and file indexes; shared or uncertain tapes are preserved. The physical cassette
is never erased by job deletion. Removed indexes are no longer searchable.
The signed release passed all eleven installed-host checks. These establish
integration and preservation, not a destructive live job-deletion test or a
real-media checkpoint run. That historical checkpoint does not describe the
current job state; use the live job page for current progress.

The schema 41 sequence keeps **one cassette per fenced operation**. Every
cassette has its own daemon operation, expected-media check, LTFS session, and
recovery fence. The authorization is immutable and binds the job, current layout
fingerprint, cassette sequence, normalized physical label, `format` operation,
and any registered-label reuse decision. Adding an ordered reserve label creates
only its own exact authority; it never changes the frozen placement or reserve
order. Saving an extension requires a fresh administrator grant when it adds a
format or reserve operation, or when another format row is `pending` or
`waiting_media`; an earlier epoch's grant never carries forward.

The drive cannot read a printed label on blank media. The displayed insertion
order is therefore authoritative until the resulting LTFS/MAM identity can be
checked. A recognized incompatible LTFS medium is never reformatted
automatically: leave the expected label visible and use the safe failure or
critical-recovery path. Imported jobs and critical recovery retain their
separate exact typed-confirmation workflows; this native sequence authorization
does not infer destructive authority for a legacy job.

After a successful finalization and eject, a nonfinal native job is
`waiting_media` for the next displayed cassette and continues after insertion.
Pause is safe only at that unloaded checkpoint. On restart, the daemon first
reconciles prior command, mount, finalization, and eject evidence; it resumes
only when the same fenced boundary is proven safe. schema 41 records immutable
continuation provenance for the original operation, job, cassette, layout epoch
and fingerprint, deterministic key, hardware target, and exact format authority
when required. Exact replay uses those persisted rows even after a later layout
extension. Incomplete or mismatched legacy provenance fails closed without
another worker or replay audit.

An administrator sees **Reset failed cassette** only when a native job has one
failed or uncertain cassette. Use this critical manual unlock only after
confirming that the exact displayed physical label is inserted. The submission
is bound to the cassette sequence and current job revision and is idempotent;
stale state or a different label is rejected. A successful reset discards only
the uncertain provisional attempt and, from release 109, directly starts the
same native job through a deterministic idempotent retry. It does not require a
second **Resume** action, rescan sources, change cassette order, or alter the
frozen layout epoch or fingerprint. Already completed tapes remain committed.
Normal recoverable interruptions do not expose or require this action; the
daemon handles them automatically.

The normal cycle optionally formats, mounts read-write, writes sequentially,
finalizes and unmounts LTFS, commits the completed block, and ejects. It does not
load media or remount a completed cassette for readback. The operator supplies
media manually. Independent readback belongs only to the disabled-by-default
physical qualification. The installed qualification workflow rejects
`long_wipe` at every planning and dispatch boundary. A standalone drive is
never loaded by software; qualification controls its own unmount and eject
boundaries and requires manual reinsertion when a later read-only sample is
planned.

## Cassette-boundary source refresh

After successful finalization and eject, an enabled native job can rescan
its original verified libraries before admitting the next unused format
cassette. Only the never-started suffix may be replanned. Completed or
attempted cassettes keep their exact contents and layout; an interrupted
cassette resumes its frozen manifest. The new suffix includes eligible
new or changed files and omits files removed before the scan. An
unavailable share or replaced source root blocks refresh rather than
appearing empty.

The replacement is atomic: all unused-suffix assignments are deleted
before replacement rows are inserted. The daemon retains capacity
calibration, physical label order and reserve positions. New format labels
need fresh administrator authority. The **Cassette-boundary refresh** panel
distinguishes queued, scanning, blocked, stale, applied, paused and
waiting-for-labels states; pending candidate counts are separate from
committed totals. If labels are insufficient, add the exact displayed
number or more through the reserve-label form.

For future jobs, source observations use size, modification time and
change time where available. Historical archived versions without a
recorded change time retain size-and-modification-time comparison with
partial coverage clearly identified. This avoids hashing terabytes of
source data during routine boundary scans. A deliberate pause stays
paused and still displays a label deficit; authenticated Resume is
required only to leave that pause. Normal enabled media exchanges
continue automatically after the expected cassette is inserted.

This feature does not reopen completed jobs, read back a normal backup,
or solve the separate case where a changed version reuses a path already
written in the completed prefix.

## Operational log browser

The **Operational log** page is the supported first view for current software
diagnostics. It combines six bounded sources: **daemon**, **WebUI**, **LTFS**,
**command broker**, **share broker**, and **qualification**. LTFS entries are
events observed and emitted by the application; this view does not expose or
claim access to vendor-internal driver logs.

Choose a closed time range of **1h**, **6h**, **24h**, **7d**, **30d**, or
**retained**. Retained means only the history still retained by the host. Newest
entries appear first. Use **Follow** for a live view and **Pause** to hold the
current page while investigating. Older and newer navigation uses an immutable
journal **cursor**. If **cursor rotation** invalidates that cursor, the page
explains the rotation and offers a restart from the newest available entry.

Controls filter by source, severity, closed range and one free-text search, and
select direction and row limit. The text search matches the normalized message
and safe **correlation** fields such as job, operation, cassette and command;
those identifiers are displayed in event details, not offered as separate
filters. Entries are normalized, **redacted**, and may be **truncated** or
**coalesced**; the UI marks each condition.

The typed API preserves healthy-source data and classifies each source that is
**temporarily unavailable**. The current WebUI deliberately withholds an
incomplete filtered row set until every requested source recovers, while
showing which sources are unavailable. During a complete reader outage the
page reports reconnecting state and does not flash an incomplete result.

## Current Linux catalog discovery

Sign in as an `operator` or `administrator` and open `/catalog`. Search and
browse read the daemon-owned schema 41 catalog only: they do not mount LTFS,
acquire the drive-operation lock, contact source shares, read tape bytes, or
provide a byte preview. Filter by library, job, physical cassette label,
SHA-256, size, copied time, and history. The physical cassette label, LTFS
volume label, and cassette number are separate identities, never fallbacks for
one another. Use cursor pagination for large result sets. Results are
metadata-only. Offline immutable restore planning is supported. Restore
execution requires the requested cassette to be inserted. Select up to 200
immutable versions, choose a configured safe root and optional
relative subdirectory, and confirm the cassette-ordered plan. Insert each
physical label when prompted; the daemon never invokes `load`. It mounts LTFS
read-only, independently verifies size and SHA-256, reports exact matches as
`skipped_verified`, and records finalization, unmount, and physical eject before
advancing. Pause, resume, cancel, and response-loss replay are durable. A
differing file remains `recovery_required` until a freshly reauthenticated
administrator authorizes that exact one-time conflict; stale, replayed, or
mismatched authority is rejected. If the daemon is unavailable, correct
the daemon/socket condition rather than mounting media or opening the database
from the WebUI.

See the [Linux catalog search guide](../linux/catalog-search.md) for filters,
cursor pagination and the metadata-only discovery boundary.

## First backup

Follow the current Linux WebUI workflow above: configure shares and libraries,
scan, review the capacity plan and exact labels, save with any required fresh
format authority, then start explicitly. Saving alone never starts a job.

A cassette is not complete while its index remains uncommitted. To pause at a
safe boundary, wait for ejection, do not insert the next cassette, and stop while
the application is waiting for media. Do not interrupt finalization or infer
completion from telemetry. APPEND preserves committed data.
