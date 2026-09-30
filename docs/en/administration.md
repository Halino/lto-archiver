# Administration

## Upgrade, rollback and catalog safety

The source contract is application **0.11.29-155**, Python runtime **3**,
external LTFS driver **22**, and catalog **schema 41**. It is not a statement
about what a particular host has installed. Read the exact signed release
notes and package identities before any installation or rollback. Application,
runtime and driver packages are independently signed and versioned; never
substitute a driver with a similar name or a package from another release.

An upgrade needs a genuinely **quiescent** cassette boundary. Confirm the
previous operation has durably finalized the LTFS index, unmounted, committed
catalog state and ejected the medium, with no unresolved command or recovery
fence. A `waiting_media` string alone is not evidence of quiescence. Do not
stop services, change packages, or touch catalog files while identification,
formatting, mounting, writing, finalization or unloading is active.

Before deployment, retain the signed predecessor RPMs, exact compatible
runtime and driver RPMs, service configuration, and a coherent catalog
backup. The supported deployment tool takes the catalog image through
SQLite's backup API from the live source into a root-private destination,
then checks integrity, foreign keys, schema, package signatures, source
identity, rollback compatibility and filesystem capacity. Keep both the
candidate and predecessor driver-input contracts in the rollback evidence.
A backup file name alone never proves a valid image. Never open the live
database manually to work around a failed admission gate.

Use the normal signed deployment request and supported installer; it records
the exact prior state and refuses mismatches before mutation. The rollback
bundle must be fresh, complete and bound to the actual pre-deployment schema
and package closure, not a historical example. On failure, preserve the
catalog, full rollback bundle, signed packages and failure report. The
supported rollback path restores and revalidates the protected source,
configuration and service activation. Do not copy a SQLite file over a
running daemon or manually unmask units after a partial transaction.

Native format authority is explicit. For a new plan, an administrator
authorizes only the exact ordered cassette/layout tuples that may be
formatted. For an older job without exact current-layout authority, use
the one-time administrator authorization action; never infer permission
from a migration. Append does not reformat committed media. A deliberately
paused job requires its protected Resume confirmation, while ordinary
`waiting_media` continuation follows the expected physical insertion
without an extra Resume. Completed cassettes and their catalog records
remain immutable during suffix replanning.

When exactly one cassette has a failed or uncertain provisional attempt,
the protected **Reset failed cassette** workflow binds the current job
revision, sequence, physical label and idempotency key. A reset is not an
ordinary retry: it must not discard completed tapes or a frozen layout.
An ambiguous command, mount, finalization or eject stays fenced until its
dedicated recovery procedure establishes fresh evidence.

## Constrained operational-log reader

The operational-log boundary is a socket-activated root **reader service** at
the **reader socket** `/run/lto-archiver-log-reader/control.sock`. The socket is
`root:lto-log-read` mode `0660`. Only the daemon is a member of
`lto-log-read` and may connect; the WebUI calls the daemon's typed API and never
reads journald or this socket directly. The reader has no tape authority and
does not invoke any drive, mount, broker, or catalog-mutating command.

Requests are restricted to six allowlisted units: `lto-archiverd.service`,
`lto-archiver-web.service`, `lto-archiver-command-broker.service`,
`lto-archiver-share-broker.service`,
`lto-archiver-ltfs-qualification.service`, and
`lto-archiver-archive-runner-qualification.service`. Execution uses the absolute
`/usr/bin/journalctl` path, a validated argument vector without a shell, a
fixed environment, a 5-second command timeout, and a 2 MiB output ceiling.
Pagination is capped at 200 entries and filtered search at 1,000 candidate
entries. Closed ranges are 1h, 6h, 24h, 7d, 30d, or retained; retained means
only host-retained journal history.

The daemon normalizes severity, source and safe correlation fields, then
redacts credentials and sensitive paths before returning data. SELinux
independently enforces the socket and process boundary even when Unix ownership
and mode are correct. A missing source is reported as partial availability;
reader failure is unavailable, not permission to fall back to broad journal
access.

## Confined Web startup and installed-host journal gate

The release-108 SELinux policy permits the confined Web domain to use only the
reference-policy client interfaces needed for read-only NSS lookup, systemd
userdb lookup, and generic certificate-store reads during Python and TLS
startup. It grants no shadow/password, account, userdb, private-key, or
certificate management authority.

The installed-host verifier evaluates priority 0-through-3 journal events from
all **nine managed units** (services and sockets) plus
`setroubleshootd.service`, from the exact maintenance-window start time. This
deployment gate is broader than the six-source reader allowlist above. A
setroubleshoot SELinux-denial diagnostic is therefore deployment evidence and
always fails closed. The signed exact unit, message-ID, and priority allowlist
applies only to the nine managed application units; it cannot allowlist
`setroubleshootd.service`. Do not hide an AVC by filtering
setroubleshoot or by moving the window start; resolve the policy or labeling
fault and rerun the complete gate.

## Current cassette recovery boundary

After verified finalization, unmount, catalog commit and physical eject,
a nonfinal native job may enter `waiting_media` for its next displayed
cassette. An enabled job can refresh only its never-started format suffix
after verifying the original libraries and source policy. Completed and
attempted cassettes, append targets, frozen placement and audit history
remain unchanged. The replacement transaction deletes every unused-suffix
assignment before inserting its new rows, preserving SQLite uniqueness.

An unavailable share, replaced root or stale file evidence blocks refresh
instead of appearing as an empty library. The WebUI shows scanning,
blocked/stale state, retained candidate quantities and exact additional-label
needs separately from tape progress. New format or reserve labels require a
fresh exact administrator grant. An explicitly paused job stays paused and
uses authenticated Resume; a normal media exchange does not.

A changed version of a source path already written in the completed prefix
remains a separate semantic limitation. This mechanism never edits a
completed cassette or reads it back. The source check for future jobs uses
recorded size, modification time and change time when available; historical
versions without change-time evidence retain the older comparison with a
visible partial-coverage limitation. It does not hash terabytes of archived
source data merely to scan a boundary.

During `critical_quarantine`, periodic media polling reports the blocker
but does not repeat a physical assessment. Only the protected administrator
reassessment action obtains fresh evidence. Startup records a new immutable
quarantine attempt under the current daemon generation without dispatching
another tape effect. Abandonment requires proof of an unmounted, idle, empty
drive and no related live command or process.

## Public-data boundary

Never attach a catalog database or backup, unsanitized logs, support tickets,
credentials, private keys, account names, hostnames, private IP addresses, real
job IDs, real cassette labels, SMB paths, device serials, registry exports, or
diagnostic captures to a public issue. Provide only sanitized excerpts with
version, generic environment, reproduction, and safety state.
