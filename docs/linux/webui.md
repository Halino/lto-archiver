# WebUI runtime boundaries

The WebUI is a separate, unprivileged process. It owns only its authentication
database and reaches `lto-archiverd` through the versioned HTTP/SSE API on
`/run/lto-archiver/daemon.sock`. It must never receive a tape/SCSI device,
source-library mount, LTFS mount, or the authoritative catalog.

## Operational log browser

The browser calls the daemon's **typed system-log API**. It does not read
journald directly, cannot connect to the root reader socket, and the legacy
`/api/v1/logs` is not a fallback. Responses expose normalized entries, per-source
availability, bounds, truncation and safe correlation data. The visible filter
controls are source, severity, closed range, direction, row limit and one text
search. That search matches normalized messages and safe correlation fields;
job, operation, cassette and command identifiers are displayed details, not
separate filters.

Follow refreshes from the newest immutable journal cursor; Pause keeps the
current page stable. Older/newer requests preserve an **immutable journal
cursor**, while rotation returns an explicit restart boundary. Transient
disconnects retain the last successful page and show reconnecting state.
The API preserves healthy-source data while classifying unavailable sources.
For a partial-source response, the current WebUI withholds the incomplete
filtered rows until recovery and shows the unavailable source names. A total
reader outage is an unavailable state, never permission for broader access.

## Prepare and build the image without network access

Select the base image explicitly. There is deliberately no default, so a local
build cannot silently change its Python or RHEL base. Development accepts a
fully qualified UBI 9 Python 3.11 tag other than `latest`; release automation
requires a digest:

```bash
export LTO_WEB_TEST_UBI_IMAGE=registry.example/ubi9/python-311:9.6
python3.11 scripts/validate-web-base-image.py \
  --development "$LTO_WEB_TEST_UBI_IMAGE"
podman image exists "$LTO_WEB_TEST_UBI_IMAGE"
python3.11 -m pip download \
  --only-binary=:all: \
  --require-hashes \
  --requirement requirements-web.lock \
  --dest wheelhouse
podman build --format=docker --network=none --pull=never \
  --build-arg UBI_IMAGE="$LTO_WEB_TEST_UBI_IMAGE" \
  --file Containerfile.web \
  --tag lto-archiver-web:test .
podman inspect --format '{{.Config.User}}' lto-archiver-web:test
```

`pip download` is the explicit acquisition step. The Containerfile then uses
only that wheelhouse with `--no-index`, verifies every selected distribution
against `requirements-web.lock`, and builds with its network disabled. It also
uses an explicit root build stage because the UBI application image may inherit
UID 1001, then returns to the numeric `1001:1001` UID/GID in the final image.
The explicit Docker image format is required because Podman's default OCI
image format drops Dockerfile `HEALTHCHECK` metadata. The final inspect command
must print `1001:1001`, and the image inspection must contain its health check.

The browser assets are included in the Python package and require no CDN or
Internet access at runtime. Release builds run the same validator with
`--release` and a protected reference of the form
`registry.example/ubi9/python-311@sha256:<64-lowercase-hex-digits>`.

Maintainers update the hash lock deliberately, review its diff, refill the
ignored wheelhouse, and rerun the offline build gate:

```bash
uv pip compile requirements-web.in \
  --python-version 3.11 \
  --universal \
  --generate-hashes \
  --no-annotate \
  --no-header \
  --output-file requirements-web.lock
```

## Provision the first administrator

There is no default account or password. Run the provisioning command with a
TTY; the password is read by `getpass` and is never accepted as a command-line
argument or environment variable:

```bash
podman run --rm --interactive --tty \
  --userns=keep-id:uid=1001,gid=1001 \
  --read-only \
  --cap-drop=all \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --volume lto-web-auth:/var/lib/lto-archiver-web:Z \
  lto-archiver-web:test \
  admin create --username admin
```

For non-interactive provisioning, pass a secret through an inherited file
descriptor. `--password-fd` reads one bounded UTF-8 line; it does not accept the
secret itself. The operator is responsible for opening the descriptor from a
protected secret store and closing it immediately after the command:

```bash
exec 3< /secure/example-password-file
podman run --rm --read-only --preserve-fds=1 \
  --userns=keep-id:uid=1001,gid=1001 \
  --cap-drop=all \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --volume lto-web-auth:/var/lib/lto-archiver-web:Z \
  lto-archiver-web:test \
  admin create --username admin --password-fd 3
exec 3<&-
```

The descriptor protocol is one bounded UTF-8 line. The first LF terminates the
secret immediately; the reader never waits for EOF and ignores every byte
after that LF, whether already buffered or written later. A CR immediately
before LF is accepted as CRLF. An empty first line, embedded NUL/CR, invalid
UTF-8, or more than 4096 bytes before LF is rejected. Producers must therefore
put exactly the intended password on the first line and must not rely on
trailing data being validated.

Do not put real secret paths or values in source control, shell history, image
layers, logs, or container environment variables.

## Development container boundary

The optional development container has a read-only root filesystem, a small no-exec tmpfs,
no added capabilities, and exactly two persistent/host mounts: the WebUI auth
volume and the daemon socket. Bind the published port only to loopback. This
container is not the production RHEL 9 service.
Set `LTO_WEB_LOOPBACK` to the host's numeric IPv4 loopback address before
running the example.

```bash
podman run --rm \
  --userns=keep-id:uid=1001,gid=1001 \
  --read-only \
  --cap-drop=all \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --volume lto-web-auth:/var/lib/lto-archiver-web:Z \
  --volume /run/lto-archiver/daemon.sock:/run/lto-archiver/daemon.sock:rw,z \
  --publish "${LTO_WEB_LOOPBACK}:8080:8080" \
  lto-archiver-web:test
```

Run this container as the dedicated `lto-web` host account configured by
`lto-archiverd --webui-user`, whose primary group is also `lto-web`. `keep-id`
maps that host UID and primary GID to the image's numeric `1001:1001`, so the
kernel `SO_PEERCRED` identity remains trusted and the process reaches the
daemon's `0660` socket through its primary group. The daemon service must be a
member of `lto-web` so it can assign that group when creating the socket.
`:rw,z` alone changes neither UID/GID mapping nor Unix DAC permissions.

The earlier Quadlet design is not the current production deployment. Use the
[direct-TLS service](#production-rhel-9-direct-tls-service) below; the rootless
container recipe above is for development. The RPM tmpfiles rule provisions
`/var/lib/lto-archiver-web` as a real (non-symlink) directory with mode `0700`
and owner/group `lto-web:lto-web`. The shipped preflight checks that directory's
type, ownership and mode; a missing or unsafe path fails admission. The current
WebUI unit runs as `lto-web:lto-web` with this directory as its only writable
state path. It does not have the former Quadlet `ExecStartPre` check.

The image health check requests the local `/login` page. Operational status
still comes exclusively from the daemon UDS; an unavailable daemon is rendered
as unavailable and never causes the browser process to open the catalog or
touch hardware. Closing or restarting the WebUI does not stop a daemon-owned
job.

Run `lto-archiver-web serve --help` to select a different listen address, port,
auth database, absolute daemon socket, or bounded daemon request timeout. The
CLI defaults are `/var/lib/lto-archiver-web/auth.sqlite3` and
`/run/lto-archiver/daemon.sock`.

## Production RHEL 9 direct-TLS service

The application RPM owns `lto-archiver-web.service` and runs the WebUI directly
as `lto-web:lto-web`; production does not use Podman or a reverse proxy. The
service executes the closed `/usr/libexec/lto-archiver/run-web-rhel9.py`
boundary with an empty environment except for a fixed safe locale. It binds one
explicit LAN IPv4 address on TCP 8443, uses the daemon Unix socket, and reads
only `/etc/lto-archiver/web.toml` and regular TLS files beneath
`/etc/lto-archiver/tls`. Its only writable path is
`/var/lib/lto-archiver-web`.

The operator supplies `/etc/lto-archiver/web.toml` as `0640 root:lto-web`, a
`0750 root:lto-web` TLS directory, a `0644 root:root` certificate, and a `0640
root:lto-web` private key. Certificates and keys are never package payloads.
Activation rejects wildcard, loopback, multicast, missing, symlinked,
mis-owned, or wrong-mode inputs.

The configured address must belong to an interface in the configured active
firewalld zone. Activation admits TCP 8443 only through source-scoped rich
rules for exactly `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`, in both
permanent and runtime state. A broad `8443/tcp` port, named service exposing
8443, different source network, wildcard listener, or wrong-zone interface
fails closed. See [RHEL 9 installation and activation](installation-rhel9.md)
for activation, health verification, custom-unit migration, and rollback.

## Current operator workflow

Use the WebUI for normal configuration and backup operations. Host paths,
devices, service identities, and the managed-source mount root remain
installation-owned and read-only in the browser.

1. Sign in with the provisioned administrator. In **Users**, create operator or
   administrator accounts, reset credentials, change roles, disable or retire
   accounts, and revoke sessions. In **Settings**, review the host boundary and
   set capacity reserve, minimum source age, copy buffer, verification policy,
   default media profile, and tape root. Finite domains use guided selections;
   in particular, the media profile list comes from the daemon's supported
   LTO-5-through-LTO-10 profiles. Saving settings never starts a job.
2. In **Shares**, create an SMB or NFS source. Configure the server and remote
   resource; choose the supported NFS version or SMB dialect. Install SMB
   credentials only through the password form: stored passwords are never shown
   again. A new share is **Active**, which makes connection and reconciliation
   automatic. The daemon reconnects an active share after restart or observed
   disconnection. To disconnect manually, set its lifecycle to **Disabled**;
   the daemon applies the normal in-use checks, safely disconnects the managed
   read-only mount, and keeps it disconnected. Set it back to **Active** to
   reconnect. The WebUI has no separate auto-connect toggle. **Test** validates
   reachability and **Reconcile** is an explicit recovery action.
   A failed operation remains visible in the live status panel with a redacted
   explanation, recommended next action, operation time, and an expandable safe
   error code. The list view shows only the concise human-readable summary;
   credentials, raw D-Bus diagnostics, and private mount evidence are never
   rendered.
3. In **Libraries**, the guided form first asks for a recognizable display name
   and then for exactly one source type: **Local folder** or **NFS/SMB share**.
   The technical library ID is proposed from the name and remains editable under
   advanced options. A network library uses a connected managed share selected
   from the list plus an optional relative subdirectory; the form links back to
   **Shares** when none is available. Create the library, then use **Scan and
   verify** to review file count, bytes, and scan state. Creation and scanning do
   not access tape. A host using only managed SMB/NFS sources may keep the local
   `source_roots` allowlist empty.
4. In **Jobs**, select one or more active scanned libraries and an LTO-5 through
   LTO-10 profile. Review native capacity, effective LTFS data-partition space,
   payload bytes, allocation and metadata overhead, per-cassette utilization,
   and the cassette estimate. Files remain indivisible and physical cassette
   labels are assigned in the displayed sequence. Additional labels become
   future reserves without changing the frozen file layout. A registered label
   is rejected by default; an administrator may explicitly authorize reuse in
   the plan form. Reuse reformats the cassette; only after format succeeds does
   the previous backup become unreadable and its catalogue entry become
   invalid. For format rows, the plan shows an admin-only **Authorize automatic
   formatting** checkbox. It authorizes only the frozen tuple for each planned
   or reserve cassette. Save the job without starting it, then use its detail
   page to start, resume, pause, extend, or add reserves. **Delete job** is a logical
   retirement: retired jobs are hidden from the active list by default and can
   be shown with **Show retired**. The current workflow also
   removes exclusively job-owned tape catalogs and their file indexes, after
   the administrator confirms the job ID. Shared tapes, uncertain ownership and
   protected restore/import history references are preserved. A blocking daemon
   operation or nonquiescent hardware command also preserves tape indexes;
   logical retirement does not schedule their deletion later. Physical tape data,
   cartridge identities, frozen assignments and job/audit history are retained.
   The result page lists removed and preserved tapes with reasons; removed file
   records are no longer searchable. This does not grant permission to format a
   subsequently reused cassette. Legacy scheduler-only deletion remains separate.
5. Insert cassettes in the displayed order and only when the daemon requests
   the exact next physical label. The drive cannot verify a printed label on
   blank media; the ordered insertion and exact schema-40 authority are the
   safety boundary. After authorization, native **Start** and **Resume** have
   no label prompt. An append never formats previously committed content.
   Recognized incompatible LTFS media is never reformatted automatically.

## Native cassette sequencing and live job detail

Schema 41 preserves one cassette per fenced operation. Each operation remains
bound to one job, cassette sequence, expected media, LTFS session, and recovery
fence. A completed nonfinal cassette becomes `waiting_media` after finalization
and attested eject; inserting the next expected cassette lets the daemon
continue automatically. **Pause** is safe at this unloaded checkpoint. A daemon
restart first reconciles durable command, mount, finalization, and eject records
and continues only when that boundary is safe.

After a deliberate **Pause**, click **Resume job** and enter the password of the
currently signed-in account in the confirmation window. There is no need to visit
Account or Users first. An invalid password stays in the same window; Cancel does
not resume the job. Without JavaScript, the password field is available directly
beside the Resume button. Passwords are not forwarded to the tape daemon.

Normal `waiting_media` transitions do not request this confirmation: insert the
next expected cassette and automatic sequencing continues after daemon checks.
An explicit pause requested at a cassette boundary still requires the password.
Critical recovery, cassette identity and formatting-authority checks remain in
force; confirming a password does not bypass them.

### Next-cassette source checks

Current application source **0.11.31-155** uses runtime **3**, driver **22**,
and catalog **schema 41**. These are source identities, not proof of
installation or physical qualification.

Before automatic continuation admits the next cassette, the daemon checks
the frozen source identity, size and modification time. Future jobs also
compare recorded change time when available; historical versions without it
retain partial coverage. This is a metadata check, not a terabyte-scale
content hash or a replacement for before/after-copy validation. Managed
shares are checked against the saved identity and unavailable shares do not
become deleted files.

The job page shows **Source check**, counts and up to 100 affected paths. Missing
or changed sources hold automatic continuation before tape admission. The check
retries after 30 seconds; restoring the exact planned sources allows normal
continuation without a manual recovery unlock. Pause, daemon takeover or a newer
layout invalidates an in-flight result. Identical failures do not add duplicate
history entries. This diagnostic supplements, not replaces, the worker's source
leases and before/after-copy checks; it is not a data snapshot or content hash scan.

A frozen library at the exact root of a verified read-only NFS/NFS4 share
can retain its saved source identity after Linux renumbers the anonymous
mount device, but only through the narrow recorded-device compatibility
check. Changed inodes, exports, unverified mounts and other saved fields
still block continuation.

After proven finalization and eject, cassette-boundary refresh rescans the
original libraries and atomically replaces only the never-started suffix.
All unused-suffix rows are deleted before replacement inserts. Completed
and attempted cassettes remain frozen; new labels require exact authority.
The panel shows scanning, failures and additional-label needs separately
from tape progress. Changed versions of paths already in the completed
prefix remain a separate unsupported case. See the
[boundary refresh workflow](../en/user-guide.md#cassette-boundary-source-refresh).

The existing **Scan now** and cadence policy run only after the current frozen
layout is complete; they do not rewrite pending cassette assignments. A missing
planned version must be restored or handled in a separate backup cycle, not
silently skipped and reported as successfully backed up.

An existing native job created before schema 37 shows a one-time administrator
authorization action bound to its current revision and layout fingerprint; it
does not inherit destructive permission. Imported jobs retain the legacy exact
per-operation confirmation control, as do protected critical-recovery actions.

Saving a new format or reserve row, or applying an extension while any format
row is `pending` or `waiting_media`, requires the administrator checkbox in
that same submission. Missing, duplicated, malformed, or operator-supplied
authority fails closed while preserving safe form inputs. An append-only
extension omits destructive authority only when no existing format row is
pending or waiting; its frozen placement and ordered reserves remain unchanged.

Each admitted continuation stores immutable schema-40 provenance for its
original operation, job, sequence, layout epoch and fingerprint, deterministic
key, hardware target, and exact format authority when required. Replay uses
only those persisted rows, including after a later extension. Missing or
mismatched legacy provenance fails closed without another worker or replay
audit.

If a native job fails with exactly one cassette in an uncertain state, its
detail page shows **Reset failed cassette** only to an administrator. This is a
critical manual unlock, not a normal resume control. It requires the exact
physical label displayed for that cassette and binds the submitted cassette
sequence, current job revision, and idempotency key. Stale pages, the wrong
label, multiple failed cassettes, imported jobs, or a changed job state fail
closed. Once confirmed, only the uncertain provisional attempt is discarded;
the cassette returns to `waiting_media` and the daemon automatically resumes
the same job without a second operator action. Completed tapes remain committed, and
the cassette order, frozen file placement, layout epoch, and layout fingerprint
remain unchanged. Routine backup interruptions continue through automatic
recovery without this unlock.

During pre-media recovery, a native cassette label (for example `TAPE13`) is
not compared with the manufacturer's MAM serial. The physical identity is sealed
separately; a different already-bound medium still blocks recovery. A read-only
reassessment can close an old identify reservation only if it never launched,
has no release authority and its exact broker scope is empty. It never signals
processes or formats, mounts, ejects or writes a tape. The first successful
identification updates the recovery proof in the same authenticated action;
replacement or resume still requires its own current authority. Reassessment
alone does not clear critical quarantine or start a backup.

Protected recovery is a single guided page reached from the job or Dashboard.
The **Recover blocked job** button selects this flow when the current operation
has critical recovery evidence. Existing reset-page links redirect to that same
review. Without matching critical evidence, **Reset blocked state** retains its
separate pre-media reset flow; navigation never executes either command.
An administrator can review it without visiting **Account**. Click the required
action and, only when the recent-authentication window has expired, enter the
current password in the confirmation dialog. Cancel sends nothing; incorrect
passwords leave the recovery form and typed cassette label available on the same
page. Without JavaScript the password field is displayed directly in each form.
The first step reassesses the state without resuming the backup; replacement
authorization is a separate, explicitly labelled action that may format the
confirmed cassette. Technical evidence and the abandon option are collapsible.
Accepted replacement/abandon commands return to their job, not the Dashboard.
If the session expires, sign-in returns to the same read-only recovery page;
commands are never replayed automatically after login. Administrator permissions,
CSRF, rate limiting, exact evidence and idempotency checks remain enforced.
Normal cassette changes continue without password prompts.

While this job is active, the Dashboard places live statistics before secondary
status details. Bytes and current MiB/s advance from bounded intra-file progress
events; a file is still counted only after successful completion. **Effective
cassette average** starts at the active operation's first write window, not at
daemon startup. **Copy time** measures POSIX data delivery and **Close time**
measures the destination flush/close boundary separately.

**Streaming efficiency** compares the operation-scoped effective rate with the
current rate. The adjacent bounded bottleneck monitor classifies no material,
moderate, or high source/inter-file overhead; it is a diagnostic hint, not a
hardware fault verdict. The page also shows current-cassette and whole-job
progress, phase, ETA where available, and the bounded MiB/s graph with real
telemetry gaps rather than invented samples. SSE drives immediate updates,
while adaptive fragment refresh remains active as a safety channel:
3 seconds during work, 10 seconds while waiting for media, and 30 seconds when
idle. Transport errors back off through 5, 10, 20, and 30 seconds. Hidden tabs
pause requests and resynchronize when visible. Only live fragments are
replaced, so forms retain unsaved input; inactive jobs show persisted progress
without live samples from another job.

Source-relative names are cataloged exactly as scanned and remain the names
shown by Jobs and Catalog. If a POSIX source component is unsafe on Windows
(for example, it ends in a space or is a reserved device name), only its
physical on-tape component is placed in the reserved `~lto1~` namespace. The
manifest records both the original relative path and the portable LTFS path;
the source is never renamed or modified. Restore and catalog tooling must use
those fields and must not infer a source name by decoding a tape filename.
Ordinary portable names remain unchanged, so existing tapes and imported
Windows manifests retain their original layout.

The normal cassette cycle is label check, optional format, read-write LTFS
mount, sequential write, manifest and index finalization, unmount, catalog
commit, and `mt eject`. The operator supplies and removes media; there is no
autoloader or `load` assumption. A normal backup does not remount the cassette
for tape readback. Only the separate, manual physical qualification performs an
independent read-only remount. The installed qualification workflow rejects
`long_wipe` at every planning and dispatch boundary; its documented standalone
sequence also excludes `load` and `unload`.

## Immutable multi-file restore execution

From **Catalog**, select up to 200 immutable file versions, including multiple
rows, then choose a configured safe local restore root and an optional relative
subdirectory. The immutable plan shows physical cassette labels in automatic
order and writes to
`<root>/<subdirectory>/<library-id>/<catalog-relative-path>`. Insert the
displayed cassette manually; this standalone-drive workflow never invokes
`load`.

The daemon holds one exclusive destination-root lease for the whole cassette,
mounts LTFS read-only, and publishes absent files atomically without replacing
an existing path. It independently checks final size and SHA-256. An identical
destination is `skipped_verified`; a differing destination remains
`recovery_required` until a freshly reauthenticated administrator authorizes
only the exact durable conflict. That authorization is one-time and evidence
bound; stale, replayed, mismatched, or broad overwrite requests fail closed.

Use **Pause**, **Resume**, or **Cancel** at durable file/cassette boundaries.
Cancel never removes already verified destinations. Repeating a request after
response loss replays its idempotent result. Per-file results remain visible,
and the daemon advances only after exact LTFS finalization/session close,
unmount, and physical eject evidence.

## Catalog entry point and no-mount boundary

After authentication, use the **Catalog** navigation item or open `/catalog`.
This is the catalog portion of the current Linux workflow for the **schema 41**
catalog. `operator` and `administrator` WebUI roles may search, browse a library
root, and open metadata-only file-version detail; account management remains an
administrator task.

The WebUI forwards catalog reads to `lto-archiverd` over its existing socket.
It does not mount LTFS, acquire the drive-operation lock, contact source
shares, receive tape/SCSI devices, or open the catalog database. A response
contains metadata only and never previews or downloads tape bytes. The browser
can therefore search while media are absent. Offline immutable restore planning
is supported. Restore execution requires the requested cassette to be inserted
and remains a distinct daemon drive operation.

Use [the catalog search guide](catalog-search.md) for filters, cursor
pagination, the separate physical cassette label, LTFS volume label, and
cassette-number identities, and the unavailable-daemon response.
