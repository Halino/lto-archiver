# Linux catalog search and browse

The supported catalog workflow is the authenticated Linux WebUI at
`/catalog`. It reads the authoritative SQLite catalog through
`lto-archiverd`; the WebUI never opens `catalog.db` itself. The current catalog
schema is **schema 41**. Search and browse remain read-only after the protected
catalog migration; this feature never mounts media or scans source trees.

## Access and safety boundary

Sign in to the WebUI, then select **Catalog** or open `/catalog`. Both the
`operator` and `administrator` WebUI roles may use catalog search, browse, and
version detail. An administrator manages WebUI accounts and service
configuration; neither role gains a tape operation merely by reading the
catalog.

Catalog requests use the daemon's read capability. Catalog search does not
acquire the drive-operation lock, does not mount LTFS, does not contact a
source share, and does not access a tape or SCSI device. They are
metadata-only: the page never downloads tape bytes and provides no byte preview.
It is therefore safe to search while tapes are absent or while a drive is busy.
Offline immutable restore planning is supported. Restore execution requires
the requested cassette to be inserted. Operators may select up to 200
immutable versions, choose a configured safe restore root and
optional relative subdirectory, and create a cassette-ordered immutable plan.
Execution remains a distinct authorized drive operation; catalog search itself
continues without mounting any tape.

Each result reports its library, attributable job, cassette identity, block,
LTFS-relative path, size, copied timestamp, SHA-256, metadata state, and
current/history state. The **physical cassette label**, LTFS volume label, and
cassette number are separate identities, never fallback identifiers for one
another. A legacy serial is diagnostic lineage only and must not be used to
select a cassette.

## Search, filters, and version history

Use **Search** when the path or file metadata is known. The query matches the
catalogued path and is combined with any selected filters:

- library and job;
- cassette identity fields and SHA-256;
- minimum and maximum size;
- copied-after and copied-before timestamps;
- include history, which shows non-current visible versions as well as the
  current one.

An empty query is valid and returns the visible current files that match the
filters. Search returns only versions from visible completed blocks. It never
makes a provisional or forgotten block appear recoverable.

Use **Browse** to traverse a library root one directory at a time. Browse is
not a global text search: it lists only current versions among the children of
the selected `parent_path`; version history is a Search-only filter. Select a
file to open its complete metadata-only detail at
`/catalog/file-versions/{version_id}`.

Results are cursor-paginated. When another page is available, use **Next**;
the current UI does not provide a Previous control. A cursor belongs to the
exact search or browse ordering that produced it, and a changed filter or query
starts a new first page. The bounded page size keeps a large catalog responsive
without loading all rows into the browser.

## Errors and operator response

- **Not signed in / insufficient role:** sign in with an `operator` or
  `administrator` account. Do not copy the daemon socket or catalog database
  into the WebUI container.
- **Invalid filter or cursor:** correct the highlighted value and start again;
  the daemon rejects malformed ranges, timestamps, and cursors without
  changing the catalog.
- **File, library, or version no longer found:** return to `/catalog` and run
  the query again. A catalog cleanup or a changed filter can invalidate an old
  link.
- **Daemon unavailable:** the WebUI renders the catalog as unavailable. Check
  the daemon health and Unix-socket boundary using the normal Linux operations
  procedure; do not mount a tape, restart a drive operation, or open the
  catalog database from the WebUI to work around it.

For the current installation entry point, see the [project overview](../../README.md).
Historical Windows 0.11.27 documents and release notes are archival records,
not the current Linux installation path.
