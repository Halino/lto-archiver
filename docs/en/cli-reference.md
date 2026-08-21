# CLI reference

LTO Archiver 0.11.26 exposes `lto-backup`. This inventory was checked against
`python -m ltobackup --help` and every subcommand's `--help`, not an old README.

## Common contract

`--state-dir PATH` selects state; `--json` makes the final result JSON;
`--version` prints the version; `-h`/`--help` prints help. Success exits 0;
validation/operational errors 2; capacity 3; Ctrl+C 130; unexpected errors 1.
Parser argument errors exit 2. JSON errors are not guaranteed. Examples use
synthetic IDs and paths only.

`init` and `telemetry` take separate startup paths: `init` saves supplied
settings and initializes the catalog, but does not run legacy-settings upgrade
or configure the rotating log; `telemetry` reads SCSI without catalog state.
Every other successfully parsed leaf command takes the state lock to run
settings upgrade, configures the rotating log, and opens then
`initialize`s/migrates the catalog. Thus a diagnostic query is not forensic
read-only: it can update `config.json`, create/rotate logs, and initialize or
migrate catalog evidence. Preserve/copy suspect state before invoking it.

## Public commands

Each row gives purpose; preconditions/arguments; destructive effect; exit/JSON
behavior; and a synthetic example. `library`, `tape`, `block`, `automatic`,
`restore`, and `catalog` are groups and require the listed leaf command.

| Command | Contract and example |
| --- | --- |
| `library` | **Group purpose:** choose library management leaf (`add`, `list`, `delete`). **Arguments/preconditions:** a leaf is required; the group itself has only help. **Effect:** none when invoked without a leaf; parsing stops before state/log/catalog initialization. **Exit/JSON:** `lto-backup library` is a parser error (exit 2), emits no result JSON; `--help` exits 0. `lto-backup library --help` |
| `tape` | **Group purpose:** choose tape leaf (`register`, `list`). **Arguments/preconditions:** a leaf is required; group only supplies help. **Effect:** none without leaf. **Exit/JSON:** missing leaf is parser exit 2/no result JSON; help exits 0. `lto-backup tape --help` |
| `block` | **Group purpose:** choose block leaf (`list`, `forget`). **Arguments/preconditions:** a leaf is required; group only supplies help. **Effect:** none without leaf. **Exit/JSON:** missing leaf is parser exit 2/no result JSON; help exits 0. `lto-backup block --help` |
| `automatic` | **Group purpose:** choose automatic recovery leaf (`reset-cassette`). **Arguments/preconditions:** a leaf is required; group only supplies help. **Effect:** none without leaf. **Exit/JSON:** missing leaf is parser exit 2/no result JSON; help exits 0. `lto-backup automatic --help` |
| `restore` | **Group purpose:** choose restore leaf (`plan`, `run`). **Arguments/preconditions:** a leaf is required; group only supplies help. **Effect:** none without leaf. **Exit/JSON:** missing leaf is parser exit 2/no result JSON; help exits 0. `lto-backup restore --help` |
| `catalog` | **Group purpose:** choose catalog leaf (`check`, `export`). **Arguments/preconditions:** a leaf is required; group only supplies help. **Effect:** none without leaf. **Exit/JSON:** missing leaf is parser exit 2/no result JSON; help exits 0. `lto-backup catalog --help` |
| `init` | Create settings/catalog. Writable `--state-dir`; optional `--reserve-gib`, `--buffer-mib` (1–64), `--min-age-seconds`. Writes local config/catalog, never tape/SMB. Exit 0 JSON `{state_dir,catalog,reserve_bytes,reserve_human}`. `lto-backup --state-dir C:\LtoState --json init --buffer-mib 16` |
| `library add` | Register source. Initialized state; `--id --name --source`; source must be usable. Writes catalog only. Exit 0 `{added,source}`. `lto-backup library add --id LIB_DEMO --name Demo --source '\\files.example.test\archive'` |
| `library list` | List active or `--all` libraries. Initialized state; optional `--all`; no effect. Exit 0 JSON row array. `lto-backup --json library list --all` |
| `library delete` | Logically delete library. Existing ID plus `--id` and exact `--confirm`. Removes catalog data only; SMB and tape data stay. Exit 0 `{deleted,...}`, bad confirmation 2. `lto-backup library delete --id LIB_DEMO --confirm LIB_DEMO` |
| `tape register` | Bind inspected LTFS identity. Initialized state, mounted LTFS; `--id --mount`, optional `--cassette-number` (ID default). Writes the unique LTFS volume label and diagnostic Win32 serial to the catalog, not tape payload/format. Exit 0 `{tape_id,cassette_number,mount,label,serial,filesystem,free_bytes}`; identity/LTFS error 2. `lto-backup tape register --id TAPE_DEMO_01 --cassette-number DEMO01 --mount L:\` |
| `tape list` | List registered tapes. Initialized state; no args/effect. Exit 0 JSON rows. `lto-backup --json tape list` |
| `scan` | Calculate next block without writes. Registered readable `--library`; optional `--min-age-seconds`. No effect. Exit 0 `{library_id,source_root,files,bytes,human,skipped_unchanged,skipped_too_recent}`. `lto-backup --json scan --library LIB_DEMO --min-age-seconds 900` |
| `backup` | Copy one block to registered mounted LTFS. Requires initialized catalog, library/tape, matching `--mount`, capacity; `--library --tape --mount`, optional age, `--dry-run`, `--json-progress`. Normal mode writes LTFS, catalog, manifest/backups; failed provisional block is failed. Dry run copies nothing. Exit 0 `nothing-to-copy` or `{status,block_id,...}`, capacity 3. With `--json-progress`, newline JSON events precede final `--json`: `file.start`, `file.activity`, `file.progress`, `file.complete`, `block.complete`/`block.failed`, warnings. `lto-backup --json backup --library LIB_DEMO --tape TAPE_DEMO_01 --mount L:\ --json-progress` |
| `block list` | List blocks, optionally `--library`, including hidden with `--all`. Initialized state; no effect. Exit 0 JSON rows. `lto-backup --json block list --library LIB_DEMO --all` |
| `block forget` | Hide a block. Existing `--id` and exact `--confirm`. Changes catalog visibility only; tape bytes stay. Exit 0 `{forgotten,tape_data_deleted:false,...}`, else 2. `lto-backup block forget --id BLOCK_DEMO --confirm BLOCK_DEMO` |
| `automatic reset-cassette` | Discard the current interrupted automatic attempt. Existing current `--job` and exact `--confirm`. It will restart from zero and reformat; use only after recovery review. Exit 0 `{job_id,sequence,status:'paused',discarded,...}`, else 2. `lto-backup automatic reset-cassette --job JOB_DEMO --confirm JOB_DEMO` |
| `restore plan` | Show tape restore requirements. Existing `--library`; no effect. Exit 0 `{tape_id,file_count,total_bytes,human}` rows. `lto-backup --json restore plan --library LIB_DEMO` |
| `restore run` | Restore from mounted registered tape. Requires `--library --tape --mount --destination`; destination writable; optional `--overwrite --json-progress`. Writes destination files; overwrite can replace them. Exit 0 `{restored_files,restored_bytes,human}`; progress JSON is `restore.skip`/`restore.complete`. `lto-backup --json restore run --library LIB_DEMO --tape TAPE_DEMO_01 --mount L:\ --destination D:\Restore --json-progress` |
| `doctor` | Check catalog and optionally mounted tape. Initialized state; supply both `--tape` and `--mount` or neither. Its query does not write tape data, but parsed invocation can upgrade settings, create logs, and initialize/migrate catalog; preserve suspect evidence before use. Exit 0 integrity, foreign-key/pending-block data and optional volume identity/capacity; one argument alone is 2. `lto-backup --json doctor --tape TAPE_DEMO_01 --mount L:\` |
| `telemetry` | One read-only SCSI snapshot. Optional `--device` (default `TAPE0`); no catalog lock, write, format/mount/unmount. Exit 0 even unavailable: `{available,detail,activity,device,read_only:true}`. Never probe a StoreOpen-owned device. `lto-backup --json telemetry --device TAPE0` |
| `catalog check` | Check schema, SQLite integrity, foreign keys, cassette numbers, visible uncommitted files. No tape payload write, but parsed invocation can upgrade settings, create logs, and initialize/migrate catalog; preserve suspect evidence first. Exit 0 `{schema_version,integrity,foreign_key_errors,missing_cassette_numbers,uncommitted_visible_files}`. `lto-backup --json catalog check` |
| `catalog export` | Atomically write portable catalog JSON. Initialized state and writable parent; `--output PATH`. Replaces output file; confidential. Exit 0 `{exported}`. `lto-backup --json catalog export --output D:\Safe\catalog-export.json` |

## Progress contract

Every progress line is one JSON event envelope with required `event` and `at`.
`file.activity` additionally has required `index`, `relative_path`, `phase`,
`copied_bytes`, and `pending_bytes`; `io_mode` is supplied by Windows paths.
`strategy.selected` includes `io_mode`, `copied_bytes: 0`, `pending_bytes: 0`.
`hash.complete` also includes `hash_complete_seconds`. `timing.complete` also
includes `data_complete_seconds`, `copy_return_seconds`,
`close_elapsed_seconds`, and `hash_complete_seconds`. Warning envelopes
`catalog.backup.warning` and `catalog.snapshot.warning` have `event`, `at`,
`block_id`, and `error` (not a file index/path).

All source-exposed activity phases are `strategy.selected`, `read.pending`,
`read.complete`, `write.pending`, `write.complete`, `flush.pending`,
`flush.complete`, `close.pending`, `close.complete`, `close_queue.pending`,
`close_queue.complete`, `hash.complete`, and `timing.complete`. `file.progress`
has `index`, `relative_path`, `copied_bytes`, `file_bytes`; `file.start` has
`index`, `total_files`, `relative_path`, `size`; `file.complete` has `index`,
`total_files`, `relative_path`, `copied_bytes`, `total_bytes`, `sha256`.

For the Windows `CopyFileEx` path, the emitted per-file lifecycle is
`file.start`, `strategy.selected`, `write.pending`, zero or more
`write.complete`/`file.progress`, `close.pending`, `close.complete`,
`hash.complete`, `timing.complete`, then `file.complete`. That is an event
ordering guarantee, not physical-tape completion. The alternate cached
sequential path can interleave `read.*` and `write.*`, or use
`close_queue.*`; fallback copying uses repeated `write.*`, then `flush.*`, then
`close.*`. Do not assume one total order across these alternatives or invent
bytes. The next backup file starts only after its `close.complete` in the
CopyFileEx path; automation preserves unknown fields and waits for final result.
