# Riferimento CLI

LTO Archiver 0.11.26 espone `lto-backup`. L'inventario deriva da
`python -m ltobackup --help` e da `--help` di ogni sottocomando, non da README
precedenti.

## Contratto comune

`--state-dir PATH` sceglie lo stato; `--json` rende JSON il risultato finale;
`--version` stampa versione; `-h`/`--help` stampa aiuto. Successo 0, errore di
validazione/operativo 2, capacita 3, Ctrl+C 130, imprevisto 1; errore parser 2.
Gli errori non sono garantiti JSON. Gli esempi sono sintetici.

`init` e `telemetry` seguono startup separati: `init` salva impostazioni fornite
e inizializza catalogo, ma non esegue upgrade legacy ne configura log rotante;
`telemetry` legge SCSI senza stato catalogo. Ogni altra foglia analizzata prende
lock stato, upgrade impostazioni, configura log rotante, apre poi
`initialize`/migra catalogo. Quindi query diagnostica non e sola lettura forense:
puo aggiornare `config.json`, creare/ruotare log, inizializzare/migrare prove.
Conservare/copiare stato sospetto prima di invocarla.

## Comandi pubblici

Ogni riga indica scopo; precondizioni/argomenti; effetto distruttivo;
uscita/JSON; esempio. `library`, `tape`, `block`, `automatic`, `restore` e
`catalog` raggruppano i comandi foglia indicati.

| Comando | Contratto ed esempio |
| --- | --- |
| `library` | **Scopo gruppo:** scegliere foglia library (`add`, `list`, `delete`). **Argomenti/precondizioni:** foglia obbligatoria; gruppo offre solo aiuto. **Effetto:** nessuno senza foglia; parser si ferma prima inizializzazione stato/log/catalogo. **Uscita/JSON:** `lto-backup library` e errore parser (uscita 2), nessun JSON risultato; `--help` esce 0. `lto-backup library --help` |
| `tape` | **Scopo gruppo:** scegliere foglia tape (`register`, `list`). **Argomenti/precondizioni:** foglia obbligatoria; solo aiuto. **Effetto:** nessuno senza foglia. **Uscita/JSON:** foglia mancante, uscita 2/nessun JSON; aiuto 0. `lto-backup tape --help` |
| `block` | **Scopo gruppo:** scegliere foglia block (`list`, `forget`). **Argomenti/precondizioni:** foglia obbligatoria; solo aiuto. **Effetto:** nessuno senza foglia. **Uscita/JSON:** foglia mancante, uscita 2/nessun JSON; aiuto 0. `lto-backup block --help` |
| `automatic` | **Scopo gruppo:** scegliere foglia recupero automatico (`reset-cassette`). **Argomenti/precondizioni:** foglia obbligatoria; solo aiuto. **Effetto:** nessuno senza foglia. **Uscita/JSON:** foglia mancante, uscita 2/nessun JSON; aiuto 0. `lto-backup automatic --help` |
| `restore` | **Scopo gruppo:** scegliere foglia restore (`plan`, `run`). **Argomenti/precondizioni:** foglia obbligatoria; solo aiuto. **Effetto:** nessuno senza foglia. **Uscita/JSON:** foglia mancante, uscita 2/nessun JSON; aiuto 0. `lto-backup restore --help` |
| `catalog` | **Scopo gruppo:** scegliere foglia catalog (`check`, `export`). **Argomenti/precondizioni:** foglia obbligatoria; solo aiuto. **Effetto:** nessuno senza foglia. **Uscita/JSON:** foglia mancante, uscita 2/nessun JSON; aiuto 0. `lto-backup catalog --help` |
| `init` | Crea impostazioni/catalogo. `--state-dir` scrivibile; opzionali `--reserve-gib`, `--buffer-mib` (1–64), `--min-age-seconds`. Scrive configurazione/catalogo locale, mai nastro/SMB. Uscita 0 JSON `{state_dir,catalog,reserve_bytes,reserve_human}`. `lto-backup --state-dir C:\LtoState --json init --buffer-mib 16` |
| `library add` | Registra sorgente. Stato inizializzato; `--id --name --source`; sorgente utilizzabile. Scrive solo catalogo. Uscita 0 `{added,source}`. `lto-backup library add --id LIB_DEMO --name Demo --source '\\files.example.test\archive'` |
| `library list` | Elenca librerie attive o tutte con `--all`. Stato inizializzato; nessun effetto. Uscita 0 array JSON. `lto-backup --json library list --all` |
| `library delete` | Elimina logicamente libreria. ID esistente, `--id` e `--confirm` identico. Rimuove dati catalogo, lascia SMB/nastro. Uscita 0 `{deleted,...}`, conferma errata 2. `lto-backup library delete --id LIB_DEMO --confirm LIB_DEMO` |
| `tape register` | Associa identità LTFS ispezionata. Stato inizializzato, LTFS montato; `--id --mount`, `--cassette-number` opzionale (ID predefinito). Scrive nel catalogo l'etichetta LTFS univoca e il seriale Win32 diagnostico, non payload/formattazione. Uscita 0 `{tape_id,cassette_number,mount,label,serial,filesystem,free_bytes}`; errore identità/LTFS 2. `lto-backup tape register --id TAPE_DEMO_01 --cassette-number DEMO01 --mount L:\` |
| `tape list` | Elenca nastri registrati. Stato inizializzato; nessun argomento/effetto. Uscita 0 righe JSON. `lto-backup --json tape list` |
| `scan` | Calcola blocco successivo senza scrivere. `--library` registrata/leggibile; `--min-age-seconds` opzionale. Nessun effetto. Uscita 0 `{library_id,source_root,files,bytes,human,skipped_unchanged,skipped_too_recent}`. `lto-backup --json scan --library LIB_DEMO --min-age-seconds 900` |
| `backup` | Copia blocco su LTFS registrato/montato. Richiede catalogo, libreria/nastro/mount corrispondente/capacita; `--library --tape --mount`, eta, `--dry-run`, `--json-progress` opzionali. Normale: scrive LTFS, catalogo, manifest/backup; provvisorio fallito marcato failed. Dry run non copia. Uscita 0 `nothing-to-copy` o `{status,block_id,...}`, capacita 3. `--json-progress` emette JSON per riga prima del risultato: `file.start`, `file.activity`, `file.progress`, `file.complete`, `block.complete`/`block.failed`, warning. `lto-backup --json backup --library LIB_DEMO --tape TAPE_DEMO_01 --mount L:\ --json-progress` |
| `block list` | Elenca blocchi, `--library` opzionale, nascosti con `--all`. Stato inizializzato; nessun effetto. Uscita 0 array JSON. `lto-backup --json block list --library LIB_DEMO --all` |
| `block forget` | Nasconde blocco. `--id` esistente e `--confirm` identico. Cambia solo visibilita catalogo; byte nastro restano. Uscita 0 `{forgotten,tape_data_deleted:false,...}`, altrimenti 2. `lto-backup block forget --id BLOCK_DEMO --confirm BLOCK_DEMO` |
| `automatic reset-cassette` | Scarta tentativo automatico interrotto corrente. `--job` esistente/corrente e `--confirm` identico. Riparte da zero e riformatta: solo dopo revisione recupero. Uscita 0 `{job_id,sequence,status:'paused',discarded,...}`, altrimenti 2. `lto-backup automatic reset-cassette --job JOB_DEMO --confirm JOB_DEMO` |
| `restore plan` | Mostra requisiti nastro di ripristino. `--library` esistente; nessun effetto. Uscita 0 righe `{tape_id,file_count,total_bytes,human}`. `lto-backup --json restore plan --library LIB_DEMO` |
| `restore run` | Ripristina da nastro registrato/montato. `--library --tape --mount --destination`; destinazione scrivibile; `--overwrite --json-progress` opzionali. Scrive file destinazione; overwrite puo sostituirli. Uscita 0 `{restored_files,restored_bytes,human}`; progress JSON `restore.skip`/`restore.complete`. `lto-backup --json restore run --library LIB_DEMO --tape TAPE_DEMO_01 --mount L:\ --destination D:\Restore --json-progress` |
| `doctor` | Controlla catalogo e opzionalmente nastro montato. Stato inizializzato; entrambi `--tape` e `--mount` o nessuno. Query non scrive payload nastro, ma invocazione analizzata puo aggiornare impostazioni, creare log, `initialize`/migrare catalogo: conservare prove sospette prima. Uscita 0 integrita/chiavi/pending e volume; uno solo e 2. `lto-backup --json doctor --tape TAPE_DEMO_01 --mount L:\` |
| `telemetry` | Snapshot SCSI sola lettura. `--device` opzionale (`TAPE0`). Nessun lock catalogo, scrittura, format/mount/unmount. Uscita 0 anche non disponibile `{available,detail,activity,device,read_only:true}`. Non sondare device posseduto StoreOpen. `lto-backup --json telemetry --device TAPE0` |
| `catalog check` | Controlla schema, SQLite, chiavi, numeri cassetta, file visibili non committed. Non scrive payload nastro, ma invocazione analizzata puo upgrade impostazioni, creare log, `initialize`/migrare catalogo: conservare prove sospette prima. Uscita 0 `{schema_version,integrity,foreign_key_errors,missing_cassette_numbers,uncommitted_visible_files}`. `lto-backup --json catalog check` |
| `catalog export` | Scrive atomicamente JSON catalogo. Stato inizializzato e padre scrivibile; `--output PATH`. Sostituisce output, riservato. Uscita 0 `{exported}`. `lto-backup --json catalog export --output D:\Safe\catalog-export.json` |

## Contratto progress

Ogni riga progress e envelope JSON con `event` e `at` obbligatori.
`file.activity` ha anche `index`, `relative_path`, `phase`, `copied_bytes`,
`pending_bytes` obbligatori; percorsi Windows forniscono `io_mode`.
`strategy.selected` include `io_mode`, `copied_bytes: 0`, `pending_bytes: 0`;
`hash.complete` include anche `hash_complete_seconds`; `timing.complete` include
`data_complete_seconds`, `copy_return_seconds`, `close_elapsed_seconds`,
`hash_complete_seconds`. Warning `catalog.backup.warning` e
`catalog.snapshot.warning` hanno `event`, `at`, `block_id`, `error` (non indice/path).

Tutte le fasi activity esposte dal sorgente sono `strategy.selected`,
`read.pending`, `read.complete`, `write.pending`, `write.complete`,
`flush.pending`, `flush.complete`, `close.pending`, `close.complete`,
`close_queue.pending`, `close_queue.complete`, `hash.complete`,
`timing.complete`. `file.progress` ha `index`, `relative_path`, `copied_bytes`,
`file_bytes`; `file.start` ha `index`, `total_files`, `relative_path`, `size`;
`file.complete` ha `index`, `total_files`, `relative_path`, `copied_bytes`,
`total_bytes`, `sha256`.

Nel percorso Windows `CopyFileEx`, ciclo per file emesso e `file.start`,
`strategy.selected`, `write.pending`, zero o piu `write.complete`/
`file.progress`, `close.pending`, `close.complete`, `hash.complete`,
`timing.complete`, poi `file.complete`. E garanzia ordine eventi, non
completamento fisico nastro. Percorso cached sequential alternativo puo
intercalare `read.*`/`write.*` o usare `close_queue.*`; fallback usa ripetuti
`write.*`, poi `flush.*`, poi `close.*`. Non assumere ordine totale tra
alternative ne inventare byte. Nel CopyFileEx il file backup successivo parte
solo dopo `close.complete`; automazione conserva campi ignoti e attende risultato.
