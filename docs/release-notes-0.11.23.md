# Note di rilascio 0.11.23

La 0.11.23 e la versione installata e verificata sul server Windows collegato al drive LTO. Mantiene la copia diretta dei file SMB su LTFS e consolida pianificazione persistente, calcolo capacita, ripresa dei job e monitoraggio delle operazioni lente.

## Scrittura e prestazioni

- Il percorso dati Windows e obbligatoriamente `windows_cached_sequential_pipeline`; non esiste fallback silenzioso.
- Tre buffer sovrappongono lettura SMB e scrittura sequenziale con cache Windows e `FILE_FLAG_SEQUENTIAL_SCAN`.
- Un solo worker chiude gli handle LTFS in ordine mentre procede il file successivo. La coda contiene al massimo due handle in attesa e applica contropressione se StoreOpen rallenta.
- Non viene eseguito `FlushFileBuffers` per ogni file e i file appena scritti non vengono riaperti per una verifica sul nastro.
- SHA-256 viene calcolato durante l'unico passaggio di lettura e resta la verifica di integrita registrata nel catalogo.

## Stato e interfaccia

- La GUI distingue `read.pending`, `write.pending` e `close_queue.pending`, senza attribuire byte non ancora confermati.
- Velocita effettiva e invio alla cache LTFS restano indicatori separati e usano assi indipendenti nel grafico mobile.
- Il pannello conserva geometria stabile durante lettura, scrittura, chiusura e finalizzazione.
- Il monitor di finalizzazione mostra chiusure completate, tempo trascorso ed ETA appresa; l'unmount espone sincronizzazione indice, rilascio lettera ed espulsione.

## Job, cassette e capacita

- Ogni cassetta futura conserva un manifest esatto di libreria, percorso, dimensione e mtime. Una ripresa non ridistribuisce i file gia assegnati.
- I file nuovi vengono aggiunti soltanto dove entrano interi: spazio residuo delle cassette future, riserve e infine nuove etichette.
- Il modello di capacita include arrotondamento degli oggetti e metadati LTFS per tutti i profili supportati da LTO-5 a LTO-10; il margine applicativo predefinito e zero.
- Dopo il mount prevale il minimo tra limite del profilo, spazio Windows e spazio nativo della partizione dati LTFS.
- Le cassette registrate sono protette. Il riuso distruttivo richiede un consenso separato e il catalogo precedente viene invalidato soltanto dopo la formattazione riuscita.

## Installazione verificata

La release genera GUI e CLI autonome, hash SHA-256, installer amministrativo, configurazione mirata di Controlled Folder Access e documentazione. La verifica post-installazione controlla versione, hash, sottosistema grafico, collegamento Desktop, integrita SQLite, schema catalogo 12, blocchi provvisori e configurazione della capacita. Lo smoke test apre tutte le pagine della GUI senza richiedere una cassetta.
