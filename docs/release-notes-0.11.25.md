# LTO Archiver 0.11.25

## Job, conflitti e avvio

- Un job fallito continua a riservare le proprie librerie finche non viene reimpostato, completato o eliminato; non e quindi possibile creare per errore un secondo piano concorrente sugli stessi dati.
- **Salva job** continua a non avviare il drive. L'esecuzione richiede la selezione del job e il comando esplicito **Avvia / riprendi job selezionato**; gli altri job sul drive restano salvati e non esiste una coda FIFO automatica.
- Le indicazioni della GUI usano lo stesso nome del comando di avvio, evitando il precedente riferimento ambiguo a un pulsante “Riprendi”.

## Copia e chiusura LTFS

- `CopyFileEx` continua a chiudere ogni singolo handle prima del file successivo: non esiste un consolidamento applicativo finale che possa chiudere in blocco gli handle, e StoreOpen mantiene il controllo dell'aggiornamento dell'indice LTFS.
- Errori nel callback nativo o nel worker SHA-256 vengono propagati con la loro causa reale e non diventano falsi annullamenti del job.
- Il worker SHA-256 ha attese limitate e i percorsi Windows lunghi usano il prefisso nativo esteso.
- Per ogni file il catalogo registra `data_complete_seconds`, `copy_return_seconds`, `close_elapsed_seconds` e `hash_complete_seconds`; una chiusura di almeno 120 secondi viene marcata e segnalata nella GUI.

## Media, finalizzazione e grafico

- **Media effettiva cassetta** sostituisce l'etichetta generica “Velocita effettiva” e rimane visibile durante l'unmount, includendo quindi il costo reale della finalizzazione LTFS.
- Il monitor di finalizzazione resta compatto durante la copia e si espande soltanto sugli eventi reali `unmount.progress`: sincronizzazione cache/indice, rilascio mappatura ed espulsione.
- Il grafico a cinque minuti usa bucket regolari di un secondo, conserva i buchi reali della cache, disegna segmenti non interpolati e stabilizza separatamente le due scale. Il rendering segue quindi i campioni effettivi senza curve approssimative o continui salti dell'asse.
- Il catalogo registra il tempo completato di ogni stadio di unmount per confrontare le finalizzazioni successive.

## Compatibilita

- Versione catalogo invariata: schema 12.
- Versione applicazione e pacchetto: 0.11.25.
- Nessuna modifica distruttiva ai job, ai manifest o ai dati gia catalogati.
