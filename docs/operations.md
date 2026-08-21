# Guida operativa

## Preparazione

Dalla 0.11.21 il piano di ogni tipo supportato (LTO-5–LTO-10) include allocazione oggetti e metadati LTFS, non soltanto la somma dei file. Sul supporto montato la capacità nativa della partizione dati letta con `ltfsattr` prevale sul solo valore di Explorer. Nella pagina Job la voce **Allocazione e metadati LTFS** è già sottratta dallo spazio disponibile.

1. Collegare una o piu librerie SMB dalla pagina **Librerie**.
2. Usare **Scansiona tutte le librerie** e attendere il riepilogo cumulativo.
3. Controllare dimensione, numero di file e data dell'ultima scansione.
4. Aprire **Piano cassette**, scegliere il tipo LTO e selezionare tutte le librerie da includere.

Il piano usa la capacita dati LTFS del tipo scelto e distribuisce i file con first-fit decreasing. Ottimizza il riempimento dell'intero job, non di una singola libreria. Un file resta indivisibile.

## Creazione del job

Inserire le etichette nell'ordine fisico previsto, una per riga. Le etichette oltre il fabbisogno diventano riserve future e non vengono formattate finche il job non cresce. Il job salva nel catalogo:

- nome e ID stabile;
- librerie incluse;
- tipo di supporto;
- sequenza delle cassette;
- checkpoint e stato di ogni cassetta.

Piu job possono coesistere, ma con un solo drive se ne esegue uno alla volta. Una libreria non puo appartenere a due job contemporaneamente non conclusi.

## Ciclo automatico della cassetta

Per ogni elemento operativo della coda il programma:

1. attende senza timeout l'inserimento della cassetta richiesta;
2. pulisce soltanto le mappature StoreOpen residue possedute dall'applicazione;
3. se l'operazione e **NUOVA**, formatta con `--force` e assegna l'etichetta; se e **APPEND**, non formatta;
4. sceglie una lettera libera, preferendo `L:`;
5. monta LTFS con aggiornamento dell'indice allo smontaggio;
6. per APPEND verifica numero cassetta, seriale ed etichetta LTFS contro il catalogo;
7. copia direttamente i file SMB con il loro nome finale;
8. smonta senza timeout, consolidando l'indice;
9. rimuove la mappatura ed espelle la cassetta;
10. passa alla successiva e torna in attesa.

L'unico intervento ordinario e rimuovere la cassetta espulsa e inserire quella indicata.

## Lettura della pagina Job

- **Progresso job**: byte confermati su tutte le cassette operative.
- **Progresso cassetta**: byte confermati rispetto allo spazio utilizzabile della cassetta corrente.
- **Velocita live**: media mobile dei ritorni di scrittura. Conserva l'ultimo campione valido e mostra separatamente da quanto manca una nuova conferma, evitando che il valore lampeggi tra numero e attesa.
- **Media effettiva cassetta**: byte confermati divisi per tutto il tempo trascorso dalla prima scrittura, comprese chiusure, intervalli tra file e unmount.
- **Invio alla cache LTFS**: ritorno corrente delle chiamate filesystem; non rappresenta la velocita fisica del nastro e puo fermarsi mentre StoreOpen drena i buffer.
- **Grafico 5 minuti**: campioni regolari di un secondo, verde per la media cassetta e ambra per l'ingresso nella cache LTFS. Le linee non sono interpolate e le scale scendono gradualmente. Un tratto ambra mancante segnala assenza di campioni; non significa automaticamente che il drive sia fermo.
- **Fascia temporale**: tempo trascorso, ETA della cassetta corrente ed ETA dell'intero set; sui display stretti i tre segmenti sono impilati.
- **Heartbeat StoreOpen**: file, blocco e secondi trascorsi mentre la chiamata LTFS non e ancora rientrata.
- **Attivita LTFS**: telemetria read-only di buffer, movimento, posizione e TapeAlert quando disponibile.
- **Heartbeat StoreOpen**: distingue la consegna dei byte dalla chiusura reale del file; durante lo smontaggio mostra sincronizzazione cache/indice, rilascio lettera ed espulsione senza inventare una percentuale interna a StoreOpen.

Il rumore del drive senza aumento dei byte non implica automaticamente un blocco: LTFS puo scrivere buffer, riposizionarsi o completare una chiamata. Se il contatore dell'heartbeat cresce, la GUI e il worker sono vivi. I byte avanzano soltanto quando StoreOpen restituisce la scrittura.

Durante una fase LTFS pendente la media effettiva viene ricalcolata sul tempo che continua a trascorrere: puo scendere e fare aumentare le ETA. Prima del primo byte le ETA mostrano `-`. L'ETA cassetta usa il carico pianificato sul supporto corrente; l'ETA set usa tutti i byte ancora previsti nel job.

Dalla 0.11.24 i file dati usano `windows_copyfileex_parallel_hash`: `CopyFileEx` delega a Windows la copia e la chiusura come Explorer, mentre un worker calcola SHA-256 leggendo in parallelo la sorgente SMB. Non viene eseguito `FlushFileBuffers` per ogni file. Il file successivo inizia soltanto dopo il ritorno di `CopyFileEx`, quindi non restano handle da consolidare o una coda da drenare a fine cassetta. Non c'e fallback al writer precedente: un errore Windows ferma il job esplicitamente. Dalla 0.11.25 il catalogo conserva i tempi di consegna dati, ritorno della copia, chiusura e hash; la GUI segnala una chiusura oltre 120 secondi. Il monitor di finalizzazione resta compatto durante la copia e si espande solo per l'unmount reale.

## Interruzione e ripresa

**Interrompi ora** viene osservato tra i blocchi di copia. Se StoreOpen sta trattenendo una chiamata, il comando diventa effettivo quando quella chiamata termina. Il tentativo corrente viene scartato, il file incompleto viene rimosso, LTFS viene smontato e la cassetta viene espulsa. Una cassetta NUOVA riparte da zero dopo la riformattazione. Una cassetta APPEND conserva tutti i blocchi completati in precedenza e riprova soltanto il nuovo ciclo, senza formattazione.

**Salva job** registra il piano senza avviare il drive. Per iniziare o proseguire, selezionare il job e usare **Avvia / riprendi job selezionato**; la conferma identifica il job, il drive e la prossima cassetta. Gli altri job sullo stesso drive restano salvati: non esiste un avvio FIFO automatico. Il programma prova prima lo spazio residuo stimato dell'ultima cassetta completata, usando soltanto file interi. Lasciare vuoto l'elenco per usare APPEND e le riserve esistenti; aggiungere nuove etichette per accodarle allo stesso job prima dell'avvio. Dopo il mount lo spazio libero reale LTFS e autorevole: se il nastro APPEND e pieno, il job passa al supporto successivo oppure resta salvato chiedendo nuove etichette.

Dalla 0.11.19, la pianificazione crea un manifest esatto per ogni cassetta. La chiusura della GUI non sposta ne rimuove i percorsi gia assegnati. Per fermarsi al confine sicuro, attendere l'espulsione della cassetta corrente, non inserire la successiva e premere **Interrompi** durante l'attesa senza timeout. Alla ripresa il programma verifica dimensione e mtime di tutti i file del manifest; un file mancante o modificato arresta il job. I file nuovi vengono aggiunti, senza rimescolare quelli esistenti, prima nello spazio residuo delle cassette future, poi nelle riserve e infine nelle nuove etichette inserite dall'operatore.

## Ricerca e ripristino offline

La struttura ad albero, la ricerca e i metadati provengono dal catalogo SQLite locale. Non serve inserire cassette per navigare. Il risultato indica cassetta, blocco e percorso LTFS; soltanto l'esecuzione del ripristino richiede i supporti elencati dal piano.

## Eliminazioni

- **Elimina job** rimuove schedulazione e coda, non librerie o dati gia catalogati.
- **Elimina libreria** rimuove dal catalogo la sola libreria e i suoi riferimenti; non cancella SMB o LTFS.
- **Dimentica blocco** e un'operazione logica e non recupera spazio sul nastro.
- La cancellazione fisica selettiva su LTFS non e una strategia affidabile di recupero spazio. Le cassette registrate restano protette per impostazione predefinita; selezionando l'autorizzazione separata al riuso, LTO Archiver riformatta integralmente il supporto e rimuove i vecchi riferimenti soltanto dopo il successo della formattazione.
