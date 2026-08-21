# Architettura, catalogo e stati

## Componenti

- `LtoBackupManager.exe`: GUI e worker del job automatico.
- `LtoBackupManagerCli.exe`: manutenzione, verifica e automazione tecnica.
- `catalog.db`: fonte autorevole per librerie, file, versioni, nastri, blocchi e job.
- StoreOpen/FUSE: formattazione, mount, filesystem LTFS, unmount ed espulsione.
- Scanner SMB: inventario incrementale e metadati Windows.

La GUI non scrive direttamente sul drive. Il motore copia su un normale percorso LTFS montato; StoreOpen traduce le operazioni filesystem in lavoro sequenziale sul nastro.

## Stati del job automatico

Il ciclo persistente di una cassetta nuova e:

`waiting_media -> formatting -> mounting -> writing -> unmounting -> ejected`

Il ciclo APPEND salta obbligatoriamente la formattazione:

`waiting_media -> mounting -> identity_check -> writing -> unmounting -> ejected`

Dopo l'ultima cassetta operativa il job diventa `completed`. Un errore porta il job o la cassetta in `failed`; un'interruzione controllata lo lascia riprendibile dal checkpoint sicuro.

Ogni riga della coda persiste `operation=format|append` e l'eventuale consenso distruttivo `reuse_registered`. Le cassette eccedenti hanno stato di riserva e non entrano nel ciclo finche nuovi file non le rendono necessarie. Una riga completata puo essere riaperta in APPEND mantenendo il riferimento al nastro registrato; i blocchi storici restano entita separate e immutabili. Per una riga NUOVA autorizzata, l'invalidazione del vecchio nastro catalogato avviene in una transazione separata soltanto dopo il successo della formattazione fisica.

Lo schema catalogo 11 aggiunge `automatic_cassette_items`. Per ogni supporto non ancora completato conserva l'ordine esatto di libreria, percorso relativo, dimensione e mtime. Il runner seleziona esclusivamente gli elementi del manifest corrente e calcola i residui dai manifest delle cassette successive: una nuova scansione non puo spostare o omettere file gia assegnati. I nuovi file possono soltanto essere aggiunti a un manifest futuro se entrano nello spazio residuo, oppure a una riserva successiva. I job dello schema precedente vengono congelati atomicamente prima del mount successivo; se le etichette residue non bastano, la scrittura non parte. Lo schema 13 usa l'etichetta LTFS come identita univoca del supporto; il seriale Win32 presentato da StoreOpen/FUSE e conservato solo per diagnostica e puo ripetersi tra cassette diverse.

## Commit del catalogo

Durante la copia i blocchi sono provvisori. Diventano visibili a ricerca e ripristino soltanto dopo l'unmount riuscito. Questo impedisce al catalogo di dichiarare recuperabili dati il cui indice LTFS non e stato consolidato.

Il checkpoint e per ciclo cassetta, non per singolo file. Dopo un arresto durante `writing`, una cassetta nuova viene riscritta da zero. Per APPEND viene invalidato soltanto il nuovo blocco provvisorio: nastro, file e blocchi gia consolidati restano validi e il retry non puo chiamare il formatter.

## Protocollo di progresso 0.11.27

Per ogni file il motore segue questa sequenza:

1. emette `file.activity` con fase `write.pending` e avvia Windows `CopyFileEx` verso LTFS;
2. i callback emettono `write.complete` e `file.progress` con i byte confermati da Windows;
3. un worker separato calcola SHA-256 leggendo in parallelo la sorgente SMB;
4. quando tutti i byte sono consegnati emette `close.pending`; il ritorno di `CopyFileEx` garantisce la chiusura dell'handle e produce `close.complete`;
5. emette `timing.complete` con tempi separati per consegna dati, ritorno `CopyFileEx`, intervallo di chiusura e completamento SHA-256;
6. soltanto dopo la chiusura e il completamento dell'hash registra il file e passa al successivo, senza riaprire ne interrogare il file LTFS.

Il reporter automatico aggiunge job, sequenza, etichetta, capacita e totali senza modificare il significato dei byte. Espone `cassette_elapsed_seconds`, `cassette_eta_seconds` e `job_eta_seconds`. La media effettiva e `byte confermati / tempo dalla prima scrittura`: comprende quindi scrittura, flush, close, verifica e intervalli tra file. L'ETA cassetta usa i byte pianificati sulla cassetta corrente; l'ETA set usa i byte pianificati ancora mancanti nel job. Prima del primo byte le ETA sono sconosciute, mai infinite o zero arbitrarie.

La GUI conserva qualsiasi fase `pending` e aggiorna localmente il tempo trascorso ogni 100 ms. Non simula byte o throughput fisico durante una chiamata pendente: conserva l'ultimo valore live valido, ne espone l'eta e ricalcola la media effettiva e le ETA sul nuovo tempo trascorso. Il valore ricavato dai callback `CopyFileEx` e indicato separatamente come **invio alla cache LTFS**, stabilizzato con una media mobile per non far oscillare continuamente la lettura; la cache Windows puo confermare i dati prima della loro scrittura fisica sul nastro. Un canvas Tk a geometria fissa conserva cinque minuti in bucket esatti di un secondo: usa segmenti lineari non interpolati, lascia una discontinuita reale nella serie cache quando mancano campioni e stabilizza separatamente le due scale. La serie media cassetta continua durante l'unmount. La fase applicativa prevale sull'ultimo campione telemetrico `idle`.

Per i dati LTFS su Windows il percorso `windows_copyfileex_parallel_hash` delega copia e chiusura a `CopyFileEx`, lo stesso percorso di sistema della copia Explorer. In parallelo un solo worker legge la sorgente SMB per SHA-256; non scrive sul nastro e viene cancellato insieme alla copia. La scrittura resta rigorosamente su un file alla volta. Non esistono chiusure concorrenti, handle differiti o una coda da drenare a fine lotto. Manifesti e catalogo non usano questo percorso. Non e previsto fallback: un errore Windows resta un errore di copia, senza un secondo tentativo nascosto. Dopo `close.complete` il motore non riapre il file ne interroga i relativi metadati sul nastro.

Il controller emette inoltre `unmount.progress` per tre stadi reali: sincronizzazione cache/indice, rilascio della lettera e espulsione. Solo questi eventi alimentano il monitor di finalizzazione cassetta; la chiusura del singolo file resta nella telemetria di copia. Un heartbeat aggiorna il tempo e la media effettiva mentre StoreOpen trattiene la chiamata, senza dedurre una percentuale interna inesistente. Gli stadi completati vengono registrati nel catalogo. Errori del callback di telemetria vengono isolati: non possono interrompere `CloseHandle`, unmount o eject.

La telemetria SCSI e indipendente e read-only. Se StoreOpen riserva il device, l'evento puo essere `unavailable` senza compromettere la copia; l'heartbeat applicativo resta disponibile.

Il percorso opera senza `FlushFileBuffers` esplicito per ogni file.

## Capacita

Il modello di capacità è unico per tutti i profili supportati, da LTO-5 a LTO-10. Oltre al payload, arrotonda ogni oggetto all'unità MiB usata dagli attributi virtuali LTFS e riserva lo spazio dei metadati e dei file di completamento di ogni blocco/libreria. In append ricostruisce lo stesso costo dai file e dai blocchi completati nel catalogo.

Dopo il mount prevale il minimo tra limite residuo del profilo, libero del volume Windows e `ltfs.mediaDataPartitionAvailableSpace`; `ltfs.mediaDataPartitionTotalCapacity` viene usato per calcolare il già occupato senza confondere la capacità generica mostrata da Explorer con la partizione dati. Il margine extra configurabile resta separato e vale zero per impostazione predefinita.

Il piano usa la capacita della partizione dati LTFS documentata per il profilo LTO selezionato. Dopo il mount, la scrittura usa il minimo tra limite del profilo, spazio libero iniziale comunicato da Windows e margine extra configurato. Il valore predefinito del margine extra e zero; non viene sottratta una riserva fissa arbitraria.

## Concorrenza e lock

`run.lock` impedisce operazioni concorrenti che possono modificare catalogo o drive. La telemetria read-only non richiede il lock del job. `CopyFileEx` scrive e chiude un solo file alla volta; il worker SHA legge soltanto la sorgente. Il file successivo non parte prima di `close.complete`.
