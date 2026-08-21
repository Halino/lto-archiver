# Diagnostica e risoluzione problemi

## Il drive gira ma i byte non avanzano

Dalla 0.11.14 controllare il testo principale del job e la fascia temporale:

- se mostra una fase StoreOpen di scrittura, scaricamento buffer, chiusura o verifica e i secondi aumentano, la chiamata LTFS e ancora attiva;
- se la telemetria mostra buffer o posizionamento, il drive sta eseguendo lavoro interno;
- se la linea ambra del grafico si interrompe, significa soltanto che non sono arrivati nuovi campioni confermati; il valore numerico resta sull'ultimo campione valido e ne mostra l'eta;
- la media effettiva include le pause e continua a cambiare durante una chiamata LTFS pendente;
- l'ETA cassetta usa il carico pianificato sul supporto, mentre l'ETA set usa tutti i dati restanti del job;
- se anche il contatore dei secondi e fermo e la finestra non risponde, raccogliere il log applicativo.

Non sommare il blocco pendente ai byte copiati: StoreOpen potrebbe ancora restituire un errore. Il contatore corretto cresce dopo `write.complete`.

Per confrontare due cassette usare la velocita effettiva finale e il tempo totale di scrittura. Il valore **Invio alla cache LTFS** puo superare la velocita fisica del drive per effetto dei buffer e non e un indicatore end-to-end affidabile.

## Attesa tra due file

LTFS puo chiudere metadati, scaricare buffer o riposizionare il nastro. Con `sync_type=unmount` l'indice principale viene rinviato allo smontaggio, ma singole chiamate filesystem possono comunque impiegare tempo. L'heartbeat distingue questo intervallo da una GUI congelata.

Se applicazione, `ltfs.exe` e `FUSE4WinSvc.exe` non accumulano I/O o CPU durante
un campione prolungato, trattare la fase come attesa nel provider o nel drive, non
come velocita di scrittura pari a zero. Procedere in quest'ordine:

1. non interrogare direttamente il device `TAPE0` mentre StoreOpen lo possiede e
   non aprire la lettera LTFS con Explorer, indicizzatori o strumenti antivirus;
2. controllare gli eventi `LTFS` e `FUSE4WinSvc`; un evento di semaforo esclusivo
   indica una possibile contesa, ma da solo non identifica il processo responsabile;
3. verificare LED e TapeAlert del drive. Pulire soltanto se il LED `Clean` lampeggia
   oppure se compare `Clean Now`, `Clean Periodic` o `Clean requested`;
4. dopo il rilascio sicuro di StoreOpen, generare un support ticket con HPE Library
   and Tape Tools e controllare salute di scrittura, margini, retry, interfaccia e
   firmware;
5. se il ticket non chiarisce il problema, eseguire il Drive Assessment soltanto
   con una cassetta scratch nota e buona, mai con la cassetta dati.

Per un drive HPE Ultrium usare esclusivamente la cartuccia di pulizia universale
`C7978A`. Non usare tamponi e non eseguire pulizie preventive quando il drive non le
richiede. Se il LED resta lampeggiante dopo la pulizia e il caricamento di una
cassetta buona, il drive richiede assistenza.

Riferimenti HPE: [indicatori LTO-6](https://support.hpe.com/hpesc/public/docDisplay?docId=c05170118&docLocale=en_US),
[controllo salute del drive](https://support.hpe.com/hpesc/public/docDisplay?docId=sd00007511en_us&docLocale=en_US&page=how_1325_check.html) e
[support ticket L&TT](https://support.hpe.com/hpesc/public/docDisplay?docId=sd00003778en_us&page=GUID-D7147C7F-2016-0901-04BD-000000000A28.html).

## Mount lungo

Un mount puo richiedere minuti per caricamento, lettura dell'indice e controllo del filesystem. Il job non applica un timeout all'attesa della cassetta; il timeout riguarda il tentativo di mount dopo che il supporto e stato rilevato. Non riutilizzare manualmente la lettera finche StoreOpen non ha concluso.

## Unmount lungo

L'unmount consolida l'indice LTFS e non ha timeout applicativo. Non spegnere il server, non fermare FUSE e non estrarre la cassetta finche la lettera non scompare e il programma non richiede l'espulsione.

## Lettera L: bloccata o mappatura residua

All'avvio di ogni ciclo LTO Archiver rimuove soltanto le mappature che corrispondono al proprio schema e al drive rilevato. Non elimina mappature estranee. Se la lettera rimane visibile dopo un arresto anomalo, chiudere StoreOpen, verificare l'assenza del volume LTFS e usare la funzione di pulizia stato prima di riprovare.

## Stato `copying` dopo un arresto

Usare dalla GUI **Reimposta e riprova cassetta**. L'operazione marca fallito soltanto il tentativo corrente e conserva i checkpoint precedenti. La stessa cassetta verra riformattata e riscritta dall'inizio.

## Controlled Folder Access o antivirus

L'installer autorizza esclusivamente:

- `C:\Program Files\LtoBackupManager\LtoBackupManager.exe`
- `C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe`

Non disattivare Defender e non creare esclusioni di cartella. Consultare [Installazione Windows](installation-windows.md) per verifica e ambienti GPO/Intune.

## Informazioni da raccogliere

- versione applicativa;
- ID e stato del job;
- etichetta e sequenza della cassetta;
- testo dell'heartbeat e secondi trascorsi;
- velocita effettiva e invio alla cache LTFS;
- stato StoreOpen/FUSE e presenza del volume LTFS;
- ultime righe di `C:\ProgramData\LtoBackupManager\logs\lto-backup.log`;
- eventuali TapeAlert.

Evitare di eseguire contemporaneamente comandi CLI che modificano il catalogo mentre la GUI possiede `run.lock`.
