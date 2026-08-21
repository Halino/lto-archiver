# Operazioni LTFS e completamento sicuro

Questa guida tratta LTO Archiver **0.11.26** con HPE StoreOpen 3.5.0. LTO e un
supporto sequenziale: una scrittura filesystem puo essere accettata dalle cache
prima del lavoro fisico nastro e dell'indice LTFS. StoreOpen/FUSE possiede
formattazione, mount, servizio filesystem LTFS, unmount ed espulsione; LTO
Archiver scrive sul filesystem montato, non direttamente sul drive.

## Proprieta e catena di completamento

LTO Archiver usa `sync_type=unmount`: l'indice LTFS principale e sincronizzato
all'unmount e non ha una percentuale deducibile dall'applicazione. Per ogni file
avvia `CopyFileEx`, ne attende il ritorno e registra `close.complete`. Il ritorno
significa che l'handle file dell'applicazione e chiuso. Il provider puo ancora
fare flush di dati e metadati cache; StoreOpen aggiorna poi l'indice LTFS e
smonta il volume. `unmount.progress` segnala gli stadi reali: sincronizzazione
cache/indice, rilascio lettera LTFS ed espulsione.

L'applicazione non puo rinviare handle aperti affinche StoreOpen li chiuda dopo.
Possiede solo l'handle aperto da se stessa; StoreOpen/FUSE possiede provider
filesystem, provider flush, aggiornamento indice, unmount e stato supporto
fisico. Rinviare handle renderebbe ambiguo il completamento, violerebbe il
contratto sequenziale di un file e non trasferisce la proprieta dell'handle
Windows a StoreOpen. Per questo non esistono chiusure concorrenti o un lotto
finale di handle: dopo `close.complete` l'applicazione non riapre ne interroga
il file LTFS, e solo allora inizia il file successivo. Non usa
`FlushFileBuffers` esplicito per ogni file.

Un blocco diventa ricercabile e ripristinabile solo dopo provider flush,
aggiornamento indice e unmount riuscito. Non fermare FUSE, spegnere il server,
rimuovere media, riusare la lettera LTFS o dichiarare completamento finche il
volume e montato o StoreOpen sta finalizzando.

## Diagnostica sicura

Se un drive e lento o una chiusura e lunga, osservare prima heartbeat
applicazione, eventi StoreOpen/FUSE e attivita LTFS. Una chiamata pending con
tempo crescente non autorizza a inventare avanzamento o aprire il nastro. Non
interrogare direttamente `TAPE0`, non inviare comandi SCSI/device e non aprire
la lettera LTFS con Explorer, indicizzatori o antivirus mentre StoreOpen possiede
il drive: si possono creare contese di semaforo esclusivo o provider.

Dopo il rilascio sicuro del device da StoreOpen, usare HPE Library and Tape
Tools (HPE L&TT) per generare un support ticket e controllare salute, margini,
retry, interfaccia e firmware. Distinguere problemi media/drive con una
cassetta scratch nota buona, solo dopo rilascio; non testare una cassetta dati
con una valutazione distruttiva.

Leggere TapeAlert e LED Clean drive. Pulire solo se il LED Clean lampeggia o
TapeAlert/supporto indica `Clean Now`, `Clean Periodic` o `Clean requested`.
Per un drive HPE Ultrium usare solo la cartuccia universale di pulizia `C7978A`;
mai tamponi o pulizia preventiva. Se il LED continua a lampeggiare dopo pulizia
e caricamento di media nota buona, predisporre assistenza drive.
