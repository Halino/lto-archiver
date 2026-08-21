# Guida utente

LTO Archiver **0.11.27** ha quattro fasi: **Librerie**, **Piano cassette**,
**Job automatici** e **Backup / catalogo e ripristino**. Il job viene salvato
prima di usare un drive, evitando azioni nastro non pianificate.

## Librerie e piano cassette

In **Librerie**, registrare ogni libreria SMB con ID stabile, nome e percorso
sorgente, poi eseguire la scansione. Controllare numero file, dimensione e data
ultima scansione. In **Piano cassette**, scegliere profilo LTO-5--LTO-10 e
librerie previste. Il piano usa capacita partizione dati LTFS, allocazione e
metadati; mantiene ogni file intero e calcola le etichette fisiche. Inserire le
etichette in ordine fisico, una per riga. Le ulteriori diventano riserve e non
sono formattate finche non servono.

## Salvataggio e avvio esplicito

**Job automatici** salva librerie, profilo, sequenza cassette e checkpoint.
Salvare non avvia il drive. Selezionare il job e usare **Avvia / riprendi job
selezionato**; la conferma identifica job, drive e prossima cassetta. Un drive
ha un solo job attivo e una libreria non puo appartenere a due job non conclusi.
Risolvere conflitti riprendendo, completando o eliminando il job esistente; non
esiste avvio FIFO automatico.

Validare l'etichetta mostrata prima di inserire il supporto. Il runner attende
la cassetta richiesta senza timeout applicativo. `NUOVA` formatta LTFS dopo
conferma distruttiva. `APPEND` non formatta e controlla numero cassetta ed
etichetta del volume LTFS contro il catalogo. Il seriale Win32 esposto da
StoreOpen/FUSE resta diagnostico e può coincidere con quello di un'altra
cassetta; l'etichetta LTFS identifica il supporto. `APPEND` conserva i blocchi
committed. Un APPEND pieno passa al successivo pianificato o lascia il job
salvato chiedendo etichette.

## Avanzamento e finalizzazione

Il runner scrive un file alla volta: `write.pending`, `write.complete`,
`file.progress`, `close.pending`, quindi `close.complete` quando `CopyFileEx`
ritorna con l'handle chiuso. SHA-256 legge in parallelo la sorgente SMB. Il file
e registrato e il successivo inizia solo dopo chiusura e hash completi.

La pagina job riporta byte confermati job/cassetta, valore live, **Media
effettiva cassetta**, ingresso cache LTFS, tempo trascorso, ETA cassetta e job,
heartbeat StoreOpen e attivita LTFS. I byte confermati non avanzano durante una
chiamata provider pending. La media effettiva e byte confermati dalla prima
scrittura divisi per il tempo trascorso, compresi chiusura, verifica, intervalli
e unmount; la cache e un valore filesystem separato, non velocita fisica nastro.

Il grafico di cinque minuti usa bucket esatti di un secondo e tracce non
interpolate. L'asse sinistro verde e **Media effettiva cassetta**; quello destro
ambra e **Invio alla cache LTFS**. Entrambi gli assi indipendenti mostrano
l'unita di velocita alle tacche esatte 100%, 50% e 0% (alto, centro, origine).
Un campione cache mancante lascia un buco ambra reale e non prova che il drive
sia fermo. Durante StoreOpen pending, tempo e media si aggiornano senza
inventare byte o percentuali provider.

Al termine cassetta `unmount.progress` guida sincronizzazione cache/indice,
rilascio lettera LTFS ed espulsione. Solo un unmount riuscito rende il blocco
visibile a ricerca e ripristino. Una cassetta non e completa finche il suo
indice rimane non committed.

## Arresto, ricerca e ripristino

**Interrompi ora** e osservato fra copie; se StoreOpen possiede una chiamata
pending ha effetto quando questa ritorna. Il file incompleto e rimosso, LTFS e
smontato e la cassetta e espulsa. Una `NUOVA` riparte riformattata da zero;
`APPEND` conserva i blocchi completati e ritenta il nuovo ciclo senza formattare.
Per fermare al confine di una cassetta, attendere l'espulsione, non inserire la
cassetta successiva e interrompere durante l'attesa del supporto.

Ricerca e albero backup usano il catalogo SQLite locale e funzionano offline.
I risultati indicano libreria, cassetta, blocco e percorso LTFS relativo.
Ripristino crea il piano: inserire i supporti elencati e scegliere la
destinazione. Rimuovere job, libreria o blocco e logico: non cancella sorgenti
SMB o contenuti LTFS.

## Primo backup

1. Registrare una libreria SMB solo di documentazione e scansionarla.
2. Creare il piano, scegliere profilo, validare etichette e confermare `NUOVA`.
3. Salvare, selezionare e usare **Avvia / riprendi job selezionato**.
4. Inserire solo la cassetta richiesta; osservare `close.complete` e
   `unmount.progress`, rimuovendo il supporto solo quando e richiesta espulsione.
