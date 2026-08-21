# Documentazione di LTO Archiver

LTO Archiver gestisce backup append-only di grandi librerie SMB su cassette LTFS. Questa documentazione descrive la versione 0.11.27.

La 0.11.27 corregge lo stato del monitor di finalizzazione: distingue fasi in
corso, completate e fallite, blocca il cronometro al termine e torna inattiva
dopo l'espulsione. Mantiene inoltre la media effettiva durante l'unmount, il
grafico puntuale a cinque minuti e l'identità dei supporti HPE StoreOpen:
cassette LTFS diverse possono condividere
il seriale Win32 diagnostico, mentre l'etichetta LTFS resta univoca e viene
verificata prima della scrittura.

## Percorsi consigliati

- Per installare o aggiornare: [Installazione Windows](installation-windows.md)
- Per creare e proseguire un job: [Guida operativa](operations.md)
- Per capire catalogo, checkpoint ed eventi: [Architettura](architecture.md)
- Per analizzare mount, scrittura e GUI: [Diagnostica](troubleshooting.md)
- Per modificare e distribuire il progetto: [Sviluppo e rilascio](development.md)
- Per le modifiche incluse nella versione corrente: [Note di rilascio 0.11.27](release-notes-0.11.27.md)

Il [README principale](../README.md) rimane il riferimento sintetico per funzioni, requisiti, comandi CLI e capacita dei supporti.

## Regole fondamentali

1. Una cassetta viene considerata conclusa soltanto dopo un unmount LTFS riuscito.
2. Un file non viene diviso tra cassette.
3. I byte mostrati come copiati sono confermati dall'applicazione; l'heartbeat StoreOpen descrive invece una chiamata ancora in corso.
4. Catalogo e job sono persistenti e non dipendono dalla presenza delle cassette.
5. La formattazione automatica delle cassette nuove e distruttiva e richiede conferma esplicita; un ciclo APPEND non formatta mai il supporto registrato.
