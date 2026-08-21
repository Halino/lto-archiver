# LTO Archiver 0.11.27

## LTFS finalization status

- The finalization monitor now reports the real state of every LTFS unmount
  phase: in progress, complete, or failed.
- A completed or failed phase keeps its recorded elapsed time instead of
  continuing to count while the application is idle.
- After StoreOpen successfully ejects the cartridge, or the automatic job
  reaches another terminal event after a completed unmount, the monitor returns
  to its compact idle state. It no longer remains on the final eject phase.
- The compact idle panel retains the 64-pixel height introduced in 0.11.26 so
  the idle label and explanatory text are fully visible.

## Compatibility and upgrade

LTO Archiver 0.11.27 supports Windows Server 2022 and StoreOpen 3.5.0. Catalog
schema 13 remains unchanged: this release performs no new catalog migration and does not
modify completed tapes, blocks, files, hashes, manifests, or checkpoints.

The release ZIP is named `LTO-Archiver-0.11.27.zip`. No production-server
operation is part of preparing or publishing this release.

## Verification

The release tests pending, completed, and failed finalization states; frozen
elapsed time after completion; reset to idle after eject; metadata consistency;
the complete public source manifest; and the packaged Windows executables.
Before distribution, both executables must report version 0.11.27 and their
Windows file/product metadata must report 0.11.27.0.

---

# LTO Archiver 0.11.27 — Italiano

## Stato della finalizzazione LTFS

- Il monitor di finalizzazione ora mostra lo stato reale di ogni fase di
  unmount LTFS: in corso, completata oppure fallita.
- Una fase completata o fallita mantiene il tempo trascorso registrato, senza
  continuare a incrementarlo mentre l'applicazione è inattiva.
- Dopo l'espulsione riuscita da StoreOpen, o un altro evento terminale del job
  automatico successivo a un unmount completato, il monitor torna allo stato
  inattivo compatto. Non resta più bloccato sull'ultima fase di espulsione.
- Il pannello inattivo conserva l'altezza di 64 pixel introdotta nella 0.11.26,
  così etichetta e testo esplicativo restano completamente visibili.

## Compatibilità e aggiornamento

LTO Archiver 0.11.27 supporta Windows Server 2022 e StoreOpen 3.5.0. Lo schema
del catalogo resta 13: questa release non esegue nuove migrazioni e non modifica
cassette completate, blocchi, file, hash, manifest o checkpoint.
Lo schema continua a trattare il seriale Win32 di StoreOpen come informazione
diagnostica e l'etichetta del volume LTFS come identità univoca della cassetta.

Lo ZIP della release è `LTO-Archiver-0.11.27.zip`. La preparazione e la
pubblicazione non includono operazioni sul server di produzione.

## Verifica

La release verifica gli stati di finalizzazione in corso, completato e fallito;
il blocco del tempo trascorso dopo il completamento; il ritorno allo stato
inattivo dopo l'espulsione; la coerenza dei metadati; il manifest pubblico
completo; e gli eseguibili Windows inclusi. Prima della distribuzione entrambi
gli eseguibili devono riportare la versione 0.11.27 e i metadati file/prodotto
Windows devono riportare 0.11.27.0.
