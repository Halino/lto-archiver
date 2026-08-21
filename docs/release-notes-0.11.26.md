# LTO Archiver 0.11.26

## LTFS cartridge identity

- Different LTFS cartridges can now share the same Win32 serial exposed by HPE
  StoreOpen/FUSE without blocking a multi-tape job.
- The Win32 value returned by `GetVolumeInformationW` remains in the catalog as
  diagnostic information; it is no longer the unique media key.
- The LTFS volume label assigned during formatting is unique and is checked
  before every write or APPEND cycle. A different label is rejected even when
  the Win32 serial matches.
- Re-registering the same LTFS label refreshes the diagnostic Win32 serial
  without changing the cartridge identity or its history.

## Graph scale and finalization panel

The write-speed chart now shows two independent 0/50/100 percent scales: the
effective tape-rate scale on the left and the LTFS cache-ingress scale on the
right. Every tick includes its rate unit, so the two coloured axes remain
readable when their ceilings differ. The idle finalization panel is 64 pixels
high and expands while unmount finalization is active.

## LTFS close diagnostics

Long gaps between files are diagnosed in this order: StoreOpen ownership and
LTFS/FUSE events, then drive LED and TapeAlert signals, then an HPE Library and
Tape Tools support ticket after StoreOpen has released the device. Do not query
`TAPE0` or open the LTFS letter while StoreOpen owns the drive. Clean the drive
only when its LED, TapeAlert, or support guidance requests it.

## Public distribution and documentation

This preparation updates the public release metadata and Windows file/product
versions to 0.11.26. The release ZIP is named `LTO-Archiver-0.11.26.zip`.
Troubleshooting guidance documents the safe diagnostic order. No production
server operation is part of public release preparation.

## Compatibility and upgrade

LTO Archiver 0.11.26 supports Windows Server 2022 and StoreOpen 3.5.0. Existing
catalogs are upgraded to schema 13. The migration removes only the former
unique index on the diagnostic Win32 serial and creates a unique index on
non-empty LTFS volume labels; completed tapes, blocks, files, hashes, and
checkpoints are not changed.

## Verification

The release checks the schema 12-to-13 migration, two distinct LTFS labels with
the same Win32 serial, rejection of a wrong label, metadata seams, GUI chart and
finalization behaviour, and documentation. Verify that the packaged Windows
executables report file/product version 0.11.26.0 before distribution.

---

# LTO Archiver 0.11.26 — Italiano

## Identità delle cassette LTFS

- Cassette LTFS diverse possono ora condividere lo stesso seriale Win32 esposto
  da HPE StoreOpen/FUSE senza bloccare un job multi-cassetta.
- Il valore Win32 restituito da `GetVolumeInformationW` resta nel catalogo come
  informazione diagnostica e non è più la chiave univoca del supporto.
- L'etichetta LTFS assegnata durante la formattazione è univoca e viene
  controllata prima di ogni scrittura o ciclo APPEND. Un'etichetta diversa viene
  rifiutata anche quando il seriale Win32 coincide.
- La nuova registrazione della stessa etichetta LTFS aggiorna il seriale Win32
  diagnostico senza modificare l'identità o la storia della cassetta.

## Scala del grafico e pannello di finalizzazione

Il grafico della velocità di scrittura mostra due scale indipendenti allo
0/50/100 percento: la velocità effettiva del nastro a sinistra e l'ingresso
nella cache LTFS a destra. Ogni tacca include l'unità di velocità. Il pannello di
finalizzazione inattivo è alto 64 pixel e si espande durante l'unmount.

## Diagnostica della chiusura LTFS

Le attese lunghe tra due file vengono diagnosticate in questo ordine: proprietà
StoreOpen ed eventi LTFS/FUSE, poi LED del drive e segnali TapeAlert, infine un
support ticket HPE Library and Tape Tools dopo che StoreOpen ha rilasciato il
device. Non interrogare `TAPE0` e non aprire la lettera LTFS mentre StoreOpen
possiede il drive. Pulire il drive soltanto quando lo richiedono LED, TapeAlert o
le indicazioni del supporto.

## Distribuzione pubblica e documentazione

La preparazione aggiorna i metadati pubblici e le versioni file/prodotto Windows
alla 0.11.26. Lo ZIP è `LTO-Archiver-0.11.26.zip`. Nessuna operazione sul server
di produzione fa parte della preparazione della release pubblica.

## Compatibilità e aggiornamento

LTO Archiver 0.11.26 supporta Windows Server 2022 e StoreOpen 3.5.0. I cataloghi
esistenti vengono migrati allo schema 13. La migrazione elimina soltanto il
vecchio indice univoco sul seriale Win32 diagnostico e crea un indice univoco
sulle etichette LTFS non vuote; cassette completate, blocchi, file, hash e
checkpoint non vengono modificati.

## Verifica

La release verifica la migrazione dallo schema 12 al 13, due etichette LTFS
distinte con lo stesso seriale Win32, il rifiuto di un'etichetta errata, i
metadati, il grafico GUI, il pannello di finalizzazione e la documentazione.
Prima della distribuzione verificare che gli eseguibili Windows riportino la
versione file/prodotto 0.11.26.0.
