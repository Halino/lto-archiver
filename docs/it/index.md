# Manuali operatore di LTO Archiver

Questi manuali operatore descrivono la release pubblica **0.11.27** per Windows
Server 2022 e archivi SMB append-only su nastro LTFS. HPE StoreOpen, driver HPE
e strumenti di supporto HPE sono prerequisiti esterni; LTO Archiver non li
include.

## Scegliere il percorso

- [Nuova installazione](installation.md): prerequisiti, checksum, installer,
  CFA, aggiornamento e rimozione.
- [Primo backup](user-guide.md#primo-backup): registrare, scansionare,
  pianificare, salvare e avviare esplicitamente il primo job.
- [Operazioni ricorrenti](user-guide.md): cambio supporti, avanzamento, arresto,
  ricerca nel catalogo, esplorazione offline e ripristino.
- [Risoluzione problemi](../troubleshooting.md): diagnosi LTFS non distruttiva.
- [Sviluppo](../development.md) e [gestione release](../release-notes-0.11.27.md):
  sviluppo locale e record della release 0.11.27.

Leggere [amministrazione](administration.md) prima di gestire lo stato condiviso
e [operazioni LTFS](ltfs-operations.md) prima di diagnosticare un drive montato.
Gli stessi manuali sono disponibili in [English](../en/index.md).

## Confine di sicurezza

La scrittura LTO e sequenziale. `NUOVA` formatta una cassetta in modo
distruttivo, mentre `APPEND` conserva i dati committed. Un file e seguito dal
successivo solo dopo `close.complete`; una cassetta e completa solo quando
StoreOpen la smonta e l'indice LTFS e consolidato.
