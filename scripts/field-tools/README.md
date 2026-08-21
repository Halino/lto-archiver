# Strumenti diagnostici di campo

Questa cartella conserva gli strumenti nati durante le verifiche sul server Windows senza confonderli con gli script di build e installazione supportati.

## `read-only`

Script diagnostici riutilizzabili. Leggono processi, servizi, catalogo, eventi Windows, configurazione Defender o metadati StoreOpen e scrivono il risultato sotto `C:\Temp\LtoBackupManager`. Non montano, smontano, formattano o espellono cassette.

`probe-system-telemetry.ps1` interroga `TAPE0` tramite la CLI. Deve essere usato soltanto quando il drive non e impegnato da StoreOpen, per evitare contesa sul device.

## `controlled`

Procedure invasive da eseguire soltanto con autorizzazione esplicita e dopo avere verificato il job interessato:

- arresto forzato di probe o processi applicativi;
- reset di una cassetta interrotta nel catalogo;
- arresto StoreOpen e rimozione delle sole mappature possedute da LTO Archiver.

Questi script non inviano comandi di espulsione, ma possono interrompere un job o modificare il catalogo e non sono controlli di routine.

## `archive/2026-08-20`

Wrapper storici usati per installazioni, task pianificati e diagnosi delle versioni 0.11.8-0.11.22. Restano disponibili come evidenza tecnica, ma contengono percorsi, nomi task e numeri di versione fissi. Non devono essere eseguiti come procedure correnti. L'eventuale job ID reale presente nel wrapper di reset e stato anonimizzato.

Per la distribuzione corrente usare gli script versionati nella cartella `scripts` principale e la procedura descritta in `docs/development.md`.
