# Amministrazione

Questa guida riguarda lo stato LTO Archiver **0.11.27** in
`C:\ProgramData\LtoBackupManager`. Mantenere la directory accessibile soltanto
a SYSTEM e Administrators come installato. Contiene `config.json`, `catalog.db`,
`logs`, `temp` e `run.lock`; cambiare permessi o copiare file mutabili durante
un job attivo puo compromettere le prove di recupero.

## Catalogo, backup e log

Il catalogo SQLite e autorevole per librerie, file, versioni, nastri, blocchi e
job. Il backup predefinito e
`C:\ProgramData\LtoBackupManager\backups\catalog\catalog-latest.db`; un
amministratore puo configurare una directory backup assoluta locale o UNC.
Conservare backup del catalogo indipendenti e provarne l'accesso prima di fare
affidamento su ricerca offline o piano ripristino.

I log sono in `C:\ProgramData\LtoBackupManager\logs`. Impostare la retention
secondo la politica privacy e incidenti, lasciando storia sufficiente per un
ciclo nastro completo e unmount. La retention deve ruotare o archiviare i log
vecchi, non cancellare le prove correnti durante un'indagine. Log e backup
catalogo sono dati operativi riservati.

## Capacita e concorrenza

Scegliere profili solo per LTO-5--LTO-10 supportati. Il piano include
allocazione LTFS e metadati di ogni oggetto e, dopo mount, usa il minimo tra
limite profilo, spazio libero Windows e `ltfs.mediaDataPartitionAvailableSpace`;
non usa la capacita generica di Explorer come partizione dati. Il margine
applicativo predefinito e zero.

`run.lock` serializza operazioni che modificano catalogo o drive. Un drive ha
un solo job attivo. La telemetria read-only puo essere indisponibile mentre
StoreOpen riserva il device, ma non deve diventare un job concorrente o probe
diretto.

## Finestre, upgrade e confini recupero

Pianificare manutenzione fuori da `formatting`, `mounting`, `writing` e
`unmounting`. Consentire upgrade solo senza job attivo, senza lettera LTFS
montata e dopo rilascio del lavoro indice StoreOpen/FUSE. Prima della modifica,
validare backup catalogo e registrare versione 0.11.27; dopo eseguire
`catalog check`.

L'applicazione recupera da stop controllato al checkpoint cassetta, ma non puo
dichiarare committed un nastro dopo provider flush o unmount interrotti.
`NUOVA` riparte da zero; `APPEND` conserva blocchi precedenti e scarta solo il
nuovo blocco provvisorio. Guasto server, applicazione, StoreOpen o alimentazione
durante finalizzazione puo richiedere strumenti HPE dopo rilascio sicuro drive.
Non forzare espulsione o eliminare stato per dichiarare completo un job.

## Confine dati pubblici

Non allegare mai a issue pubblici database catalogo o backup, log non
sanitizzati, support ticket, credenziali, chiavi private, account, hostname, IP
privati, ID job reali, etichette cassette reali, percorsi SMB, seriali device,
export registry o catture diagnostiche. Fornire solo estratti sanitizzati con
versione, ambiente generico, riproduzione e stato sicurezza.
