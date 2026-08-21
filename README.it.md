# LTO Archiver

[English](README.md)

Versione corrente: **0.11.26**.

## Cosa fa

LTO Archiver e un gestore Windows di backup e catalogo per archivi SMB
append-only su nastri LTFS. Scrive i file direttamente sul filesystem LTFS,
quindi restano normali file LTFS e non archivi TAR o contenitori proprietari.
Il catalogo SQLite locale supporta pianificazione, ricerca, esplorazione
offline, ripristino e verifica SHA-256.

## Modello di sicurezza

La scrittura su nastro e sequenziale: LTO Archiver scrive un file alla volta e
il successivo inizia solo dopo `close.complete`. La formattazione di una
cassetta nuova (`NUOVA`) e distruttiva. `APPEND` non formatta mai il nastro e
conserva i dati gia committed. Una cassetta e completa solo dopo l'unmount
riuscito di StoreOpen; fino ad allora l'indice LTFS e i nuovi dati scritti non
sono considerati committed.

## Funzionalita

- Pianifica la capacita su supporti da LTO-5 a LTO-10 senza dividere i file.
- Crea job salvati che richiedono un avvio esplicito, con un solo job attivo per
  drive e stato catalogo protetto.
- Copia direttamente su LTFS con `CopyFileEx`, registra SHA-256 ed espone
  avanzamento `write.pending`, `close.complete` e `unmount.progress`.
- Identifica le cassette LTFS tramite l'etichetta del volume. Il seriale Win32
  esposto da StoreOpen/FUSE resta diagnostico e può coincidere su cassette
  differenti.
- Registra un manifest per cassetta e distingue "Media effettiva cassetta"
  dall'ingresso nella cache LTFS. Il grafico usa "campioni regolari di un
  secondo" e la telemetria "non incrementa i byte" senza byte confermati.
- Cataloga i blocchi completati per ricerca offline, piano di ripristino e
  rimozione logica senza cancellare file SMB sorgenti o contenuti del nastro.

## Requisiti

- Windows Server 2022 x64.
- HPE StoreOpen 3.5.0 e driver HPE LTO versione 1.0.9.4 o una versione
  successiva supportata, oltre a drive e supporti compatibili.
- Accesso amministrativo per installazione e operazioni StoreOpen; lettura SMB
  delle sorgenti e scrittura sul volume LTFS per il lavoro di backup.

HPE StoreOpen, driver, firmware, Library and Tape Tools e installer sono
prerequisiti esterni. Non sono inclusi nel progetto.

## Avvio rapido

Dopo aver verificato il checksum della release, installare come amministratore
e confermare la versione della CLI installata:

```powershell
Get-FileHash .\LTO-Archiver-0.11.26.zip -Algorithm SHA256
& '.\install-lto-backup-manager.ps1' -SourceDirectory '.'
& 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe' --version
```

Registrare una libreria SMB solo di documentazione, poi usare la guida utente
per pianificare e avviare il primo job:

```powershell
LtoBackupManagerCli.exe library add `
  --id MEDIA_01 `
  --name 'Media Library 01' `
  --source '\\files.example.test\archive'
```

Non formattare, montare, smontare o espellere un nastro seguendo procedure
diverse dal flusso documentato.

## Documentazione

Iniziare dalla [documentazione italiana][it-index]. Le procedure estese sono
nella [guida di installazione][it-installation], [guida utente][it-user-guide],
[guida amministrativa][it-administration], [guida alle operazioni LTFS][it-ltfs],
[riferimento CLI][it-cli], [guida alla risoluzione problemi][it-troubleshooting],
[guida di sicurezza][it-security], [guida di sviluppo][it-development],
[processo di release][it-release-process] e [FAQ][it-faq].

## Release e verifica

Release pubblica corrente: **0.11.26**. Consultare il [changelog](CHANGELOG.md)
e il [processo di release][it-release-process] per controlli riproducibili.
Verificare SHA-256 dello ZIP e versione GUI/CLI prima della distribuzione.
Nessuna operazione sul server di produzione fa parte della preparazione della
release.

## Stato del progetto e limiti

La 0.11.26 aggiorna i cataloghi esistenti allo schema 13. La migrazione elimina
il vecchio vincolo univoco sul seriale Win32 diagnostico e rende univoca ogni
etichetta LTFS non vuota; non modifica cassette completate, blocchi, file, hash
o checkpoint. LTFS, StoreOpen, il drive e l'operatore controllano il
comportamento fisico del supporto. Una copia su nastro non e di per se una
strategia di ridondanza; il recupero dopo un unmount interrotto puo richiedere
gli strumenti HPE descritti nella [guida alle operazioni LTFS][it-ltfs].

## Contributi, supporto e sicurezza

Leggere la futura [guida ai contributi][contributing], [politica di supporto][support]
e [politica di sicurezza][security] prima di aprire un issue. Non inserire mai
credenziali, chiavi private, database catalogo, log non sanitizzati, support
ticket o identificatori operativi nei report pubblici.

## Licenza e marchi

Copyright 2026 Alessandro Gnagni. LTO Archiver e rilasciato con licenza
[Apache-2.0](LICENSE). HPE, StoreOpen, StoreEver e i nomi correlati sono marchi
dei rispettivi proprietari. LTO Archiver e indipendente e non e affiliato ne
approvato da Hewlett Packard Enterprise.

[it-index]: docs/it/index.md
[it-installation]: docs/it/installation.md
[it-user-guide]: docs/it/user-guide.md
[it-administration]: docs/it/administration.md
[it-ltfs]: docs/it/ltfs-operations.md
[it-cli]: docs/it/cli-reference.md
[it-troubleshooting]: docs/it/troubleshooting.md
[it-security]: docs/it/security.md
[it-development]: docs/it/development.md
[it-release-process]: docs/it/release-process.md
[it-faq]: docs/it/faq.md
[contributing]: CONTRIBUTING.md
[support]: SUPPORT.md
[security]: SECURITY.md
