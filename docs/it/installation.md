# Installazione su Windows Server 2022

Questa procedura installa LTO Archiver **0.11.26**. Supporta Windows Server
2022 x64, HPE StoreOpen 3.5.0, un driver HPE LTO supportato e drive e supporti
HPE LTO compatibili. Installazione e operazioni StoreOpen richiedono un
amministratore; gli operatori backup necessitano anche di lettura della sorgente
SMB e scrittura sul volume LTFS.

## Ottenere i prerequisiti e verificare la release

Ottenere StoreOpen 3.5.0, il driver supportato, informazioni firmware e HPE
Library and Tape Tools direttamente da HPE per l'hardware installato. Lo ZIP di
LTO Archiver non contiene ne ridistribuisce software HPE. Scaricare il checksum
pubblicato con la release e confrontarlo con:

```powershell
Get-FileHash .\LTO-Archiver-0.11.26.zip -Algorithm SHA256
```

Estrarre localmente soltanto uno ZIP il cui SHA-256 coincide con il valore
pubblicato. Avviare PowerShell come amministratore e lanciare l'installer:

```powershell
& '.\install-lto-backup-manager.ps1' -SourceDirectory '.'
& 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe' --version
```

Il comando versione deve riportare `0.11.26`. L'installer verifica gli hash GUI
e CLI, installa in `C:\Program Files\LtoBackupManager`, protegge
`C:\ProgramData\LtoBackupManager` per SYSTEM e Administrators e crea un backup
del catalogo esistente prima di sostituire gli eseguibili.

## Controlled Folder Access e permessi di stato

Con Controlled Folder Access (CFA) attivo, l'installer aggiunge soltanto questi
due percorsi applicativi alla allow-list e verifica la regola salvata:

- `C:\Program Files\LtoBackupManager\LtoBackupManager.exe`
- `C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe`

Non disattiva Defender e non crea esclusioni ampie di cartella, processo o
device. Se CFA e gestito da GPO o Intune, usare `-SkipControlledFolderAccess` e
autorizzare centralmente esattamente quei percorsi. Non allentare l'ACL di
`C:\ProgramData\LtoBackupManager`: contiene catalogo, checkpoint,
configurazione, backup e stato job.

Dopo l'installazione controllare anche il catalogo con la stessa directory di
stato privilegiata:

```powershell
& 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe' `
  --state-dir 'C:\ProgramData\LtoBackupManager' catalog check
```

Con la 0.11.26 il comando riporta schema catalogo 13. La migrazione conserva il
seriale Win32 di StoreOpen come informazione diagnostica, consente che cassette
diverse condividano quel valore e rende univoca ogni etichetta LTFS non vuota.
Prima di un job reale, verificare che la GUI mostri `write.pending`,
`close.pending`, `close.complete` e `timing.complete`; il file successivo non
deve iniziare prima di `close.complete`.

## Aggiornamento e disinstallazione

Aggiornare solo quando nessun job e `formatting`, `mounting`, `writing` o
`unmounting`. Fermare a un confine sicuro oppure lasciare completare la
cassetta, attendere la scomparsa della lettera LTFS e la fine del lavoro indice
StoreOpen/FUSE, chiudere la GUI e rieseguire l'installer. Non sostituire file
manualmente a GUI aperta. L'installer conserva `config.json`, `catalog.db`, job,
checkpoint e backup catalogo.

Per disinstallare, prima accertarsi che non esistano job attivi ne volumi LTFS
montati; conservare un backup verificato del catalogo se serve per esplorazione
offline o piano di ripristino. Rimuovere l'applicazione con il meccanismo di
disinstallazione Windows. Rimuovere l'applicazione o la allow-list CFA non
cancella di per se catalogo, job o backup; non eliminare la directory di stato
finche il suo valore di recupero non sia stato deliberatamente dismesso.
