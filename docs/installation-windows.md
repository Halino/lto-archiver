# Installazione Windows di LTO Archiver

Versione corrente: **0.11.27**.

Questa procedura vale per nuove installazioni e aggiornamenti. La release corrente e la **0.11.27**. L'archivio contiene i due eseguibili, i relativi SHA-256, l'installer, il configuratore di Controlled Folder Access (CFA) e una copia di questa guida.

## Prerequisiti

- Windows Server 2022 x64;
- HPE StoreOpen e driver del drive LTO gia installati;
- PowerShell avviata **come amministratore**;
- accesso SMB alle librerie da archiviare.

## Installazione automatica

Estrarre il rilascio in una cartella locale e avviare:

```powershell
& '.\install-lto-backup-manager.ps1' -SourceDirectory $PWD
```

L'installer:

1. verifica gli SHA-256 di GUI e CLI;
2. protegge `C:\ProgramData\LtoBackupManager` con ACL per SYSTEM e Administrators;
3. crea un backup pre-aggiornamento del catalogo esistente;
4. installa i file in `C:\Program Files\LtoBackupManager`;
5. se CFA e attivo, aggiunge alla sola allow-list applicativa i percorsi esatti di GUI e CLI e ne verifica la persistenza;
6. controlla il catalogo e crea il collegamento `LTO Archiver` sul Desktop pubblico.

Defender, protezione in tempo reale e scansione antivirus restano attivi. Non vengono create esclusioni di cartella, processo o dispositivo.

## Aggiornamento di un'installazione esistente

1. Non avviare l'aggiornamento durante `formatting`, `mounting`, `writing` o `unmounting`.
2. Se e in corso una copia, usare **Interrompi ora** e attendere la conclusione dell'unmount; in alternativa lasciare completare la cassetta.
3. Verificare che la lettera LTFS sia scomparsa e che il servizio StoreOpen/FUSE non stia ancora consolidando l'indice.
4. Chiudere LTO Archiver.
5. Estrarre la nuova release in una cartella locale e rieseguire lo stesso installer amministrativo.

L'installer conserva `config.json`, `catalog.db`, job, checkpoint e backup del catalogo. Prima di sostituire gli eseguibili crea una copia consistente del catalogo. Non e supportata la sostituzione manuale dei file mentre la GUI e aperta.

Per la 0.11.27, la verifica minima dopo l'aggiornamento e:

```powershell
& 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe' --version
& 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe' `
  --state-dir 'C:\ProgramData\LtoBackupManager' catalog check
```

Il primo comando deve riportare `0.11.27` e il controllo catalogo deve riportare schema `13`; questa release non esegue nuove migrazioni. Lo schema 13 conserva il seriale Win32 di StoreOpen come informazione diagnostica, consente che cassette differenti espongano lo stesso valore e rende univoca l'etichetta LTFS. Prima di una formattazione, eventuali mappature StoreOpen residue marcate `LTOArchiver` devono essere fermate e rimosse; una mappatura estranea deve invece bloccare il job senza essere modificata. Alla prima scrittura, la pagina del job deve mostrare `write.pending`, `close.pending`, `close.complete` e `timing.complete`. Il file successivo deve iniziare soltanto dopo `close.complete`; non deve comparire una coda residua di handle a fine blocco. Durante una chiamata StoreOpen bloccante il tempo trascorso deve continuare ad avanzare. La GUI deve distinguere **Media effettiva cassetta** da **Invio alla cache LTFS**; il grafico a cinque minuti deve usare campioni regolari di un secondo, non interpolare i punti e lasciare un buco quando manca un campione cache. Il monitor di finalizzazione deve distinguere le fasi in corso, completate e fallite, bloccare il cronometro al termine e tornare inattivo dopo l'espulsione; la media cassetta deve restare visibile durante la sincronizzazione dell'indice. Prima di riprendere un job creato con una versione precedente, il catalogo deve creare il manifest delle cassette residue; nessun mount deve iniziare se un percorso pianificato manca o risulta modificato. Alla ripresa di un job concluso la coda deve distinguere **APPEND - conserva i dati** da **NUOVA - formatta LTFS**. Il controllo capacita deve inoltre mostrare il libero nativo LTFS e l'allocazione/metadati separati dal payload. Per provare il riuso distruttivo, verificare inoltre che una cassetta registrata sia rifiutata senza il consenso separato e accettata quando l'opzione e selezionata.

## Ambienti gestiti centralmente

Se CFA viene configurato esclusivamente tramite GPO, Intune o un altro sistema centrale, evitare la modifica locale con:

```powershell
& '.\install-lto-backup-manager.ps1' -SourceDirectory $PWD -SkipControlledFolderAccess
```

In questo caso la gestione centrale deve autorizzare:

- `C:\Program Files\LtoBackupManager\LtoBackupManager.exe`
- `C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe`

## Verifica

```powershell
$preference = Get-MpPreference
$preference.EnableControlledFolderAccess
$preference.ControlledFolderAccessAllowedApplications
& 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe' --version
& 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe' `
  --state-dir 'C:\ProgramData\LtoBackupManager' catalog check
```

Con CFA attivo, il primo comando deve restituire `1` e l'elenco deve contenere entrambi gli eseguibili. Se CFA viene attivato dopo l'installazione, la GUI ripete il controllo al successivo avvio elevato.

## Sicurezza e rimozione della regola

L'allow-list CFA autorizza soltanto i due file applicativi installati. Gli aggiornamenti mantengono gli stessi percorsi e ripetono la verifica. Per rimuovere in seguito le sole autorizzazioni applicative:

```powershell
Remove-MpPreference -ControlledFolderAccessAllowedApplications `
  'C:\Program Files\LtoBackupManager\LtoBackupManager.exe', `
  'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe'
```

La rimozione non cancella catalogo, job o backup, ma Defender tornera a bloccare l'accesso diretto al drive finche i percorsi non vengono nuovamente autorizzati.

## Installazioni future automatizzate

Il pacchetto e autosufficiente: non richiede Python sul server. Per una distribuzione ripetibile conservare insieme tutti i file estratti e invocare soltanto `install-lto-backup-manager.ps1`. Lo script e idempotente sui percorsi installati, verifica gli hash prima della copia e applica l'allow-list CFA soltanto quando necessaria.

Non automatizzare la chiusura forzata durante una scrittura. Un orchestratore deve prima verificare l'assenza di un job attivo e di un volume LTFS montato. Se la sicurezza endpoint e gestita centralmente, usare `-SkipControlledFolderAccess` e distribuire separatamente le due regole applicative esatte indicate sopra.
