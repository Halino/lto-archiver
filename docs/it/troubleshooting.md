# Risoluzione problemi

Usare il confine in tre parti per ogni sintomo. “Vietate” include secondo job,
CLI mutante, Explorer su nastro montato, probe diretto `TAPE0`, arresto
`FUSE4WinSvc`, eject o riuso lettera salvo rilascio sicuro esplicito. Redigere
sempre le prove.

## Copia sicura per diagnostica catalogo

Prima di `doctor` o `catalog check`, assicurarsi che non esista job attivo e
chiudere tutte le istanze GUI/CLI LTO Archiver. Preservare directory stato
originale intatta; creare copia eliminabile dell'*intera* directory, poi usare
globale `--state-dir` sulla copia. Non eseguire mai la diagnostica contro
l'originale preservato.

```powershell
$stateDirectory = 'C:\ProgramData\LtoBackupManager'
$diagnosticRoot = Join-Path $env:TEMP ("LtoArchiver-DiagnosticCopy-" + [guid]::NewGuid())
$diagnosticStateDirectory = Join-Path $diagnosticRoot 'LtoBackupManager'
if (Get-Process -Name 'LtoBackupManager','LtoBackupManagerCli' -ErrorAction SilentlyContinue) {
  throw 'Chiudere tutte le istanze LTO Archiver prima di copiare lo stato.'
}
New-Item -ItemType Directory -Path $diagnosticRoot -ErrorAction Stop | Out-Null
Copy-Item -LiteralPath $stateDirectory -Destination $diagnosticRoot -Recurse -ErrorAction Stop
& 'C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe' `
  --state-dir $diagnosticStateDirectory catalog check
```

Usare lo stesso `--state-dir $diagnosticStateDirectory` copiato per `doctor`;
non aprire copia diagnostica concorrente con applicazione live. Originale resta
per prove/recupero anche se copia upgrade impostazioni, crea log, migra catalogo.
Directory unica e nuova a ogni esecuzione; se creazione o copia ricorsiva fallisce,
`-ErrorAction Stop` impedisce di proseguire con comando diagnostico.

## Job salvato ma non avviato

**Osservazione sicura:** confermare stato salvato, libreria e richiesta avvio
esplicito. **Azioni concorrenti vietate:** non avviare duplicato ne trattare
salvato come running. **Escalation:** fornire stato/timestamp anonimizzati ad admin.

## Job conflittuale o `run.lock`

**Osservazione sicura:** identificare owner e confine sicuro. **Azioni
concorrenti vietate:** non uccidere owner, prendere lock, creare altro writer.
**Escalation:** conservare tempi lock/log per revisione admin dopo rilascio.

## Mount lento

**Osservazione sicura:** osservare heartbeat, lettera LTFS, eventi `ltfs.exe`/
`FUSE4WinSvc`; mount puo richiedere minuti. **Azioni concorrenti vietate:** non
riusare lettera, sondare device, lanciare altro job. **Escalation:** dopo rilascio
sicuro fornire eventi StoreOpen/FUSE sanitizzati a supporto HPE.

## Close `CopyFileEx` bloccato

**Osservazione sicura:** in `write.pending`/`close.pending` osservare heartbeat;
completamento solo `close.complete`. **Azioni concorrenti vietate:** non forzare
close, Explorer, query device. **Escalation:** dopo rilascio raccogliere log e
support ticket HPE L&TT.

## Nessun campione cache

**Osservazione sicura:** traccia assente significa nessun campione confermato,
non velocita zero; confrontare eta campione/media effettiva. **Azioni
concorrenti vietate:** non inventare byte o riavviare job. **Escalation:**
conservare timeline log/heartbeat e far rivedere telemetria StoreOpen dopo rilascio.

## Unmount lungo

**Osservazione sicura:** osservare `unmount.progress`, sync indice, rilascio
lettera/eject; non esiste timeout applicativo. **Azioni concorrenti vietate:**
non spegnere, fermare FUSE, togliere media, dichiarare committed. **Escalation:**
dopo rilascio fornire log finalizzazione e prove HPE L&TT.

## Lettera drive residua

**Osservazione sicura:** verificare StoreOpen chiuso e assenza volume LTFS.
**Azioni concorrenti vietate:** non cancellare mapping ignoto o riusare lettera.
**Escalation:** conservare log, pulizia supportata solo dopo owner identificato.

## Defender o Controlled Folder Access

**Osservazione sicura:** ispezionare cronologia Defender e percorso eseguibile.
**Azioni concorrenti vietate:** non disabilitare Defender/esclusioni ampie.
**Escalation:** chiedere solo allow-list GUI/CLI installati via GPO/Intune con
prova evento bloccato.

## Nastro errato

**Osservazione sicura:** confrontare l'etichetta del volume LTFS registrata con
`doctor --tape ... --mount ...`; il seriale Win32 è diagnostico e può coincidere
su cassette diverse. Il comando può aggiornare impostazioni, creare log e
inizializzare/migrare il catalogo, quindi conservare prima lo stato sospetto.
**Azioni concorrenti vietate:** mai scrivere “per prova” o aggirare l'identità.
**Escalation:** fornire mismatch dell'etichetta e log anonimizzati all'operatore.

## Nastro pieno

**Osservazione sicura:** conservare errore capacita e valori pianificati/restanti.
**Azioni concorrenti vietate:** non eliminare file LTFS/righe catalogo per spazio.
**Escalation:** pianificare altra cassetta e inviare prova capacita all'operatore.

## TapeAlert

**Osservazione sicura:** registrare TapeAlert e log sicuri. **Azioni concorrenti
vietate:** non assessment distruttivo su media dati. **Escalation:** dopo rilascio
allegare lettura a support ticket HPE L&TT.

## LED Clean

**Osservazione sicura:** ispezionare LED fisico e guida vendor. **Azioni
concorrenti vietate:** non tamponi/pulizia preventiva. **Escalation:** pulire solo
LED lampeggiante o `Clean Now`, `Clean Periodic`, `Clean requested`, con `C7978A`;
richiesta persistente dopo media buona richiede assistenza drive.

## Integrita catalogo

**Osservazione sicura:** prima copiare stato sospetto; poi, solo se accettabile,
`catalog check`/`doctor`, non sola lettura forense: possono upgrade impostazioni,
creare log, `initialize`/migrare catalogo. **Azioni concorrenti vietate:** non
modificare SQLite o secondo writer. **Escalation:** output integrita/chiavi e backup
verificato a administrator.

## Job interrotto

**Osservazione sicura:** stabilire interruzione prima/durante flush/unmount.
**Azioni concorrenti vietate:** non forzare eject, eliminare checkpoint, dichiarare
blocco provvisorio completo. **Escalation:** reset automatico riparte/riformatta
da zero; preservare stato ed escalare failure finalizzazione dopo rilascio media.

## Verifica release

**Osservazione sicura:** confrontare SHA-256, `--version`, `catalog check`,
eseguibili, contenuto ZIP; preservare stato prima di `catalog check` perche puo
mutare prove diagnostiche. **Azioni concorrenti vietate:** non distribuire,
sovrascrivere install, pubblicare log/catalogo/identificativi se fallisce.
**Escalation:** riportare controllo fallito e metadata artefatto anonimizzati per
recupero release deliberato.

Riferimenti: [indicatori HPE](https://support.hpe.com/hpesc/public/docDisplay?docId=c05170118&docLocale=en_US), [ticket HPE L&TT](https://support.hpe.com/hpesc/public/docDisplay?docId=sd00003778en_us&page=GUID-D7147C7F-2016-0901-04BD-000000000A28.html), [CFA Microsoft](https://learn.microsoft.com/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-antivirus/controlled-folders).
